use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use boringtun::noise::Tunn;
use vita_sync::Mutex;

use crate::WgError;

/// Optional path-selection oracle the pump consults at send time.
///
/// Implementors (e.g. `ts-magicsock::MagicSocketCtl`) report whether a
/// peer has a Disco-validated direct UDP path right now. If `Some(addr)`,
/// the pump uses `TransportAddr::Udp(addr)`; if `None`, falls back to the
/// peer's cached `transport_addr` (Derp).
pub trait DirectPathHint: Send + Sync {
    fn alive_endpoint(&self, peer_pubkey: &[u8; 32]) -> Option<SocketAddr>;
}

/// Where to send encrypted WireGuard datagrams for a peer.
///
/// - `Udp` (M2): direct UDP — used by the M2 hardcoded-peer ICMP harness
///   and by anyone running a wireguard-go peer on the same network.
/// - `Derp` (M8): Tailscale DERP relay over TLS/443. The `peer_pubkey`
///   is the destination's `key.NodePublic` (32 raw bytes); the relay
///   uses it to demux SendPacket → RecvPacket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportAddr {
    Udp(SocketAddr),
    Derp {
        region: u16,
        peer_pubkey: [u8; 32],
    },
}

/// A `prefix`-bit IPv4 CIDR. Hand-rolled to avoid pulling smoltcp into
/// the wg-engine crate (smoltcp is for the in-tunnel netstack, not the
/// outer engine).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Ipv4Cidr {
    pub fn parse(s: &str) -> Result<Self, WgError> {
        let (addr_s, prefix_s) = s
            .split_once('/')
            .ok_or_else(|| WgError::BadCidr(s.into()))?;
        let addr: Ipv4Addr = addr_s.parse().map_err(|_| WgError::BadCidr(s.into()))?;
        let prefix: u8 = prefix_s.parse().map_err(|_| WgError::BadCidr(s.into()))?;
        if prefix > 32 {
            return Err(WgError::BadCidr(s.into()));
        }
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask: u32 = if self.prefix == 0 {
            0
        } else {
            (!0u32) << (32 - self.prefix)
        };
        let net = u32::from(self.addr) & mask;
        (u32::from(ip) & mask) == net
    }
}

/// Caller-supplied per-peer configuration.
pub struct PeerConfig {
    pub pubkey: x25519_dalek::PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive_secs: Option<u16>,
    pub allowed_ips: Vec<Ipv4Cidr>,
    pub initial_endpoint: Option<TransportAddr>,
}

/// One peer's runtime state. Constructed once at `Engine::new`; the
/// engine holds an `Arc<Peer>` in three different lookup tables.
pub struct Peer {
    pub pubkey: [u8; 32],
    /// The peer index we passed to `Tunn::new`. BoringTun shifts this left
    /// by 8 internally to derive session indices, so for inbound dispatch
    /// we extract it back via `receiver_idx >> 8`.
    pub our_index: u32,
    pub allowed_ips: Vec<Ipv4Cidr>,
    pub transport_addr: ArcSwap<Option<TransportAddr>>,
    /// WireGuard-style roaming endpoint: the source of the most recent
    /// AUTHENTICATED inbound packet (a handshake/data that the `Tunn` accepted),
    /// plus WHEN it arrived. Replies go here first — exactly like a Disco pong
    /// replies to the ping's source — so a roaming/symmetric-NAT peer is
    /// answered at wherever it actually reached us from, not a possibly-stale
    /// Disco-discovered endpoint. Set only on authenticated packets (safe re:
    /// M12's "don't roam on junk").
    ///
    /// M20-A3: the timestamp bounds trust (upstream `trustUDPAddrDuration`,
    /// 6.5 s). Refreshed on every authenticated inbound, so it only goes stale
    /// across idle gaps — and a stale one is exactly how the 2026-07-04
    /// WAN-hairpin address stayed selected for 2½ minutes. `pick_addr` skips
    /// (but doesn't clear) a stale entry and falls to the Disco hint, which the
    /// 3 s heartbeat (M20-A1) keeps continuously alive to catch the handoff.
    pub auth_src: ArcSwap<Option<(TransportAddr, Instant)>>,
    /// `Tunn` is `!Sync`. Held only on the wg_engine thread; never held
    /// across I/O or filesystem operations.
    pub tunn: Mutex<Tunn>,
    pub stats: Mutex<PeerStats>,
}

impl Peer {
    pub fn transport_addr_load(&self) -> Option<TransportAddr> {
        // Guard derefs to Arc<Option<T>>, as_ref() yields &Option<T>; T is Copy
        // so deref-copying the Option is fine.
        *self.transport_addr.load().as_ref()
    }

    pub fn set_transport_addr(&self, addr: TransportAddr) {
        self.transport_addr.store(Arc::new(Some(addr)));
    }

    /// The auth_src address regardless of freshness — for diagnostics
    /// (selection_log). Path selection must use `auth_src_fresh`.
    pub fn auth_src_load(&self) -> Option<TransportAddr> {
        self.auth_src.load().as_ref().map(|(addr, _)| addr)
    }

    /// The auth_src address only while inside its trust window
    /// (`AUTH_SRC_TRUST`). `now` is a parameter for testability.
    pub fn auth_src_fresh(&self, now: Instant) -> Option<TransportAddr> {
        self.auth_src.load().as_ref().and_then(|(addr, at)| {
            (now.duration_since(at) < crate::AUTH_SRC_TRUST).then_some(addr)
        })
    }

    pub fn set_auth_src(&self, addr: TransportAddr) {
        self.auth_src.store(Arc::new(Some((addr, Instant::now()))));
    }

    /// Test-only: backdate the auth_src stamp to simulate an idle gap.
    #[cfg(test)]
    pub fn set_auth_src_at(&self, addr: TransportAddr, at: Instant) {
        self.auth_src.store(Arc::new(Some((addr, at))));
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct PeerStats {
    pub handshakes_started: u64,
    pub handshakes_completed: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_rx: Option<Instant>,
    pub last_handshake: Option<Instant>,
}
