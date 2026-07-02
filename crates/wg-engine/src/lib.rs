//! Multi-peer BoringTun host for tailscale-vita.
//!
//! M2 wires this against `UdpTransport` and a hand-crafted ICMP test
//! harness; M3 plugs it into smoltcp via `Arc<Mutex<VecDeque<Vec<u8>>>>`
//! shared with `EngineRunning`; M8 swaps `UdpTransport` for `DerpTransport`.
//!
//! The hot loop lives in `pump.rs`. Public API is `Engine::new` →
//! `Engine::start` → drain `EngineRunning.tun_rx` / push to `tun_tx`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use vita_thread::JoinHandle;

use arc_swap::ArcSwap;
use boringtun::noise::Tunn;
use vita_sync::{Condvar, Mutex};
use vita_log::info;

mod config;
mod dispatch;
pub mod icmp;
mod indices;
mod peer;
mod pump;
mod queue;
mod transport;

mod error;

pub use config::{build_engine_inputs, decode_priv_key, decode_pub_key, read_wg_toml, WgToml};
pub use error::WgError;
pub use peer::{DirectPathHint, Ipv4Cidr, Peer, PeerConfig, PeerStats, TransportAddr};
pub use transport::{NoopTransport, Transport, UdpTransport};

/// Fork-B diagnostic: bounded ring of outbound path-selection decisions,
/// pre-formatted for raw tracing. `handle_outbound` (data), `tick_timers`
/// (timer keepalives) and `handle_inbound` (src-addr replies) record here;
/// the egress probe's harvest loop drains it into `wgsel:` trace lines.
/// Answers "which PEER did the engine map this reply to, and why did
/// pick_addr choose that endpoint" — the question send-level records
/// structurally cannot (see docs/EGRESS-PROBE.md).
pub mod selection_log {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    static LOG: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
    const CAP: usize = 96;

    pub(crate) fn record(line: String) {
        let mut g = match LOG.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if g.len() >= CAP {
            g.pop_front();
        }
        g.push_back(line);
    }

    /// Drain all recorded selection lines.
    pub fn take() -> Vec<String> {
        let mut g = match LOG.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        g.drain(..).collect()
    }
}

use indices::Indices;

/// Caller-supplied engine configuration.
pub struct EngineConfig {
    pub our_static_secret: x25519_dalek::StaticSecret,
    /// In-tunnel MTU. v1 default 1280.
    pub mtu: usize,
    pub peers: Vec<PeerConfig>,
}

impl EngineConfig {
    pub fn from_wg_toml(toml: &WgToml) -> Result<Self, WgError> {
        let (secret, peers) = build_engine_inputs(toml)?;
        Ok(Self {
            our_static_secret: secret,
            mtu: 1280,
            peers,
        })
    }
}

/// Shared engine state. Cheap to clone (it's `Arc<Inner>`-shaped via the
/// `Arc<Indices>` interior). Construct once at startup; `start` spawns
/// the pump thread driving a `Transport`.
pub struct Engine {
    indices: Arc<Indices>,
    next_idx: AtomicU32,
    our_static_secret: x25519_dalek::StaticSecret,
}

impl Engine {
    /// Build an engine with the given peer set. Each peer gets a fresh
    /// `Tunn` instance; on `start`, the pump primes the handshake init
    /// for any peer with a known transport address.
    pub fn new(cfg: EngineConfig) -> Result<Self, WgError> {
        let indices = Arc::new(Indices::new());
        let next_idx = AtomicU32::new(1);
        let engine = Self {
            indices,
            next_idx,
            our_static_secret: cfg.our_static_secret,
        };
        for peer_cfg in cfg.peers {
            engine.upsert_peer(peer_cfg)?;
        }
        Ok(engine)
    }

    /// Add or update a peer entry by pubkey.
    ///
    /// Fast path: if the peer already exists with the SAME `allowed_ips`,
    /// this is an attribute update (endpoint roam, online/offline, DERP-home,
    /// NetInfo) — NOT a new peer. We PRESERVE the existing `Tunn` + `our_index`
    /// so the established WireGuard session survives, and only refresh the
    /// endpoint. Only a new pubkey or a changed route set allocates a fresh
    /// `Tunn`.
    ///
    /// Why this matters: the old code did an unconditional remove+recreate,
    /// reassigning `our_index` on EVERY control-plane peer update (constant in
    /// a live tailnet). That tore down the session; the peer kept sending data
    /// to the old receiver-index, which `route_inbound` dropped as unroutable
    /// Junk — so real inbound ping/TCP almost never decrypted while Disco
    /// (magicsock) still pong'd. (wg data-plane bug, root-caused 2026-06-24.)
    pub fn upsert_peer(&self, cfg: PeerConfig) -> Result<(), WgError> {
        let pubkey_bytes: [u8; 32] = *cfg.pubkey.as_bytes();

        // Fast path: same peer, same route set → update endpoint in place,
        // keep the live session. The read guard is dropped after `.cloned()`.
        let existing = self.indices.by_pubkey.read().get(&pubkey_bytes).cloned();
        if let Some(peer) = existing {
            if peer.allowed_ips == cfg.allowed_ips {
                if let Some(ep) = cfg.initial_endpoint {
                    peer.set_transport_addr(ep);
                }
                return Ok(());
            }
            // allowed_ips changed: a genuine route-set change for this peer.
            // Fall through to a full rebuild (rare).
        }

        // New peer, or changed route set: (re)build with a fresh Tunn.
        self.indices.remove(&pubkey_bytes);

        let our_index = self.next_idx.fetch_add(1, Ordering::Relaxed);
        let tunn = Tunn::new(
            self.our_static_secret.clone(),
            cfg.pubkey,
            cfg.preshared_key,
            cfg.persistent_keepalive_secs,
            our_index,
            None,
        );

        let peer = Arc::new(Peer {
            pubkey: pubkey_bytes,
            our_index,
            allowed_ips: cfg.allowed_ips,
            transport_addr: ArcSwap::from(Arc::new(cfg.initial_endpoint)),
            auth_src: ArcSwap::from(Arc::new(None)),
            tunn: Mutex::new(tunn),
            stats: Mutex::new(PeerStats::default()),
        });

        self.indices.insert(peer);
        Ok(())
    }

    pub fn remove_peer(&self, pubkey: &x25519_dalek::PublicKey) {
        self.indices.remove(pubkey.as_bytes());
    }

    pub fn set_endpoint(&self, pubkey: &x25519_dalek::PublicKey, endpoint: TransportAddr) {
        if let Some(peer) = self.indices.by_pubkey.read().get(pubkey.as_bytes()).cloned() {
            peer.set_transport_addr(endpoint);
        }
    }

    pub fn peer_stats(&self, pubkey: &x25519_dalek::PublicKey) -> Option<PeerStats> {
        self.indices
            .by_pubkey
            .read()
            .get(pubkey.as_bytes())
            .map(|p| *p.stats.lock())
    }

    /// Snapshot peer count. Cheap (single read-lock + len). Used by M7
    /// to verify that the netmap delta stream has populated the engine.
    pub fn peer_count(&self) -> usize {
        self.indices.by_pubkey.read().len()
    }

    /// Spawn the pump thread driving `transport`. Returns an `EngineRunning`
    /// with the rx/tx queues for callers to interact with the tunnel.
    ///
    /// Takes `&self` so the caller keeps the `Engine` alive after start —
    /// M7's control thread needs to call `upsert_peer` / `remove_peer`
    /// based on `MapResponse` deltas.
    pub fn start<T: Transport + 'static>(
        &self,
        transport: T,
    ) -> Result<EngineRunning, WgError> {
        self.start_with_hint(transport, None)
    }

    /// Like [`Engine::start`], with an optional [`DirectPathHint`] oracle
    /// the pump consults at send time. M12 wires `MagicSocketCtl` here.
    pub fn start_with_hint<T: Transport + 'static>(
        &self,
        transport: T,
        direct_path_hint: Option<Arc<dyn DirectPathHint>>,
    ) -> Result<EngineRunning, WgError> {
        let transport = Arc::new(transport);
        let tun_rx_q = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
        let tun_tx_q = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
        let rx_notify = Arc::new((Mutex::new(false), Condvar::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let join = {
            let indices = Arc::clone(&self.indices);
            let transport = Arc::clone(&transport);
            let tun_rx_q = Arc::clone(&tun_rx_q);
            let tun_tx_q = Arc::clone(&tun_tx_q);
            let rx_notify = Arc::clone(&rx_notify);
            let shutdown = Arc::clone(&shutdown);
            let hint = direct_path_hint.clone();
            vita_thread::Builder::new()
                .name("wg_engine")
                .stack_size(256 * 1024)
                .spawn(move || {
                    pump::run(
                        indices,
                        transport,
                        hint,
                        tun_rx_q,
                        tun_tx_q,
                        rx_notify,
                        shutdown,
                    )
                })
                .map_err(WgError::Io)?
        };

        info!(
            peers = self.indices.count(),
            direct_hint = direct_path_hint.is_some(),
            "wg-engine started"
        );

        Ok(EngineRunning {
            tun_rx: tun_rx_q,
            tun_tx: tun_tx_q,
            rx_notify,
            shutdown,
            join: Some(join),
        })
    }
}

/// Handle to a running engine. Drop or call `shutdown` to stop.
pub struct EngineRunning {
    /// Decapsulated plaintext IPv4 packets from peers. Drain to consume.
    pub tun_rx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Plaintext IPv4 packets to encapsulate and send. Push to send.
    pub tun_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Wakes whenever `tun_rx` gets a new packet. M3 smoltcp wakeup hook.
    pub rx_notify: Arc<(Mutex<bool>, Condvar)>,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle>,
}

impl EngineRunning {
    /// Signal shutdown and join the pump thread.
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for EngineRunning {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Outcome of [`data_plane_selftest`]. Each field is a stage of the WG
/// data-plane crypto round-trip; `summary()` renders a one-line trace + verdict.
#[derive(Debug, Default, Clone)]
pub struct SelfTestReport {
    /// init → response → keepalive handshake dance completed (B reached `Done`).
    pub handshake_ok: bool,
    /// An EMPTY-payload transport frame (the working production case: keepalive,
    /// type-4 datalen=0, 32 B) decapsulated cleanly (`Done`).
    pub keepalive_ok: bool,
    /// A NON-EMPTY-payload transport frame (the suspect: type-4 datalen>0)
    /// decapsulated to `WriteToTunnelV4` — i.e. the AEAD tag verified.
    pub data_ok: bool,
    /// On-wire length of the non-empty data frame we built (header+ct+tag).
    pub data_len: usize,
    /// Decrypted payload bytes equal the bytes we sent (catches silent
    /// corruption that somehow still passes the tag).
    pub roundtrip_match: bool,
    /// First failing stage's category + any underlying `WireGuardError`,
    /// else empty. A `String` (one tiny alloc at startup) so the exact error
    /// variant reaches the trace — `InvalidAeadTag` is the Fork-A signature.
    pub note: String,
}

impl SelfTestReport {
    /// One-line summary for the SUPRX raw trace, ending in a fork verdict:
    /// `AEAD_NONEMPTY_MISCOMPILE` (Fork A — on-device crypto), or
    /// `CRYPTO_OK_NETWORK_SUSPECT` (Fork B — egress).
    pub fn summary(&self) -> String {
        let verdict = if !self.handshake_ok {
            "HANDSHAKE_FAILED"
        } else if self.keepalive_ok && !self.data_ok {
            "AEAD_NONEMPTY_MISCOMPILE"
        } else if self.data_ok && self.roundtrip_match {
            "CRYPTO_OK_NETWORK_SUSPECT"
        } else {
            "INCONCLUSIVE"
        };
        format!(
            "hs={} ka={} data={} dlen={} match={} note={} VERDICT={}",
            self.handshake_ok as u8,
            self.keepalive_ok as u8,
            self.data_ok as u8,
            self.data_len,
            self.roundtrip_match as u8,
            if self.note.is_empty() { "-" } else { self.note.as_str() },
            verdict,
        )
    }
}

/// In-process WG data-plane crypto self-test. Stands up two `Tunn`s, runs a
/// full handshake between them, then exercises both an EMPTY-payload frame
/// (the production case that reaches peers) and a NON-EMPTY-payload frame (the
/// one that mysteriously never does), decapsulating each locally.
///
/// This isolates crypto from the network with zero peers and zero sockets:
/// if the empty frame round-trips on a target but the non-empty one does not,
/// the AEAD seal is miscompiling for non-empty payloads on that target (a
/// ChaCha20Poly1305/SIMD cross-compile hazard) — proving the bug is local crypto,
/// not UDP egress. If both round-trip, on-device crypto is sound and the bug is
/// in the network path. See `summary()` for the verdict mapping.
pub fn data_plane_selftest() -> SelfTestReport {
    use boringtun::noise::TunnResult;
    use rand_core::{OsRng, RngCore};

    let mut report = SelfTestReport::default();

    // Two ephemeral peers (A = initiator, B = responder).
    let a_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let a_public = x25519_dalek::PublicKey::from(&a_secret);
    let b_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let b_public = x25519_dalek::PublicKey::from(&b_secret);
    let mut a = Tunn::new(a_secret, b_public, None, None, OsRng.next_u32(), None);
    let mut b = Tunn::new(b_secret, a_public, None, None, OsRng.next_u32(), None);

    let mut buf = [0u8; 2048];

    // --- Handshake: init (A→B) → response (B→A) → keepalive (A→B) → Done (B). ---
    let init = match a.encapsulate(&[], &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => {
            report.note = format!("init_not_network:{}", tunn_kind(&other));
            return report;
        }
    };
    let resp = match b.decapsulate(None, &init, &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => {
            report.note = format!("resp_not_network:{}", tunn_kind(&other));
            return report;
        }
    };
    let keepalive = match a.decapsulate(None, &resp, &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => {
            report.note = format!("keepalive_not_network:{}", tunn_kind(&other));
            return report;
        }
    };
    match b.decapsulate(None, &keepalive, &mut buf) {
        TunnResult::Done => report.handshake_ok = true,
        other => {
            report.note = format!("hs_keepalive:{}", tunn_kind(&other));
            return report;
        }
    }

    // --- Empty-payload control (the production case that DOES reach peers). ---
    let ka_frame = match a.encapsulate(&[], &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => {
            report.note = format!("ka_encap:{}", tunn_kind(&other));
            return report;
        }
    };
    match b.decapsulate(None, &ka_frame, &mut buf) {
        TunnResult::Done => report.keepalive_ok = true,
        other => report.note = format!("ka_decap:{}", tunn_kind(&other)),
    }

    // --- Non-empty-payload test (the suspect: type-4 datalen>0). ---
    // A minimal but VALID IPv4 packet: a clean decap runs boringtun's
    // post-decryption IP validation (`validate_decapsulated_packet`), which
    // reads the total-length field (bytes 2..4, big-endian) and rejects the
    // packet as `InvalidPacket` if it exceeds the buffer. So the length field
    // MUST equal the real length, or we'd misread a perfectly-decrypted frame
    // as a failure. version=4, IHL=5 (0x45); total_length = 64; rest filler.
    let mut payload = [0u8; 64];
    let total_len = payload.len() as u16;
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&total_len.to_be_bytes());
    for (i, byte) in payload.iter_mut().enumerate().skip(4) {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    let data_frame = match a.encapsulate(&payload, &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => {
            report.note = format!("data_encap:{}", tunn_kind(&other));
            return report;
        }
    };
    report.data_len = data_frame.len();
    let mut out = [0u8; 2048];
    match b.decapsulate(None, &data_frame, &mut out) {
        TunnResult::WriteToTunnelV4(p, _) => {
            report.data_ok = true;
            report.roundtrip_match = &p[..] == &payload[..];
        }
        other => report.note = format!("data_decap:{}", tunn_kind(&other)),
    }

    report
}

/// Compact label for a `TunnResult` (variant + the `WireGuardError` for `Err`),
/// for the self-test `note`. `InvalidAeadTag` here would be the Fork-A signature.
fn tunn_kind(r: &boringtun::noise::TunnResult<'_>) -> String {
    use boringtun::noise::TunnResult;
    match r {
        TunnResult::Done => "Done".to_string(),
        TunnResult::Err(e) => format!("Err({e:?})"),
        TunnResult::WriteToNetwork(_) => "Network".to_string(),
        TunnResult::WriteToTunnelV4(..) => "TunnelV4".to_string(),
        TunnResult::WriteToTunnelV6(..) => "TunnelV6".to_string(),
    }
}

#[cfg(test)]
mod selftest_tests {
    use super::*;

    /// Baseline: on the host (x86_64) the full crypto round-trip must pass.
    /// This is what makes a FAIL on the Vita target meaningful — if this
    /// passes on host but the on-device `wgst:` trace shows `data=0`, the
    /// AEAD is miscompiling for non-empty payloads on the Vita target.
    #[test]
    fn data_plane_selftest_passes_on_host() {
        let r = data_plane_selftest();
        assert!(
            r.handshake_ok && r.keepalive_ok && r.data_ok && r.roundtrip_match,
            "selftest should fully pass on host: {r:?} ({})",
            r.summary()
        );
    }
}
