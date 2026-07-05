use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use vita_sync::{Condvar, Mutex};
use vita_log::{debug, error, info, trace, warn};

use crate::dispatch::{parse_ipv4_dst, peer_for_ip, route_inbound, InboundRoute};
use crate::indices::Indices;
use crate::peer::{DirectPathHint, Peer, TransportAddr};
use crate::transport::Transport;

/// Buffer size for `Tunn::encapsulate` / `decapsulate` work area. Per
/// boringtun docs: at least src.len() + 32 and at least 148 bytes.
const SCRATCH: usize = 2048;

/// Transport recv timeout — short enough to keep latency low, long enough
/// that the pump isn't busy-spinning when idle.
const RECV_TIMEOUT: Duration = Duration::from_millis(50);

/// Timer-tick cadence (per WireGuard whitepaper §5.6 + boringtun reference Device).
const TIMER_TICK: Duration = Duration::from_millis(250);

/// Owned outcome of a single Tunn call. Contains no borrows from the
/// scratch buffer — safe to return across the catch_unwind boundary.
#[derive(Debug)]
enum Outcome {
    Done,
    Network(Vec<u8>),
    TunnelV4(Vec<u8>),
    /// IPv6 packet — v1 ignores. Logged at trace.
    TunnelV6,
}

/// Run the wg-engine pump loop. Returns when `shutdown` is set.
pub(crate) fn run<T: Transport + ?Sized>(
    indices: Arc<Indices>,
    transport: Arc<T>,
    direct_path_hint: Option<Arc<dyn DirectPathHint>>,
    tun_rx_q: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tun_tx_q: Arc<Mutex<VecDeque<Vec<u8>>>>,
    rx_notify: Arc<(Mutex<bool>, Condvar)>,
    shutdown: Arc<AtomicBool>,
) {
    info!(peers = indices.count(), "wg-engine pump starting");

    let hint_ref = direct_path_hint.as_deref();
    // NOTE: do NOT prime handshakes to every peer at startup. Real WireGuard
    // initiates ON-DEMAND (handle_outbound's encapsulate starts the handshake
    // on the first real outbound packet to a peer). Blasting all 31 peers here
    // floods the ~30 idle ones into perpetual ConnectionExpired churn on every
    // tick (~120 errors/s, masking the real session) and risks both-initiator
    // handshake collisions during a peer roam.

    let mut last_tick = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        // 1. Inbound: blocks up to RECV_TIMEOUT.
        match transport.recv_with_timeout(RECV_TIMEOUT) {
            Ok(Some((src_addr, datagram))) => {
                info!(?src_addr, n = datagram.len(), "wg.net.rx");
                handle_inbound(
                    &indices,
                    &*transport,
                    src_addr,
                    &datagram,
                    &tun_rx_q,
                    &rx_notify,
                );
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "transport recv error"),
        }

        // 2. Outbound: drain tun_tx_q.
        loop {
            let pkt = tun_tx_q.lock().pop_front();
            match pkt {
                Some(p) => handle_outbound(&indices, &*transport, hint_ref, &p),
                None => break,
            }
        }

        // 3. Timer tick.
        if last_tick.elapsed() >= TIMER_TICK {
            tick_timers(&indices, &*transport, hint_ref);
            last_tick = Instant::now();
        }
    }

    info!("wg-engine pump exiting");
}

/// Pick the best transport addr for a peer right now. Prefers a
/// Disco-validated direct UDP path if the optional hint says one is
/// alive; otherwise falls back to the peer's cached `transport_addr`
/// (typically Derp).
///
/// Emits a `debug!` log per call describing the chosen variant — set
/// `RUST_LOG=wg_engine=debug` to observe whether direct paths are
/// being used vs falling back to DERP. Default (`info`) is silent
/// since `pick_addr` is on the hot path.
fn pick_addr(
    peer: &Peer,
    hint: Option<&dyn DirectPathHint>,
) -> Option<TransportAddr> {
    let pick = if let Some(auth) = peer.auth_src_fresh(std::time::Instant::now()) {
        // WireGuard roaming: reply to where the peer's last AUTHENTICATED packet
        // actually arrived from. This beats a possibly-stale Disco endpoint for
        // a roaming/symmetric-NAT peer and is exactly what makes Disco pongs
        // work (reply to the ping's source). M20-A3: honored only within
        // AUTH_SRC_TRUST (6.5 s) of the last authenticated inbound — past
        // that, an idle-gap address (e.g. a WAN-hairpin mapping the router
        // happened to deliver once) must not outrank a Disco-validated path.
        Some(auth)
    } else if let Some(h) = hint {
        if let Some(udp) = h.alive_endpoint(&peer.pubkey) {
            Some(TransportAddr::Udp(udp))
        } else {
            peer.transport_addr_load()
        }
    } else {
        peer.transport_addr_load()
    };
    if let Some(addr) = &pick {
        match addr {
            TransportAddr::Udp(sa) => debug!(
                peer_pub = %short_hex(&peer.pubkey),
                addr = %sa,
                "wg.path.choose variant=udp"
            ),
            TransportAddr::Derp { region, .. } => debug!(
                peer_pub = %short_hex(&peer.pubkey),
                region,
                "wg.path.choose variant=derp"
            ),
        }
    }
    pick
}

fn handle_inbound<T: Transport + ?Sized>(
    indices: &Indices,
    transport: &T,
    src_addr: TransportAddr,
    datagram: &[u8],
    tun_rx_q: &Arc<Mutex<VecDeque<Vec<u8>>>>,
    rx_notify: &Arc<(Mutex<bool>, Condvar)>,
) {
    let route = route_inbound(indices, datagram);
    let peers: Vec<Arc<Peer>> = match route {
        InboundRoute::SinglePeer(p) => vec![p],
        InboundRoute::Broadcast => indices.by_pubkey.read().values().cloned().collect(),
        InboundRoute::Junk => {
            trace!(len = datagram.len(), "dropping junk inbound");
            return;
        }
    };

    for peer in peers {
        // M12: only update peer's cached transport_addr for Derp arrivals.
        // Direct UDP packets MUST NOT overwrite the Derp fallback —
        // path selection at send time is handled by `DirectPathHint`,
        // not by which transport we last received on. (Pre-M12 behavior
        // was to roam unconditionally; that broke Derp-as-fallback once
        // a single direct-path packet arrived.)
        if matches!(src_addr, TransportAddr::Derp { .. }) {
            peer.set_transport_addr(src_addr);
        }

        // First decapsulate consumes `datagram`. Subsequent calls drain queued
        // tx with empty input (per boringtun docs).
        let mut net_outputs: Vec<Vec<u8>> = Vec::new();
        let mut tun_outputs: Vec<Vec<u8>> = Vec::new();

        let first = call_tunn(&peer, |tunn, buf| tunn.decapsulate(None, datagram, buf));
        // boringtun's contract: ONLY re-call with empty input when the result
        // was WriteToNetwork (a handshake msg, whose follow-up keepalive + any
        // queued packets must be drained). For Done / Err / WriteToTunnel there
        // is nothing queued, and calling decapsulate(empty) just parses a
        // zero-length packet → spurious decap error. Guarding on Network avoids
        // that noise (and a needless tunn lock per datagram).
        let mut drain = false;
        match first {
            Outcome::Done => {}
            Outcome::Network(b) => {
                net_outputs.push(b);
                drain = true;
            }
            Outcome::TunnelV4(b) => tun_outputs.push(b),
            Outcome::TunnelV6 => {}
        }

        while drain {
            match call_tunn(&peer, |tunn, buf| tunn.decapsulate(None, &[], buf)) {
                Outcome::Done => break,
                Outcome::Network(b) => net_outputs.push(b),
                Outcome::TunnelV4(b) => tun_outputs.push(b),
                Outcome::TunnelV6 => {}
            }
        }

        // On an AUTHENTICATED inbound (the Tunn accepted it → produced output),
        // remember where this peer actually reached us from so replies go
        // straight back there (handles a roaming/symmetric-NAT peer; mirrors
        // how Disco pongs reply to the ping's source). pick_addr prefers this
        // over the Disco endpoint.
        //
        // CRITICAL: only roam to DIRECT (UDP) sources. Tailscale sprays some
        // packets over DERP as a backup path; if we let a DERP-relayed
        // arrival flip auth_src to a DERP addr, our replies go out over DERP
        // — which is NOT delivering for this peer — even though the direct
        // UDP path is live (keepalives + Disco round-trip on it). Wire
        // captures showed 15/16 replies wrongly egressing via DERP this way.
        // A DERP arrival must never hijack a working direct reply path.
        if !net_outputs.is_empty() || !tun_outputs.is_empty() {
            if matches!(src_addr, TransportAddr::Udp(_)) {
                peer.set_auth_src(src_addr);
            }
        }

        // Net outputs from decapsulate (handshake reply, keepalive)
        // get routed back through the same channel they arrived on
        // (src_addr). This stays correct in M12 because Disco-direct
        // paths handle their own bidirectional liveness — if a WG
        // packet arrived via Udp(addr), we already validated that
        // path with Disco and addr is reachable.
        for bytes in net_outputs {
            crate::selection_log::record(format!(
                "k=r peer={} idx={} to={} n={}",
                short_hex(&peer.pubkey),
                peer.our_index,
                fmt_sel(&Some(src_addr)),
                bytes.len(),
            ));
            send_outbound(transport, &peer.pubkey, src_addr, &bytes);
        }

        let any_inbound_data = !tun_outputs.is_empty();
        for plaintext in tun_outputs {
            let len = plaintext.len();
            {
                let mut s = peer.stats.lock();
                s.rx_bytes += len as u64;
                s.last_rx = Some(Instant::now());
            }
            tun_rx_q.lock().push_back(plaintext);
            info!(peer_pub = %short_hex(&peer.pubkey), n = len, "wg.tun.rx");
        }

        if any_inbound_data {
            let (m, cv) = &**rx_notify;
            *m.lock() = true;
            cv.notify_all();
        }
    }
}

fn handle_outbound<T: Transport + ?Sized>(
    indices: &Indices,
    transport: &T,
    hint: Option<&dyn DirectPathHint>,
    plaintext: &[u8],
) {
    let dst = match parse_ipv4_dst(plaintext) {
        Some(d) => d,
        None => {
            trace!(len = plaintext.len(), "dropping outbound non-ipv4");
            return;
        }
    };
    let peer = match peer_for_ip(indices, dst) {
        Some(p) => p,
        None => {
            trace!(%dst, "no peer for outbound dst");
            return;
        }
    };
    // Fork-B: record the FULL selection — which peer the allowed-ips
    // index resolved this inner dst to, and every pick_addr input — so
    // the probe's `wgsel:` trace attributes each data frame to a peer
    // object (pubkey + our_index disambiguates zombie instances).
    let picked = pick_addr(&peer, hint);
    crate::selection_log::record(format!(
        "k=d dst={dst} peer={} idx={} pick={} auth={} hint={} ta={} n={}",
        short_hex(&peer.pubkey),
        peer.our_index,
        fmt_sel(&picked),
        fmt_sel(&peer.auth_src_load()),
        hint.and_then(|h| h.alive_endpoint(&peer.pubkey))
            .map(|sa| format!("udp:{sa}"))
            .unwrap_or_else(|| "none".into()),
        fmt_sel(&peer.transport_addr_load()),
        plaintext.len(),
    ));
    let addr = match picked {
        Some(a) => a,
        None => {
            trace!(peer_pub = %short_hex(&peer.pubkey), "no known transport addr; dropping");
            return;
        }
    };

    let outcome = call_tunn(&peer, |tunn, buf| tunn.encapsulate(plaintext, buf));
    match outcome {
        Outcome::Network(bytes) => {
            peer.stats.lock().tx_bytes += plaintext.len() as u64;
            send_outbound(transport, &peer.pubkey, addr, &bytes);
        }
        Outcome::Done => {
            trace!(
                peer_pub = %short_hex(&peer.pubkey),
                "encapsulate produced no datagram (queued for handshake)"
            );
        }
        Outcome::TunnelV4(_) | Outcome::TunnelV6 => {
            unreachable!("encapsulate cannot produce WriteToTunnel*")
        }
    }
}

fn tick_timers<T: Transport + ?Sized>(
    indices: &Indices,
    transport: &T,
    hint: Option<&dyn DirectPathHint>,
) {
    let snapshot: Vec<Arc<Peer>> = indices.by_pubkey.read().values().cloned().collect();
    for peer in snapshot {
        // Skip peers we've never heard from. `update_timers` on a peer with no
        // established session just returns `ConnectionExpired` every tick — with
        // ~30 idle tailnet peers that's ~120 errors/s of pure noise that burns
        // the pump's time, adds latency to real inbound/reply servicing (which
        // makes the active peer re-handshake → session churn → badkey decap
        // failures), and drowns the real error signal. Only tick peers with a
        // live session (we've received at least one authenticated packet).
        if peer.stats.lock().last_rx.is_none() {
            continue;
        }
        let addr = match pick_addr(&peer, hint) {
            Some(a) => a,
            None => continue,
        };
        let outcome = call_tunn(&peer, |tunn, buf| tunn.update_timers(buf));
        if let Outcome::Network(bytes) = outcome {
            crate::selection_log::record(format!(
                "k=t peer={} idx={} pick={} auth={} hint={} ta={} n={}",
                short_hex(&peer.pubkey),
                peer.our_index,
                fmt_sel(&Some(addr)),
                fmt_sel(&peer.auth_src_load()),
                hint.and_then(|h| h.alive_endpoint(&peer.pubkey))
                    .map(|sa| format!("udp:{sa}"))
                    .unwrap_or_else(|| "none".into()),
                fmt_sel(&peer.transport_addr_load()),
                bytes.len(),
            ));
            send_outbound(transport, &peer.pubkey, addr, &bytes);
        }
    }
}

/// Compact `TransportAddr` formatting for selection-log lines.
fn fmt_sel(a: &Option<TransportAddr>) -> String {
    match a {
        None => "none".into(),
        Some(TransportAddr::Udp(sa)) => format!("udp:{sa}"),
        Some(TransportAddr::Derp { region, .. }) => format!("derp:{region}"),
    }
}

/// Lock the peer's `Tunn` and run a single call inside `catch_unwind`,
/// returning an owned outcome. Releases the buffer borrow before
/// returning, so the caller can immediately call again or send on the wire.
fn call_tunn<F>(peer: &Peer, op: F) -> Outcome
where
    F: for<'a> FnOnce(&mut Tunn, &'a mut [u8]) -> TunnResult<'a>,
{
    let mut tunn = peer.tunn.lock();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut buf = [0u8; SCRATCH];
        let r = op(&mut tunn, &mut buf);
        match r {
            TunnResult::Done => Outcome::Done,
            TunnResult::Err(_e) => Outcome::Done,
            TunnResult::WriteToNetwork(b) => Outcome::Network(b.to_vec()),
            TunnResult::WriteToTunnelV4(b, _ip) => Outcome::TunnelV4(b.to_vec()),
            TunnResult::WriteToTunnelV6(_, _) => Outcome::TunnelV6,
        }
    }));
    match result {
        Ok(o) => o,
        Err(p) => {
            let msg = panic_message(&p);
            error!(peer_pub = %short_hex(&peer.pubkey), panic = %msg, "tunn panic caught");
            Outcome::Done
        }
    }
}

fn send_outbound<T: Transport + ?Sized>(
    transport: &T,
    peer_pub: &[u8; 32],
    addr: TransportAddr,
    bytes: &[u8],
) {
    if let Err(e) = transport.send(addr, bytes) {
        warn!(peer_pub = %short_hex(peer_pub), error = %e, "transport send error");
    } else {
        // `to=` matters: without the destination this line can't distinguish
        // direct-vs-DERP-vs-hairpin egress (how the 2026-07-04 path flap was seen).
        info!(
            peer_pub = %short_hex(peer_pub),
            to = %fmt_sel(&Some(addr)),
            bytes = bytes.len(),
            "wg.net.tx"
        );
    }
}

fn panic_message(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "<unknown panic>".into()
    }
}

fn short_hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(12);
    for b in &bytes[..6] {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod pick_addr_tests {
    use super::*;
    use crate::peer::PeerStats;
    use arc_swap::ArcSwap;
    use rand_core::{OsRng, RngCore};
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn test_peer(fallback: Option<TransportAddr>) -> Peer {
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let peer_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::random_from_rng(OsRng));
        Peer {
            pubkey: *peer_pub.as_bytes(),
            our_index: OsRng.next_u32() & 0xFF_FFFF,
            allowed_ips: vec![],
            transport_addr: ArcSwap::from(Arc::new(fallback)),
            auth_src: ArcSwap::from(Arc::new(None)),
            tunn: Mutex::new(Tunn::new(secret, peer_pub, None, None, 7, None)),
            stats: Mutex::new(PeerStats::default()),
        }
    }

    struct FixedHint(Option<SocketAddr>);
    impl DirectPathHint for FixedHint {
        fn alive_endpoint(&self, _node: &[u8; 32]) -> Option<SocketAddr> {
            self.0
        }
    }

    const DERP: TransportAddr = TransportAddr::Derp {
        region: 1,
        peer_pubkey: [0u8; 32],
    };

    /// M20-A3 precedence: a FRESH auth_src outranks the disco hint —
    /// roaming/symmetric-NAT replies keep working.
    #[test]
    fn fresh_auth_src_wins_over_hint() {
        let peer = test_peer(Some(DERP));
        peer.set_auth_src(TransportAddr::Udp(addr(1000)));
        let hint = FixedHint(Some(addr(2000)));
        assert_eq!(
            pick_addr(&peer, Some(&hint)),
            Some(TransportAddr::Udp(addr(1000)))
        );
    }

    /// M20-A3: past the trust window the auth_src is skipped and the
    /// Disco-validated hint takes over (the WAN-hairpin-stale case).
    #[test]
    fn stale_auth_src_falls_to_hint() {
        let peer = test_peer(Some(DERP));
        peer.set_auth_src_at(
            TransportAddr::Udp(addr(1000)),
            Instant::now() - crate::AUTH_SRC_TRUST - Duration::from_millis(100),
        );
        let hint = FixedHint(Some(addr(2000)));
        assert_eq!(
            pick_addr(&peer, Some(&hint)),
            Some(TransportAddr::Udp(addr(2000)))
        );
    }

    /// M20-A3: stale auth_src + no alive hint → DERP fallback, never
    /// the stale address.
    #[test]
    fn stale_auth_src_no_hint_falls_to_derp() {
        let peer = test_peer(Some(DERP));
        peer.set_auth_src_at(
            TransportAddr::Udp(addr(1000)),
            Instant::now() - crate::AUTH_SRC_TRUST - Duration::from_millis(100),
        );
        let hint = FixedHint(None);
        assert_eq!(pick_addr(&peer, Some(&hint)), Some(DERP));
    }

    /// No auth_src at all → hint, then DERP (pre-M20 behavior intact).
    #[test]
    fn no_auth_src_uses_hint_then_derp() {
        let peer = test_peer(Some(DERP));
        let hint = FixedHint(Some(addr(2000)));
        assert_eq!(
            pick_addr(&peer, Some(&hint)),
            Some(TransportAddr::Udp(addr(2000)))
        );
        let dead_hint = FixedHint(None);
        assert_eq!(pick_addr(&peer, Some(&dead_hint)), Some(DERP));
    }
}
