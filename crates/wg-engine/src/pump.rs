use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use parking_lot::{Condvar, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::dispatch::{parse_ipv4_dst, peer_for_ip, route_inbound, InboundRoute};
use crate::indices::Indices;
use crate::peer::{Peer, TransportAddr};
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
    tun_rx_q: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tun_tx_q: Arc<Mutex<VecDeque<Vec<u8>>>>,
    rx_notify: Arc<(Mutex<bool>, Condvar)>,
    shutdown: Arc<AtomicBool>,
) {
    info!(peers = indices.count(), "wg-engine pump starting");

    prime_handshakes(&indices, &*transport);

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
                Some(p) => handle_outbound(&indices, &*transport, &p),
                None => break,
            }
        }

        // 3. Timer tick.
        if last_tick.elapsed() >= TIMER_TICK {
            tick_timers(&indices, &*transport);
            last_tick = Instant::now();
        }
    }

    info!("wg-engine pump exiting");
}

fn prime_handshakes<T: Transport + ?Sized>(indices: &Indices, transport: &T) {
    let snapshot: Vec<Arc<Peer>> = indices.by_pubkey.read().values().cloned().collect();
    for peer in snapshot {
        let addr = match peer.transport_addr_load() {
            Some(a) => a,
            None => continue,
        };
        let outcome = call_tunn(&peer, |tunn, buf| tunn.encapsulate(&[], buf));
        match outcome {
            Outcome::Network(bytes) => {
                send_outbound(transport, &peer.pubkey, addr, &bytes);
                peer.stats.lock().handshakes_started += 1;
                debug!(peer_pub = %short_hex(&peer.pubkey), n = bytes.len(), "handshake init queued");
            }
            _ => {
                trace!(peer_pub = %short_hex(&peer.pubkey), "no handshake init produced (already up?)");
            }
        }
    }
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
        peer.set_transport_addr(src_addr);

        // First decapsulate consumes `datagram`. Subsequent calls drain queued
        // tx with empty input (per boringtun docs).
        let mut net_outputs: Vec<Vec<u8>> = Vec::new();
        let mut tun_outputs: Vec<Vec<u8>> = Vec::new();

        let first = call_tunn(&peer, |tunn, buf| tunn.decapsulate(None, datagram, buf));
        match first {
            Outcome::Done => {}
            Outcome::Network(b) => net_outputs.push(b),
            Outcome::TunnelV4(b) => tun_outputs.push(b),
            Outcome::TunnelV6 => {}
        }

        // If the first call produced output, the peer's session may have more
        // queued. Drain by re-calling with empty input until Done.
        loop {
            let next = call_tunn(&peer, |tunn, buf| tunn.decapsulate(None, &[], buf));
            match next {
                Outcome::Done => break,
                Outcome::Network(b) => net_outputs.push(b),
                Outcome::TunnelV4(b) => tun_outputs.push(b),
                Outcome::TunnelV6 => {}
            }
        }

        for bytes in net_outputs {
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
    let addr = match peer.transport_addr_load() {
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

fn tick_timers<T: Transport + ?Sized>(indices: &Indices, transport: &T) {
    let snapshot: Vec<Arc<Peer>> = indices.by_pubkey.read().values().cloned().collect();
    for peer in snapshot {
        let addr = match peer.transport_addr_load() {
            Some(a) => a,
            None => continue,
        };
        let outcome = call_tunn(&peer, |tunn, buf| tunn.update_timers(buf));
        if let Outcome::Network(bytes) = outcome {
            send_outbound(transport, &peer.pubkey, addr, &bytes);
        }
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
        info!(peer_pub = %short_hex(peer_pub), bytes = bytes.len(), "wg.net.tx");
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
