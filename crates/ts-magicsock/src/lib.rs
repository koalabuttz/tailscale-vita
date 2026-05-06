//! `MagicSocket` — shared UDP socket for Disco probing + direct-path WG.
//!
//! M12D scope: own one `UdpSocket`, run a receive worker that:
//!   1. Inspects magic bytes (`TS💬`).
//!   2. Disco frames (Ping/Pong) stay internal — Pong reply on Ping,
//!      RTT recording on matching Pong.
//!   3. Non-Disco frames forward via `crossbeam-channel` for
//!      wg-engine to consume (M12E hooks this up).
//!
//! Every 5 s the worker iterates known peers and sends a Disco Ping
//! to each candidate endpoint that hasn't seen a recent Pong, so the
//! "alive direct path" map stays fresh.
//!
//! What this crate does NOT do: path selection. wg-engine asks
//! `MagicSocketCtl::alive_endpoint(node_pub)` to learn whether there's
//! a direct path right now — that decision lives in wg-engine.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use tracing::{debug, info, trace, warn};

use ts_disco::keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use ts_disco::{Header, MessageType, Packet, Ping, Pong};

mod error;
pub use error::MagicError;

/// Default Tailscale UDP port for direct paths.
pub const DEFAULT_PORT: u16 = 41641;

/// Period between Ping bursts for each peer-endpoint pair.
const PING_INTERVAL: Duration = Duration::from_secs(5);
/// A direct path is "alive" if we've received a Pong for it within
/// this many seconds.
const ALIVE_TTL: Duration = Duration::from_secs(30);
/// recv_from timeout; bounds how long we wait between ping pumps.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
/// Max receive buffer (Disco packets are small; WG handshake max ~256
/// bytes; Tailscale's MTU is 1280; round up).
const RECV_BUF: usize = 64 * 1024;
/// 32-byte WireGuard node public key — same NodeKeyBytes type used
/// elsewhere in the workspace.
pub type NodeKey = [u8; 32];

/// A non-Disco datagram received by the magic socket — forwarded for
/// wg-engine's RX path (or anyone interested in raw UDP).
pub type NonDiscoPacket = (SocketAddr, Vec<u8>);

/// Peer's per-endpoint Disco state.
struct PathState {
    last_ping_at: Option<Instant>,
    last_pong_at: Option<Instant>,
    /// Most recent outstanding ping's tx_id (overwritten on each new
    /// ping; v1 doesn't track multiple in-flight pings per path).
    outstanding_tx_id: Option<[u8; 12]>,
    rtt: Option<Duration>,
}

impl PathState {
    fn new() -> Self {
        Self {
            last_ping_at: None,
            last_pong_at: None,
            outstanding_tx_id: None,
            rtt: None,
        }
    }

    fn alive(&self, now: Instant) -> bool {
        self.last_pong_at
            .map(|t| now.duration_since(t) < ALIVE_TTL)
            .unwrap_or(false)
    }
}

/// Peer-level Disco state. Indexed by node pubkey.
struct PeerState {
    disco_pub: DiscoPublicKey,
    endpoints: Vec<SocketAddr>,
    paths: HashMap<SocketAddr, PathState>,
}

#[derive(Default)]
struct MagicState {
    peers: HashMap<NodeKey, PeerState>,
    /// Reverse index: disco pubkey → node pubkey. When a Disco frame
    /// arrives, the header's `sender_pub` tells us which Disco identity
    /// sent it; this map resolves to the node identity for the
    /// `peers` lookup.
    disco_to_node: HashMap<DiscoPublicKey, NodeKey>,
}

/// Public handle. Cloneable; runtime + wg-engine both hold copies.
#[derive(Clone)]
pub struct MagicSocketCtl {
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<MagicState>>,
    shutdown: Arc<AtomicBool>,
    local_addr: SocketAddr,
}

/// Spawned worker side. Drop joins the receive thread.
pub struct MagicSocket {
    worker: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl MagicSocket {
    /// Bind a UDP socket and spawn the receive + ping-pump worker.
    /// `bind_addr` is normally `0.0.0.0:DEFAULT_PORT`; if 41641 is
    /// taken (or the OS rejects the port), pass `0.0.0.0:0` and the
    /// kernel assigns one. The actual bound address is on the returned
    /// ctl handle via `local_addr`.
    pub fn bind(
        bind_addr: SocketAddr,
        our_disco_priv: DiscoPrivateKey,
        our_node_pub: NodePublicKey,
        non_disco_tx: Sender<NonDiscoPacket>,
    ) -> Result<(Self, MagicSocketCtl), MagicError> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(RECV_TIMEOUT))?;
        let local_addr = socket.local_addr()?;
        info!(%local_addr, "magicsock.bind");

        let socket = Arc::new(socket);
        let state = Arc::new(Mutex::new(MagicState::default()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let ctl = MagicSocketCtl {
            socket: Arc::clone(&socket),
            state: Arc::clone(&state),
            shutdown: Arc::clone(&shutdown),
            local_addr,
        };

        let worker_state = Arc::clone(&state);
        let worker_socket = Arc::clone(&socket);
        let worker_shutdown = Arc::clone(&shutdown);
        // SECURITY: our_disco_priv is moved into the worker — the
        // ctl side cannot decrypt incoming Disco frames.
        let worker = thread::Builder::new()
            .name("ts-magicsock".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let our_node_pub = our_node_pub;
                worker_loop(
                    worker_socket,
                    worker_state,
                    worker_shutdown,
                    our_disco_priv,
                    our_node_pub,
                    non_disco_tx,
                );
            })
            .map_err(MagicError::Io)?;

        Ok((
            Self {
                worker: Some(worker),
                shutdown,
            },
            ctl,
        ))
    }
}

impl Drop for MagicSocket {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

impl MagicSocketCtl {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Add or replace a peer's Disco state. Endpoints not present in
    /// `endpoints` have their PathState dropped.
    pub fn upsert_peer(
        &self,
        node_pub: NodeKey,
        disco_pub: DiscoPublicKey,
        endpoints: Vec<SocketAddr>,
    ) {
        let mut s = self.state.lock();
        // Re-link disco_to_node: drop any stale mapping for this node.
        s.disco_to_node
            .retain(|_d, n| *n != node_pub);
        s.disco_to_node.insert(disco_pub, node_pub);

        let entry = s.peers.entry(node_pub).or_insert_with(|| PeerState {
            disco_pub,
            endpoints: vec![],
            paths: HashMap::new(),
        });
        entry.disco_pub = disco_pub;
        entry.endpoints = endpoints.clone();

        // Drop paths for endpoints no longer in the candidate list.
        entry.paths.retain(|addr, _| endpoints.contains(addr));
        // Add fresh PathState entries for new endpoints.
        for addr in endpoints {
            entry.paths.entry(addr).or_insert_with(PathState::new);
        }
    }

    /// Remove a peer entirely. Outstanding pings to it become silent.
    pub fn remove_peer(&self, node_pub: &NodeKey) {
        let mut s = self.state.lock();
        if let Some(p) = s.peers.remove(node_pub) {
            s.disco_to_node.remove(&p.disco_pub);
        }
    }

    /// Query: is there a Disco-validated direct path right now?
    /// Returns the lowest-RTT alive endpoint if so.
    pub fn alive_endpoint(&self, node_pub: &NodeKey) -> Option<SocketAddr> {
        let now = Instant::now();
        let s = self.state.lock();
        let peer = s.peers.get(node_pub)?;
        peer.paths
            .iter()
            .filter(|(_, st)| st.alive(now))
            .min_by_key(|(_, st)| st.rtt.unwrap_or(Duration::from_secs(60)))
            .map(|(addr, _)| *addr)
    }

    /// Send a raw datagram to an arbitrary UDP address. wg-engine uses
    /// this to send WG packets along an alive direct path.
    pub fn send_to(&self, addr: SocketAddr, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket.send_to(bytes, addr)
    }

    /// Best-effort: signal the worker to exit. Returns immediately;
    /// the receive thread polls the flag at most every `RECV_TIMEOUT`.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

// ============================================================
// Worker: receive loop + periodic ping pump.
// ============================================================

fn worker_loop(
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<MagicState>>,
    shutdown: Arc<AtomicBool>,
    our_disco_priv: DiscoPrivateKey,
    our_node_pub: NodePublicKey,
    non_disco_tx: Sender<NonDiscoPacket>,
) {
    info!(local = ?socket.local_addr(), "magicsock.worker.start");
    let mut buf = vec![0u8; RECV_BUF];
    let mut last_ping_pump = Instant::now() - PING_INTERVAL;

    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        // Periodic ping pump.
        if last_ping_pump.elapsed() >= PING_INTERVAL {
            ping_pump(&socket, &state, &our_disco_priv, &our_node_pub);
            last_ping_pump = Instant::now();
        }

        // Receive (blocks up to RECV_TIMEOUT).
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                handle_recv(
                    &buf[..n],
                    src,
                    &socket,
                    &state,
                    &our_disco_priv,
                    &non_disco_tx,
                );
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No traffic this window — loop and re-check shutdown.
            }
            Err(e) => {
                warn!(error = %e, "magicsock.recv_from.error");
                break;
            }
        }
    }
    info!("magicsock.worker.exit");
}

fn handle_recv(
    bytes: &[u8],
    src: SocketAddr,
    socket: &UdpSocket,
    state: &Mutex<MagicState>,
    our_disco_priv: &DiscoPrivateKey,
    non_disco_tx: &Sender<NonDiscoPacket>,
) {
    if !ts_disco::is_disco_message(bytes) {
        // Forward raw bytes for wg-engine. If the channel is full or
        // disconnected, drop — wg's existing retransmits cover it.
        let _ = non_disco_tx.try_send((src, bytes.to_vec()));
        return;
    }
    handle_disco(bytes, src, socket, state, our_disco_priv);
}

fn handle_disco(
    bytes: &[u8],
    src: SocketAddr,
    socket: &UdpSocket,
    state: &Mutex<MagicState>,
    our_disco_priv: &DiscoPrivateKey,
) {
    // Decryption is in-place; copy into a mutable owned buffer.
    let mut owned = bytes.to_vec();
    let encrypted = match Packet::<ts_disco::Encrypted>::from_encrypted_bytes_mut(
        &mut owned,
    ) {
        Ok(p) => p,
        Err(e) => {
            trace!(?e, %src, "magicsock.disco.parse_failed");
            return;
        }
    };
    let sender_pub = encrypted.header().sender_pub();
    let plaintext = match encrypted.decrypt_in_place(our_disco_priv) {
        Ok(p) => p,
        Err(e) => {
            trace!(?e, %src, "magicsock.disco.decrypt_failed");
            return;
        }
    };

    match plaintext.ty() {
        Some(MessageType::Ping) => {
            let ping = match plaintext.as_msg::<Ping>() {
                Some(p) => p,
                None => return,
            };
            let tx_id = ping.tx_id;
            // Resolve sender → node, but tolerate unknown peers — a
            // legit peer may ping us before we've MapResponse'd them.
            let maybe_node = {
                let s = state.lock();
                s.disco_to_node.get(&sender_pub).copied()
            };
            debug!(
                %src,
                ?maybe_node,
                "magicsock.disco.ping.recv"
            );
            // Always reply with a Pong — ping-from-unknown is fine; the
            // peer's MapResponse may catch up in a moment.
            send_pong(socket, our_disco_priv, &sender_pub, src, tx_id);
        }
        Some(MessageType::Pong) => {
            let pong = match plaintext.as_msg::<Pong>() {
                Some(p) => p,
                None => return,
            };
            let now = Instant::now();
            let mut s = state.lock();
            let node_pub = match s.disco_to_node.get(&sender_pub).copied() {
                Some(n) => n,
                None => {
                    trace!(%src, "magicsock.disco.pong.unknown_sender");
                    return;
                }
            };
            if let Some(peer) = s.peers.get_mut(&node_pub) {
                if let Some(path) = peer.paths.get_mut(&src) {
                    if path.outstanding_tx_id == Some(pong.tx_id) {
                        let rtt = path
                            .last_ping_at
                            .map(|t| now.duration_since(t))
                            .unwrap_or_default();
                        path.last_pong_at = Some(now);
                        path.rtt = Some(rtt);
                        path.outstanding_tx_id = None;
                        info!(
                            %src,
                            rtt_ms = rtt.as_millis() as u64,
                            "magicsock.disco.pong.alive"
                        );
                    } else {
                        trace!(%src, "magicsock.disco.pong.tx_mismatch");
                    }
                }
            }
        }
        Some(other) => {
            trace!(?other, %src, "magicsock.disco.unhandled_type");
        }
        None => {
            trace!(%src, "magicsock.disco.unknown_type_byte");
        }
    }
}

fn ping_pump(
    socket: &UdpSocket,
    state: &Mutex<MagicState>,
    our_disco_priv: &DiscoPrivateKey,
    our_node_pub: &NodePublicKey,
) {
    let now = Instant::now();
    // Snapshot the (peer_disco, endpoint) pairs to ping; keep the lock
    // window short. Do work outside the lock.
    let to_ping: Vec<(NodeKey, DiscoPublicKey, SocketAddr)> = {
        let s = state.lock();
        let mut out = Vec::new();
        for (node_pub, peer) in &s.peers {
            for addr in &peer.endpoints {
                let path = peer.paths.get(addr);
                let needs_ping = match path {
                    None => true,
                    Some(p) => {
                        // Re-ping if no recent ping AND no recent pong.
                        let stale_ping = p
                            .last_ping_at
                            .map(|t| now.duration_since(t) >= PING_INTERVAL)
                            .unwrap_or(true);
                        let dead = !p.alive(now);
                        stale_ping && dead
                    }
                };
                if needs_ping {
                    out.push((*node_pub, peer.disco_pub, *addr));
                }
            }
        }
        out
    };

    for (node_pub, peer_disco, addr) in to_ping {
        let tx_id = match send_ping(socket, our_disco_priv, our_node_pub, &peer_disco, addr) {
            Ok(tx) => tx,
            Err(e) => {
                trace!(?e, %addr, "magicsock.disco.ping.send_failed");
                continue;
            }
        };
        // Record the ping under its node + path. Re-acquire lock per
        // ping; pump frequency is 5 s so the per-ping lock contention
        // is irrelevant.
        let mut s = state.lock();
        if let Some(peer) = s.peers.get_mut(&node_pub) {
            let path = peer
                .paths
                .entry(addr)
                .or_insert_with(PathState::new);
            path.last_ping_at = Some(now);
            path.outstanding_tx_id = Some(tx_id);
        }
    }
}

/// Build + encrypt + send a Disco Ping. Returns the tx_id used.
fn send_ping(
    socket: &UdpSocket,
    our_disco_priv: &DiscoPrivateKey,
    our_node_pub: &NodePublicKey,
    peer_disco_pub: &DiscoPublicKey,
    addr: SocketAddr,
) -> Result<[u8; 12], MagicError> {
    let mut tx_id = [0u8; 12];
    OsRng.fill_bytes(&mut tx_id);
    let mut nonce = [0u8; Header::NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let body_size = Ping::size_with_padding(0);
    let pkt_size = Packet::<ts_disco::Plaintext>::size_for_message(body_size);
    let mut buf = vec![0u8; pkt_size];

    {
        let pkt = Packet::<ts_disco::Plaintext>::init_from_bytes::<Ping>(
            &mut buf,
            |ping| {
                ping.tx_id = tx_id;
                ping.node_key = *our_node_pub;
            },
        )?;
        pkt.encrypt_in_place(our_disco_priv, peer_disco_pub, nonce)?;
    } // pkt borrow ends; buf is now the encrypted bytes

    socket.send_to(&buf, addr)?;
    debug!(%addr, "magicsock.disco.ping.sent");
    Ok(tx_id)
}

/// Build + encrypt + send a Disco Pong in reply to a received Ping.
fn send_pong(
    socket: &UdpSocket,
    our_disco_priv: &DiscoPrivateKey,
    peer_disco_pub: &DiscoPublicKey,
    src: SocketAddr,
    tx_id: [u8; 12],
) {
    let mut nonce = [0u8; Header::NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let pkt_size = Packet::<ts_disco::Plaintext>::size_for_message(Pong::size());
    let mut buf = vec![0u8; pkt_size];

    let result = (|| -> Result<(), MagicError> {
        let pkt = Packet::<ts_disco::Plaintext>::init_from_bytes::<Pong>(
            &mut buf,
            |pong| {
                pong.tx_id = tx_id;
                pong.src = src.into();
            },
        )?;
        pkt.encrypt_in_place(our_disco_priv, peer_disco_pub, nonce)?;
        Ok(())
    })();
    if let Err(e) = result {
        trace!(?e, %src, "magicsock.disco.pong.build_failed");
        return;
    }

    if let Err(e) = socket.send_to(&buf, src) {
        trace!(?e, %src, "magicsock.disco.pong.send_failed");
        return;
    }
    debug!(%src, "magicsock.disco.pong.sent");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;
    use std::net::Ipv4Addr;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    /// End-to-end Ping→Pong round-trip between two MagicSockets on
    /// loopback. Validates: bind, peer registration, ping pump,
    /// receive worker, decrypt, Pong reply, RTT recording.
    #[test]
    fn ping_pong_loopback() {
        // Two sides: A and B. A pings B; B Pong-replies.
        let a_priv = DiscoPrivateKey::random();
        let b_priv = DiscoPrivateKey::random();
        let a_pub = a_priv.public_key();
        let b_pub = b_priv.public_key();

        // Node pubkeys for the Ping body — arbitrary; we just need them
        // distinct so the indexes don't collide.
        let a_node_bytes = [0xAA; 32];
        let b_node_bytes = [0xBB; 32];
        let a_node = NodePublicKey::from(a_node_bytes);
        let b_node = NodePublicKey::from(b_node_bytes);

        let (a_non_tx, _a_non_rx) = unbounded::<NonDiscoPacket>();
        let (b_non_tx, _b_non_rx) = unbounded::<NonDiscoPacket>();

        let (_a_sock, a_ctl) = MagicSocket::bind(
            loopback(0),
            DiscoPrivateKey::from_bytes(*a_priv.as_bytes()),
            a_node,
            a_non_tx,
        )
        .unwrap();
        let (_b_sock, b_ctl) = MagicSocket::bind(
            loopback(0),
            DiscoPrivateKey::from_bytes(*b_priv.as_bytes()),
            b_node,
            b_non_tx,
        )
        .unwrap();

        // A registers B as a peer; vice versa for B (so B's recv
        // disco_to_node lookup resolves the Pong's sender).
        a_ctl.upsert_peer(b_node_bytes, b_pub, vec![b_ctl.local_addr()]);
        b_ctl.upsert_peer(a_node_bytes, a_pub, vec![a_ctl.local_addr()]);

        // Wait up to 8 s for the ping pump (5s interval) + receive +
        // pong reply path.
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(addr) = a_ctl.alive_endpoint(&b_node_bytes) {
                assert_eq!(addr, b_ctl.local_addr());
                break;
            }
            if Instant::now() >= deadline {
                panic!("no alive endpoint after 8s");
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}
