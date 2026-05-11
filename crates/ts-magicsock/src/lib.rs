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

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Receiver, Sender};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use tracing::{debug, info, trace, warn};

use ts_disco::keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use ts_disco::{CallMeMaybe, Endpoint, Header, MessageType, Packet, Ping, Pong};

mod error;
pub mod netcheck;
pub mod stun;
pub use error::MagicError;

/// Default Tailscale UDP port for direct paths.
pub const DEFAULT_PORT: u16 = 41641;

/// Format the first 8 hex chars of a 32-byte key for compact log output.
fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(8);
    for b in &bytes[..4] {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Format the first 8 hex chars of a `DiscoPublicKey` for compact log
/// output.
fn hex32_disco(d: &DiscoPublicKey) -> String {
    hex32(&d.0)
}

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
/// How long to ping a peer without success before falling back to
/// CallMeMaybe. Matches upstream Go's `endpointState.pingTimeout` —
/// long enough for 2 ping retries on each candidate before assuming
/// the NAT won't open spontaneously.
const CMM_TRIGGER_AFTER: Duration = Duration::from_secs(10);
/// Minimum interval between CallMeMaybe sends for the same peer.
/// Matches Go's 5 s rate-limit — DERP relay traffic isn't free.
const CMM_RATE_LIMIT: Duration = Duration::from_secs(5);
/// Cap on how many CallMeMaybe endpoints we advertise. Real Tailscale
/// caps at 16; we don't need more (Vita has 1 LAN IP + 1 STUN-reflected
/// public IP — well under the limit, but defending against config
/// drift is cheap).
const CMM_MAX_ENDPOINTS: usize = 16;
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

/// In-flight STUN binding-request awaiting a response on this magicsock.
struct StunInflight {
    sent_at: Instant,
    result_tx: Sender<StunResult>,
}

/// In-flight Disco ping awaiting a matching Pong on this magicsock.
/// Used by `MagicSocketCtl::ping_now` (M14) — the LocalAPI `/ping`
/// endpoint synchronously triggers a ping and awaits the round-trip.
/// Background ping_pump pings are NOT routed through this map;
/// they use `PathState.outstanding_tx_id` instead and emit logs only.
struct PingInflight {
    sent_at: Instant,
    target: SocketAddr,
    result_tx: Sender<PingResult>,
}

/// Outcome of an active Disco ping: `(endpoint, RTT)` on Pong return.
pub type PingResult = Result<(SocketAddr, Duration), MagicError>;

/// Outcome of a STUN binding probe: the public-mapped reflected
/// address as seen by the STUN server, plus round-trip time.
pub type StunResult = Result<(SocketAddr, Duration), MagicError>;

#[derive(Default)]
struct MagicState {
    peers: HashMap<NodeKey, PeerState>,
    /// Reverse index: disco pubkey → node pubkey. When a Disco frame
    /// arrives, the header's `sender_pub` tells us which Disco identity
    /// sent it; this map resolves to the node identity for the
    /// `peers` lookup.
    disco_to_node: HashMap<DiscoPublicKey, NodeKey>,
    /// STUN binding-requests awaiting reply. Keyed by 12-byte
    /// transaction ID. `MagicSocketCtl::stun_probe` registers a sender;
    /// `handle_recv` matches incoming STUN responses by tx_id and
    /// fulfills the channel.
    stun_outstanding: HashMap<[u8; 12], StunInflight>,
    /// Active Disco pings awaiting Pong, keyed by tx_id. Populated by
    /// `MagicSocketCtl::ping_now`; consumed in the Pong arm of
    /// `handle_disco`. Distinct from `PathState.outstanding_tx_id`
    /// (background pump tracking) so a synchronous ping_now caller
    /// gets the actual Pong instead of having to poll alive_endpoint.
    ping_outstanding: HashMap<[u8; 12], PingInflight>,
    /// Our own endpoints to advertise in outgoing CallMeMaybe. Set by
    /// runtime after netcheck completes; consumed by the CMM trigger
    /// path in `ping_pump`. Empty until set.
    local_endpoints: Vec<SocketAddr>,
    /// Per-peer rate limit: latest CallMeMaybe-send timestamp. Prevents
    /// our pump from flooding DERP with CMMs when a peer is unreachable.
    last_cmm_sent_at: HashMap<NodeKey, Instant>,
    /// CallMeMaybe send queue. Magicsock encrypts + enqueues; the
    /// runtime polls via `take_pending_cmm` and dispatches over DERP.
    cmm_pending: VecDeque<(NodeKey, Vec<u8>)>,
}

/// Public handle. Cloneable; runtime + wg-engine both hold copies.
#[derive(Clone)]
pub struct MagicSocketCtl {
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<MagicState>>,
    shutdown: Arc<AtomicBool>,
    local_addr: SocketAddr,
    /// Our Disco identity. Shared with the worker thread (which also
    /// holds an Arc). Needed on the ctl side so `handle_disco_from_derp`
    /// can decrypt CallMeMaybe frames the runtime relays from DERP.
    our_disco_priv: Arc<DiscoPrivateKey>,
    /// Our node public key — encoded into outbound Pings (and inbound
    /// CMM-triggered Pings) so receivers can correlate disco→node.
    our_node_pub: NodePublicKey,
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
        // Share the disco-priv via Arc so the ctl side can decrypt
        // CallMeMaybe frames that arrive via DERP (Stage 4). The worker
        // also holds an Arc; both sides read-only — no mutation.
        let our_disco_priv = Arc::new(our_disco_priv);

        let ctl = MagicSocketCtl {
            socket: Arc::clone(&socket),
            state: Arc::clone(&state),
            shutdown: Arc::clone(&shutdown),
            local_addr,
            our_disco_priv: Arc::clone(&our_disco_priv),
            our_node_pub,
        };

        let worker_state = Arc::clone(&state);
        let worker_socket = Arc::clone(&socket);
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_priv = Arc::clone(&our_disco_priv);
        let worker = thread::Builder::new()
            .name("ts-magicsock".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let our_node_pub = our_node_pub;
                worker_loop(
                    worker_socket,
                    worker_state,
                    worker_shutdown,
                    worker_priv,
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
        let endpoint_count = endpoints.len();
        let endpoint_summary: Vec<String> =
            endpoints.iter().map(|a| a.to_string()).collect();
        info!(
            peer_pub = %hex32(&node_pub),
            disco_pub = %hex32_disco(&disco_pub),
            count = endpoint_count,
            endpoints = ?endpoint_summary,
            "magicsock.peer.endpoints"
        );

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

    /// Last-measured RTT on this peer's best alive direct path. None
    /// when no alive path exists. M14 LocalAPI's snapshot publishes
    /// this as `PeerView.direct_path_rtt_ms`.
    pub fn peer_rtt(&self, node_pub: &NodeKey) -> Option<Duration> {
        let now = Instant::now();
        let s = self.state.lock();
        let peer = s.peers.get(node_pub)?;
        peer.paths
            .values()
            .filter(|st| st.alive(now))
            .filter_map(|st| st.rtt)
            .min()
    }

    /// Send a raw datagram to an arbitrary UDP address. wg-engine uses
    /// this to send WG packets along an alive direct path.
    pub fn send_to(&self, addr: SocketAddr, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket.send_to(bytes, addr)
    }

    /// Issue a STUN binding-request to `target` (typically a DERP
    /// region's `:3478` address) via this magic socket. Returns a
    /// receiver that resolves to the public-mapped reflected address
    /// + RTT once the response arrives, or `MagicError` on send failure
    /// (timeouts are the caller's responsibility — `recv_timeout()`).
    ///
    /// The reflected address represents how the STUN server saw our
    /// source UDP endpoint — i.e., our public-mapped IP + port for
    /// MapRequest.Endpoints advertisement. Issued via the magicsock's
    /// own UDP socket (NOT a fresh ephemeral port) so the reflected
    /// port matches the one peers can actually direct-connect to.
    pub fn stun_probe(&self, target: SocketAddr) -> Result<Receiver<StunResult>, MagicError> {
        // Random 12-byte transaction ID.
        let mut tx_id = [0u8; 12];
        OsRng.fill_bytes(&mut tx_id);
        // bounded(1) — we only ever send one response per probe.
        let (tx, rx) = bounded(1);
        let req = stun::encode_binding_request(&tx_id);
        // Register BEFORE sending so the RX worker can route the
        // response even if we race.
        {
            let mut s = self.state.lock();
            s.stun_outstanding.insert(
                tx_id,
                StunInflight {
                    sent_at: Instant::now(),
                    result_tx: tx,
                },
            );
        }
        if let Err(e) = self.socket.send_to(&req, target) {
            // Roll back the registration so the entry doesn't leak.
            self.state.lock().stun_outstanding.remove(&tx_id);
            return Err(e.into());
        }
        debug!(%target, tx_id = %short_hex_tx(&tx_id), "magicsock.stun.probe.sent");
        Ok(rx)
    }

    /// Best-effort: signal the worker to exit. Returns immediately;
    /// the receive thread polls the flag at most every `RECV_TIMEOUT`.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Synchronous Disco ping with caller-provided timeout. Returns
    /// `(endpoint, RTT)` on Pong return, or `MagicError::PingTimeout`
    /// if no Pong arrives in `timeout`. Used by M14 LocalAPI's
    /// `/ping` endpoint — the background pump's own pings DON'T
    /// route through this channel.
    ///
    /// Endpoint selection: prefer the peer's currently-alive direct
    /// path; else the first registered candidate. Returns
    /// `MagicError::UnknownPeer` if we have no record of the peer
    /// (caller didn't call `upsert_peer` first).
    pub fn ping_now(
        &self,
        node_pub: &NodeKey,
        timeout: Duration,
    ) -> PingResult {
        // Pick target endpoint + peer's disco_pub under the lock.
        let (target, peer_disco) = {
            let s = self.state.lock();
            let peer = s
                .peers
                .get(node_pub)
                .ok_or(MagicError::UnknownPeer)?;
            let alive = peer
                .paths
                .iter()
                .find(|(_, st)| st.alive(Instant::now()))
                .map(|(addr, _)| *addr);
            let target = alive
                .or_else(|| peer.endpoints.first().copied())
                .ok_or(MagicError::NoEndpoints)?;
            (target, peer.disco_pub)
        };

        // Build + send ping + register the inflight slot.
        let mut tx_id = [0u8; 12];
        OsRng.fill_bytes(&mut tx_id);
        let (tx, rx) = bounded(1);
        {
            let mut s = self.state.lock();
            s.ping_outstanding.insert(
                tx_id,
                PingInflight {
                    sent_at: Instant::now(),
                    target,
                    result_tx: tx,
                },
            );
        }
        if let Err(e) = encode_and_send_ping(
            &self.socket,
            &self.our_disco_priv,
            &self.our_node_pub,
            &peer_disco,
            target,
            tx_id,
        ) {
            // Send failed; clean up the inflight slot so it doesn't leak.
            self.state.lock().ping_outstanding.remove(&tx_id);
            return Err(e);
        }
        debug!(
            target = %target,
            tx_id = %short_hex_tx(&tx_id),
            "magicsock.ping_now.sent"
        );
        // Wait for the worker thread to fulfill the channel from
        // handle_disco's Pong arm. On timeout, garbage-collect the
        // inflight slot.
        match rx.recv_timeout(timeout) {
            Ok(res) => res,
            Err(_elapsed) => {
                self.state.lock().ping_outstanding.remove(&tx_id);
                Err(MagicError::PingTimeout)
            }
        }
    }

    /// Set our own advertise-able endpoints. Used as the body of any
    /// CallMeMaybe we send (we're telling the peer: "ping me at these
    /// addresses to open the NAT"). Typically: magicsock's local UDP
    /// binding + STUN-reflected public-mapped endpoint.
    ///
    /// Callable at any time; the latest value wins. Pass an empty vec
    /// to disable outbound CMM until endpoints are re-discovered.
    pub fn set_local_endpoints(&self, endpoints: Vec<SocketAddr>) {
        let count = endpoints.len();
        let mut s = self.state.lock();
        s.local_endpoints = endpoints;
        info!(count, "magicsock.local_endpoints.set");
    }

    /// Drain queued CallMeMaybe sends. Each `(peer_node_key,
    /// encrypted_bytes)` tuple is ready to dispatch over DERP to the
    /// named peer (the caller looks up the peer's home region + uses
    /// `DerpTransport`/`DerpTransportCtl::send`).
    ///
    /// Magicsock can't send DERP frames itself — it owns the magic UDP
    /// socket, not the DERP conn pool. So it stages CMM bytes here and
    /// the runtime drains the queue.
    pub fn take_pending_cmm(&self) -> Vec<(NodeKey, Vec<u8>)> {
        let mut s = self.state.lock();
        s.cmm_pending.drain(..).collect()
    }

    /// Handle a Disco-formatted frame that arrived via DERP (not UDP).
    ///
    /// DualTransport sniffs `TS💬` magic on DERP-delivered bytes and
    /// dispatches them here; the only Disco type expected on DERP is
    /// CallMeMaybe. Ping/Pong over DERP would defeat the purpose
    /// (DERP is the slow path we're trying to escape) — log + drop.
    pub fn handle_disco_from_derp(&self, bytes: &[u8]) {
        let mut owned = bytes.to_vec();
        let encrypted = match Packet::<ts_disco::Encrypted>::from_encrypted_bytes_mut(&mut owned) {
            Ok(p) => p,
            Err(e) => {
                trace!(?e, "magicsock.derp_disco.parse_failed");
                return;
            }
        };
        let sender_pub = encrypted.header().sender_pub();
        let plaintext = match encrypted.decrypt_in_place(&self.our_disco_priv) {
            Ok(p) => p,
            Err(e) => {
                trace!(?e, "magicsock.derp_disco.decrypt_failed");
                return;
            }
        };
        match plaintext.ty() {
            Some(MessageType::CallMeMaybe) => {
                let cmm = match plaintext.as_msg::<CallMeMaybe>() {
                    Some(m) => m,
                    None => {
                        trace!("magicsock.derp_disco.callme.body_invalid");
                        return;
                    }
                };
                handle_call_me_maybe(
                    &self.socket,
                    &self.state,
                    &self.our_disco_priv,
                    &self.our_node_pub,
                    sender_pub,
                    cmm,
                );
            }
            Some(other) => {
                trace!(?other, "magicsock.derp_disco.unexpected_type");
            }
            None => {
                trace!("magicsock.derp_disco.unknown_type_byte");
            }
        }
    }
}

/// 8-hex-char short form of a 12-byte STUN tx_id, for log compactness.
fn short_hex_tx(tx: &[u8; 12]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(8);
    for b in &tx[..4] {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// wg-engine's path-selection oracle. The pump asks per send.
impl wg_engine::DirectPathHint for MagicSocketCtl {
    fn alive_endpoint(&self, peer_pubkey: &[u8; 32]) -> Option<SocketAddr> {
        MagicSocketCtl::alive_endpoint(self, peer_pubkey)
    }
}

// ============================================================
// Worker: receive loop + periodic ping pump.
// ============================================================

fn worker_loop(
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<MagicState>>,
    shutdown: Arc<AtomicBool>,
    our_disco_priv: Arc<DiscoPrivateKey>,
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
                    &our_node_pub,
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
    our_node_pub: &NodePublicKey,
    non_disco_tx: &Sender<NonDiscoPacket>,
) {
    // Three-way demux: STUN response → netcheck; Disco → handler;
    // anything else → wg-engine.
    if stun::looks_like_stun(bytes) {
        handle_stun_response(bytes, src, state);
        return;
    }
    if !ts_disco::is_disco_message(bytes) {
        // Forward raw bytes for wg-engine. If the channel is full or
        // disconnected, drop — wg's existing retransmits cover it.
        let _ = non_disco_tx.try_send((src, bytes.to_vec()));
        return;
    }
    handle_disco(bytes, src, socket, state, our_disco_priv, our_node_pub);
}

/// Match a STUN binding-success response against the
/// `stun_outstanding` table by transaction ID; if found, parse the
/// XOR-MAPPED-ADDRESS and fulfill the probe's result channel.
fn handle_stun_response(
    bytes: &[u8],
    src: SocketAddr,
    state: &Mutex<MagicState>,
) {
    let tx_id = match stun::tx_id_from(bytes) {
        Some(id) => id,
        None => return,
    };
    // Lock briefly to remove the inflight entry; release before
    // touching the channel.
    let inflight = {
        let mut s = state.lock();
        s.stun_outstanding.remove(&tx_id)
    };
    let inflight = match inflight {
        Some(i) => i,
        None => {
            trace!(%src, "magicsock.stun.unknown_tx_id");
            return;
        }
    };
    let rtt = inflight.sent_at.elapsed();
    let parsed = stun::parse_binding_response(bytes);
    match parsed {
        Some(reflected) => {
            info!(
                %src,
                %reflected,
                rtt_ms = rtt.as_millis() as u64,
                "magicsock.stun.response"
            );
            let _ = inflight.result_tx.try_send(Ok((reflected, rtt)));
        }
        None => {
            warn!(%src, "magicsock.stun.parse_failed");
            let _ = inflight
                .result_tx
                .try_send(Err(MagicError::StunParseFailed));
        }
    }
}

fn handle_disco(
    bytes: &[u8],
    src: SocketAddr,
    socket: &UdpSocket,
    state: &Mutex<MagicState>,
    our_disco_priv: &DiscoPrivateKey,
    our_node_pub: &NodePublicKey,
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
            let pong_tx_id = pong.tx_id;
            let now = Instant::now();
            // First check if a synchronous `ping_now` is waiting on
            // this tx_id; if so, fulfill it and continue (the same
            // Pong still updates `PathState` below for the alive-path
            // selector).
            {
                let mut s = state.lock();
                if let Some(inflight) = s.ping_outstanding.remove(&pong_tx_id) {
                    let rtt = now.duration_since(inflight.sent_at);
                    let _ = inflight.result_tx.try_send(Ok((inflight.target, rtt)));
                }
            }
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
                        let first_pong = path.last_pong_at.is_none();
                        path.last_pong_at = Some(now);
                        path.rtt = Some(rtt);
                        path.outstanding_tx_id = None;
                        if first_pong {
                            // Direct path from "untested" → "alive" —
                            // worth surfacing at info level.
                            info!(
                                peer_pub = %hex32(&node_pub),
                                %src,
                                rtt_ms = rtt.as_millis() as u64,
                                "magicsock.disco.pong.alive (first)"
                            );
                        } else {
                            debug!(
                                peer_pub = %hex32(&node_pub),
                                %src,
                                rtt_ms = rtt.as_millis() as u64,
                                "magicsock.disco.pong.alive"
                            );
                        }
                    } else {
                        trace!(%src, "magicsock.disco.pong.tx_mismatch");
                    }
                }
            }
        }
        Some(MessageType::CallMeMaybe) => {
            // CallMeMaybe should arrive via DERP, not UDP. If we got
            // one over UDP, the path's already direct — pinging again
            // is harmless but redundant. Accept it anyway for protocol
            // robustness (upstream Go's design is "decode anywhere,
            // act idempotently").
            let cmm = match plaintext.as_msg::<CallMeMaybe>() {
                Some(m) => m,
                None => {
                    trace!(%src, "magicsock.disco.callme.body_invalid");
                    return;
                }
            };
            handle_call_me_maybe(socket, state, our_disco_priv, our_node_pub, sender_pub, cmm);
        }
        Some(other) => {
            trace!(?other, %src, "magicsock.disco.unhandled_type");
        }
        None => {
            trace!(%src, "magicsock.disco.unknown_type_byte");
        }
    }
}

/// Handle an incoming CallMeMaybe: the sender is telling us "I think
/// you can reach me at these endpoints; please ping them to open the
/// reverse NAT mapping." Action:
///
/// 1. For each advertised endpoint, ensure the peer's `PathState` has
///    an entry for it (the ping pump will pick it up on the next cycle).
/// 2. Send an immediate Ping to each endpoint so the outbound NAT
///    mapping opens NOW — don't wait up to 5 s for the next pump.
///
/// `socket`/`our_disco_priv` are needed for the immediate-ping path.
/// Looked up via `sender_pub` → `disco_to_node` reverse map; if the
/// peer is unknown (CMM from a peer not yet in our netmap), drop —
/// the next MapResponse will catch up.
///
/// Worker thread takes `&DiscoPrivateKey`; ctl side takes
/// `&Arc<DiscoPrivateKey>` and `&*arc` to coerce.
fn handle_call_me_maybe(
    socket: &UdpSocket,
    state: &Mutex<MagicState>,
    our_disco_priv: &DiscoPrivateKey,
    our_node_pub: &NodePublicKey,
    sender_pub: DiscoPublicKey,
    cmm: &CallMeMaybe,
) {
    // Snapshot the endpoint list out of the packed zerocopy view
    // before we re-enter the lock — packed-field access via deref
    // gets unwieldy with the lock guard alive.
    let advertised: Vec<SocketAddr> = cmm.endpoints.iter().map(|e| e.socket_addr()).collect();
    let now = Instant::now();
    let (node_pub, peer_disco) = {
        let mut s = state.lock();
        let node_pub = match s.disco_to_node.get(&sender_pub).copied() {
            Some(n) => n,
            None => {
                debug!(
                    sender = %hex32_disco(&sender_pub),
                    "magicsock.callme.recv.unknown_sender"
                );
                return;
            }
        };
        let peer = match s.peers.get_mut(&node_pub) {
            Some(p) => p,
            None => return,
        };
        // Merge advertised endpoints into peer's candidate list. Fresh
        // ones get a new PathState so the ping pump picks them up;
        // already-known ones stay (don't disrupt their RTT history).
        for ep in &advertised {
            if !peer.endpoints.contains(ep) {
                peer.endpoints.push(*ep);
            }
            peer.paths.entry(*ep).or_insert_with(PathState::new);
        }
        (node_pub, peer.disco_pub)
    };
    info!(
        peer_pub = %hex32(&node_pub),
        endpoint_count = advertised.len(),
        "magicsock.callme.recv"
    );
    // Fire an immediate Ping to each advertised endpoint. Each Ping
    // also opens our outbound NAT mapping for the sender's reply.
    for ep in advertised {
        match send_ping(socket, our_disco_priv, our_node_pub, &peer_disco, ep) {
            Ok(tx_id) => {
                let mut s = state.lock();
                if let Some(peer) = s.peers.get_mut(&node_pub) {
                    let path = peer.paths.entry(ep).or_insert_with(PathState::new);
                    path.last_ping_at = Some(now);
                    path.outstanding_tx_id = Some(tx_id);
                }
            }
            Err(e) => trace!(?e, %ep, "magicsock.callme.recv.immediate_ping_failed"),
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

    // CallMeMaybe trigger: for each peer where (we know endpoints) AND
    // (we've been pinging at least CMM_TRIGGER_AFTER seconds with no
    // alive Pong) AND (we haven't sent a CMM for this peer in
    // CMM_RATE_LIMIT seconds), queue a Disco-encrypted CallMeMaybe.
    // Runtime drains the queue and dispatches via DERP.
    cmm_pump(state, our_disco_priv, now);
}

/// Build + queue CallMeMaybe sends for any peer that needs NAT-
/// traversal help. Idempotent + rate-limited; safe to call every pump.
fn cmm_pump(
    state: &Mutex<MagicState>,
    our_disco_priv: &DiscoPrivateKey,
    now: Instant,
) {
    // Snapshot what to send + our local endpoints, all under one lock.
    let (local_endpoints, to_cmm): (Vec<SocketAddr>, Vec<(NodeKey, DiscoPublicKey)>) = {
        let s = state.lock();
        if s.local_endpoints.is_empty() {
            // Nothing to advertise — runtime hasn't called
            // set_local_endpoints yet (no netcheck completed).
            return;
        }
        let local = s.local_endpoints.clone();
        let mut out = Vec::new();
        for (node_pub, peer) in &s.peers {
            if peer.endpoints.is_empty() {
                continue;
            }
            // Any alive path? Then no CMM needed.
            if peer.paths.values().any(|p| p.alive(now)) {
                continue;
            }
            // Have we been pinging long enough? Earliest last_ping_at
            // across this peer's paths.
            let earliest = peer
                .paths
                .values()
                .filter_map(|p| p.last_ping_at)
                .min();
            let stale_long_enough = earliest
                .map(|t| now.duration_since(t) >= CMM_TRIGGER_AFTER)
                .unwrap_or(false);
            if !stale_long_enough {
                continue;
            }
            // Per-peer rate limit.
            let too_soon = s
                .last_cmm_sent_at
                .get(node_pub)
                .map(|t| now.duration_since(*t) < CMM_RATE_LIMIT)
                .unwrap_or(false);
            if too_soon {
                continue;
            }
            out.push((*node_pub, peer.disco_pub));
        }
        (local, out)
    };

    if to_cmm.is_empty() {
        return;
    }
    // Truncate endpoints to the wire cap.
    let ep_slice: &[SocketAddr] = if local_endpoints.len() > CMM_MAX_ENDPOINTS {
        &local_endpoints[..CMM_MAX_ENDPOINTS]
    } else {
        &local_endpoints
    };

    for (node_pub, peer_disco) in to_cmm {
        let bytes = match build_call_me_maybe(our_disco_priv, &peer_disco, ep_slice) {
            Ok(b) => b,
            Err(e) => {
                trace!(?e, "magicsock.callme.build_failed");
                continue;
            }
        };
        let mut s = state.lock();
        s.last_cmm_sent_at.insert(node_pub, now);
        s.cmm_pending.push_back((node_pub, bytes));
        info!(
            peer_pub = %hex32(&node_pub),
            endpoint_count = ep_slice.len(),
            "magicsock.callme.queued"
        );
    }
}

/// Build + Disco-encrypt a CallMeMaybe destined for `peer_disco_pub`,
/// advertising `endpoints` as places the peer can reach us. Returns
/// ready-to-send bytes; the caller is responsible for delivery (always
/// via DERP, since by definition UDP-direct doesn't work yet).
fn build_call_me_maybe(
    our_disco_priv: &DiscoPrivateKey,
    peer_disco_pub: &DiscoPublicKey,
    endpoints: &[SocketAddr],
) -> Result<Vec<u8>, MagicError> {
    let mut nonce = [0u8; Header::NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let body_size = CallMeMaybe::size_for_endpoint_count(endpoints.len());
    let pkt_size = Packet::<ts_disco::Plaintext>::size_for_message(body_size);
    let mut buf = vec![0u8; pkt_size];

    {
        let pkt = Packet::<ts_disco::Plaintext>::init_from_bytes::<CallMeMaybe>(
            &mut buf,
            |cmm| {
                for (i, ep) in endpoints.iter().enumerate() {
                    cmm.endpoints[i] = Endpoint::from_socket_addr(*ep);
                }
            },
        )?;
        pkt.encrypt_in_place(our_disco_priv, peer_disco_pub, nonce)?;
    }
    Ok(buf)
}

/// Build + encrypt + send a Disco Ping with a freshly-generated
/// tx_id. Returns the tx_id used for caller-side correlation.
fn send_ping(
    socket: &UdpSocket,
    our_disco_priv: &DiscoPrivateKey,
    our_node_pub: &NodePublicKey,
    peer_disco_pub: &DiscoPublicKey,
    addr: SocketAddr,
) -> Result<[u8; 12], MagicError> {
    let mut tx_id = [0u8; 12];
    OsRng.fill_bytes(&mut tx_id);
    encode_and_send_ping(
        socket,
        our_disco_priv,
        our_node_pub,
        peer_disco_pub,
        addr,
        tx_id,
    )?;
    Ok(tx_id)
}

/// Build + encrypt + send a Disco Ping with the caller-provided
/// tx_id. Returns the tx_id (echoed) on success so call sites can
/// chain without re-binding. Used by both `send_ping` (random tx_id)
/// and `ping_now` (caller already registered the tx_id in the
/// inflight map).
fn encode_and_send_ping(
    socket: &UdpSocket,
    our_disco_priv: &DiscoPrivateKey,
    our_node_pub: &NodePublicKey,
    peer_disco_pub: &DiscoPublicKey,
    addr: SocketAddr,
    tx_id: [u8; 12],
) -> Result<[u8; 12], MagicError> {
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
    }

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

    /// M14 ping_now: A calls `ping_now(B)`, B's worker auto-Pongs, A's
    /// channel resolves with the RTT. Validates that
    /// `ping_outstanding` lookup + Pong arm fire correctly without
    /// going through `PathState.outstanding_tx_id`.
    #[test]
    fn ping_now_returns_rtt() {
        let a_priv = DiscoPrivateKey::random();
        let b_priv = DiscoPrivateKey::random();
        let a_pub = a_priv.public_key();
        let b_pub = b_priv.public_key();
        let a_node_bytes = [0xEE; 32];
        let b_node_bytes = [0xFF; 32];
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

        // A must know B's endpoint to ping. B must know A's disco
        // identity so its Pong addresses A correctly.
        a_ctl.upsert_peer(b_node_bytes, b_pub, vec![b_ctl.local_addr()]);
        b_ctl.upsert_peer(a_node_bytes, a_pub, vec![a_ctl.local_addr()]);

        let result = a_ctl.ping_now(&b_node_bytes, Duration::from_secs(3));
        match result {
            Ok((endpoint, rtt)) => {
                assert_eq!(endpoint, b_ctl.local_addr());
                assert!(rtt < Duration::from_millis(500), "rtt too high: {rtt:?}");
            }
            Err(e) => panic!("ping_now failed: {e:?}"),
        }
    }

    #[test]
    fn ping_now_returns_unknown_peer_for_unregistered_node() {
        let priv_key = DiscoPrivateKey::random();
        let node = NodePublicKey::from([0u8; 32]);
        let (non_tx, _non_rx) = unbounded::<NonDiscoPacket>();
        let (_sock, ctl) = MagicSocket::bind(
            loopback(0),
            DiscoPrivateKey::from_bytes(*priv_key.as_bytes()),
            node,
            non_tx,
        )
        .unwrap();
        let err = ctl
            .ping_now(&[0x99; 32], Duration::from_millis(100))
            .unwrap_err();
        assert!(matches!(err, MagicError::UnknownPeer), "got: {err:?}");
    }

    /// Build CMM bytes via the internal helper and decode them back via
    /// the receiver's path. Validates that:
    /// 1. The encrypted bytes start with Disco magic (so DualTransport's
    ///    `is_disco_message` peek correctly identifies them on DERP).
    /// 2. The receiver's `handle_disco_from_derp` decrypts the frame and
    ///    queues an immediate Ping to the advertised endpoint — which we
    ///    observe by bouncing the Ping into a bound UDP listener that
    ///    pretends to be the peer at the advertised address.
    #[test]
    fn cmm_roundtrip_triggers_immediate_ping() {
        let a_priv = DiscoPrivateKey::random();
        let b_priv = DiscoPrivateKey::random();
        let a_pub = a_priv.public_key();
        let b_pub = b_priv.public_key();
        let a_node_bytes = [0xCC; 32];
        let b_node_bytes = [0xDD; 32];
        let b_node = NodePublicKey::from(b_node_bytes);

        // Bind a "spoofed" endpoint socket — when B reacts to the CMM
        // it'll ping this address; we'll observe the Disco Ping arrival.
        let fake_a_endpoint = UdpSocket::bind(loopback(0)).unwrap();
        let fake_a_addr = fake_a_endpoint.local_addr().unwrap();
        fake_a_endpoint
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let (b_non_tx, _b_non_rx) = unbounded::<NonDiscoPacket>();
        let (_b_sock, b_ctl) = MagicSocket::bind(
            loopback(0),
            DiscoPrivateKey::from_bytes(*b_priv.as_bytes()),
            b_node,
            b_non_tx,
        )
        .unwrap();

        // B needs to know "node A's disco identity" before it can decode
        // the CMM (sender_pub → node_pub lookup) and ping back. Register
        // with empty endpoints — the CMM itself will deliver fake_a_addr.
        b_ctl.upsert_peer(a_node_bytes, a_pub, vec![]);

        // A builds CMM for B advertising fake_a_addr.
        let cmm_bytes = build_call_me_maybe(&a_priv, &b_pub, &[fake_a_addr]).unwrap();
        assert!(ts_disco::is_disco_message(&cmm_bytes));

        // Deliver to B as if relayed over DERP.
        b_ctl.handle_disco_from_derp(&cmm_bytes);

        // B should now immediately Ping fake_a_addr. Read one packet.
        let mut buf = [0u8; 1500];
        let (n, src) = fake_a_endpoint
            .recv_from(&mut buf)
            .expect("expected immediate Ping from B at fake_a_addr");
        assert!(ts_disco::is_disco_message(&buf[..n]));
        assert_eq!(src, b_ctl.local_addr());
    }
}
