//! Per-region DERP connection with a dedicated OS thread.
//!
//! Why a dedicated thread per conn (rather than tokio + select):
//!
//! - rustls is single-threaded internally — no two threads can drive
//!   the same `ClientConnection` concurrently.
//! - `DerpMux` holds 1–8 of these conns. Putting them all on a tokio
//!   current-thread runtime would serialize every write across regions.
//! - One OS thread per conn (with biased select for pong priority) is
//!   the same shape as M5's `noise_pump` and M7's `ts-gz` worker.
//! - `std::thread::Builder::new().stack_size(256 * 1024)`. Vita's 64 KiB
//!   default isn't enough for rustls + frame buffers.
//!
//! Pong priority: when a `FramePing` arrives, the read side pushes a
//! `DerpTx::Pong(payload)` back onto the conn's own tx channel. The
//! drain loop separates pongs from other tx in each iteration and
//! writes pongs first. PLAN-V1 §"DERP relay protocol" calls this out
//! because servers tear down conns within ~10 s of an unanswered ping.

use std::io::{ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use vita_thread::{self as thread, JoinHandle};
use std::time::{Duration, Instant};

use vita_chan::{Receiver, Sender};
use vita_sync::Mutex;
use vita_log::{debug, info, trace, warn};

use crate::frame::{
    parse_peer_gone, parse_ping, parse_recv_packet, parse_restarting, read_frame,
    write_note_preferred, write_pong, write_send_packet, FrameType,
};
use crate::handshake::{dial_and_handshake, DerpTls};
use crate::magic::{KEEPALIVE_DEADLINE, READ_TICK};
use crate::{DerpError, DerpNodeAddr, NodeKeyBytes};

/// Outbound message from the caller (or self-pong from the conn thread)
/// to be written to the relay.
#[derive(Clone, Debug)]
pub enum DerpTx {
    SendPacket {
        dst_pubkey: NodeKeyBytes,
        wg_bytes: Vec<u8>,
    },
    NotePreferred(bool),
    /// Echo of an incoming Ping. Always written before any other tx
    /// on the same iteration (pong-priority).
    Pong([u8; 8]),
}

/// Inbound packet seen by the conn thread, forwarded via the shared
/// `rx_sink` channel to the `DerpMux`/`DerpTransport`.
#[derive(Clone, Debug)]
pub struct DerpRx {
    pub src_pubkey: NodeKeyBytes,
    pub wg_bytes: Vec<u8>,
}

/// Handle to one connected DERP relay (one region).
pub struct DerpConn {
    pub region: u16,
    /// Caller-side sender — push outbound frames here.
    tx: Sender<DerpTx>,
    /// Set by the I/O thread on the most recent activity. Used by
    /// `DerpMux::evict_lru` (never evicts the home).
    last_used: Arc<Mutex<Instant>>,
    /// True if this conn is the home region (has had `NotePreferred(true)`
    /// sent at least once).
    is_home: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle>,
}

impl DerpConn {
    /// Try `nodes` in order until one connects + completes the
    /// handshake. Spawns the I/O thread on success.
    ///
    /// `rx_sink` is the shared inbound channel handed to the mux's
    /// `DerpTransport`. The conn pushes `(region, DerpRx)` to it; the
    /// transport drains.
    pub fn dial_and_spawn(
        region: u16,
        nodes: Vec<DerpNodeAddr>,
        our_priv: NodeKeyBytes,
        our_pub: NodeKeyBytes,
        rx_sink: Sender<(u16, DerpRx)>,
        is_home: bool,
    ) -> Result<Self, DerpError> {
        if nodes.is_empty() {
            return Err(DerpError::UnknownRegion { region });
        }
        let mut last_err: Option<DerpError> = None;
        for node in &nodes {
            match dial_and_handshake(node, &our_priv, &our_pub) {
                Ok(out) => {
                    info!(
                        region,
                        node = %node.name,
                        is_home,
                        "derp.handshake.ok"
                    );
                    return Ok(Self::spawn_io(region, out.tls, rx_sink, is_home)?);
                }
                Err(e) => {
                    warn!(region, node = %node.name, error = %e, "derp.handshake.fail");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap_or(DerpError::Internal(format!("no nodes for region {region}"))))
    }

    fn spawn_io(
        region: u16,
        tls: DerpTls,
        rx_sink: Sender<(u16, DerpRx)>,
        is_home: bool,
    ) -> Result<Self, DerpError> {
        let (tx_send, tx_recv) = vita_chan::unbounded::<DerpTx>();
        let last_used = Arc::new(Mutex::new(Instant::now()));
        let is_home_flag = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));

        let join = {
            let tx_self = tx_send.clone();
            let last_used = Arc::clone(&last_used);
            let shutdown = Arc::clone(&shutdown);
            thread::Builder::new()
                .name(format!("derp-{region}"))
                .stack_size(256 * 1024)
                .spawn(move || {
                    io_loop(
                        region,
                        tls,
                        tx_self,
                        tx_recv,
                        rx_sink,
                        last_used,
                        shutdown,
                        is_home,
                    );
                    info!(region, "derp.conn.thread.exit");
                })
                .map_err(DerpError::Io)?
        };

        if is_home {
            is_home_flag.store(true, Ordering::Relaxed);
            // Send the home marker. Ignore push failure — thread is alive.
            let _ = tx_send.send(DerpTx::NotePreferred(true));
        }

        Ok(DerpConn {
            region,
            tx: tx_send,
            last_used,
            is_home: is_home_flag,
            shutdown,
            join: Some(join),
        })
    }

    pub fn send(&self, msg: DerpTx) -> Result<(), DerpError> {
        self.tx
            .send(msg)
            .map_err(|_| DerpError::ConnDied(format!("region {} thread closed", self.region)))
    }

    pub fn last_used(&self) -> Instant {
        *self.last_used.lock()
    }

    pub fn is_home(&self) -> bool {
        self.is_home.load(Ordering::Relaxed)
    }

    /// Mark this conn as home (or un-home). Sends a `NotePreferred`
    /// frame to the relay.
    pub fn set_home(&self, home: bool) -> Result<(), DerpError> {
        self.is_home.store(home, Ordering::Relaxed);
        self.send(DerpTx::NotePreferred(home))
    }

    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Drop the tx so the thread sees disconnect.
        // (We can't drop self.tx directly; replace with a local drop pattern.)
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }

    pub fn is_alive(&self) -> bool {
        self.join.as_ref().map(|j| !j.is_finished()).unwrap_or(false)
    }
}

impl Drop for DerpConn {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

// ---------- I/O thread loop ----------------------------------------------

#[allow(clippy::too_many_arguments)]
fn io_loop(
    region: u16,
    mut tls: DerpTls,
    tx_self: Sender<DerpTx>,
    tx_recv: Receiver<DerpTx>,
    rx_sink: Sender<(u16, DerpRx)>,
    last_used: Arc<Mutex<Instant>>,
    shutdown: Arc<AtomicBool>,
    initial_home: bool,
) {
    info!(region, is_home = initial_home, "derp.conn.thread.start");
    // Per-poll read timeout; rustls inherits this on the underlying TcpStream.
    let _ = tls.sock.set_read_timeout(Some(READ_TICK));
    let mut last_rx = Instant::now();
    let mut tx_count: u64 = 0;
    let mut rx_count: u64 = 0;

    while !shutdown.load(Ordering::Relaxed) {
        // 1. Drain tx with priority for Pongs.
        let mut pongs: Vec<DerpTx> = Vec::new();
        let mut others: Vec<DerpTx> = Vec::new();
        while let Ok(msg) = tx_recv.try_recv() {
            match msg {
                DerpTx::Pong(_) => pongs.push(msg),
                _ => others.push(msg),
            }
        }
        let pong_n = pongs.len();
        let other_n = others.len();
        for msg in pongs.into_iter().chain(others.into_iter()) {
            if let Err(e) = write_outbound(&mut tls, &msg) {
                warn!(region, error = %e, "derp.tx.error");
                return;
            }
            tx_count += 1;
        }
        if pong_n > 0 || other_n > 0 {
            // Single flush per batch to amortize TLS/TCP overhead.
            if let Err(e) = tls.flush() {
                warn!(region, error = %e, "derp.tx.flush.error");
                return;
            }
            *last_used.lock() = Instant::now();
            trace!(
                region,
                pongs = pong_n,
                others = other_n,
                tx_total = tx_count,
                "derp.tx.batch"
            );
        }

        // 2. Try one read with READ_TICK timeout.
        match read_frame(&mut tls) {
            Ok((ty, payload)) => {
                last_rx = Instant::now();
                rx_count += 1;
                if let HandleAction::Restart { delay } =
                    handle_frame(region, ty, payload, &tx_self, &rx_sink)
                {
                    warn!(
                        region,
                        delay_ms = delay.as_millis() as u64,
                        "derp.restarting.honored"
                    );
                    thread::sleep(delay);
                    return;
                }
            }
            Err(DerpError::Io(e))
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                // No frame ready; loop.
            }
            Err(e) => {
                warn!(region, error = %e, rx_total = rx_count, "derp.rx.error");
                return;
            }
        }

        // 3. Watchdog.
        if last_rx.elapsed() > KEEPALIVE_DEADLINE {
            warn!(
                region,
                idle_secs = last_rx.elapsed().as_secs(),
                "derp.watchdog.dead-conn"
            );
            return;
        }
    }

    info!(
        region,
        tx_total = tx_count,
        rx_total = rx_count,
        "derp.conn.shutdown.requested"
    );
}

enum HandleAction {
    Continue,
    Restart { delay: Duration },
}

fn handle_frame(
    region: u16,
    ty: FrameType,
    payload: Vec<u8>,
    tx_self: &Sender<DerpTx>,
    rx_sink: &Sender<(u16, DerpRx)>,
) -> HandleAction {
    match ty {
        FrameType::RecvPacket => match parse_recv_packet(&payload) {
            Ok((src, body)) => {
                let _ = rx_sink.send((
                    region,
                    DerpRx {
                        src_pubkey: src,
                        wg_bytes: body.to_vec(),
                    },
                ));
                trace!(region, src = %short_hex(&src), bytes = body.len(), "derp.rx");
            }
            Err(e) => warn!(region, error = %e, "derp.recv_packet.parse_error"),
        },
        FrameType::Ping => match parse_ping(&payload) {
            Ok(echo) => {
                let _ = tx_self.send(DerpTx::Pong(echo));
                trace!(region, "derp.ping.received");
            }
            Err(e) => warn!(region, error = %e, "derp.ping.parse_error"),
        },
        FrameType::KeepAlive => debug!(region, "derp.keepalive"),
        FrameType::PeerGone => match parse_peer_gone(&payload) {
            Ok((pk, reason)) => debug!(
                region,
                peer = %short_hex(&pk),
                reason,
                "derp.peer_gone"
            ),
            Err(e) => warn!(region, error = %e, "derp.peer_gone.parse_error"),
        },
        FrameType::Health => info!(
            region,
            msg = %String::from_utf8_lossy(&payload),
            "derp.health"
        ),
        FrameType::Restarting => match parse_restarting(&payload) {
            Ok((reconnect_in_ms, try_for_ms)) => {
                info!(
                    region,
                    reconnect_in_ms,
                    try_for_ms,
                    "derp.restarting"
                );
                return HandleAction::Restart {
                    delay: Duration::from_millis(reconnect_in_ms as u64),
                };
            }
            Err(e) => warn!(region, error = %e, "derp.restarting.parse_error"),
        },
        FrameType::ServerKey | FrameType::ServerInfo | FrameType::ClientInfo => {
            warn!(region, ?ty, "derp.unexpected.handshake_frame");
        }
        FrameType::PeerPresent
        | FrameType::ForwardPacket
        | FrameType::WatchConns
        | FrameType::ClosePeer
        | FrameType::Pong
        | FrameType::SendPacket
        | FrameType::NotePreferred => {
            trace!(region, ?ty, "derp.frame.unhandled");
        }
    }
    HandleAction::Continue
}

fn write_outbound(tls: &mut DerpTls, msg: &DerpTx) -> Result<(), DerpError> {
    match msg {
        DerpTx::SendPacket {
            dst_pubkey,
            wg_bytes,
        } => write_send_packet(tls, dst_pubkey, wg_bytes),
        DerpTx::NotePreferred(b) => write_note_preferred(tls, *b),
        DerpTx::Pong(p) => write_pong(tls, *p),
    }
}

fn short_hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(16);
    for byte in &b[..b.len().min(8)] {
        let _ = write!(s, "{:02x}", byte);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_outbound_routes_each_variant() {
        let mut buf = Vec::new();
        // SendPacket
        let dst = [0x11; 32];
        write_outbound_to_writer(
            &mut buf,
            &DerpTx::SendPacket {
                dst_pubkey: dst,
                wg_bytes: b"wg".to_vec(),
            },
        )
        .unwrap();
        assert_eq!(buf[0], 0x04);
        buf.clear();
        // NotePreferred
        write_outbound_to_writer(&mut buf, &DerpTx::NotePreferred(true)).unwrap();
        assert_eq!(buf[0], 0x07);
        assert_eq!(buf[5], 0x01);
        buf.clear();
        // Pong
        write_outbound_to_writer(&mut buf, &DerpTx::Pong([1, 2, 3, 4, 5, 6, 7, 8])).unwrap();
        assert_eq!(buf[0], 0x13);
        assert_eq!(&buf[5..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// Same logic as `write_outbound` but writes to `&mut Vec<u8>`
    /// instead of a TLS stream — the actual write_outbound takes
    /// `&mut DerpTls` which we can't construct in unit tests.
    fn write_outbound_to_writer<W: Write>(w: &mut W, msg: &DerpTx) -> Result<(), DerpError> {
        match msg {
            DerpTx::SendPacket {
                dst_pubkey,
                wg_bytes,
            } => write_send_packet(w, dst_pubkey, wg_bytes),
            DerpTx::NotePreferred(b) => write_note_preferred(w, *b),
            DerpTx::Pong(p) => write_pong(w, *p),
        }
    }

    #[test]
    fn handle_frame_keepalive_continues() {
        let (tx_self, _tx_recv) = vita_chan::unbounded::<DerpTx>();
        let (rx_sink, _rx) = vita_chan::unbounded::<(u16, DerpRx)>();
        let action = handle_frame(1, FrameType::KeepAlive, vec![], &tx_self, &rx_sink);
        assert!(matches!(action, HandleAction::Continue));
    }

    #[test]
    fn handle_frame_ping_pushes_pong_to_self() {
        let (tx_self, tx_recv) = vita_chan::unbounded::<DerpTx>();
        let (rx_sink, _rx) = vita_chan::unbounded::<(u16, DerpRx)>();
        let echo: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];
        let mut payload = Vec::new();
        payload.extend_from_slice(&echo);
        let _ = handle_frame(1, FrameType::Ping, payload, &tx_self, &rx_sink);
        let msg = tx_recv.try_recv().unwrap();
        assert!(matches!(msg, DerpTx::Pong(p) if p == echo));
    }

    #[test]
    fn handle_frame_recv_packet_emits_to_sink() {
        let (tx_self, _tx_recv) = vita_chan::unbounded::<DerpTx>();
        let (rx_sink, rx) = vita_chan::unbounded::<(u16, DerpRx)>();
        let src = [0xaa; 32];
        let mut payload = Vec::new();
        payload.extend_from_slice(&src);
        payload.extend_from_slice(b"WGBYTES");
        let _ = handle_frame(7, FrameType::RecvPacket, payload, &tx_self, &rx_sink);
        let (region, derp_rx) = rx.try_recv().unwrap();
        assert_eq!(region, 7);
        assert_eq!(derp_rx.src_pubkey, src);
        assert_eq!(derp_rx.wg_bytes, b"WGBYTES");
    }

    #[test]
    fn handle_frame_restarting_returns_delay() {
        let (tx_self, _) = vita_chan::unbounded::<DerpTx>();
        let (rx_sink, _) = vita_chan::unbounded::<(u16, DerpRx)>();
        let payload = [0, 0, 0x01, 0x00, 0, 0, 0x10, 0x00];
        let action = handle_frame(1, FrameType::Restarting, payload.to_vec(), &tx_self, &rx_sink);
        match action {
            HandleAction::Restart { delay } => assert_eq!(delay.as_millis(), 256),
            _ => panic!("expected Restart"),
        }
    }
}
