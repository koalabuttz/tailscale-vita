#![allow(dead_code)] // consumers (dashboard/render) are vita-gated; host sees these as dead

//! M17-A S2 — loopback LocalAPI client + background poller.
//!
//! The dashboard is a pure HTTP client of the runtime's LocalAPI
//! (`127.0.0.1:41112`), whether the runtime lives in the SUPRX
//! (suprx_host_only) or in this eboot (normal mode). One poller thread
//! GETs `/status` every `POLL_INTERVAL` into `Shared`; ping requests
//! ride the same thread ON PURPOSE — LocalAPI has a single accept
//! thread and `/ping` blocks it up to 5 s, so a parallel `/status`
//! poll would only stall behind it (see docs/PLAN-M17A.md).

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use vita_chan::{Receiver, RecvTimeoutError};
use vita_log::{debug, info, warn};

use tailscale_vita::RuntimeSnapshot;

const LOCALAPI_ADDR: &str = "127.0.0.1:41112";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const STATUS_READ_TIMEOUT: Duration = Duration::from_secs(3);
/// `/ping` blocks server-side up to 5 s; leave headroom.
const PING_READ_TIMEOUT: Duration = Duration::from_secs(7);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_RESPONSE: usize = 512 * 1024;

/// UI-facing state written by the poller thread, read each frame by
/// the render loop. Lock is held only for field copies.
pub struct Shared {
    /// Latest good snapshot. `None` until the first successful poll
    /// (runtime still starting, or SUPRX not loaded).
    pub snapshot: Option<RuntimeSnapshot>,
    /// Bumped on every successful poll — lets the render loop rebuild
    /// its viewmodel only when something actually changed.
    pub generation: u64,
    pub last_ok_at: Option<Instant>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub ping: PingState,
}

impl Shared {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            snapshot: None,
            generation: 0,
            last_ok_at: None,
            last_error: None,
            consecutive_failures: 0,
            ping: PingState::Idle,
        }))
    }
}

#[derive(Clone)]
pub enum PingState {
    Idle,
    InFlight { peer_name: String },
    Done { line: String, ok: bool, at: Instant },
}

/// A ping request from the UI thread to the poller.
pub struct PingRequest {
    pub ip: Ipv4Addr,
    pub peer_name: String,
}

/// Spawn the poller thread. Exits when the ping channel disconnects
/// (i.e. the UI side dropped its Sender).
pub fn spawn_poller(shared: Arc<Mutex<Shared>>, ping_rx: Receiver<PingRequest>) {
    let spawned = vita_thread::Builder::new()
        .name("ui-poller")
        .stack_size(128 * 1024)
        .spawn(move || poller_loop(shared, ping_rx));
    if let Err(e) = spawned {
        warn!(error = %e, "ui.poller.spawn_failed");
    }
}

fn poller_loop(shared: Arc<Mutex<Shared>>, ping_rx: Receiver<PingRequest>) {
    info!("ui.poller.start");
    loop {
        match fetch_status() {
            Ok(snap) => {
                let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
                s.snapshot = Some(snap);
                s.generation += 1;
                s.last_ok_at = Some(Instant::now());
                s.last_error = None;
                s.consecutive_failures = 0;
                debug!(generation = s.generation, "ui.poll.ok");
            }
            Err(e) => {
                let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
                s.consecutive_failures += 1;
                s.last_error = Some(e.clone());
                // Bump generation so the UI re-renders banners promptly.
                s.generation += 1;
                if s.consecutive_failures <= 3 || s.consecutive_failures % 15 == 0 {
                    warn!(error = %e, failures = s.consecutive_failures, "ui.poll.err");
                }
            }
        }

        // The poll pacing doubles as the ping mailbox wait.
        match ping_rx.recv_timeout(POLL_INTERVAL) {
            Ok(req) => {
                {
                    let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
                    s.ping = PingState::InFlight {
                        peer_name: req.peer_name.clone(),
                    };
                }
                info!(ip = %req.ip, peer = %req.peer_name, "ui.ping.sent");
                let (line, ok) = do_ping(&req);
                info!(result = %line, "ui.ping.result");
                let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
                s.ping = PingState::Done {
                    line,
                    ok,
                    at: Instant::now(),
                };
                s.generation += 1;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                info!("ui.poller.exit");
                return;
            }
        }
    }
}

/// GET /localapi/v0/status → RuntimeSnapshot.
fn fetch_status() -> Result<RuntimeSnapshot, String> {
    let (status, body) = http_get("/localapi/v0/status", STATUS_READ_TIMEOUT)?;
    if status != 200 {
        return Err(format!("status HTTP {status}"));
    }
    serde_json::from_slice(&body).map_err(|e| format!("bad status JSON: {e}"))
}

/// `/ping` response body — success carries rtt_ms+endpoint, domain
/// failures (timeout / no endpoints) come back 200 with `error`.
#[derive(Deserialize)]
struct PingResp {
    rtt_ms: Option<u64>,
    endpoint: Option<String>,
    error: Option<String>,
}

/// Run one blocking disco ping via LocalAPI; returns the display line
/// plus success flag.
fn do_ping(req: &PingRequest) -> (String, bool) {
    let path = format!("/localapi/v0/ping?ip={}", req.ip);
    match http_get(&path, PING_READ_TIMEOUT) {
        Ok((status, body)) => match serde_json::from_slice::<PingResp>(&body) {
            Ok(PingResp {
                rtt_ms: Some(rtt),
                endpoint,
                ..
            }) => (
                format!(
                    "pong from {}: {} ms @ {}",
                    req.peer_name,
                    rtt,
                    endpoint.unwrap_or_else(|| "?".into())
                ),
                true,
            ),
            Ok(PingResp {
                error: Some(e), ..
            }) => (format!("ping {}: {}", req.peer_name, e), false),
            Ok(_) => (
                format!("ping {}: malformed reply (HTTP {status})", req.peer_name),
                false,
            ),
            Err(e) => (format!("ping {}: bad JSON: {e}", req.peer_name), false),
        },
        Err(e) => (format!("ping {}: {e}", req.peer_name), false),
    }
}

/// Minimal loopback HTTP/1.1 GET. Reads to EOF (LocalAPI closes per
/// request). Returns (status_code, body).
fn http_get(path: &str, read_timeout: Duration) -> Result<(u16, Vec<u8>), String> {
    let addr: SocketAddr = LOCALAPI_ADDR
        .parse()
        .map_err(|e| format!("bad addr: {e}"))?;
    let mut conn = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("runtime down ({e})"))?;
    conn.set_read_timeout(Some(read_timeout))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    conn.set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("set_write_timeout: {e}"))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: localhost:41112\r\n\
         Connection: close\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    conn.write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut response = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    loop {
        if response.len() >= MAX_RESPONSE {
            return Err("response too large".into());
        }
        match conn.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                return Err(format!("read timeout: {e}"));
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    parse_http_response(&response)
}

/// Split a raw HTTP/1.1 response into (status_code, body). Pure —
/// host-tested.
fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header terminator")?;
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| "non-utf8 head")?;
    let status_line = head.lines().next().ok_or("empty head")?;
    // "HTTP/1.1 200 OK"
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("bad status line")?
        .parse::<u16>()
        .map_err(|_| "bad status code")?;
    Ok((code, raw[head_end + 4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_response_splits_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, b"{\"ok\":true}");

        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 404);
        assert!(body.is_empty());

        assert!(parse_http_response(b"garbage").is_err());
    }

    #[test]
    fn ping_resp_parses_both_shapes() {
        let ok: PingResp =
            serde_json::from_str(r#"{"rtt_ms":4,"endpoint":"192.168.8.211:54415"}"#).unwrap();
        assert_eq!(ok.rtt_ms, Some(4));
        assert_eq!(ok.endpoint.as_deref(), Some("192.168.8.211:54415"));

        let err: PingResp =
            serde_json::from_str(r#"{"error":"ping_now timed out (no Pong within window)"}"#)
                .unwrap();
        assert!(err.rtt_ms.is_none());
        assert!(err.error.is_some());
    }

    /// The load-bearing contract test: a snapshot serialized by
    /// tailscale-vita's LocalAPI deserializes into the same types here.
    #[test]
    fn runtime_snapshot_round_trips_through_json() {
        let snap = RuntimeSnapshot::empty("vita".into(), "0.0.0.0:41641".parse().unwrap());
        let json = serde_json::to_string(&snap).unwrap();
        let back: RuntimeSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hostname, "vita");
        assert_eq!(back.peer_count, 0);
        let rejson = serde_json::to_string(&back).unwrap();
        // Full-fidelity round trip: byte-identical re-serialization.
        assert_eq!(json, rejson);
    }
}
