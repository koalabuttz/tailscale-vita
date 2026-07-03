#![allow(dead_code)] // consumers (dashboard/render) are vita-gated; host sees these as dead

//! M17-A/B — loopback LocalAPI client + background worker.
//!
//! The dashboard is a pure HTTP client of the runtime's LocalAPI
//! (`127.0.0.1:41112`), whether the runtime lives in the SUPRX
//! (suprx_host_only) or in this eboot (normal mode). One worker thread
//! polls `/status` every `POLL_INTERVAL` into `Shared`, and executes UI
//! ACTIONS (ping / reconnect / config toggle) that arrive on a mailbox
//! — serialized with polls ON PURPOSE (LocalAPI has a single accept
//! thread and `/ping` blocks it up to 5 s, so a parallel poll would
//! only stall behind it; see docs/PLAN-M17A.md).

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use vita_chan::{Receiver, RecvTimeoutError};
use vita_log::{debug, info, warn};

use tailscale_vita::RuntimeSnapshot;

use super::config_edit;

const LOCALAPI_ADDR: &str = "127.0.0.1:41112";
/// config.toml path — the eboot rewrites this for [ftp] toggles.
pub const CONFIG_PATH: &str = "ux0:/data/tailscale-vita/config.toml";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const STATUS_READ_TIMEOUT: Duration = Duration::from_secs(3);
/// `/ping` and `/reconnect` block server-side; leave headroom.
const ACTION_READ_TIMEOUT: Duration = Duration::from_secs(7);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_RESPONSE: usize = 512 * 1024;

/// UI-facing state written by the worker thread, read each frame by the
/// render loop. Lock is held only for field copies.
pub struct Shared {
    pub snapshot: Option<RuntimeSnapshot>,
    /// Bumped on every poll (ok or err) so the UI rebuilds promptly.
    pub generation: u64,
    pub last_ok_at: Option<Instant>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub action: ActionState,
    /// Live config.toml values (re-read after each toggle). `None` =
    /// couldn't read the file.
    pub ftp_enabled: Option<bool>,
    pub ftp_read_only: Option<bool>,
}

impl Shared {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            snapshot: None,
            generation: 0,
            last_ok_at: None,
            last_error: None,
            consecutive_failures: 0,
            action: ActionState::Idle,
            ftp_enabled: None,
            ftp_read_only: None,
        }))
    }
}

/// Status of the most recent UI action, shown in the footer.
#[derive(Clone)]
pub enum ActionState {
    Idle,
    InFlight { label: String },
    Done { line: String, ok: bool, at: Instant },
}

/// A request from the UI thread to the worker.
pub enum UiAction {
    Ping { ip: Ipv4Addr, peer_name: String },
    Reconnect,
    /// Toggle a `[ftp]` bool (`"enabled"` or `"read_only"`).
    ToggleFtp { key: &'static str },
    /// M19 lifecycle actions (zero-parameter LocalAPI POSTs). `TailnetUp`/
    /// `TailnetDown` also persist `[tailnet] want_running` for next boot.
    TailnetUp,
    TailnetDown,
    Logout,
    LoginInteractive,
}

impl UiAction {
    fn inflight_label(&self) -> String {
        match self {
            UiAction::Ping { peer_name, .. } => format!("pinging {peer_name}..."),
            UiAction::Reconnect => "reconnecting...".into(),
            UiAction::ToggleFtp { key } => format!("saving ftp.{key}..."),
            UiAction::TailnetUp => "starting tailnet...".into(),
            UiAction::TailnetDown => "stopping tailnet...".into(),
            UiAction::Logout => "logging out...".into(),
            UiAction::LoginInteractive => "starting login...".into(),
        }
    }
}

/// Spawn the worker thread. Exits when the action channel disconnects.
pub fn spawn_worker(shared: Arc<Mutex<Shared>>, action_rx: Receiver<UiAction>) {
    // Seed the live config values before the first frame.
    {
        let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
        s.ftp_enabled = config_edit::read_toggle(CONFIG_PATH, "ftp", "enabled");
        s.ftp_read_only = config_edit::read_toggle(CONFIG_PATH, "ftp", "read_only");
    }
    let spawned = vita_thread::Builder::new()
        .name("ui-worker")
        .stack_size(128 * 1024)
        .spawn(move || worker_loop(shared, action_rx));
    if let Err(e) = spawned {
        warn!(error = %e, "ui.worker.spawn_failed");
    }
}

fn worker_loop(shared: Arc<Mutex<Shared>>, action_rx: Receiver<UiAction>) {
    info!("ui.worker.start");
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
                s.generation += 1;
                if s.consecutive_failures <= 3 || s.consecutive_failures % 15 == 0 {
                    warn!(error = %e, failures = s.consecutive_failures, "ui.poll.err");
                }
            }
        }

        match action_rx.recv_timeout(POLL_INTERVAL) {
            Ok(action) => run_action(&shared, action),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                info!("ui.worker.exit");
                return;
            }
        }
    }
}

fn run_action(shared: &Arc<Mutex<Shared>>, action: UiAction) {
    {
        let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
        s.action = ActionState::InFlight {
            label: action.inflight_label(),
        };
        s.generation += 1;
    }
    let (line, ok) = match action {
        UiAction::Ping { ip, peer_name } => {
            info!(ip = %ip, peer = %peer_name, "ui.action.ping");
            do_ping(ip, &peer_name)
        }
        UiAction::Reconnect => {
            info!("ui.action.reconnect");
            do_reconnect()
        }
        UiAction::ToggleFtp { key } => {
            info!(key, "ui.action.toggle_ftp");
            do_toggle_ftp(shared, key)
        }
        UiAction::TailnetUp => {
            info!("ui.action.tailnet_up");
            do_tailnet_up()
        }
        UiAction::TailnetDown => {
            info!("ui.action.tailnet_down");
            do_tailnet_down()
        }
        UiAction::Logout => {
            info!("ui.action.logout");
            do_logout()
        }
        UiAction::LoginInteractive => {
            info!("ui.action.login_interactive");
            do_login_interactive()
        }
    };
    info!(result = %line, ok, "ui.action.result");
    let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
    s.action = ActionState::Done {
        line,
        ok,
        at: Instant::now(),
    };
    s.generation += 1;
}

fn fetch_status() -> Result<RuntimeSnapshot, String> {
    let (status, body) = http_req("GET", "/localapi/v0/status", STATUS_READ_TIMEOUT)?;
    if status != 200 {
        return Err(format!("status HTTP {status}"));
    }
    serde_json::from_slice(&body).map_err(|e| format!("bad status JSON: {e}"))
}

#[derive(Deserialize)]
struct PingResp {
    rtt_ms: Option<u64>,
    endpoint: Option<String>,
    error: Option<String>,
}

fn do_ping(ip: Ipv4Addr, peer_name: &str) -> (String, bool) {
    let path = format!("/localapi/v0/ping?ip={ip}");
    match http_req("GET", &path, ACTION_READ_TIMEOUT) {
        Ok((_status, body)) => match serde_json::from_slice::<PingResp>(&body) {
            Ok(PingResp { rtt_ms: Some(rtt), endpoint, .. }) => (
                format!(
                    "pong from {peer_name}: {rtt} ms @ {}",
                    endpoint.unwrap_or_else(|| "?".into())
                ),
                true,
            ),
            Ok(PingResp { error: Some(e), .. }) => (format!("ping {peer_name}: {e}"), false),
            Ok(_) => (format!("ping {peer_name}: malformed reply"), false),
            Err(e) => (format!("ping {peer_name}: bad JSON: {e}"), false),
        },
        Err(e) => (format!("ping {peer_name}: {e}"), false),
    }
}

#[derive(Deserialize)]
struct ReconnectResp {
    ok: Option<bool>,
    error: Option<String>,
}

fn do_reconnect() -> (String, bool) {
    match http_req("POST", "/localapi/v0/reconnect", ACTION_READ_TIMEOUT) {
        Ok((status, body)) => {
            let parsed: Option<ReconnectResp> = serde_json::from_slice(&body).ok();
            match (status, parsed) {
                (202, _) => ("reconnect requested — rebuilding session".into(), true),
                (_, Some(ReconnectResp { error: Some(e), .. })) => {
                    (format!("reconnect refused: {e}"), false)
                }
                (s, _) => (format!("reconnect: HTTP {s}"), false),
            }
        }
        Err(e) => (format!("reconnect: {e}"), false),
    }
}

/// POST a zero-parameter M19 lifecycle endpoint (`/up`, `/down`,
/// `/logout`, `/login-interactive`) and map the reply to a footer line —
/// same 202/409/error shape as [`do_reconnect`]. 202 = accepted (watch
/// /status); a JSON `error` = refused; anything else = the raw status.
fn post_lifecycle(path: &str, noun: &str, accepted: &str) -> (String, bool) {
    match http_req("POST", path, ACTION_READ_TIMEOUT) {
        Ok((status, body)) => {
            let parsed: Option<ReconnectResp> = serde_json::from_slice(&body).ok();
            match (status, parsed) {
                (202, _) => (accepted.to_string(), true),
                (_, Some(ReconnectResp { error: Some(e), .. })) => {
                    (format!("{noun} refused: {e}"), false)
                }
                (s, _) => (format!("{noun}: HTTP {s}"), false),
            }
        }
        Err(e) => (format!("{noun}: {e}"), false),
    }
}

fn do_tailnet_up() -> (String, bool) {
    // Persist want_running for next boot (best-effort), then resume live.
    let _ = config_edit::apply_set(CONFIG_PATH, "tailnet", "want_running", true);
    post_lifecycle("/localapi/v0/up", "tailnet up", "tailnet up — reconnecting")
}

fn do_tailnet_down() -> (String, bool) {
    let _ = config_edit::apply_set(CONFIG_PATH, "tailnet", "want_running", false);
    post_lifecycle("/localapi/v0/down", "tailnet down", "tailnet stopped")
}

fn do_logout() -> (String, bool) {
    post_lifecycle(
        "/localapi/v0/logout",
        "logout",
        "logged out — control key expired",
    )
}

fn do_login_interactive() -> (String, bool) {
    post_lifecycle(
        "/localapi/v0/login-interactive",
        "login",
        "login started — scan the QR",
    )
}

fn do_toggle_ftp(shared: &Arc<Mutex<Shared>>, key: &'static str) -> (String, bool) {
    match config_edit::apply_toggle(CONFIG_PATH, "ftp", key) {
        Ok(new_val) => {
            // Re-read the live config values OUTSIDE the lock (file I/O),
            // then take the lock only to store — keeps the render thread
            // from stalling on sceIo reads.
            let en = config_edit::read_toggle(CONFIG_PATH, "ftp", "enabled");
            let ro = config_edit::read_toggle(CONFIG_PATH, "ftp", "read_only");
            {
                let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
                s.ftp_enabled = en;
                s.ftp_read_only = ro;
            }
            (
                format!(
                    "ftp.{key} = {new_val} saved — relaunch to apply",
                    key = key
                ),
                true,
            )
        }
        Err(e) => (format!("save ftp.{key} failed: {e}"), false),
    }
}

/// Minimal loopback HTTP/1.1 request (`Connection: close`, read to EOF).
/// Returns (status_code, body).
fn http_req(method: &str, path: &str, read_timeout: Duration) -> Result<(u16, Vec<u8>), String> {
    let addr: SocketAddr = LOCALAPI_ADDR.parse().map_err(|e| format!("bad addr: {e}"))?;
    let mut conn =
        TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| format!("runtime down ({e})"))?;
    conn.set_read_timeout(Some(read_timeout))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    conn.set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("set_write_timeout: {e}"))?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: localhost:41112\r\n\
         Connection: close\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    conn.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
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

/// Split a raw HTTP/1.1 response into (status_code, body). Pure.
fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header terminator")?;
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| "non-utf8 head")?;
    let status_line = head.lines().next().ok_or("empty head")?;
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
        let raw = b"HTTP/1.1 202 Accepted\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap().0, 202);
        assert!(parse_http_response(b"garbage").is_err());
    }

    #[test]
    fn ping_resp_parses_both_shapes() {
        let ok: PingResp =
            serde_json::from_str(r#"{"rtt_ms":4,"endpoint":"192.168.8.211:54415"}"#).unwrap();
        assert_eq!(ok.rtt_ms, Some(4));
        let err: PingResp = serde_json::from_str(r#"{"error":"timed out"}"#).unwrap();
        assert!(err.rtt_ms.is_none() && err.error.is_some());
    }

    #[test]
    fn reconnect_resp_parses() {
        let ok: ReconnectResp = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert_eq!(ok.ok, Some(true));
        let refused: ReconnectResp =
            serde_json::from_str(r#"{"ok":false,"error":"fatal state"}"#).unwrap();
        assert_eq!(refused.error.as_deref(), Some("fatal state"));
    }

    #[test]
    fn runtime_snapshot_round_trips_through_json() {
        let snap = RuntimeSnapshot::empty("vita".into(), "0.0.0.0:41641".parse().unwrap());
        let json = serde_json::to_string(&snap).unwrap();
        let back: RuntimeSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hostname, "vita");
        assert_eq!(json, serde_json::to_string(&back).unwrap());
    }
}
