//! ts-peerapi — Taildrop **receive** over the tailnet.
//!
//! The second optional in-process *service* on the tailscale-vita runtime
//! (after ts-ftp). It binds a [`netstack::TcpListener`] on the node's
//! tailnet IP and serves Tailscale's `peerapi` PUT surface, so
//! `tailscale file cp <file> vita:` from any same-tailnet device drops the
//! file straight onto the Vita's memory card — AirDrop for homebrew.
//!
//! ## How a sender finds us
//!
//! Discovery is control-driven: our MapRequest advertises
//! `Hostinfo.Services = [{Proto:"peerapi4", Port, Description:"peerapi"}]`
//! (wired in ts-control from [`TaildropConfig::port`]); control propagates
//! it into peers' netmaps. Without that entry `tailscale file cp` reports
//! "no targets". We only advertise it when this service is actually enabled
//! (`runtime.rs` gates the ts-control plumbing on `taildrop.enabled`).
//!
//! ## Surface
//!
//! `PUT /v0/put/<url-escaped-basename>`, plain HTTP/1.1 over the WireGuard
//! tunnel, body = raw bytes with `Content-Length`. One file per PUT.
//! Replies `200` (empty body) on success; `400` bad/missing name, `405`
//! non-PUT, `411` no Content-Length, `413` over `max_size`, `500` on a
//! write/rename failure. Query params (resume offsets) are ignored — we
//! always treat a PUT as full-from-zero.
//!
//! ## Security posture
//!
//! Same as ts-ftp: WireGuard encrypts the transport and **the tailnet ACL
//! is the boundary** — any peer the ACL lets reach the port may write. The
//! service is config-gated (`enabled = false` by default), jailed to a
//! dedicated `dir`, and bounded by `max_size`. The one hardening the code
//! itself owns is filename sanitization (see [`name`]) so a hostile name
//! can never escape `dir`. `user_id`-based receiver enforcement is a
//! documented future hardening, not v1.
//!
//! ## Lifecycle
//!
//! Mirrors ts-ftp / the M14 LocalAPI: [`TsPeerApi::spawn`] returns `None`
//! (non-fatal) on bind failure, each accepted connection runs on its own
//! bounded thread (reaped when done), and `Drop` signals shutdown + joins.

use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use netstack::{StackHandle, TcpListener};
use serde::Deserialize;
use vita_log::{info, warn};
use vita_thread::{self as thread, JoinHandle};

mod handler;
mod http;
mod name;

/// Concurrent SYNs the listener pool absorbs before the next is RST'd (the
/// client retries). Sized like ts-ftp's control pool.
const ACCEPT_POOL: usize = 4;
/// Max concurrent connection threads. Past this, new connections get a
/// `503` so the accept loop never blocks. Bounds thread/stack/heap use if a
/// peer opens a flood of transfers.
const MAX_CONNS: usize = 6;
/// Per-connection thread stack. The body streams through a heap buffer
/// (`http::BODY_CHUNK`), so the stack only holds parse scratch — but
/// httparse + `format!` want headroom, so match ts-ftp's accept-thread size.
const CONN_STACK: usize = 256 * 1024;
/// Accept-loop poll period — bounds how quickly the loop notices `shutdown`.
const ACCEPT_TICK: Duration = Duration::from_millis(500);

/// `[taildrop]` config section (embedded in the runtime's `Config`).
#[derive(Clone, Debug, Deserialize)]
pub struct TaildropConfig {
    /// Master switch. Off by default — Taildrop lets any ACL-permitted peer
    /// write files to `dir`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Directory incoming files land in. Point it at `ux0:/vpk` to turn the
    /// Vita into a VPK sideload inbox.
    #[serde(default = "default_dir")]
    pub dir: String,
    /// TCP port the peerapi listens on at the tailnet IP; advertised to
    /// peers as `peerapi4`. Tailscale's conventional peerapi port is 8098.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Reject any PUT whose `Content-Length` exceeds this (bytes) with a
    /// `413`, before reading the body — bounds the blast radius of an
    /// abusive peer against a finite memory card. Default 256 MB.
    #[serde(default = "default_max_size")]
    pub max_size: u64,
}

fn default_enabled() -> bool {
    false
}
fn default_dir() -> String {
    "ux0:/data/tailscale-vita/taildrop".to_string()
}
fn default_port() -> u16 {
    8098
}
fn default_max_size() -> u64 {
    268_435_456 // 256 MB
}

impl Default for TaildropConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            dir: default_dir(),
            port: default_port(),
            max_size: default_max_size(),
        }
    }
}

/// A completed (or failed) Taildrop PUT, reported to the runtime via the
/// [`TaildropSink`] so it can surface recent drops in its snapshot.
///
/// ts-peerapi can't depend on the runtime crate (that would cycle:
/// tailscale-vita → ts-peerapi), so it reports through this plain struct +
/// callback rather than touching `RuntimeSnapshot` directly.
#[derive(Clone, Debug)]
pub struct TaildropReport {
    /// Final on-disk name (post collision-rename), or the rejected name for
    /// a failure outcome.
    pub name: String,
    /// Bytes written (0 for a rejection before/at the body).
    pub size: u64,
    /// Source tailnet address string (`ip:port`, post-WG-decap).
    pub sender: String,
    /// Short outcome tag: `"ok"`, `"rejected: …"`, or `"error: …"`.
    pub status: String,
}

/// Callback the runtime installs to record [`TaildropReport`]s. Invoked
/// from a connection thread, so it must be `Send + Sync`.
pub type TaildropSink = Arc<dyn Fn(TaildropReport) + Send + Sync>;

/// Per-server context shared (via `Arc`) into every connection thread.
pub(crate) struct Ctx {
    pub(crate) cfg: TaildropConfig,
    pub(crate) sink: Option<TaildropSink>,
}

/// Running Taildrop service. Dropping it signals shutdown and joins the
/// accept thread.
pub struct TsPeerApi {
    worker: Option<JoinHandle>,
    shutdown: Arc<AtomicBool>,
}

impl TsPeerApi {
    /// Bind the listener and spawn the accept thread. Returns `None`
    /// (non-fatal) if the bind or thread spawn fails — the runtime keeps
    /// running without Taildrop. The caller is responsible for ensuring
    /// `cfg.dir` exists (the runtime `create_dir_all`s it at spawn time).
    pub fn spawn(
        stack: StackHandle,
        cfg: TaildropConfig,
        sink: Option<TaildropSink>,
    ) -> Option<Self> {
        let port = cfg.port;
        let listener = match TcpListener::bind_handle(&stack, port, ACCEPT_POOL) {
            Ok(l) => l,
            Err(e) => {
                warn!(port, error = %e, "ts-peerapi.bind.failed");
                return None;
            }
        };
        info!(port, dir = %cfg.dir, max_size = cfg.max_size, "ts-peerapi.listening");

        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let ctx = Ctx { cfg, sink };

        let worker = match thread::Builder::new()
            .name("ts-peerapi")
            .stack_size(256 * 1024)
            .spawn(move || accept_loop(listener, worker_shutdown, ctx))
        {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "ts-peerapi.thread.spawn_failed");
                return None;
            }
        };

        Some(Self {
            worker: Some(worker),
            shutdown,
        })
    }
}

impl Drop for TsPeerApi {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

/// One in-flight connection thread and its completion flag.
struct LiveConn {
    handle: JoinHandle,
    done: Arc<AtomicBool>,
}

/// Join + drop every finished connection thread, reclaiming its SCE thread
/// slot (`vita_thread` deletes the handle in `join`, not on thread exit).
/// Only touches `done`-flagged threads, so it never blocks a live transfer.
fn reap(live: &mut Vec<LiveConn>) {
    let mut i = 0;
    while i < live.len() {
        if live[i].done.load(Ordering::Acquire) {
            let c = live.swap_remove(i);
            let _ = c.handle.join();
        } else {
            i += 1;
        }
    }
}

/// Accept connections and run each on its own bounded thread so a slow
/// transfer never blocks new ones; finished threads are reaped each pass.
fn accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>, ctx: Ctx) {
    let ctx = Arc::new(ctx);
    let mut live: Vec<LiveConn> = Vec::new();

    while !shutdown.load(Ordering::Acquire) {
        reap(&mut live);
        match listener.accept_timeout(ACCEPT_TICK) {
            Ok((stream, peer)) => {
                reap(&mut live);
                if live.len() >= MAX_CONNS {
                    // At capacity: refuse fast so the accept loop stays free.
                    let mut stream = stream;
                    let _ = crate::http::write_response(&mut stream, 503);
                    warn!(%peer, active = live.len(), "ts-peerapi.conn.rejected_at_cap");
                    continue;
                }
                let done = Arc::new(AtomicBool::new(false));
                let cctx = Arc::clone(&ctx);
                let cdone = Arc::clone(&done);
                info!(%peer, active = live.len() + 1, "ts-peerapi.conn.start");
                // Contain panics so `done` is always set (else the handle
                // never reaps and its SCE thread slot leaks).
                // `AssertUnwindSafe`: TcpStream / &Ctx aren't `UnwindSafe`.
                let spawned = thread::Builder::new()
                    .name("ts-peerapi-conn")
                    .stack_size(CONN_STACK)
                    .spawn(move || {
                        let _ = catch_unwind(AssertUnwindSafe(|| {
                            handler::handle(stream, peer, &cctx);
                        }));
                        cdone.store(true, Ordering::Release);
                        info!(%peer, "ts-peerapi.conn.end");
                    });
                match spawned {
                    Ok(handle) => live.push(LiveConn { handle, done }),
                    Err(e) => warn!(%peer, error = %e, "ts-peerapi.conn.spawn_failed"),
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(e) => {
                warn!(error = %e, "ts-peerapi.accept.error");
                thread::sleep(ACCEPT_TICK);
            }
        }
    }

    // Shutdown: in-flight transfers wind down within IO_TIMEOUT; join all to
    // reclaim their thread handles.
    for c in live {
        let _ = c.handle.join();
    }
    info!("ts-peerapi.accept_loop.exit");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taildrop_config_defaults() {
        let cfg = TaildropConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.dir, "ux0:/data/tailscale-vita/taildrop");
        assert_eq!(cfg.port, 8098);
        assert_eq!(cfg.max_size, 256 * 1024 * 1024);
    }

    #[test]
    fn taildrop_config_deserializes_partial_toml() {
        // A [taildrop] section that only flips `enabled` must inherit every
        // other field's default (the per-field `#[serde(default)]`).
        let cfg: TaildropConfig = toml::from_str("enabled = true\n").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.port, 8098);
        assert_eq!(cfg.dir, "ux0:/data/tailscale-vita/taildrop");
        assert_eq!(cfg.max_size, 256 * 1024 * 1024);
    }
}
