//! ts-ftp — a minimal FTP server on the tailnet.
//!
//! The first optional in-process *service* on the tailscale-vita runtime.
//! It binds a [`netstack::TcpListener`] on the node's tailnet IP, so the
//! Vita filesystem is reachable from any network via a standard FTP client.
//!
//! ## Why a from-scratch server
//!
//! Existing Vita FTP servers bind Sony's SCE socket layer, which can't see
//! our userspace WireGuard netstack — connections arrive over WireGuard and
//! only touch [`netstack`]. So we serve FTP on the netstack directly, backed
//! by [`vita_fs`] for file ops.
//!
//! ## Security posture
//!
//! Plaintext + permissive auth is deliberate: WireGuard already encrypts the
//! transport, and the **tailnet ACL is the boundary** (whoever the ACL lets
//! reach the port is authorized). The server is config-gated (`enabled =
//! false` by default) and jailed to a configurable `root`.
//!
//! ## v1 scope
//!
//! Single-threaded (serial sessions; the listener pool absorbs concurrent
//! SYNs), **PASV** data channel only, IPv4 only. Lifecycle mirrors the M14
//! LocalAPI server: [`TsFtpServer::spawn`] returns `None` on bind failure,
//! and `Drop` signals shutdown + joins the accept thread.

use std::io;
use std::net::Ipv4Addr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use netstack::{StackHandle, TcpListener};
use serde::Deserialize;
use vita_log::{info, warn};
use vita_thread::{self as thread, JoinHandle};

mod command;
mod data;
mod listing;
mod reply;
mod session;
mod vfs;

/// Concurrent control-connection SYNs the listener pool absorbs before the
/// next one is RST'd (the client retries). The pool (self-healing per accept —
/// see `netstack::TcpListener`) is sized for headroom under an external
/// client's rapid-reconnect churn.
const CONTROL_POOL: usize = 4;
/// Max concurrent session threads. Each accepted control connection runs on its
/// own thread so one slow/stalled client can't block others (a serial accept
/// loop let a single hung session wedge the whole server for up to
/// `CTRL_IDLE_TIMEOUT` — 2026-07-04). Past the cap, new connections get a `421`
/// so the accept loop never blocks. Bounds thread/stack/heap use under churn.
const MAX_SESSIONS: usize = 8;
/// Per-session thread stack. FTP dispatch is light (file bytes go to the heap
/// via `vita_fs::read`), so this is smaller than the control-plane workers.
const SESSION_STACK: usize = 192 * 1024;
/// Accept-loop poll period — bounds how quickly the loop notices `shutdown`.
const ACCEPT_TICK: Duration = Duration::from_millis(500);
/// Control-read poll period: a session re-checks `shutdown`/idle between reads
/// on this cadence instead of one long blocking read (see `session::read_line`).
pub(crate) const CTRL_POLL: Duration = Duration::from_secs(1);
/// Idle control connection drop timeout (a stuck/idle client frees the slot).
pub(crate) const CTRL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for the client to open the PASV data connection.
pub(crate) const DATA_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
/// Read/write timeout on a data transfer.
pub(crate) const DATA_RW_TIMEOUT: Duration = Duration::from_secs(60);

/// Shared holder for the node's tailnet IPv4, published by the runtime once
/// the first MapResponse lands. `None` until then — PASV replies `425` in
/// that window. Read at PASV time for the `227` reply.
pub type TailnetIp = Arc<vita_sync::Mutex<Option<Ipv4Addr>>>;

/// `[ftp]` config section (embedded in the runtime's `Config`).
#[derive(Clone, Debug, Deserialize)]
pub struct FtpConfig {
    /// Master switch. Off by default — FTP exposes the filesystem.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Control port on the tailnet IP (FTP is 21).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Jail root. Client `/` maps here; `..` cannot escape above it.
    #[serde(default = "default_root")]
    pub root: String,
    /// Deny STOR/DELE/MKD/RNFR when true.
    #[serde(default)]
    pub read_only: bool,
    /// Low end of the PASV data-port range.
    #[serde(default = "default_pasv_lo")]
    pub passive_port_lo: u16,
    /// High end of the PASV data-port range (inclusive).
    #[serde(default = "default_pasv_hi")]
    pub passive_port_hi: u16,
}

fn default_enabled() -> bool {
    false
}
fn default_port() -> u16 {
    21
}
fn default_root() -> String {
    "ux0:".to_string()
}
fn default_pasv_lo() -> u16 {
    30000
}
fn default_pasv_hi() -> u16 {
    30009
}

impl Default for FtpConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            port: default_port(),
            root: default_root(),
            read_only: false,
            passive_port_lo: default_pasv_lo(),
            passive_port_hi: default_pasv_hi(),
        }
    }
}

/// Per-server context threaded into the accept loop and each session.
/// Cheap to clone (StackHandle is an Arc, FtpConfig is small, TailnetIp is Arc).
pub(crate) struct Ctx {
    pub(crate) stack: StackHandle,
    pub(crate) cfg: FtpConfig,
    pub(crate) tailnet_ip: TailnetIp,
    /// Shared passive-port cursor, rotated across ALL sessions so consecutive
    /// transfers spread over `[passive_port_lo, passive_port_hi]` instead of
    /// every one-shot session reusing `lo`. See [`data::bind_passive`].
    pub(crate) next_pasv_port: Arc<AtomicU16>,
}

/// Running FTP service. Dropping it signals shutdown and joins the thread.
pub struct TsFtpServer {
    worker: Option<JoinHandle>,
    shutdown: Arc<AtomicBool>,
}

impl TsFtpServer {
    /// Bind the control listener and spawn the accept thread. Returns `None`
    /// (non-fatal) if the bind or thread spawn fails — the runtime keeps
    /// running without FTP.
    pub fn spawn(stack: StackHandle, cfg: FtpConfig, tailnet_ip: TailnetIp) -> Option<Self> {
        let port = cfg.port;
        let listener = match TcpListener::bind_handle(&stack, port, CONTROL_POOL) {
            Ok(l) => l,
            Err(e) => {
                warn!(port, error = %e, "ts-ftp.bind.failed");
                return None;
            }
        };
        info!(port, root = %cfg.root, read_only = cfg.read_only, "ts-ftp.listening");

        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let next_pasv_port = Arc::new(AtomicU16::new(cfg.passive_port_lo));
        let ctx = Ctx {
            stack,
            cfg,
            tailnet_ip,
            next_pasv_port,
        };

        let worker = match thread::Builder::new()
            .name("ts-ftp")
            .stack_size(256 * 1024)
            .spawn(move || accept_loop(listener, worker_shutdown, ctx))
        {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "ts-ftp.thread.spawn_failed");
                return None;
            }
        };

        Some(Self {
            worker: Some(worker),
            shutdown,
        })
    }
}

impl Drop for TsFtpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

/// One in-flight session thread and its completion flag.
struct LiveSession {
    handle: JoinHandle,
    done: Arc<AtomicBool>,
}

/// Join and drop every session whose thread has finished, reclaiming its SCE
/// thread handle (detaching would leak thread slots — `vita_thread` deletes the
/// handle in `join`, not on thread exit). Only touches `done`-flagged threads,
/// so it never blocks on a still-running session; the `join` on a done thread
/// returns as soon as it reaches `sceKernelExitThread`.
fn reap(live: &mut Vec<LiveSession>) {
    let mut i = 0;
    while i < live.len() {
        if live[i].done.load(Ordering::Acquire) {
            let s = live.swap_remove(i);
            let _ = s.handle.join();
        } else {
            i += 1;
        }
    }
}

/// Accept control connections and run each on its own bounded session thread,
/// so a slow or stalled client never blocks new connections (the old serial
/// loop let one hung session wedge the whole server for up to
/// `CTRL_IDLE_TIMEOUT`). Finished threads are reaped each iteration.
fn accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>, ctx: Ctx) {
    let ctx = Arc::new(ctx);
    let mut live: Vec<LiveSession> = Vec::new();

    while !shutdown.load(Ordering::Acquire) {
        reap(&mut live);
        match listener.accept_timeout(ACCEPT_TICK) {
            Ok((stream, peer)) => {
                reap(&mut live);
                if live.len() >= MAX_SESSIONS {
                    // At capacity: refuse fast so the accept loop stays free.
                    let mut stream = stream;
                    let _ = crate::reply::reply(&mut stream, 421, "too many connections, retry shortly");
                    warn!(%peer, active = live.len(), "ts-ftp.session.rejected_at_cap");
                    continue;
                }
                let done = Arc::new(AtomicBool::new(false));
                let sctx = Arc::clone(&ctx);
                let sshut = Arc::clone(&shutdown);
                let sdone = Arc::clone(&done);
                info!(%peer, active = live.len() + 1, "ts-ftp.session.start");
                // `vita_sync::Mutex` doesn't poison and the thread trampoline
                // already contains panics, but catch here too so `done` is set
                // even on a panicking session — otherwise its handle is never
                // reaped and its SCE thread slot leaks. `AssertUnwindSafe`:
                // TcpStream / &Ctx aren't `UnwindSafe`.
                let spawned = thread::Builder::new()
                    .name("ts-ftp-sess")
                    .stack_size(SESSION_STACK)
                    .spawn(move || {
                        let _ = catch_unwind(AssertUnwindSafe(|| {
                            session::handle(stream, peer, &sctx, &sshut);
                        }));
                        sdone.store(true, Ordering::Release);
                        info!(%peer, "ts-ftp.session.end");
                    });
                match spawned {
                    Ok(handle) => live.push(LiveSession { handle, done }),
                    Err(e) => warn!(%peer, error = %e, "ts-ftp.session.spawn_failed"),
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(e) => {
                warn!(error = %e, "ts-ftp.accept.error");
                thread::sleep(ACCEPT_TICK);
            }
        }
    }

    // Shutdown: sessions observe `shutdown` via their poll-read and wind down
    // within ~CTRL_POLL; join them all to reclaim their thread handles.
    for s in live {
        let _ = s.handle.join();
    }
    info!("ts-ftp.accept_loop.exit");
}
