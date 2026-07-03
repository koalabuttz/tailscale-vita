//! M10 demo eboot — links `tailscale-vita` for the Runtime + Config,
//! `netstack::TcpListener` for inbound HTTP, exposes a static
//! `hello from vita\n` body on `:demo_port` of the Vita's tailnet IP.
//!
//! Architecture:
//!
//! - main thread: load config, bring up Runtime, bind TcpListener,
//!   accept-loop with per-connection HTTP handler.
//! - worker thread: drives Runtime::run_event_loop until either the
//!   accept loop signals stop, or run_window_secs deadline elapses.
//!
//! Config lives at `ux0:/data/tailscale-vita/config.toml`; on first
//! run, a template is written and the demo exits with an actionable
//! "fill in auth_key" message.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use vita_log::{error, info, warn};
use vita_log::LogError;

use netstack::{Stack, TcpListener};
use tailscale_vita::{run_supervised, Config, ConfigError};

mod handler;
mod ui;

const CONFIG_PATH: &str = "ux0:/data/tailscale-vita/config.toml";
const ACCEPT_POLL: Duration = Duration::from_millis(500);

fn main() {
    // M11 Phase 2: when the SUPRX is staged under *TVIT00010, its
    // module_start runs BEFORE this `main` and inits vita-log first.
    // Treat AlreadyInitialized as benign — it just means the SUPRX
    // beat us.
    match vita_log::init() {
        Ok(()) => {}
        Err(LogError::AlreadyInitialized) => {}
        Err(e) => {
            eprintln!("vita-log init failed: {e}");
            return;
        }
    }
    // vita_log has no span concept; emit the startup fields as a
    // one-shot info! (was an info_span!(...).entered() under tracing).
    info!(
        milestone = "M10",
        build = env!("BUILD_TIMESTAMP"),
        build_unix = env!("BUILD_UNIX"),
        "startup"
    );
    info!(build = env!("BUILD_TIMESTAMP"), "binary build timestamp");

    if let Err(e) = run() {
        error!(error = %e, "M10 demo failed");
    }
    vita_log::flush();
    thread::sleep(Duration::from_secs(1));
}

#[derive(Debug)]
enum DemoError {
    Config(ConfigError),
    Runtime(tailscale_vita::RuntimeError),
    Io(std::io::Error),
}

impl std::fmt::Display for DemoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemoError::Config(e) => write!(f, "config: {e}"),
            DemoError::Runtime(e) => write!(f, "runtime: {e}"),
            DemoError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl From<ConfigError> for DemoError {
    fn from(e: ConfigError) -> Self {
        DemoError::Config(e)
    }
}
impl From<tailscale_vita::RuntimeError> for DemoError {
    fn from(e: tailscale_vita::RuntimeError) -> Self {
        DemoError::Runtime(e)
    }
}
impl From<std::io::Error> for DemoError {
    fn from(e: std::io::Error) -> Self {
        DemoError::Io(e)
    }
}

fn run() -> Result<(), DemoError> {
    // 1. Load config (or write template + exit).
    let config = match Config::load_or_template(Path::new(CONFIG_PATH)) {
        Ok(c) => c,
        Err(ConfigError::TemplateWritten { path }) => {
            warn!(
                path = %path,
                "config template written; fill in `auth_key` and re-launch"
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    info!(
        control_url = %config.control_url,
        hostname = %config.hostname,
        demo_port = config.demo_port,
        listener_pool_size = config.listener_pool_size,
        run_window_secs = ?config.run_window_secs,
        suprx_host_only = config.suprx_host_only,
        "demo.config.loaded"
    );

    // M11 Phase 2 / M17-A: if the SUPRX is the runtime owner, the eboot
    // keeps the process alive AND owns the screen — the dashboard UI
    // runs here (docs/PLAN-M17A.md). It must NOT call Runtime::up —
    // the SUPRX's bootstrap thread already owns the runtime in this
    // same process; the dashboard reads its LocalAPI over loopback.
    if config.suprx_host_only {
        info!("demo: suprx_host_only=true — SUPRX owns the runtime; starting dashboard UI");
        let never_exit = AtomicBool::new(false);
        ui::run_dashboard(&never_exit);
        return Ok(());
    }

    // M18: an empty auth_key is no longer an abort — the interactive login
    // (QR on screen; scan + approve on a phone) runs inside Runtime::up.

    // 2. Supervised runtime on a worker thread. `run_supervised` owns the
    //    up() -> run_event_loop loop and drops+rebuilds the whole Runtime on
    //    a mid-life re-login (M19 Finding 1). The `setup` closure binds a
    //    fresh inbound-HTTP listener + accept loop on each incarnation's
    //    netstack (via `AcceptSession`), so a relogin rebinds cleanly. The
    //    run_window deadline drives `should_stop`.
    let pool_size = config.listener_pool_size;
    let demo_port = config.demo_port;
    let deadline = config
        .run_window_secs
        .map(|s| Instant::now() + Duration::from_secs(s));

    let ui_exit = Arc::new(AtomicBool::new(false));
    let runtime_handle = thread::Builder::new()
        .name("ts-runtime".into())
        .stack_size(256 * 1024)
        .spawn({
            let ui_exit = Arc::clone(&ui_exit);
            move || {
                let stats = run_supervised(
                    config,
                    || deadline.map(|d| Instant::now() >= d).unwrap_or(false),
                    |runtime| AcceptSession::spawn(runtime.netstack(), demo_port, pool_size),
                );
                match stats {
                    Ok(s) => info!(?s, "demo.runtime.exit"),
                    Err(e) => error!(error = %e, "demo.runtime.exit.error"),
                }
                // Release the dashboard once the supervisor returns.
                ui_exit.store(true, Ordering::Release);
            }
        })?;

    // 3. Dashboard on the main thread until the supervisor exits.
    ui::run_dashboard(&ui_exit);

    let _ = runtime_handle.join();
    info!("M10 demo done");
    Ok(())
}

/// Owns the demo's inbound-HTTP accept loop for one `Runtime` incarnation.
/// `run_supervised` calls [`AcceptSession::spawn`] after each `up()` (fresh
/// netstack) and drops the returned guard before tearing that Runtime down;
/// `Drop` stops the accept thread so the next incarnation rebinds cleanly.
struct AcceptSession {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl AcceptSession {
    fn spawn(stack: &Stack, port: u16, pool: usize) -> AcceptSession {
        let stop = Arc::new(AtomicBool::new(false));
        let handle = match TcpListener::bind(stack, port, pool) {
            Ok(listener) => {
                info!(port, pool, "demo.listen");
                let stop_c = Arc::clone(&stop);
                thread::Builder::new()
                    .name("demo-accept".into())
                    .stack_size(256 * 1024)
                    .spawn(move || accept_loop(listener, stop_c))
                    .ok()
            }
            Err(e) => {
                warn!(error = %e, port, "demo.listen.bind_failed");
                None
            }
        };
        AcceptSession { stop, handle }
    }
}

impl Drop for AcceptSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn accept_loop(listener: TcpListener, stop: Arc<AtomicBool>) {
    let mut accept_count = 0u32;
    while !stop.load(Ordering::Acquire) {
        match listener.accept_timeout(ACCEPT_POLL) {
            Ok((stream, peer)) => {
                accept_count += 1;
                info!(%peer, count = accept_count, "demo.accept");
                handler::serve(stream, peer);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                // No connection in this window; loop.
            }
            Err(e) => {
                warn!(error = %e, "demo.accept.error");
                break;
            }
        }
    }
    drop(listener);
    info!(accept_count, "demo.accept.done");
}
