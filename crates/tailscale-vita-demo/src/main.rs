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
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, RecvTimeoutError};
use tracing::{error, info, info_span, warn};

use netstack::TcpListener;
use tailscale_vita::{Config, ConfigError, Runtime};

mod handler;

const CONFIG_PATH: &str = "ux0:/data/tailscale-vita/config.toml";
const ACCEPT_POLL: Duration = Duration::from_millis(500);

fn main() {
    if let Err(e) = vita_log::init() {
        eprintln!("vita-log init failed: {e}");
        return;
    }
    let _span = info_span!(
        "startup",
        milestone = "M10",
        build = env!("BUILD_TIMESTAMP"),
        build_unix = env!("BUILD_UNIX"),
    )
    .entered();
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
        "demo.config.loaded"
    );

    if config.auth_key.is_empty() {
        warn!(
            "config.auth_key is empty; aborting before we hit the Headscale 401. \
             Generate via `headscale preauthkeys create --user 1 -e 720h --reusable` \
             and paste into config.toml."
        );
        return Ok(());
    }

    // 2. Bring up the runtime.
    let pool_size = config.listener_pool_size;
    let demo_port = config.demo_port;
    let run_window = config.run_window_secs;
    let mut runtime = Runtime::up(config)?;
    info!("demo.runtime.up");

    // 3. Bind the TCP listener on the tailnet IP. Smoltcp binds with
    //    `IpListenEndpoint { addr: None }` so we accept on whatever
    //    local IP gets plumbed via stack.set_local_addrs (happens
    //    inside the runtime's event loop on first MapResponse).
    let listener = TcpListener::bind(runtime.netstack(), demo_port, pool_size)?;
    info!(port = demo_port, pool = pool_size, "demo.listen");

    // 4. Worker thread for the runtime event loop.
    let (stop_tx, stop_rx) = bounded::<()>(1);
    let runtime_handle = thread::Builder::new()
        .name("ts-runtime".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            let stats = runtime.run_event_loop(|| match stop_rx.recv_timeout(Duration::from_millis(0)) {
                Ok(()) => true,
                Err(RecvTimeoutError::Timeout) => false,
                Err(RecvTimeoutError::Disconnected) => true,
            });
            match stats {
                Ok(s) => info!(?s, "demo.runtime.exit"),
                Err(e) => error!(error = %e, "demo.runtime.exit.error"),
            }
            runtime.shutdown();
        })?;

    // 5. Accept loop on the main thread.
    let deadline = run_window.map(|s| Instant::now() + Duration::from_secs(s));
    let mut accept_count = 0u32;
    loop {
        if let Some(d) = deadline {
            if Instant::now() >= d {
                break;
            }
        }
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

    // 6. Stop the runtime worker, drop the listener (which removes
    //    its pool sockets from netstack).
    let _ = stop_tx.send(());
    let _ = runtime_handle.join();
    drop(listener);
    info!(accept_count, "M10 demo done");
    Ok(())
}
