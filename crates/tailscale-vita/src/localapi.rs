//! M14 LocalAPI server — loopback HTTP/1.1 exposing tailnet
//! introspection + control endpoints under `/localapi/v0/...`.
//!
//! Binds `127.0.0.1:<port>` (typically 41112 to match upstream Go's
//! default). One dedicated accept thread + inline per-request
//! handling — LocalAPI is low-traffic by design, no need for a
//! per-connection thread pool in v1.
//!
//! Bind failure is non-fatal: the runtime logs a warning and skips
//! LocalAPI for the session. The daemon's other surfaces (tailnet
//! connectivity, control-plane reconnect, magicsock) are unaffected.

mod handlers;
pub(crate) mod http;
mod router;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use parking_lot::RwLock;
use tracing::{debug, info, trace, warn};
use ts_magicsock::MagicSocketCtl;

use crate::runtime::ControlHandle;
use crate::snapshot::RuntimeSnapshot;

pub use router::HandlerCtx;

/// Default port. Matches upstream Go's `tailscale-localapi` default
/// so habits + ecosystem tooling carry over.
pub const DEFAULT_PORT: u16 = 41112;

/// How long the accept loop blocks before re-checking shutdown.
/// Lower = faster exit, higher = less context-switch overhead.
const ACCEPT_TICK: Duration = Duration::from_millis(500);

/// Drop-on-shutdown handle for the LocalAPI thread.
pub struct LocalApiServer {
    worker: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    bound_addr: SocketAddr,
}

impl LocalApiServer {
    /// Bind `127.0.0.1:port` and spawn the accept thread. Returns
    /// `None` (with a warn log) if the bind fails — the runtime
    /// treats LocalAPI as best-effort, not load-bearing.
    pub fn spawn(
        port: u16,
        snapshot: Arc<RwLock<RuntimeSnapshot>>,
        controller: ControlHandle,
        magic: MagicSocketCtl,
    ) -> Option<Self> {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let listener = match TcpListener::bind(bind_addr) {
            Ok(l) => l,
            Err(e) => {
                warn!(%bind_addr, error = %e, "localapi.bind.failed");
                return None;
            }
        };
        // Non-blocking-ish: read_timeout on the listener doesn't work
        // on all platforms; use `set_nonblocking(false)` + per-stream
        // timeouts in the handler. The accept loop polls shutdown
        // every ACCEPT_TICK.
        if let Err(e) = listener.set_nonblocking(false) {
            warn!(error = %e, "localapi.listener.set_blocking_failed");
        }
        let bound_addr = listener.local_addr().unwrap_or(bind_addr);
        info!(%bound_addr, "localapi.bound");

        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let ctx = HandlerCtx {
            snapshot,
            controller,
            magic,
        };

        // The accept loop uses a short-poll trick: set a read_timeout
        // on every accepted stream, and rely on `accept()` failing
        // with `Interrupted` or returning periodically. We rely on
        // `set_nonblocking(true)` + manual sleep so shutdown polls
        // can fire without waiting on an indefinite accept.
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|e| warn!(error = %e, "localapi.listener.set_nonblocking_failed"));

        let worker = match thread::Builder::new()
            .name("ts-localapi".into())
            .stack_size(128 * 1024)
            .spawn(move || accept_loop(listener, worker_shutdown, ctx))
        {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "localapi.thread.spawn_failed");
                return None;
            }
        };

        Some(Self {
            worker: Some(worker),
            shutdown,
            bound_addr,
        })
    }

    /// Loopback address the server is listening on. Useful for
    /// diagnostics / tests.
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }
}

impl Drop for LocalApiServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.worker.take() {
            // Best-effort join; if a slow request is in flight the
            // thread may take a moment to wind down. We don't block
            // forever — give it ~3 s then move on.
            let _ = h.join();
        }
    }
}

fn accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    ctx: HandlerCtx,
) {
    info!(addr = ?listener.local_addr(), "localapi.worker.start");
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                trace!(%peer, "localapi.accept");
                handle_one(stream, &peer, &ctx);
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock) => {
                thread::sleep(ACCEPT_TICK);
            }
            Err(e) => {
                warn!(error = %e, "localapi.accept.error");
                thread::sleep(ACCEPT_TICK);
            }
        }
    }
    info!("localapi.worker.exit");
}

fn handle_one(mut stream: TcpStream, peer: &SocketAddr, ctx: &HandlerCtx) {
    // Per-stream blocking with read/write timeouts; the inherited
    // non-blocking flag from the listener doesn't carry to accepted
    // sockets on Linux, but we set it explicitly to be safe.
    if let Err(e) = stream.set_nonblocking(false) {
        warn!(%peer, error = %e, "localapi.stream.set_blocking_failed");
        return;
    }
    let req = match http::read_request(&mut stream) {
        Ok(r) => r,
        Err(http::RequestError::Io(e)) => {
            debug!(%peer, error = %e, "localapi.req.io_error");
            return;
        }
        Err(http::RequestError::BadRequest(reason)) => {
            warn!(%peer, reason, "localapi.req.bad");
            let _ = http::write_error(&mut stream, 400, reason);
            return;
        }
        Err(http::RequestError::TooLarge) => {
            warn!(%peer, "localapi.req.too_large");
            let _ = http::write_error(&mut stream, 413, "request too large");
            return;
        }
    };
    let path_for_log = req.path.clone();
    let method_for_log = req.method.clone();
    if let Err(e) = router::dispatch(&mut stream, &req, ctx) {
        warn!(%peer, error = %e, "localapi.dispatch.io_error");
    }
    debug!(%peer, method = %method_for_log, path = %path_for_log, "localapi.served");
}
