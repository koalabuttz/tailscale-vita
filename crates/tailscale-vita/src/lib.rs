//! Tailscale-on-Vita public Runtime + Config.
//!
//! M10 milestone of PLAN-V1. Embedding applications (the official
//! demo eboot at `crates/tailscale-vita-demo`, plus any future
//! sample apps) statically link this crate. Use the M5 Plan-A
//! threading model: blocking calls only, no tokio in the public API.
//!
//! Bring-up:
//!
//! ```ignore
//! use tailscale_vita::{run_supervised, Config};
//! use std::path::Path;
//!
//! let cfg = Config::load_or_template(Path::new("ux0:/data/tailscale-vita/config.toml"))?;
//! // The supervisor owns the up() -> run_event_loop loop and rebuilds the
//! // whole Runtime on a mid-life re-login. `setup` binds a listener on the
//! // fresh netstack each incarnation and returns a guard dropped on relogin.
//! run_supervised(cfg, || should_stop(), |rt| {
//!     netstack::TcpListener::bind(rt.netstack(), 8080, 4).map(AcceptGuard::spawn)
//! })?;
//! ```

mod config;
pub mod dual_transport;
pub mod egress_probe;
mod error;
pub mod lifecycle;
pub mod localapi;
mod proto;
pub mod runtime;
pub mod snapshot;

pub use config::Config;
pub use dual_transport::DualTransport;
pub use error::{ConfigError, RuntimeError};
pub use lifecycle::{FatalKind, LifecycleTracker, OnlineState};
pub use localapi::LocalApiServer;
pub use runtime::{
    run_supervised, wg_selftest_line, ControlHandle, ControlSignal, LoopExit, RunStats, Runtime,
};
pub use snapshot::{AclSummary, AllowedIpView, PeerView, RuntimeSnapshot};
