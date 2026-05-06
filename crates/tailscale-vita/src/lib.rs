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
//! use tailscale_vita::{Config, Runtime};
//! use std::path::Path;
//!
//! let cfg = Config::load_or_template(Path::new("ux0:/data/tailscale-vita/config.toml"))?;
//! let mut rt = Runtime::up(cfg)?;
//! let listener = netstack::TcpListener::bind(rt.netstack(), 8080, 4)?;
//! // ...accept loop in one thread, rt.run_event_loop in another...
//! rt.shutdown();
//! ```

mod config;
pub mod dual_transport;
mod error;
pub mod lifecycle;
mod proto;
pub mod runtime;

pub use config::Config;
pub use dual_transport::DualTransport;
pub use error::{ConfigError, RuntimeError};
pub use lifecycle::{LifecycleTracker, OnlineState};
pub use runtime::{RunStats, Runtime};
