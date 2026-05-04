//! Tailscale / Headscale control-plane client.
//!
//! M4 ships `fetch_server_key` (the Noise pubkey bootstrap from
//! `GET /key?v=N`) and the on-disk pin/load helpers. M5+ adds the Noise
//! tunnel, HTTP/2 framing, register, and map long-poll. See PLAN-V1.md
//! §"Wire protocols summary".

mod error;
mod persist;
mod server_key;
mod types;
pub mod url;

pub use error::ControlError;
pub use persist::{atomic_write, pin_or_load_server_key};
pub use server_key::fetch_server_key;
pub use types::{
    DiscoPrivate, DiscoPublic, MachinePrivate, MachinePublic, NodePrivate, NodePublic,
    DISCOKEY_PREFIX, MKEY_PREFIX, NODEKEY_PREFIX,
};
