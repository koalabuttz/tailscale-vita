//! Tailscale / Headscale control-plane client.
//!
//! M4 ships `fetch_server_key` (the Noise pubkey bootstrap from
//! `GET /key?v=N`) and the on-disk pin/load helpers. M5+ adds the Noise
//! tunnel, HTTP/2 framing, register, and map long-poll. See PLAN-V1.md
//! §"Wire protocols summary".

pub mod async_io;
mod error;
pub mod http2;
pub mod keystore;
pub mod map;
pub mod netmap;
pub mod noise;
mod persist;
pub mod record;
pub mod register;
mod server_key;
mod types;
pub mod upgrade;
pub mod url;

pub use error::ControlError;
pub use keystore::KeyStore;
pub use map::{MapClient, MapEvent, NetMapSnapshot};
pub use netmap::{AllowedIp, NetMap, NetMapDelta, PeerSnapshot, RekeyedPeer};
pub use noise::{NoiseHandshaker, NoiseTransport};
pub use persist::{atomic_write, pin_or_load_server_key};
pub use register::{register, RegistrationOutcome};
pub use server_key::fetch_server_key;
pub use types::{
    generate_machine_keypair, DiscoPrivate, DiscoPublic, MachinePrivate, MachinePublic,
    NodePrivate, NodePublic, DISCOKEY_PREFIX, MKEY_PREFIX, NODEKEY_PREFIX,
};
