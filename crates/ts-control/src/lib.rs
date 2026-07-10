//! Tailscale / Headscale control-plane client.
//!
//! M4 ships `fetch_server_key` (the Noise pubkey bootstrap from
//! `GET /key?v=N`) and the on-disk pin/load helpers. M5+ adds the Noise
//! tunnel, HTTP/2 framing, register, and map long-poll. See PLAN-V1.md
//! §"Wire protocols summary".

/// Single source of truth for `tailcfg.CurrentCapabilityVersion`. Used in
/// four places that MUST agree (per upstream Go `control/ts2021/client.go`
/// + tailscale-rs `ts_control/src/tokio/connect.rs`):
///
/// 1. `noise::PROTOCOL_VERSION` — the BE u16 in the Noise upgrade envelope
///    plus the ASCII base-10 form mixed into the prologue. The server
///    re-derives the prologue from this and must match for AEAD to decrypt.
/// 2. `MapRequest.Version` JSON field.
/// 3. `RegisterRequest.Version` JSON field.
/// 4. `?v=<n>` query param on `GET /key` (via `config.capver` default).
///
/// M14C bumped from 90 → 138 to unify the triple. M14H drops to 130 as a
/// diagnostic: tailscale-rs (running the same rustls/h2 stack from the
/// host) registers and gets DiscoKey committed at `CapabilityVersion::CURRENT
/// = 130`; our Vita at 138 has DiscoKey silently zeroed. If 130 fixes
/// our DiscoKey, real Tailscale's coord server has stricter validation
/// at >=138 that we don't satisfy (likely the HardwareAttestationKey gate
/// from capver 130's note: "Client can send key.HardwareAttestationPublic
/// and key.HardwareAttestationKeySignature in MapRequest" — clients above
/// that may be expected to send the fields, and the Vita has no TPM).
pub const CAPVER: u16 = 130;

pub mod async_io;
pub mod control_stream;
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

pub use async_io::AsyncNoiseStream;
pub use control_stream::{wrap_tls, ControlStream};
pub use error::ControlError;
pub use http2::Http2Conn;
pub use keystore::KeyStore;
pub use map::{MapClient, MapEvent, NetMapSnapshot};
pub use netmap::{
    AllowedIp, FilterRule, NetMap, NetMapDelta, NetPortRange, PacketFilter, PeerSnapshot,
    RekeyedPeer,
};
pub use noise::{NoiseHandshaker, NoiseTransport};
pub use persist::{atomic_write, pin_or_load_server_key};
pub use record::NoiseStream;
pub use register::{logout, register, RegistrationOutcome};
pub use server_key::{
    fetch_server_key, fetch_server_key_cached, invalidate_server_key_cache, SERVER_KEY_CACHE_TTL,
};
pub use types::{
    generate_machine_keypair, DiscoPrivate, DiscoPublic, MachinePrivate, MachinePublic,
    NodePrivate, NodePublic, DISCOKEY_PREFIX, MKEY_PREFIX, NODEKEY_PREFIX,
};
pub use upgrade::{dial_and_upgrade, UpgradedSocket};
