//! Tailscale DERP relay client.
//!
//! Per `PLAN-V1.md` §"DERP relay protocol": every encrypted WireGuard
//! datagram in v1 traverses a TLS-443 connection to a DERP relay (no
//! direct paths, no STUN, no `magicsock`). This crate implements:
//!
//! - **Frame codec** (`frame.rs`): the 12 frame types we read/write.
//!   Layout `1 B type || 4 B BE length || payload`. Max 64 KiB.
//! - **Handshake** (`handshake.rs`): TLS dial + HTTP/1.1 `Upgrade:
//!   DERP` exchange + `FrameServerKey` / `FrameClientInfo` /
//!   `FrameServerInfo` NaCl-box dance.
//! - **Per-region connection** (`conn.rs`): one OS thread per
//!   `DerpConn`, single-threaded against rustls. Biased select so
//!   pongs always preempt other tx.
//! - **Region pool** (`mux.rs`): cap 8 conns; LRU eviction (never the
//!   home).
//! - **Home selection** (`probe.rs`): TCP-RTT probe, 25% hysteresis,
//!   5-min cache.
//! - **Transport adapter** (`transport.rs`): implements
//!   `wg_engine::Transport` so the engine pump can `send` / `recv` over
//!   DERP without knowing the relay layer exists.

pub mod conn;
mod error;
pub mod frame;
pub mod handshake;
pub mod magic;
pub mod mux;
pub mod probe;
pub mod transport;

pub use conn::{DerpConn, DerpRx, DerpTx};
pub use error::DerpError;
pub use handshake::{
    dial_and_handshake, ClientInfoWire, DerpHandshakeOutput, DerpTls, ServerInfoWire,
};
pub use mux::DerpMux;
pub use probe::{HomeProbe, HomeProbeCache};
pub use transport::{DerpTransport, DerpTransportCtl};

/// 32 raw bytes — Tailscale's `key.NodePublic` wire form.
pub type NodeKeyBytes = [u8; 32];

/// One DERP relay node's contact info, extracted from `MapResponse.DERPMap`.
#[derive(Clone, Debug)]
pub struct DerpNodeAddr {
    pub region_id: u16,
    pub name: String,
    pub hostname: String,
    pub ipv4: String,
    pub ipv6: String,
    pub derp_port: u16,
}

impl DerpNodeAddr {
    /// The `host:port` string for `TcpStream::connect`. Prefers
    /// `hostname` (so TLS SNI / cert validation works); falls back to
    /// IPv4 if hostname is empty. Defaults port to 443 if `derp_port`
    /// is 0 (Tailscale's spec lets servers use 443 by default).
    pub fn dial_addr(&self) -> String {
        let host = if !self.hostname.is_empty() {
            self.hostname.clone()
        } else {
            self.ipv4.clone()
        };
        let port = if self.derp_port == 0 {
            443
        } else {
            self.derp_port
        };
        format!("{host}:{port}")
    }
}

/// All DERP regions our client knows about. Built from `MapResponse.DERPMap`
/// by the demo and handed to `DerpMux::set_derp_map`.
#[derive(Clone, Debug, Default)]
pub struct DerpMap {
    pub regions: std::collections::HashMap<u16, Vec<DerpNodeAddr>>,
}
