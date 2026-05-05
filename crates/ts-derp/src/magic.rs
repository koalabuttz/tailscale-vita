//! DERP wire constants. Verified against `tailscale.com/derp/derp.go`
//! during M8 research (see `~/.claude/plans/m8-derp.md` "Wire spec").

use std::time::Duration;

/// `b"DERP\xf0\x9f\x94\x91"` (8 bytes, literal "DERP🔑"). Prefixes the
/// `FrameServerKey` payload so a misbehaving (or wrong-protocol) server
/// can be detected at first read.
pub const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";

/// DERP protocol we speak. Servers expect this in the `ClientInfo`
/// JSON body and themselves report this in `ServerInfo`.
pub const PROTOCOL_VERSION: u32 = 2;

/// Max payload length per frame (post-header). Tailscale's
/// `derp.MaxPacketSize`. A malformed `0x00FFFFFF` length must NOT
/// trigger a 16 MiB allocation that OOMs the Vita.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// 1 B frame type + 4 B BE length.
pub const FRAME_HEADER_LEN: usize = 5;

/// Per-server TCP+TLS dial budget. Each region has 1+ nodes; we try
/// them in order. Tailscale uses 1500 ms.
pub const DIAL_TIMEOUT: Duration = Duration::from_millis(1500);

/// Read budget on the conn thread before assuming the conn is dead.
/// Tailscale's `recvTimeout` is 120 s; we add 5 s slack to absorb
/// keepalive jitter.
pub const KEEPALIVE_DEADLINE: Duration = Duration::from_secs(125);

/// Per-poll read timeout on the I/O thread. Short enough that pongs
/// and outbound tx don't queue more than ~100 ms behind a slow read.
pub const READ_TICK: Duration = Duration::from_millis(100);

/// Max region conns we keep alive concurrently. Per PLAN-V1 §M8.
pub const DEFAULT_MAX_CONNS: usize = 8;

/// Home-region probe cache TTL.
pub const HOME_PROBE_CACHE: Duration = Duration::from_secs(300);

/// Hysteresis: only switch home if new winner is at least this much
/// faster than current home. 25% means new_rtt < current_rtt * 0.75.
pub const HOME_SWITCH_FRACTION: f32 = 0.75;
