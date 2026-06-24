//! TS2021 protocol helpers used during `Runtime::up`. Lifted verbatim
//! from the M9 demo's main.rs.
//!
//! These are private to the Runtime — embedding apps don't see them.

use std::io::Read;
use std::time::Duration;

use vita_log::info;

use ts_control::record::NoiseStream;
use ts_control::upgrade::UpgradedSocket;
use ts_control::{ControlError, ControlStream};

const EARLY_PAYLOAD_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";
const SERVER_RESP_LEN: usize = 51;

/// Consume Tailscale's EarlyPayload prefix (5 B magic + u32_be length +
/// JSON) before handing the Noise-framed stream to h2. Required for
/// protocolVersion ≥ 49 — our 90.
pub(crate) fn consume_early_payload(
    stream: &mut NoiseStream<ControlStream>,
) -> Result<(), ControlError> {
    let mut hdr = [0u8; 9];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| ControlError::Transport(format!("early payload header: {e}")))?;
    if &hdr[..5] != EARLY_PAYLOAD_MAGIC {
        return Err(ControlError::Transport(format!(
            "early payload missing magic; got first 5 bytes = {:02x?}",
            &hdr[..5]
        )));
    }
    let len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
    if len > 64 * 1024 {
        return Err(ControlError::Transport(format!(
            "early payload length absurd: {len}"
        )));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| ControlError::Transport(format!("early payload body: {e}")))?;
    info!(
        len,
        body_preview = %String::from_utf8_lossy(&body[..body.len().min(80)]),
        "control.early_payload"
    );
    Ok(())
}

/// Read the 51-byte Noise IK response off the upgraded TCP socket.
/// Anything past 51 bytes is the start of the first record stream and
/// gets stashed back into `upgraded.leftover` for the NoiseStream to
/// pick up.
pub(crate) fn read_server_response(
    upgraded: &mut UpgradedSocket,
) -> Result<Vec<u8>, ControlError> {
    let mut out = std::mem::take(&mut upgraded.leftover);
    let needed = SERVER_RESP_LEN;
    upgraded.tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut tmp = [0u8; 64];
    while out.len() < needed {
        let to_read = (needed - out.len()).min(tmp.len());
        let n = upgraded.tcp.read(&mut tmp[..to_read])?;
        if n == 0 {
            return Err(ControlError::Transport(format!(
                "noise: server closed before sending {needed} bytes"
            )));
        }
        out.extend_from_slice(&tmp[..n]);
    }
    if out.len() > needed {
        let extra = out.split_off(needed);
        upgraded.leftover = extra;
    }
    Ok(out)
}

pub(crate) fn hex_short(b: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(16);
    for byte in &b[..8] {
        let _ = write!(s, "{:02x}", byte);
    }
    s
}
