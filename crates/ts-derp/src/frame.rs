//! DERP frame codec.
//!
//! Wire layout (verified against `tailscale.com/derp/derp.go`):
//!
//! ```text
//! ┌──────────┬───────────────┬──────────────────────────┐
//! │ 1 B type │ 4 B BE length │ payload (length bytes)   │
//! └──────────┴───────────────┴──────────────────────────┘
//! ```
//!
//! Frame type byte:
//!
//! | Hex  | Name           | Direction | We…                        |
//! |------|----------------|-----------|----------------------------|
//! | 0x01 | ServerKey      | S→C       | parse + verify magic       |
//! | 0x02 | ClientInfo     | C→S       | encode in handshake        |
//! | 0x03 | ServerInfo     | S→C       | parse in handshake         |
//! | 0x04 | SendPacket     | C→S       | encode for outbound WG     |
//! | 0x05 | RecvPacket     | S→C       | parse for inbound WG       |
//! | 0x06 | KeepAlive      | S→C       | refresh dead-conn timer    |
//! | 0x07 | NotePreferred  | C→S       | encode home-region marker  |
//! | 0x08 | PeerGone       | S→C       | log + clear cached state   |
//! | 0x12 | Ping           | S→C       | reply with Pong            |
//! | 0x13 | Pong           | C→S       | encode reply               |
//! | 0x14 | Health         | S→C       | log only                   |
//! | 0x15 | Restarting     | S→C       | sleep + reconnect          |
//!
//! Frame types we don't implement (mesh / privileged): 0x09 PeerPresent,
//! 0x0A ForwardPacket, 0x10 WatchConns, 0x11 ClosePeer. Decoder logs at
//! TRACE and drops.

use std::io::{Read, Write};

use crate::magic::{FRAME_HEADER_LEN, MAX_PAYLOAD};
use crate::{DerpError, NodeKeyBytes};

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameType {
    ServerKey = 0x01,
    ClientInfo = 0x02,
    ServerInfo = 0x03,
    SendPacket = 0x04,
    RecvPacket = 0x05,
    KeepAlive = 0x06,
    NotePreferred = 0x07,
    PeerGone = 0x08,
    PeerPresent = 0x09,
    ForwardPacket = 0x0a,
    WatchConns = 0x10,
    ClosePeer = 0x11,
    Ping = 0x12,
    Pong = 0x13,
    Health = 0x14,
    Restarting = 0x15,
}

impl FrameType {
    pub fn from_byte(b: u8) -> Result<Self, DerpError> {
        match b {
            0x01 => Ok(FrameType::ServerKey),
            0x02 => Ok(FrameType::ClientInfo),
            0x03 => Ok(FrameType::ServerInfo),
            0x04 => Ok(FrameType::SendPacket),
            0x05 => Ok(FrameType::RecvPacket),
            0x06 => Ok(FrameType::KeepAlive),
            0x07 => Ok(FrameType::NotePreferred),
            0x08 => Ok(FrameType::PeerGone),
            0x09 => Ok(FrameType::PeerPresent),
            0x0a => Ok(FrameType::ForwardPacket),
            0x10 => Ok(FrameType::WatchConns),
            0x11 => Ok(FrameType::ClosePeer),
            0x12 => Ok(FrameType::Ping),
            0x13 => Ok(FrameType::Pong),
            0x14 => Ok(FrameType::Health),
            0x15 => Ok(FrameType::Restarting),
            _ => Err(DerpError::BadFrameType { byte: b }),
        }
    }
}

// ---------- raw codec ----------------------------------------------------

/// Write `[1 B type | 4 B BE length | payload]` to `out`.
pub fn write_frame<W: Write>(
    out: &mut W,
    ty: FrameType,
    payload: &[u8],
) -> Result<(), DerpError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(DerpError::FrameTooLarge {
            len: payload.len(),
            cap: MAX_PAYLOAD,
        });
    }
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    hdr[0] = ty as u8;
    hdr[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out.write_all(&hdr)?;
    out.write_all(payload)?;
    Ok(())
}

/// Read one full frame from `r` blocking. Caps payload at `MAX_PAYLOAD`
/// to defend against malformed `0x00FFFFFF` length prefixes.
pub fn read_frame<R: Read>(r: &mut R) -> Result<(FrameType, Vec<u8>), DerpError> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    r.read_exact(&mut hdr)?;
    let ty = FrameType::from_byte(hdr[0])?;
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(DerpError::FrameTooLarge {
            len,
            cap: MAX_PAYLOAD,
        });
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok((ty, payload))
}

/// Resumable framed reader over a timeout-bounded byte stream.
///
/// FIX (DERP read desync): the io_loop sets a ~100 ms read timeout on the TLS
/// stream and called [`read_frame`] (which uses `read_exact`) once per loop.
/// `read_exact` gives NO partial-read guarantee — when a frame straddles the
/// read-timeout boundary it consumes bytes into its buffer, then returns
/// `WouldBlock`/`TimedOut`, and those bytes are DISCARDED. The next read starts
/// mid-frame → stream desync → bogus frame type → the io_loop tears the home
/// DERP conn down. A single CMM frame fits one read (no straddle), which is why
/// CMM worked but sustained WG data didn't.
///
/// `FrameReader` accumulates bytes across calls so a straddling frame is never
/// lost: [`poll_frame`](Self::poll_frame) reads at most one chunk (preserving
/// the buffer on timeout) and returns the next complete frame once enough bytes
/// have arrived.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Read at most one chunk from `r` (respecting its read timeout) and return
    /// the next complete frame if one is now buffered. `Ok(None)` = "need more
    /// bytes" (timeout/WouldBlock or a partial frame); the buffer is preserved,
    /// call again. `Err` is a real IO/protocol error (including EOF).
    pub fn poll_frame<R: Read>(
        &mut self,
        r: &mut R,
    ) -> Result<Option<(FrameType, Vec<u8>)>, DerpError> {
        // A full frame may already be buffered from a prior read.
        if let Some(f) = self.try_extract()? {
            return Ok(Some(f));
        }
        let mut tmp = [0u8; 8192];
        match r.read(&mut tmp) {
            Ok(0) => Err(DerpError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "derp connection closed by peer",
            ))),
            Ok(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                self.try_extract()
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Timeout: keep the partial buffer and resume on the next call.
                Ok(None)
            }
            Err(e) => Err(DerpError::Io(e)),
        }
    }

    /// Extract one complete frame from the buffer if present, consuming it.
    fn try_extract(&mut self) -> Result<Option<(FrameType, Vec<u8>)>, DerpError> {
        if self.buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let ty = FrameType::from_byte(self.buf[0])?;
        let len =
            u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if len > MAX_PAYLOAD {
            return Err(DerpError::FrameTooLarge {
                len,
                cap: MAX_PAYLOAD,
            });
        }
        let total = FRAME_HEADER_LEN + len;
        if self.buf.len() < total {
            return Ok(None); // header parsed; payload not fully arrived yet
        }
        let payload = self.buf[FRAME_HEADER_LEN..total].to_vec();
        self.buf.drain(..total);
        Ok(Some((ty, payload)))
    }
}

// ---------- typed helpers ------------------------------------------------

/// `FrameSendPacket`: `dst_pubkey(32) || wg_bytes`.
pub fn write_send_packet<W: Write>(
    out: &mut W,
    dst_pubkey: &NodeKeyBytes,
    wg_bytes: &[u8],
) -> Result<(), DerpError> {
    let total = 32 + wg_bytes.len();
    if total > MAX_PAYLOAD {
        return Err(DerpError::FrameTooLarge {
            len: total,
            cap: MAX_PAYLOAD,
        });
    }
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    hdr[0] = FrameType::SendPacket as u8;
    hdr[1..5].copy_from_slice(&(total as u32).to_be_bytes());
    out.write_all(&hdr)?;
    out.write_all(dst_pubkey)?;
    out.write_all(wg_bytes)?;
    Ok(())
}

/// `FrameRecvPacket` payload: `src_pubkey(32) || wg_bytes`.
pub fn parse_recv_packet(payload: &[u8]) -> Result<(NodeKeyBytes, &[u8]), DerpError> {
    if payload.len() < 32 {
        return Err(DerpError::FrameTooShort {
            ty: "RecvPacket",
            len: payload.len(),
            need: 32,
        });
    }
    let mut src = [0u8; 32];
    src.copy_from_slice(&payload[..32]);
    Ok((src, &payload[32..]))
}

/// `FrameNotePreferred` payload: 1 B (0x01 = mark home, 0x00 = un-mark).
pub fn write_note_preferred<W: Write>(out: &mut W, is_home: bool) -> Result<(), DerpError> {
    write_frame(
        out,
        FrameType::NotePreferred,
        &[if is_home { 0x01 } else { 0x00 }],
    )
}

/// `FramePong` payload: 8 B opaque echo of the corresponding `Ping`.
pub fn write_pong<W: Write>(out: &mut W, payload: [u8; 8]) -> Result<(), DerpError> {
    write_frame(out, FrameType::Pong, &payload)
}

/// `FramePing` payload: 8 B opaque (server expects us to echo in Pong).
pub fn parse_ping(payload: &[u8]) -> Result<[u8; 8], DerpError> {
    if payload.len() < 8 {
        return Err(DerpError::FrameTooShort {
            ty: "Ping",
            len: payload.len(),
            need: 8,
        });
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(&payload[..8]);
    Ok(out)
}

/// `FramePeerGone` payload: `pubkey(32) || reason(1)`. Reason byte
/// values per upstream: 0 = generic, 1 = unknown, 2 = mesh-too-deep.
pub fn parse_peer_gone(payload: &[u8]) -> Result<(NodeKeyBytes, u8), DerpError> {
    if payload.len() < 32 {
        return Err(DerpError::FrameTooShort {
            ty: "PeerGone",
            len: payload.len(),
            need: 33,
        });
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&payload[..32]);
    let reason = payload.get(32).copied().unwrap_or(0);
    Ok((pk, reason))
}

/// `FrameRestarting` payload: `reconnect_in_ms(4 BE) || try_for_ms(4 BE)`.
pub fn parse_restarting(payload: &[u8]) -> Result<(u32, u32), DerpError> {
    if payload.len() < 8 {
        return Err(DerpError::FrameTooShort {
            ty: "Restarting",
            len: payload.len(),
            need: 8,
        });
    }
    let reconnect_in = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let try_for = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    Ok((reconnect_in, try_for))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_type_roundtrip_all() {
        for byte in [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15,
        ] {
            let ty = FrameType::from_byte(byte).unwrap();
            assert_eq!(ty as u8, byte);
        }
    }

    #[test]
    fn frame_type_unknown_byte() {
        assert!(matches!(
            FrameType::from_byte(0xff),
            Err(DerpError::BadFrameType { byte: 0xff })
        ));
    }

    #[test]
    fn write_then_read_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, FrameType::Pong, b"\x01\x02\x03\x04\x05\x06\x07\x08").unwrap();
        let mut cursor = std::io::Cursor::new(&buf);
        let (ty, payload) = read_frame(&mut cursor).unwrap();
        assert_eq!(ty, FrameType::Pong);
        assert_eq!(payload, b"\x01\x02\x03\x04\x05\x06\x07\x08");
        // Header was 5 bytes.
        assert_eq!(buf.len(), 5 + 8);
    }

    #[test]
    fn send_packet_layout() {
        let mut buf = Vec::new();
        let dst = [0xaa; 32];
        let wg = b"hello";
        write_send_packet(&mut buf, &dst, wg).unwrap();
        // Header: type=0x04, length=37 BE.
        assert_eq!(buf[0], 0x04);
        assert_eq!(&buf[1..5], &(37u32).to_be_bytes());
        assert_eq!(&buf[5..37], &dst);
        assert_eq!(&buf[37..], wg);
    }

    #[test]
    fn recv_packet_split() {
        let mut payload = Vec::new();
        let src = [0xbb; 32];
        payload.extend_from_slice(&src);
        payload.extend_from_slice(b"world");
        let (got_src, body) = parse_recv_packet(&payload).unwrap();
        assert_eq!(got_src, src);
        assert_eq!(body, b"world");
    }

    #[test]
    fn recv_packet_too_short() {
        let payload = vec![0u8; 16];
        assert!(matches!(
            parse_recv_packet(&payload),
            Err(DerpError::FrameTooShort {
                ty: "RecvPacket",
                ..
            })
        ));
    }

    #[test]
    fn note_preferred_byte() {
        let mut buf = Vec::new();
        write_note_preferred(&mut buf, true).unwrap();
        assert_eq!(buf, &[0x07, 0, 0, 0, 1, 0x01]);
        buf.clear();
        write_note_preferred(&mut buf, false).unwrap();
        assert_eq!(buf, &[0x07, 0, 0, 0, 1, 0x00]);
    }

    #[test]
    fn pong_writes_8_bytes() {
        let mut buf = Vec::new();
        let p = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        write_pong(&mut buf, p).unwrap();
        assert_eq!(buf[0], 0x13);
        assert_eq!(&buf[1..5], &8u32.to_be_bytes());
        assert_eq!(&buf[5..], &p);
    }

    #[test]
    fn ping_parse() {
        let p = [0x99u8; 12];
        let echo = parse_ping(&p).unwrap();
        assert_eq!(echo, [0x99u8; 8]);
    }

    #[test]
    fn peer_gone_parse() {
        let mut payload = vec![0xcc; 32];
        payload.push(0x01);
        let (pk, reason) = parse_peer_gone(&payload).unwrap();
        assert_eq!(pk, [0xccu8; 32]);
        assert_eq!(reason, 0x01);
    }

    #[test]
    fn restarting_parse() {
        let payload = [0, 0, 0x01, 0x00, 0, 0, 0x10, 0x00];
        let (reconnect, try_for) = parse_restarting(&payload).unwrap();
        assert_eq!(reconnect, 256);
        assert_eq!(try_for, 4096);
    }

    #[test]
    fn rejects_oversize_payload() {
        let mut buf = Vec::new();
        let huge = vec![0u8; MAX_PAYLOAD + 1];
        assert!(matches!(
            write_frame(&mut buf, FrameType::SendPacket, &huge),
            Err(DerpError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_oversize_length_in_read() {
        // Hand-craft a header claiming 16 MiB length on identity stream.
        let mut buf = Vec::new();
        buf.push(0x05); // RecvPacket
        buf.extend_from_slice(&(16u32 * 1024 * 1024).to_be_bytes());
        let mut cursor = std::io::Cursor::new(&buf);
        assert!(matches!(
            read_frame(&mut cursor),
            Err(DerpError::FrameTooLarge { .. })
        ));
    }
}
