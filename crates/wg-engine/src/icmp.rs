//! M2-only test harness: synthesize and parse IPv4 ICMP echo packets.
//!
//! Once smoltcp owns the in-tunnel IP layer (M3), this module is deleted.
//! It exists to validate that BoringTun's `encapsulate`/`decapsulate`
//! handle real data — not just the handshake init we proved in Phase 0.

use std::net::Ipv4Addr;

/// IPv4 header length when no options are set.
const IPV4_HEADER_LEN: usize = 20;

/// ICMP echo header length (type/code/csum/ident/seq).
const ICMP_HEADER_LEN: usize = 8;

/// Build an IPv4 ICMP echo-request packet.
///
/// `payload` is the echo data (defaults to ~32 bytes of "ping" pattern in
/// callers). Returned bytes are ready to push into `EngineRunning.tun_tx`.
pub fn build_icmp_echo_request(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + ICMP_HEADER_LEN + payload.len();
    let mut buf = vec![0u8; total_len];

    // ---- IPv4 header ----
    buf[0] = (4 << 4) | 5; // version 4, IHL 5 (20-byte header)
    buf[1] = 0; // DSCP/ECN
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes()); // total length
    buf[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, fragment-offset=0
    buf[8] = 64; // TTL
    buf[9] = 1; // protocol = ICMP
    // csum at [10..12]; computed below
    buf[12..16].copy_from_slice(&src.octets());
    buf[16..20].copy_from_slice(&dst.octets());
    let ip_csum = internet_checksum(&buf[..IPV4_HEADER_LEN]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ---- ICMP echo request ----
    let icmp = &mut buf[IPV4_HEADER_LEN..];
    icmp[0] = 8; // type = Echo Request
    icmp[1] = 0; // code
                 // csum at [2..4]; computed after payload copy
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    icmp[ICMP_HEADER_LEN..ICMP_HEADER_LEN + payload.len()].copy_from_slice(payload);
    let icmp_csum = internet_checksum(&buf[IPV4_HEADER_LEN..]);
    buf[IPV4_HEADER_LEN + 2..IPV4_HEADER_LEN + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    buf
}

/// Parsed ICMP echo reply.
#[derive(Debug, Clone)]
pub struct EchoReply {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ident: u16,
    pub seq: u16,
    pub payload: Vec<u8>,
}

/// Try to parse a raw IPv4 packet as an ICMP echo reply. Returns `None` if
/// it isn't, or if any length/version/type check fails.
pub fn parse_icmp_echo_reply(pkt: &[u8]) -> Option<EchoReply> {
    if pkt.len() < IPV4_HEADER_LEN + ICMP_HEADER_LEN {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if ihl < IPV4_HEADER_LEN || pkt.len() < ihl + ICMP_HEADER_LEN {
        return None;
    }
    if pkt[9] != 1 {
        return None; // not ICMP
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let icmp = &pkt[ihl..];
    if icmp[0] != 0 || icmp[1] != 0 {
        return None; // not Echo Reply
    }
    let ident = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    let payload = icmp[ICMP_HEADER_LEN..].to_vec();
    Some(EchoReply {
        src,
        dst,
        ident,
        seq,
        payload,
    })
}

/// Standard internet checksum (RFC 1071) — one's-complement of one's-complement
/// 16-bit sum of `data`. Pads with a zero byte if odd length.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        // Synthesize echo request, mutate to look like reply, parse back.
        let mut req = build_icmp_echo_request(
            Ipv4Addr::new(10, 6, 0, 2),
            Ipv4Addr::new(10, 6, 0, 1),
            0xBEEF,
            7,
            b"ping payload!",
        );

        // Total length: 20 + 8 + 13 = 41
        assert_eq!(req.len(), 41);

        // Flip type 8 → 0 (echo request → reply), recompute csum, swap addrs.
        req[20] = 0;
        // zero csum, recompute
        req[20 + 2] = 0;
        req[20 + 3] = 0;
        let new_csum = internet_checksum(&req[20..]);
        req[20 + 2..20 + 4].copy_from_slice(&new_csum.to_be_bytes());
        // swap src/dst
        let mut src_octets = [0u8; 4];
        src_octets.copy_from_slice(&req[12..16]);
        let mut dst_octets = [0u8; 4];
        dst_octets.copy_from_slice(&req[16..20]);
        req[12..16].copy_from_slice(&dst_octets);
        req[16..20].copy_from_slice(&src_octets);
        // Recompute IP csum.
        req[10] = 0;
        req[11] = 0;
        let ipc = internet_checksum(&req[..20]);
        req[10..12].copy_from_slice(&ipc.to_be_bytes());

        let reply = parse_icmp_echo_reply(&req).expect("parse echo reply");
        assert_eq!(reply.src, Ipv4Addr::new(10, 6, 0, 1));
        assert_eq!(reply.dst, Ipv4Addr::new(10, 6, 0, 2));
        assert_eq!(reply.ident, 0xBEEF);
        assert_eq!(reply.seq, 7);
        assert_eq!(reply.payload, b"ping payload!");
    }

    #[test]
    fn rejects_non_icmp() {
        let mut pkt = build_icmp_echo_request(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            0,
            0,
            b"x",
        );
        pkt[9] = 17; // protocol = UDP
        assert!(parse_icmp_echo_reply(&pkt).is_none());
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse_icmp_echo_reply(&[]).is_none());
        assert!(parse_icmp_echo_reply(&[0x45]).is_none());
    }
}
