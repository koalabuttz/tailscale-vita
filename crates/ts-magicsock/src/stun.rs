//! Minimal STUN binding-request client (RFC 5389).
//!
//! Only what's needed to probe DERP servers' STUN ports (UDP/3478) and
//! extract our public-mapped IPv4 endpoint via XOR-MAPPED-ADDRESS.
//! No authentication, no message-integrity, no fingerprinting — just
//! the binding request/response with the basic XOR-MAPPED-ADDRESS
//! attribute that all STUN servers (including Tailscale DERP) reply
//! with.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// `0x2112A442` — RFC 5389 §6 magic cookie. Always at bytes 4..8 of
/// every STUN message.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Length of the STUN message header (type + length + cookie + tx_id).
pub const HEADER_LEN: usize = 20;

/// Length of the transaction ID field (post-magic-cookie).
pub const TX_ID_LEN: usize = 12;

/// `0x0001` — STUN Binding Request message type. (Class=Request, Method=Binding.)
const TYPE_BINDING_REQUEST: u16 = 0x0001;

/// `0x0101` — STUN Binding Success Response. (Class=SuccessResponse, Method=Binding.)
const TYPE_BINDING_SUCCESS: u16 = 0x0101;

/// `0x0020` — XOR-MAPPED-ADDRESS attribute type (RFC 5389 §15.2).
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// XOR-MAPPED-ADDRESS family byte: IPv4.
const FAMILY_IPV4: u8 = 0x01;

/// XOR-MAPPED-ADDRESS family byte: IPv6.
const FAMILY_IPV6: u8 = 0x02;

/// Build a STUN Binding Request packet. 20 bytes, no attributes.
/// `tx_id` is the 12-byte transaction ID; the caller must remember it
/// to match the response.
pub fn encode_binding_request(tx_id: &[u8; TX_ID_LEN]) -> [u8; HEADER_LEN] {
    let mut buf = [0u8; HEADER_LEN];
    buf[0..2].copy_from_slice(&TYPE_BINDING_REQUEST.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // body length = 0
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(tx_id);
    buf
}

/// Detect a STUN message by looking at the magic cookie at bytes 4..8.
/// This is what we use in the magicsock RX demux to recognize STUN
/// responses arriving on the same UDP socket as Disco/WG packets.
///
/// Note: STUN messages also have the top 2 bits of byte 0 zero — we
/// don't check that since the magic cookie is sufficient to
/// disambiguate from Disco (`TS💬` magic) and WireGuard (which
/// starts with the message-type byte 0x01–0x04).
pub fn looks_like_stun(bytes: &[u8]) -> bool {
    if bytes.len() < HEADER_LEN {
        return false;
    }
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    cookie == MAGIC_COOKIE
}

/// Extract the 12-byte transaction ID from a STUN message.
pub fn tx_id_from(bytes: &[u8]) -> Option<[u8; TX_ID_LEN]> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let mut tx = [0u8; TX_ID_LEN];
    tx.copy_from_slice(&bytes[8..20]);
    Some(tx)
}

/// Parse a STUN Binding Success Response and extract the
/// XOR-MAPPED-ADDRESS attribute. Returns `None` if the message isn't a
/// success response, the magic cookie is wrong, or no
/// XOR-MAPPED-ADDRESS attribute is present.
pub fn parse_binding_response(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if msg_type != TYPE_BINDING_SUCCESS {
        return None;
    }
    let body_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if bytes.len() < HEADER_LEN + body_len {
        return None;
    }
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return None;
    }
    // Walk the attribute list looking for XOR-MAPPED-ADDRESS.
    let mut tx_id_full = [0u8; 16];
    tx_id_full[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    tx_id_full[4..16].copy_from_slice(&bytes[8..20]);

    let mut i = HEADER_LEN;
    let end = HEADER_LEN + body_len;
    while i + 4 <= end {
        let attr_type = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        let attr_len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        let val_start = i + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return None;
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return parse_xor_mapped_address(&bytes[val_start..val_end], &tx_id_full);
        }
        // STUN attributes are 32-bit-aligned (pad with zeros to next
        // multiple of 4).
        let padded_len = (attr_len + 3) & !3;
        i = val_start + padded_len;
    }
    None
}

/// Decode the body of an XOR-MAPPED-ADDRESS attribute.
///
/// Layout per RFC 5389 §15.2:
/// - 1 byte reserved (must be 0)
/// - 1 byte family (0x01 IPv4, 0x02 IPv6)
/// - 2 bytes X-Port = port XOR (high 16 bits of magic cookie)
/// - 4 or 16 bytes X-Address (XOR'd with magic cookie || tx_id)
fn parse_xor_mapped_address(body: &[u8], tx_id_full: &[u8; 16]) -> Option<SocketAddr> {
    if body.len() < 4 {
        return None;
    }
    let family = body[1];
    let x_port = u16::from_be_bytes([body[2], body[3]]);
    let port = x_port ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        FAMILY_IPV4 => {
            if body.len() < 8 {
                return None;
            }
            let mut addr_bytes = [0u8; 4];
            for k in 0..4 {
                addr_bytes[k] = body[4 + k] ^ tx_id_full[k];
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr_bytes)), port))
        }
        FAMILY_IPV6 => {
            if body.len() < 20 {
                return None;
            }
            let mut addr_bytes = [0u8; 16];
            for k in 0..16 {
                addr_bytes[k] = body[4 + k] ^ tx_id_full[k];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr_bytes)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_shape() {
        let tx = [0x42u8; 12];
        let req = encode_binding_request(&tx);
        assert_eq!(req.len(), 20);
        // type
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), TYPE_BINDING_REQUEST);
        // length = 0 (no attrs)
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        // magic cookie
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            MAGIC_COOKIE
        );
        // tx id echoed
        assert_eq!(&req[8..20], &tx);
    }

    #[test]
    fn looks_like_stun_yes() {
        let req = encode_binding_request(&[0u8; 12]);
        assert!(looks_like_stun(&req));
    }

    #[test]
    fn looks_like_stun_no() {
        // WireGuard handshake init starts with msg-type 0x01.
        assert!(!looks_like_stun(&[0x01, 0, 0, 0, 0, 0, 0, 0]));
        // Disco magic prefix.
        assert!(!looks_like_stun(b"TS\xf0\x9f\x92\xac"));
    }

    #[test]
    fn parse_round_trip_ipv4() {
        // Hand-craft a STUN response with XOR-MAPPED-ADDRESS attr.
        let tx = [0x11u8; 12];
        let public_ip = Ipv4Addr::new(203, 0, 113, 5);
        let public_port: u16 = 53492;

        // Compute XOR-encoded values.
        let x_port = public_port ^ ((MAGIC_COOKIE >> 16) as u16);
        let mut x_addr = [0u8; 4];
        let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
        let ip_bytes = public_ip.octets();
        for i in 0..4 {
            x_addr[i] = ip_bytes[i] ^ cookie_bytes[i];
        }

        let mut resp = Vec::new();
        // Header: type=0x0101 (success), length=12 (4 hdr + 8 attr value)
        resp.extend_from_slice(&TYPE_BINDING_SUCCESS.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tx);
        // Attribute: type=0x0020, length=8
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0); // reserved
        resp.push(FAMILY_IPV4);
        resp.extend_from_slice(&x_port.to_be_bytes());
        resp.extend_from_slice(&x_addr);

        let parsed = parse_binding_response(&resp).expect("parse failed");
        assert_eq!(parsed, SocketAddr::new(IpAddr::V4(public_ip), public_port));
    }

    #[test]
    fn parse_rejects_bad_cookie() {
        let mut resp = vec![0u8; 28];
        resp[0..2].copy_from_slice(&TYPE_BINDING_SUCCESS.to_be_bytes());
        resp[2..4].copy_from_slice(&8u16.to_be_bytes());
        // Wrong cookie:
        resp[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        assert!(parse_binding_response(&resp).is_none());
    }

    #[test]
    fn tx_id_extracts() {
        let tx = [0x99u8; 12];
        let req = encode_binding_request(&tx);
        assert_eq!(tx_id_from(&req), Some(tx));
    }
}
