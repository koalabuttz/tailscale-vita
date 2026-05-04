use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::indices::Indices;
use crate::peer::Peer;

/// WireGuard message types (from boringtun source).
const HANDSHAKE_INIT: u32 = 1;
const HANDSHAKE_RESP: u32 = 2;
const COOKIE_REPLY: u32 = 3;
const PACKET_DATA: u32 = 4;

pub enum InboundRoute {
    /// Datagram has a known receiver-index; dispatch directly to one peer.
    SinglePeer(Arc<Peer>),
    /// Datagram is a HandshakeInit — no receiver-index in the wire format.
    /// Caller should iterate all peers and try `decapsulate` on each;
    /// exactly one will accept.
    Broadcast,
    /// Datagram is too short or has an unknown type byte.
    Junk,
}

/// Inspect a raw inbound WireGuard datagram and determine which `Peer`
/// (if any) should handle it. Encapsulates the `receiver_idx >> 8`
/// trick that turns the 4-byte little-endian sender/receiver index
/// into our `our_index` lookup key.
///
/// This does not mutate `Tunn` — it only peeks at the first 12 bytes.
pub fn route_inbound(idx: &Indices, datagram: &[u8]) -> InboundRoute {
    if datagram.len() < 4 {
        return InboundRoute::Junk;
    }
    let msg_type = u32::from_le_bytes(datagram[0..4].try_into().unwrap());

    match msg_type {
        HANDSHAKE_INIT => InboundRoute::Broadcast,
        HANDSHAKE_RESP | COOKIE_REPLY | PACKET_DATA => {
            // Layout for these three: 4 B type, then 4 B sender_idx (HANDSHAKE_RESP)
            // or receiver_idx. For HANDSHAKE_RESP: 4..8 = sender_idx (peer's choice),
            // 8..12 = receiver_idx (our choice). For COOKIE_REPLY/PACKET_DATA:
            // 4..8 = receiver_idx directly.
            let recv_idx_offset = if msg_type == HANDSHAKE_RESP { 8 } else { 4 };
            if datagram.len() < recv_idx_offset + 4 {
                return InboundRoute::Junk;
            }
            let recv_idx = u32::from_le_bytes(
                datagram[recv_idx_offset..recv_idx_offset + 4]
                    .try_into()
                    .unwrap(),
            );
            // BoringTun uses the lower 8 bits as session id within the peer.
            let peer_idx = recv_idx >> 8;
            match idx.by_idx.read().get(&peer_idx) {
                Some(p) => InboundRoute::SinglePeer(Arc::clone(p)),
                None => InboundRoute::Junk,
            }
        }
        _ => InboundRoute::Junk,
    }
}

/// Look up which peer's tunnel an outbound IPv4 packet should go through,
/// via longest-prefix-match on AllowedIPs.
pub fn peer_for_ip(idx: &Indices, dst: Ipv4Addr) -> Option<Arc<Peer>> {
    idx.by_ip.read().lookup(dst)
}

/// Parse the destination address out of a raw IPv4 packet.
/// Returns `None` if too short or not IPv4.
pub fn parse_ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}
