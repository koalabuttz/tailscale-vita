//! Tailscale Disco protocol — NaCl-box encrypted Ping/Pong/CallMeMaybe
//! over UDP for direct-path liveness probing.
//!
//! Lifted from `tailscale-rs::ts_disco_protocol` 2026-05-05 for M12.
//! Key types (`DiscoPublicKey` etc.) are minimal newtypes in
//! [`keys`] rather than the full ts_keys macro tree — see that module
//! for the boundary.

#![cfg_attr(not(test), no_std)]

#[cfg(any(feature = "alloc", test))]
extern crate alloc;

mod call_me_maybe;
mod endpoint;
mod error;
mod header;
pub mod keys;
mod message_type;
mod packet;
mod ping;
mod pong;

pub use call_me_maybe::CallMeMaybe;
pub use endpoint::Endpoint;
pub use error::Error;
pub use header::Header;
pub use message_type::MessageType;
pub use packet::Packet;
pub use ping::Ping;
pub use pong::Pong;

/// Common disco message functionality — the type byte each variant uses.
pub trait Message {
    const TYPE: MessageType;
}

/// Best-effort sniff: does `buf` start with a Disco header magic?
pub fn is_disco_message(buf: &[u8]) -> bool {
    Header::from_bytes(buf).is_ok()
}

#[cfg(test)]
mod test {
    use core::fmt::Debug;
    use core::net::{Ipv6Addr, SocketAddrV6};

    use zerocopy::IntoBytes;

    use super::*;
    use crate::keys::{DiscoPrivateKey, NodePublicKey};

    fn rand_array<const N: usize>(rng: &mut impl rand::Rng) -> [u8; N] {
        let mut a = [0u8; N];
        rng.fill_bytes(&mut a[..]);
        a
    }

    #[test]
    fn roundtrip_header() {
        let mut rng = rand::thread_rng();
        let pk: [u8; 32] = rand_array(&mut rng);
        let nonce: [u8; 24] = rand_array(&mut rng);

        let header = Header::new(pk.into(), nonce);
        header.validate().unwrap();

        let bytes = header.as_bytes();
        let (parsed, rest) = Header::from_bytes(bytes).unwrap();
        assert_eq!(parsed, &header);
        assert!(rest.is_empty());
    }

    fn roundtrip_msg<Msg>(size: usize, init: impl FnOnce(&mut Msg))
    where
        Msg: Message
            + ?Sized
            + zerocopy::Immutable
            + zerocopy::FromBytes
            + zerocopy::IntoBytes
            + zerocopy::KnownLayout,
        for<'a> &'a Msg: PartialEq + Debug,
    {
        let mut rng = rand::thread_rng();

        let mut buf = alloc::vec![0; Packet::size_for_message(size)];
        let pkt = Packet::init_from_bytes::<Msg>(&mut buf, init).unwrap();

        let init_bytes = pkt.as_bytes().to_vec();
        let init_pkt = unsafe { Packet::from_bytes_unchecked(&init_bytes) }.unwrap();

        let sender = DiscoPrivateKey::random();
        let receiver = DiscoPrivateKey::random();
        let nonce: [u8; 24] = rand_array(&mut rng);

        let pkt = pkt
            .encrypt_in_place(&sender, &receiver.public_key(), nonce)
            .unwrap();

        let decrypted = pkt.decrypt_in_place(&receiver).unwrap();
        let dec_nonce: [u8; 24] = decrypted.header().nonce;
        assert_eq!(dec_nonce, nonce);
        assert_eq!(decrypted.header().sender_pub, sender.public_key());
        assert_eq!(decrypted.ty(), Some(Msg::TYPE));

        let result = decrypted.as_msg::<Msg>().unwrap();
        assert_eq!(init_pkt.as_msg::<Msg>().unwrap(), result);
    }

    #[test]
    fn roundtrip_ping() {
        let mut rng = rand::thread_rng();
        let node_key_bytes: [u8; 32] = rand_array(&mut rng);
        let tx: [u8; 12] = rand_array(&mut rng);

        roundtrip_msg::<Ping>(Ping::size_with_padding(0), |ping| {
            ping.node_key = NodePublicKey::from(node_key_bytes);
            ping.tx_id = tx;
        });
    }

    #[test]
    fn roundtrip_pong() {
        let mut rng = rand::thread_rng();
        let payload = Pong {
            tx_id: rand_array(&mut rng),
            src: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 1, 0, 0).into(),
        };

        roundtrip_msg(Pong::size(), |pong| {
            *pong = payload;
        });
    }

    #[test]
    fn roundtrip_callmemaybe() {
        roundtrip_msg::<CallMeMaybe>(CallMeMaybe::size_for_endpoint_count(3), |cmm| {
            cmm.endpoints[0] = "[a:b::]:80".parse::<SocketAddrV6>().unwrap().into();
            cmm.endpoints[1] = "[b:c::]:8080".parse::<SocketAddrV6>().unwrap().into();
            cmm.endpoints[2] = "[c:d::]:1234".parse::<SocketAddrV6>().unwrap().into();
        });
    }

    #[test]
    fn is_disco_message_recognizes_magic() {
        let mut buf = vec![0u8; size_of::<Header>()];
        buf[..6].copy_from_slice(&Header::MAGIC);
        assert!(is_disco_message(&buf));
        buf[0] = b'X';
        assert!(!is_disco_message(&buf));
    }
}
