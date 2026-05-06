use crate::{Endpoint, Message, MessageType};

/// A pong message — response to a [`Ping`][crate::Ping] with the same `tx_id`.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct Pong {
    /// Same tx_id from the associated ping.
    pub tx_id: [u8; 12],

    /// The ping sender's source IP+port, as observed by the receiver.
    pub src: Endpoint,
}

impl Message for Pong {
    const TYPE: MessageType = MessageType::Pong;
}

impl Pong {
    pub const fn size() -> usize {
        size_of::<Self>()
    }
}
