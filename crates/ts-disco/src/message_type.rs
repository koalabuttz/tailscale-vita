use num_traits::FromPrimitive;

/// Disco message types. Wire-encoded as a single byte at the start of
/// the encrypted payload.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum MessageType {
    /// [`Ping`][crate::Ping] — request that the recipient send a
    /// [`Pong`][crate::Pong] back.
    Ping = 0x1,
    /// [`Pong`][crate::Pong] — response to a [`Ping`][crate::Ping].
    Pong = 0x2,
    /// [`CallMeMaybe`][crate::CallMeMaybe] — request that the recipient open
    /// a magicsock path back to the sender.
    CallMeMaybe = 0x3,
    /// First message in a bind UDP relay handshake (M13+).
    BindUdpRelayEndpoint = 0x4,
    /// UDP relay endpoint challenge (M13+).
    BindUdpRelayEndpointChallenge = 0x5,
    /// UDP relay challenge answer (M13+).
    BindUdpRelayEndpointAnswer = 0x6,
    /// Like [`MessageType::CallMeMaybe`] but the response path travels
    /// through a relay (M13+).
    CallMeMaybeVia = 0x7,
    /// Request allocation of a relay endpoint on a UDP relay server (M13+).
    AllocateUdpRelayEndpointsRequest = 0x8,
    /// Response to a request for allocation of a relay endpoint (M13+).
    AllocateUdpRelayEndpointsResponse = 0x9,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or(())
    }
}
