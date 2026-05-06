use core::fmt::{Debug, Formatter};
use core::hash::{Hash, Hasher};

use crate::keys::NodePublicKey;
use crate::{Message, MessageType};

/// A ping message from one node to another.
#[derive(
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct Ping {
    /// Random per-ping transaction id; echoed in the [`Pong`][crate::Pong].
    pub tx_id: [u8; 12],

    /// Sender's WireGuard node public key. Lets receivers reduce the
    /// disco→node correlation from 1:N to 1:1.
    pub node_key: NodePublicKey,

    /// Trailing zero padding used for path-MTU probing.
    pub padding: [u8],
}

impl Message for Ping {
    const TYPE: MessageType = MessageType::Ping;
}

impl Ping {
    /// Size of a ping message with `n` bytes of padding.
    pub const fn size_with_padding(n: usize) -> usize {
        12 + size_of::<NodePublicKey>() + n
    }
}

impl Debug for &Ping {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ping")
            .field("tx_id", &self.tx_id)
            .field("node_key", &self.node_key)
            .field("padding", &&self.padding)
            .finish()
    }
}

impl PartialEq for &Ping {
    fn eq(&self, other: &Self) -> bool {
        self.tx_id == other.tx_id
            && self.node_key == other.node_key
            && self.padding == other.padding
    }
}

impl Eq for &Ping {}

impl Hash for &Ping {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tx_id.hash(state);
        self.node_key.hash(state);
        self.padding.hash(state);
    }
}
