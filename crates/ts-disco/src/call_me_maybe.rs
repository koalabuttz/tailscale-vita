use core::fmt::{Debug, Formatter};
use core::hash::{Hash, Hasher};

use crate::{Endpoint, Message, MessageType};

/// CallMeMaybe — sent over DERP to ask the recipient to open a magicsock
/// path back to the sender. Sender should already have sent UDP packets
/// to the recipient's expected addresses to open inbound NAT mappings.
#[derive(
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct CallMeMaybe {
    /// Endpoints the sender thinks are reachable to it.
    pub endpoints: [Endpoint],
}

impl Message for CallMeMaybe {
    const TYPE: MessageType = MessageType::CallMeMaybe;
}

impl CallMeMaybe {
    pub const fn size_for_endpoint_count(endpoint_count: usize) -> usize {
        size_of::<Endpoint>() * endpoint_count
    }
}

impl Debug for &CallMeMaybe {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallMeMaybe")
            .field("endpoints", &&self.endpoints)
            .finish()
    }
}

impl PartialEq for &CallMeMaybe {
    fn eq(&self, other: &Self) -> bool {
        self.endpoints.eq(&other.endpoints)
    }
}

impl Eq for &CallMeMaybe {}

impl PartialOrd for &CallMeMaybe {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for &CallMeMaybe {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.endpoints.cmp(&other.endpoints)
    }
}

impl Hash for &CallMeMaybe {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.endpoints.hash(state);
    }
}
