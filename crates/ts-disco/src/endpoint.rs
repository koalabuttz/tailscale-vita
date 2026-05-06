use core::cmp::Ordering;
use core::hash::Hash;
use core::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use zerocopy::NetworkEndian;

/// An endpoint included in a [`CallMeMaybe`][crate::CallMeMaybe] message:
/// a socket address on which a node believes it's reachable.
///
/// All addresses are encoded as IPv6; IPv4 is mapped via `::ffff:0:0/96`.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct Endpoint {
    addr: [zerocopy::U16<NetworkEndian>; 8],
    port: zerocopy::U16<NetworkEndian>,
}

impl Endpoint {
    /// Address part as IPv6 (no IPv4-in-IPv6 unwrapping).
    pub const fn addr_v6(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            self.addr[0].get(),
            self.addr[1].get(),
            self.addr[2].get(),
            self.addr[3].get(),
            self.addr[4].get(),
            self.addr[5].get(),
            self.addr[6].get(),
            self.addr[7].get(),
        )
    }

    /// Address part with IPv4-in-IPv6 mapping unwrapped.
    pub const fn addr(&self) -> IpAddr {
        let addr = self.addr_v6();
        match addr.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(addr),
        }
    }

    pub const fn port(&self) -> u16 {
        self.port.get()
    }

    pub const fn socket_addr_v6(&self) -> SocketAddrV6 {
        SocketAddrV6::new(self.addr_v6(), self.port(), 0, 0)
    }

    pub const fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr(), self.port())
    }

    pub const fn from_socket_addr(sa: SocketAddr) -> Self {
        let ip = match sa.ip() {
            IpAddr::V4(sa) => sa.to_ipv6_mapped(),
            IpAddr::V6(sa) => sa,
        };
        Self {
            addr: zerocopy::transmute!(ip.segments()),
            port: zerocopy::U16::new(sa.port()),
        }
    }
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.socket_addr().cmp(&other.socket_addr())
    }
}

impl From<Endpoint> for SocketAddrV6 {
    fn from(value: Endpoint) -> Self {
        value.socket_addr_v6()
    }
}

impl From<Endpoint> for SocketAddr {
    fn from(value: Endpoint) -> Self {
        value.socket_addr()
    }
}

impl From<SocketAddrV6> for Endpoint {
    fn from(value: SocketAddrV6) -> Self {
        Self {
            addr: zerocopy::transmute!(value.ip().segments()),
            port: value.port().into(),
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(value: SocketAddr) -> Self {
        Self::from_socket_addr(value)
    }
}
