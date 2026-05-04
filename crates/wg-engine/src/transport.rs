use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::peer::TransportAddr;
use crate::WgError;

/// Abstraction over the encrypted-datagram transport. M2 implements
/// `UdpTransport` directly over `std::net::UdpSocket`. M8 will add a
/// `DerpTransport` that wraps the relay frame loop. Both implement this
/// same trait so the wg-engine pump doesn't change.
pub trait Transport: Send + Sync + 'static {
    /// Send `datagram` to `addr`. Synchronous; blocks until kernel accepts
    /// (which is typically immediate for UDP).
    fn send(&self, addr: TransportAddr, datagram: &[u8]) -> Result<(), WgError>;

    /// Wait up to `timeout` for an inbound datagram. Returns `Ok(None)` on
    /// timeout. Reads up to 1532 bytes (1500 MTU + 32-byte WG overhead).
    fn recv_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<(TransportAddr, Vec<u8>)>, WgError>;
}

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Bind a UDP socket. Pass `0.0.0.0:0` for an ephemeral port.
    pub fn bind(addr: SocketAddr) -> Result<Self, WgError> {
        let socket = UdpSocket::bind(addr).map_err(WgError::Io)?;
        Ok(Self { socket })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, WgError> {
        self.socket.local_addr().map_err(WgError::Io)
    }
}

impl Transport for UdpTransport {
    fn send(&self, addr: TransportAddr, datagram: &[u8]) -> Result<(), WgError> {
        let TransportAddr::Udp(sa) = addr;
        self.socket.send_to(datagram, sa).map_err(WgError::Io)?;
        Ok(())
    }

    fn recv_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<(TransportAddr, Vec<u8>)>, WgError> {
        // M2 strategy: per-call timeout. set_read_timeout is cheap and Vita's
        // newlib honors it (verified in M2 smoke test).
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(WgError::Io)?;
        let mut buf = [0u8; 1532];
        match self.socket.recv_from(&mut buf) {
            Ok((n, addr)) => Ok(Some((TransportAddr::Udp(addr), buf[..n].to_vec()))),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(WgError::Io(e)),
        }
    }
}
