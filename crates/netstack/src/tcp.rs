use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use tracing::{debug, trace};

use crate::buf::{make_tcp_buffers, DEFAULT_TCP_RX_BUF, DEFAULT_TCP_TX_BUF};
use crate::handle::HandleSlot;
use crate::poll::poke;
use crate::{Stack, StackInner};

/// Atomic counter for ephemeral local-port allocation. Starts at 49152
/// (the IANA-recommended ephemeral floor) and wraps to 49152 at 65535.
static NEXT_EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(49152);

fn alloc_local_port() -> u16 {
    let p = NEXT_EPHEMERAL_PORT.fetch_add(1, Ordering::Relaxed);
    if p < 49152 {
        // wrapped; reset
        NEXT_EPHEMERAL_PORT.store(49152, Ordering::Relaxed);
    }
    p.max(49152)
}

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RW_TIMEOUT: Duration = Duration::from_secs(30);

pub struct TcpStream {
    inner: Arc<StackInner>,
    handle: SocketHandle,
    slot: Arc<HandleSlot>,
    peer: SocketAddr,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    closed: bool,
}

impl TcpStream {
    pub fn connect<A: Into<SocketAddr>>(stack: &Stack, addr: A) -> io::Result<TcpStream> {
        let inner = stack.inner();
        let peer: SocketAddr = addr.into();
        let local_port = alloc_local_port();

        let (rx_buf, tx_buf) = make_tcp_buffers(DEFAULT_TCP_RX_BUF, DEFAULT_TCP_TX_BUF);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(60)));

        let handle = {
            let mut iface = inner.iface.lock();
            let mut sockets = inner.sockets.lock();
            let h = sockets.add(socket);
            let s = sockets.get_mut::<tcp::Socket>(h);
            let remote = ip_endpoint(peer)?;
            s.connect(iface.context(), remote, local_port)
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("smoltcp connect: {e:?}")))?;
            h
        };

        let slot = inner.handles.register(handle);
        poke(&inner.wake);

        debug!(remote = %peer, local_port, ?handle, "tcp.connect");

        let deadline = Instant::now() + DEFAULT_CONNECT_TIMEOUT;
        loop {
            let (established, closed) = {
                let mut sockets = inner.sockets.lock();
                let s = sockets.get_mut::<tcp::Socket>(handle);
                let est = matches!(s.state(), tcp::State::Established);
                let closed = matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait);
                (est, closed)
            };
            if established {
                debug!(remote = %peer, ?handle, "tcp.connect.established");
                return Ok(TcpStream {
                    inner,
                    handle,
                    slot,
                    peer,
                    read_timeout: Some(DEFAULT_RW_TIMEOUT),
                    write_timeout: Some(DEFAULT_RW_TIMEOUT),
                    closed: false,
                });
            }
            if closed {
                inner.handles.unregister(handle);
                inner.sockets.lock().remove(handle);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "smoltcp socket closed during connect",
                ));
            }
            if Instant::now() >= deadline {
                inner.handles.unregister(handle);
                inner.sockets.lock().remove(handle);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
            }
            slot.wait_until(deadline.min(Instant::now() + Duration::from_millis(200)), |ev| {
                ev.became_established || ev.closed
            });
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Ok(0);
        }
        let deadline = match self.read_timeout {
            Some(t) => Instant::now() + t,
            None => Instant::now() + Duration::from_secs(86400),
        };
        loop {
            let (n_or_state, did_eof) = {
                let mut sockets = self.inner.sockets.lock();
                let s = sockets.get_mut::<tcp::Socket>(self.handle);
                if s.recv_queue() > 0 {
                    let n = s
                        .recv_slice(buf)
                        .map_err(|e| io::Error::other(format!("smoltcp recv: {e:?}")))?;
                    (Some(n), false)
                } else if !s.may_recv() {
                    (Some(0), true)
                } else {
                    (None, false)
                }
            };
            if let Some(n) = n_or_state {
                if did_eof {
                    self.closed = true;
                }
                if n > 0 || did_eof {
                    trace!(?self.handle, n, "tcp.read");
                    return Ok(n);
                }
                // n == 0 but not eof — shouldn't happen, but loop.
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "read timed out"));
            }
            self.slot
                .wait_until(deadline.min(Instant::now() + Duration::from_millis(200)), |ev| {
                    ev.readable || ev.closed
                });
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
        }
        let deadline = match self.write_timeout {
            Some(t) => Instant::now() + t,
            None => Instant::now() + Duration::from_secs(86400),
        };
        loop {
            let (n_or_state, broken) = {
                let mut sockets = self.inner.sockets.lock();
                let s = sockets.get_mut::<tcp::Socket>(self.handle);
                if !s.may_send() {
                    (Some(0), true)
                } else if s.can_send() {
                    let n = s
                        .send_slice(buf)
                        .map_err(|e| io::Error::other(format!("smoltcp send: {e:?}")))?;
                    (Some(n), false)
                } else {
                    (None, false)
                }
            };
            poke(&self.inner.wake);
            if let Some(n) = n_or_state {
                if broken {
                    self.closed = true;
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "send half closed"));
                }
                if n > 0 {
                    trace!(?self.handle, n, "tcp.write");
                    return Ok(n);
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "write timed out"));
            }
            self.slot
                .wait_until(deadline.min(Instant::now() + Duration::from_millis(200)), |ev| {
                    ev.writable || ev.closed
                });
        }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        // smoltcp transmits on poll; nothing more to do beyond poking.
        poke(&self.inner.wake);
        Ok(())
    }

    pub fn shutdown(&mut self, _how: std::net::Shutdown) -> io::Result<()> {
        let mut sockets = self.inner.sockets.lock();
        let s = sockets.get_mut::<tcp::Socket>(self.handle);
        s.close();
        drop(sockets);
        poke(&self.inner.wake);
        self.closed = true;
        Ok(())
    }

    pub fn set_read_timeout(&mut self, t: Option<Duration>) -> io::Result<()> {
        self.read_timeout = t;
        Ok(())
    }

    pub fn set_write_timeout(&mut self, t: Option<Duration>) -> io::Result<()> {
        self.write_timeout = t;
        Ok(())
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.shutdown(std::net::Shutdown::Both);
        }
        self.inner.handles.unregister(self.handle);
        // Remove from SocketSet.
        let mut sockets = self.inner.sockets.lock();
        let _ = sockets.remove(self.handle);
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TcpStream::read(self, buf)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TcpStream::write(self, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        TcpStream::flush(self)
    }
}

fn ip_endpoint(addr: SocketAddr) -> io::Result<IpEndpoint> {
    use smoltcp::wire::{IpAddress, Ipv4Address};
    match addr {
        SocketAddr::V4(v4) => {
            let oct = v4.ip().octets();
            Ok(IpEndpoint::new(
                IpAddress::Ipv4(Ipv4Address::new(oct[0], oct[1], oct[2], oct[3])),
                v4.port(),
            ))
        }
        SocketAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "v1 netstack is IPv4-only",
        )),
    }
}
