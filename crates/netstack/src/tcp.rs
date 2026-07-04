use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use vita_log::{debug, trace};

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

/// Max time `Drop` waits for the smoltcp socket to drain its TX queue
/// and complete the FIN handshake before tearing the socket down.
/// Without this wait, large responses get truncated mid-flight — the
/// SocketSet removal severs the buffer before the poll thread can
/// emit the queued bytes.
///
/// Bound chosen for tailnet RTTs (~300 ms typical, up to ~1 s on
/// cross-country DERP-relayed paths) + small safety margin. A silent
/// peer that never ACKs our FIN still wakes the dropping caller in
/// at most this duration.
const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// Poll interval when waiting on smoltcp state transitions in Drop.
/// We can't subscribe to "reached FinWait2" — only `is_active()`
/// transitions emit slot events, and FinWait2 is still active. So
/// poll the socket state at this cadence as a fallback.
const CLOSE_POLL_INTERVAL: Duration = Duration::from_millis(50);

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

    /// Bytes queued in the TX buffer that smoltcp has not yet handed to the
    /// device *and* had ACK'd (i.e. still in flight or unsent). `0` means the
    /// peer has acknowledged everything we wrote. Used to diagnose a transfer
    /// that reports success but delivered nothing (2026-07-03 ts-ftp probe).
    pub fn send_queue(&self) -> usize {
        let mut sockets = self.inner.sockets.lock();
        sockets.get_mut::<tcp::Socket>(self.handle).send_queue()
    }

    /// Construct a `TcpStream` wrapping a socket handle that has just
    /// transitioned to Established via the listener accept path. The
    /// caller (TcpListener) is responsible for ensuring the handle is
    /// freshly Established and the slot's HandleSlot is registered.
    pub(crate) fn from_listener_handle(
        inner: Arc<StackInner>,
        handle: SocketHandle,
        slot: Arc<HandleSlot>,
        peer: SocketAddr,
    ) -> Self {
        TcpStream {
            inner,
            handle,
            slot,
            peer,
            read_timeout: Some(DEFAULT_RW_TIMEOUT),
            write_timeout: Some(DEFAULT_RW_TIMEOUT),
            closed: false,
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // Step 1: initiate close if the caller hasn't already.
        // `shutdown(Both)` calls smoltcp's `tcp::Socket::close()`,
        // which transitions state Established → FinWait1 and queues
        // a FIN to be sent after the TX buffer drains.
        if !self.closed {
            let _ = self.shutdown(std::net::Shutdown::Both);
        }

        // Step 2: wait (bounded) for the close to make progress on
        // the wire. Without this, the SocketSet removal below would
        // discard the smoltcp socket while it still has unsent bytes
        // — observed truncating ~800 bytes off an 11 KB tailnet
        // response in the M14 LocalAPI proxy.
        //
        // We're done waiting when state reaches FinWait2 (our FIN was
        // ACK'd, so all queued bytes + the FIN itself made it to the
        // peer) or any later state. Closing/TimeWait/LastAck/Closed
        // are all "our side of the close is complete." If the timeout
        // elapses first we tear down anyway — better to lose the tail
        // of a stuck stream than block the dropping thread forever.
        let drained = wait_for_drain(&self.inner, self.handle, &self.slot);

        self.inner.handles.unregister(self.handle);
        let mut sockets = self.inner.sockets.lock();
        // If the graceful close never completed (peer's window stuck, path
        // lossy, or our FIN/data never got ACK'd within the drain budget),
        // send a RST instead of silently removing the socket. A silent
        // removal leaves the peer's connection open with no data and no FIN
        // — it hangs until its own timeout (the ts-ftp 0-byte-RETR symptom,
        // 2026-07-03). `abort()` queues a RST so the peer gets a hard close
        // and fails fast; we poke so the poll thread emits it before removal.
        if !drained {
            let needs_rst = {
                let s = sockets.get_mut::<tcp::Socket>(self.handle);
                !matches!(s.state(), tcp::State::Closed)
            };
            if needs_rst {
                sockets.get_mut::<tcp::Socket>(self.handle).abort();
                drop(sockets);
                poke(&self.inner.wake);
                trace!(?self.handle, "tcp.drop.abort_rst");
                sockets = self.inner.sockets.lock();
            }
        }
        let _ = sockets.remove(self.handle);
    }
}

/// Block until the socket's TX is drained + FIN handshake complete,
/// or `CLOSE_DRAIN_TIMEOUT` elapses. Pure read-only inspection — no
/// mutation. Safe to call after `close()` has been issued. See
/// `CLOSE_DRAIN_TIMEOUT` doc for the rationale. Returns `true` if the
/// graceful close completed, `false` if the timeout elapsed first (the
/// caller then sends a RST rather than removing the socket silently).
fn wait_for_drain(
    inner: &Arc<StackInner>,
    handle: SocketHandle,
    slot: &Arc<HandleSlot>,
) -> bool {
    let deadline = Instant::now() + CLOSE_DRAIN_TIMEOUT;
    loop {
        let done = {
            let sockets = inner.sockets.lock();
            // The socket may have been removed already (e.g., RST
            // tore it down). Treat absence as "done."
            //
            // SocketSet doesn't expose a `try_get` that returns
            // Option, so we use `iter().find()` which returns an
            // immutable Socket ref — sufficient for state inspection.
            let socket_state = sockets
                .iter()
                .find(|(h, _)| *h == handle)
                .and_then(|(_, sock)| match sock {
                    smoltcp::socket::Socket::Tcp(s) => Some(s.state()),
                    _ => None,
                });
            match socket_state {
                Some(state) => {
                    use tcp::State;
                    matches!(
                        state,
                        State::FinWait2
                            | State::Closing
                            | State::TimeWait
                            | State::LastAck
                            | State::Closed
                    )
                }
                None => true, // socket gone / non-TCP — nothing to wait for
            }
        };
        if done {
            trace!(?handle, "tcp.drop.drain.done");
            return true;
        }
        if Instant::now() >= deadline {
            trace!(?handle, "tcp.drop.drain.timeout");
            return false;
        }
        // The slot's `closed` event fires when `is_active()` flips
        // false (i.e., on TimeWait/Closed). FinWait2 is still active,
        // so we wouldn't get a notify from there — short polling
        // window catches it.
        slot.wait_until(
            deadline.min(Instant::now() + CLOSE_POLL_INTERVAL),
            |ev| ev.closed,
        );
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
