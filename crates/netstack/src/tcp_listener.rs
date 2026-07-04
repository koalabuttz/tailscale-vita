//! In-tunnel TCP listener (M10).
//!
//! smoltcp 0.12 doesn't have an accept backlog — each `tcp::Socket`
//! handles one connection at a time. To support concurrent inbound
//! connections, we pre-allocate a pool of N sockets, all `listen()`-ing
//! on the same `port` (via `IpListenEndpoint { addr: None, port }` so
//! smoltcp accepts on any of our local IPv4 addresses).
//!
//! When a peer SYN arrives, exactly one pool socket transitions
//! `Listen → SynReceived → Established`. `accept_timeout` walks the
//! pool, finds the Established socket, hands it off as a `TcpStream`,
//! and immediately allocates a fresh socket in its place so the pool
//! stays at full capacity.
//!
//! Wakeup signal: rather than wiring listener-pool awareness into
//! `notify_handles`, the listener polls the pool with a short
//! `accept_poll_period` (50 ms by default). For the M10 demo's HTTP
//! server use case, 50 ms accept latency is invisible against the
//! 80–500 ms DERP-relayed network RTT. If hot-path latency ever
//! matters, a per-pool Condvar can be added; for now, the simpler
//! polling approach wins on code-volume grounds.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpListenEndpoint};
use vita_log::{debug, info, warn};

use crate::buf::{make_tcp_buffers, DEFAULT_TCP_RX_BUF, DEFAULT_TCP_TX_BUF};
use crate::handle::HandleSlot;
use crate::poll::poke;
use crate::tcp::TcpStream;
use crate::{Stack, StackHandle, StackInner};

/// How long `accept_timeout` sleeps between polls of the socket pool.
/// 50 ms keeps accept latency invisible against DERP-relayed RTT.
const ACCEPT_POLL_PERIOD: Duration = Duration::from_millis(50);

/// Default pool size per PLAN-V1 §M10.
pub const DEFAULT_LISTENER_POOL: usize = 4;

pub struct TcpListener {
    inner: Arc<StackInner>,
    /// Pre-allocated pool. Each entry is one socket sitting in
    /// `Listen` state on `port`. When one transitions to `Established`,
    /// `accept` claims it and re-allocates a fresh slot.
    pool: vita_sync::Mutex<Vec<(SocketHandle, Arc<HandleSlot>)>>,
    port: u16,
}

impl TcpListener {
    /// Bind a TCP listener on `port` of all local addresses (i.e.,
    /// `IpListenEndpoint { addr: None, port }`). `pool_size` controls
    /// how many concurrent half-open / accept-pending connections the
    /// listener can hold; the (pool_size+1)th SYN gets RST'd and the
    /// client retries.
    pub fn bind(stack: &Stack, port: u16, pool_size: usize) -> io::Result<Self> {
        Self::bind_inner(stack.inner(), port, pool_size)
    }

    /// Like [`bind`](Self::bind), but from a [`StackHandle`] — usable on a
    /// thread that doesn't own the `Stack`. ts-ftp uses this to bind a
    /// fresh PASV data-channel listener mid-session, on its own thread.
    pub fn bind_handle(handle: &StackHandle, port: u16, pool_size: usize) -> io::Result<Self> {
        Self::bind_inner(Arc::clone(&handle.inner), port, pool_size)
    }

    fn bind_inner(inner: Arc<StackInner>, port: u16, pool_size: usize) -> io::Result<Self> {
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TcpListener::bind: port must be non-zero",
            ));
        }
        let pool_size = pool_size.max(1);

        let mut pool = Vec::with_capacity(pool_size);
        {
            let mut sockets = inner.sockets.lock();
            for _ in 0..pool_size {
                let (handle, slot) = alloc_listening_socket(&inner, &mut sockets, port)?;
                pool.push((handle, slot));
            }
        }
        // Wake the poll thread so smoltcp picks up the freshly-listening
        // sockets immediately.
        poke(&inner.wake);

        info!(port, pool_size, "netstack.tcp_listener.bound");
        Ok(Self {
            inner,
            pool: vita_sync::Mutex::new(pool),
            port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Accept one connection, blocking forever.
    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        // 1 day == "forever" for our purposes; the real loop just polls
        // until a connection arrives.
        self.accept_timeout(Duration::from_secs(86400))
    }

    /// Block up to `timeout` for the next inbound connection. Returns
    /// `Err(io::ErrorKind::TimedOut)` if no connection arrived in time.
    pub fn accept_timeout(&self, timeout: Duration) -> io::Result<(TcpStream, SocketAddr)> {
        let deadline = Instant::now() + timeout;
        loop {
            // Walk the pool looking for a slot in Established state.
            // We scan all entries each iteration so the order doesn't
            // matter (no preference for "earlier" slots).
            if let Some((stream, peer)) = self.try_claim_established()? {
                return Ok((stream, peer));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "accept timed out"));
            }
            let park = (deadline - now).min(ACCEPT_POLL_PERIOD);
            std::thread::sleep(park);
        }
    }

    /// One pass over the pool. Reaps dead slots (churn self-heal) and, if a
    /// slot is Established, claims it. Returns Ok(Some(...)) on a successful
    /// claim; Ok(None) if no slot is ready yet; Err on internal failure.
    ///
    /// **Reaper (BUG B fix, 2026-07-03):** a pool socket that leaves `Listen`
    /// without being claimed-while-`Established` — a client that connects then
    /// bails (→ `Closed`/`CloseWait`), or a connection that Established and
    /// closed inside the ≤120 s window a serial session holds the accept
    /// thread — was previously never re-armed. After `pool_size` such events
    /// the pool held zero `Listen` sockets and smoltcp RST'd every inbound SYN
    /// → port went dead with "Connection refused" while the accept thread was
    /// still alive (observed under an external client's rapid-reconnect probe).
    /// Each poll we now overwrite any dead slot in place with a fresh `Listen`
    /// socket, so capacity self-heals. `SynReceived` (handshake in flight) and
    /// `Established` (claimable) are left alone.
    fn try_claim_established(&self) -> io::Result<Option<(TcpStream, SocketAddr)>> {
        // Hold the pool lock across the SocketSet lock; we replace the
        // claimed entry with a fresh listener before releasing pool.
        let mut pool = self.pool.lock();

        // Heal any dead slots first (churn self-heal), so the scan below sees
        // a pool that's all Listen/Established/SynReceived. Done as its own
        // pass so a (near-impossible) re-listen failure can drop a slot
        // cleanly without ever leaving a removed handle in the pool for the
        // next `get_mut` to panic on.
        self.heal_pool(&mut pool);

        let mut found_idx: Option<(usize, SocketAddr)> = None;
        {
            let mut sockets = self.inner.sockets.lock();
            for (i, (handle, _slot)) in pool.iter().enumerate() {
                let s = sockets.get_mut::<tcp::Socket>(*handle);
                if matches!(s.state(), tcp::State::Established) {
                    let peer = match s.remote_endpoint() {
                        Some(ep) => match ip_endpoint_to_std(ep) {
                            Some(addr) => addr,
                            None => {
                                warn!("netstack.accept.skip_non_ipv4_peer");
                                continue;
                            }
                        },
                        None => {
                            warn!("netstack.accept.no_remote_endpoint");
                            continue;
                        }
                    };
                    found_idx = Some((i, peer));
                    break;
                }
            }
        }

        let (idx, peer) = match found_idx {
            Some(x) => x,
            None => return Ok(None),
        };

        // Claim the slot and replace it with a fresh listener.
        let (claimed_handle, claimed_slot) = pool.swap_remove(idx);
        let (new_handle, new_slot) = {
            let mut sockets = self.inner.sockets.lock();
            alloc_listening_socket(&self.inner, &mut sockets, self.port)?
        };
        pool.push((new_handle, new_slot));
        drop(pool);
        poke(&self.inner.wake);

        debug!(
            ?claimed_handle,
            ?new_handle,
            %peer,
            "netstack.tcp_listener.accept"
        );
        let stream = TcpStream::from_listener_handle(
            Arc::clone(&self.inner),
            claimed_handle,
            claimed_slot,
            peer,
        );
        Ok(Some((stream, peer)))
    }

    /// Re-arm dead pool slots so the listener never runs out of `Listen`
    /// sockets under connection churn (BUG B, 2026-07-03 — see
    /// [`try_claim_established`]). A slot whose socket is neither `Listen`
    /// (ready), `Established` (claimable), nor `SynReceived` (handshake in
    /// flight) is dead — a peer connected and left, or half-opened and died,
    /// without the serial accept loop claiming it. smoltcp never returns such
    /// a socket to `Listen` on its own, so we drop it and allocate a fresh
    /// `Listen` socket in its place. Runs every accept poll; a no-op when the
    /// pool is healthy. Caller holds the pool lock.
    fn heal_pool(&self, pool: &mut Vec<(SocketHandle, Arc<HandleSlot>)>) {
        let mut reaped = 0usize;
        {
            let mut sockets = self.inner.sockets.lock();
            let mut i = 0;
            while i < pool.len() {
                let handle = pool[i].0; // SocketHandle: Copy; don't move the Arc slot
                let alive = matches!(
                    sockets.get_mut::<tcp::Socket>(handle).state(),
                    tcp::State::Listen | tcp::State::Established | tcp::State::SynReceived
                );
                if alive {
                    i += 1;
                    continue;
                }
                // Dead slot: drop it and try to re-listen in place.
                self.inner.handles.unregister(handle);
                let _ = sockets.remove(handle);
                match alloc_listening_socket(&self.inner, &mut sockets, self.port) {
                    Ok(fresh) => {
                        pool[i] = fresh;
                        i += 1;
                    }
                    Err(e) => {
                        // Re-listen failed (near-impossible for a valid port).
                        // Drop the slot rather than keep a removed handle the
                        // next scan would `get_mut`-panic on; `swap_remove`
                        // pulls the tail in, so re-check the same index.
                        warn!(error = %e, "netstack.tcp_listener.relisten_failed");
                        pool.swap_remove(i);
                    }
                }
                reaped += 1;
            }
        }
        if reaped > 0 {
            poke(&self.inner.wake);
            debug!(reaped, live = pool.len(), port = self.port, "netstack.tcp_listener.healed");
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let entries = std::mem::take(&mut *self.pool.lock());
        let mut sockets = self.inner.sockets.lock();
        for (handle, _slot) in entries {
            self.inner.handles.unregister(handle);
            sockets.remove(handle);
        }
        info!(port = self.port, "netstack.tcp_listener.dropped");
    }
}

/// Allocate one fresh `tcp::Socket` in `Listen` state for the given
/// port, register its handle, and return both. Caller holds the
/// SocketSet lock.
fn alloc_listening_socket(
    inner: &Arc<StackInner>,
    sockets: &mut smoltcp::iface::SocketSet<'static>,
    port: u16,
) -> io::Result<(SocketHandle, Arc<HandleSlot>)> {
    let (rx, tx) = make_tcp_buffers(DEFAULT_TCP_RX_BUF, DEFAULT_TCP_TX_BUF);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(60)));
    socket
        .listen(IpListenEndpoint { addr: None, port })
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("smoltcp listen: {e:?}")))?;
    let handle = sockets.add(socket);
    let slot = inner.handles.register(handle);
    Ok((handle, slot))
}

fn ip_endpoint_to_std(ep: smoltcp::wire::IpEndpoint) -> Option<SocketAddr> {
    let IpAddress::Ipv4(v4) = ep.addr;
    let oct = v4.octets();
    Some(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(oct[0], oct[1], oct[2], oct[3]),
        ep.port,
    )))
}

// No host-side unit tests: bind/accept require a live Stack +
// EngineRunning which can't be constructed without a real WG transport.
// Real verification lives in the M10 Tier-A hardware run + the
// `curl http://100.64.0.1:8080/` Tier-B test.
