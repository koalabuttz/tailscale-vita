//! In-tunnel `std::net`-shaped networking on top of smoltcp + wg-engine.
//!
//! `Stack::start` spawns the app-thread poll loop driving smoltcp's
//! `Interface` against `WgDevice` (which bridges to wg-engine's plaintext
//! IPv4 queues). Caller code uses `tcp::TcpStream::connect` etc. against
//! peer addresses inside the WireGuard tunnel.
//!
//! M3 ships TcpStream only. TcpListener and UdpSocket land in M9 / M10.
//!
//! ## Why `Stack` wraps `Arc<StackInner>` instead of being directly Arc-shared
//!
//! Earlier `Stack::start` returned `Arc<Stack>` and the poll thread captured
//! a clone. That created a cycle: as long as the poll thread is alive, the
//! Arc refcount on `Stack` is ≥ 2, so dropping the user-visible handle
//! never triggers `Stack::Drop` — meaning the poll thread runs forever
//! until process exit, where pthread teardown blows up on freed TLS in
//! `pte_pop_cleanup -> pthread_getspecific`. The fix is to share only
//! `Arc<StackInner>` (which has no thread join semantics); `Stack` itself
//! is a non-Arc owner whose Drop joins the poll thread synchronously.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use vita_thread::JoinHandle;
use std::time::Instant as StdInstant;

use vita_sync::{Condvar, Mutex};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Cidr};
use vita_log::info;

mod buf;
mod device;
mod error;
mod handle;
mod poll;
pub mod tcp;
pub mod tcp_listener;

pub use error::NetstackError;
pub use smoltcp::wire::Ipv4Cidr as Ipv4CidrRe;
pub use tcp_listener::{TcpListener, DEFAULT_LISTENER_POOL};

use crate::device::WgDevice;
use crate::handle::HandleRegistry;

#[derive(Clone, Default)]
pub struct StackConfig {
    /// `None` = no IPs set at construction; smoltcp will drop all
    /// inbound packets until `Stack::set_local_addrs` is called. M9's
    /// demo uses this — our tailnet IP only arrives in the first
    /// `MapResponse`, so the netstack starts empty and gets populated
    /// after register+map.
    pub local_ip: Option<Ipv4Cidr>,
    pub mtu: usize,
}

impl StackConfig {
    pub fn new() -> Self {
        Self {
            local_ip: None,
            mtu: 1280,
        }
    }

    pub fn with_local_ip(local_ip: Ipv4Cidr) -> Self {
        Self {
            local_ip: Some(local_ip),
            mtu: 1280,
        }
    }
}

/// Shared state — the parts that the poll thread and TcpStreams both touch.
/// No thread/teardown semantics here, so it's safe to share via `Arc` without
/// creating ownership cycles.
pub struct StackInner {
    pub(crate) iface: Mutex<Interface>,
    pub(crate) sockets: Mutex<SocketSet<'static>>,
    pub(crate) handles: Arc<HandleRegistry>,
    pub(crate) wake: Arc<(Mutex<bool>, Condvar)>,
    pub(crate) shutdown: Arc<AtomicBool>,
}

/// Owner of the netstack. **Not** `Arc`-shareable — there's exactly one
/// `Stack` per process, and dropping it joins the poll thread + the
/// underlying wg-engine. Per-socket types hold `Arc<StackInner>` to access
/// the shared state.
pub struct Stack {
    inner: Arc<StackInner>,
    poll_join: Option<JoinHandle>,
    /// Holds the wg-engine alive for the lifetime of the Stack.
    _engine: Option<wg_engine::EngineRunning>,
}

/// A `Send + Clone` handle to a running [`Stack`], for creating sockets
/// (`TcpListener::bind_handle`, `TcpStream::connect_handle`) from threads
/// that do **not** own the `Stack`. `Stack` itself isn't shareable, but an
/// in-process service (e.g. ts-ftp binding PASV data listeners on its own
/// thread) needs to create sockets where the `Stack` lives elsewhere.
///
/// Holds an `Arc<StackInner>`, so it keeps the shared netstack state alive
/// but does NOT keep the poll thread running — that ends with the `Stack`.
/// Creating sockets after the `Stack` is dropped yields sockets that never
/// get polled; services should stop before the runtime tears down (the
/// LocalAPI/ts-ftp `Drop`-then-join lifecycle ensures this).
#[derive(Clone)]
pub struct StackHandle {
    pub(crate) inner: Arc<StackInner>,
}

impl Stack {
    pub fn start(
        cfg: StackConfig,
        engine: wg_engine::EngineRunning,
    ) -> Result<Stack, NetstackError> {
        let mut device = WgDevice::new(
            Arc::clone(&engine.tun_rx),
            Arc::clone(&engine.tun_tx),
            cfg.mtu,
        );

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::from(StdInstant::now()));
        if let Some(local_ip) = cfg.local_ip {
            iface.update_ip_addrs(|store| {
                let _ = store.push(IpCidr::Ipv4(local_ip));
            });
        }

        let inner = Arc::new(StackInner {
            iface: Mutex::new(iface),
            sockets: Mutex::new(SocketSet::new(Vec::new())),
            handles: Arc::new(HandleRegistry::new()),
            wake: Arc::clone(&engine.rx_notify),
            shutdown: Arc::new(AtomicBool::new(false)),
        });

        let inner_for_thread = Arc::clone(&inner);
        let join = vita_thread::Builder::new()
            .name("netstack-poll")
            .stack_size(256 * 1024)
            .spawn(move || poll::run(inner_for_thread, device))
            .map_err(NetstackError::Io)?;

        info!(local_ip = ?cfg.local_ip, "netstack started");

        Ok(Stack {
            inner,
            poll_join: Some(join),
            _engine: Some(engine),
        })
    }

    /// Internal handle to the shared state. Cloned into per-socket types.
    pub(crate) fn inner(&self) -> Arc<StackInner> {
        Arc::clone(&self.inner)
    }

    /// A `Send + Clone` [`StackHandle`] for creating sockets from threads
    /// that don't own this `Stack`. See [`StackHandle`].
    pub fn handle(&self) -> StackHandle {
        StackHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Replace the iface's IPv4 address list. Called by the demo from
    /// each `MapResponse.Node.Addresses` (M7 surfaces this as
    /// `NetMapSnapshot.our_addrs`).
    ///
    /// Why M9 needs this: smoltcp's `iface.poll` only **accepts**
    /// inbound packets whose destination address is in `iface.ip_addrs`.
    /// Without our tailnet IP (100.64.0.x) registered, smoltcp drops
    /// pings before its `process_icmpv4` can auto-reply.
    ///
    /// smoltcp 0.12's `process_icmpv4` does the actual ICMP echo-reply
    /// synthesis (we verified in source: `iface/interface/ipv4.rs`
    /// lines 337–351). No explicit ICMP socket needed.
    pub fn set_local_addrs(&self, addrs: Vec<Ipv4Cidr>) {
        let mut iface = self.inner.iface.lock();
        iface.update_ip_addrs(|store| {
            store.clear();
            for cidr in &addrs {
                let _ = store.push(IpCidr::Ipv4(*cidr));
            }
        });
        drop(iface);
        info!(?addrs, "netstack.local_addrs.set");
        crate::poll::poke(&self.inner.wake);
    }

    pub fn shutdown(&mut self) {
        self.inner.shutdown.store(true, Ordering::Relaxed);
        crate::poll::poke(&self.inner.wake);
        if let Some(j) = self.poll_join.take() {
            let _ = j.join();
        }
        // Drop the engine explicitly so its pump-thread join happens here
        // (with the netstack-poll thread already gone), not later in field
        // drop order interleaved with other Arc decrements.
        let _ = self._engine.take();
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.shutdown();
    }
}
