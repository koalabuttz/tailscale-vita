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
use std::thread::JoinHandle;
use std::time::Instant as StdInstant;

use parking_lot::{Condvar, Mutex};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Cidr};
use tracing::info;

mod buf;
mod device;
mod error;
mod handle;
mod poll;
pub mod tcp;

pub use error::NetstackError;
pub use smoltcp::wire::Ipv4Cidr as Ipv4CidrRe;

use crate::device::WgDevice;
use crate::handle::HandleRegistry;

#[derive(Clone)]
pub struct StackConfig {
    pub local_ip: Ipv4Cidr,
    pub mtu: usize,
}

impl StackConfig {
    pub fn new(local_ip: Ipv4Cidr) -> Self {
        Self {
            local_ip,
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
    poll_join: Option<JoinHandle<()>>,
    /// Holds the wg-engine alive for the lifetime of the Stack.
    _engine: Option<wg_engine::EngineRunning>,
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
        iface.update_ip_addrs(|store| {
            let _ = store.push(IpCidr::Ipv4(cfg.local_ip));
        });

        let inner = Arc::new(StackInner {
            iface: Mutex::new(iface),
            sockets: Mutex::new(SocketSet::new(Vec::new())),
            handles: Arc::new(HandleRegistry::new()),
            wake: Arc::clone(&engine.rx_notify),
            shutdown: Arc::new(AtomicBool::new(false)),
        });

        let inner_for_thread = Arc::clone(&inner);
        let join = std::thread::Builder::new()
            .name("netstack-poll".into())
            .stack_size(256 * 1024)
            .spawn(move || poll::run(inner_for_thread, device))
            .map_err(NetstackError::Io)?;

        info!(local_ip = %cfg.local_ip, "netstack started");

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
