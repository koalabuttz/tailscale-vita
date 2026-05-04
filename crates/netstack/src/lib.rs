//! In-tunnel `std::net`-shaped networking on top of smoltcp + wg-engine.
//!
//! `Stack::start` spawns the app-thread poll loop driving smoltcp's
//! `Interface` against `WgDevice` (which bridges to wg-engine's plaintext
//! IPv4 queues). Caller code uses `tcp::TcpStream::connect` etc. against
//! peer addresses inside the WireGuard tunnel.
//!
//! M3 ships TcpStream only. TcpListener and UdpSocket land in M9 / M10.

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
    /// Our tunnel-side IPv4 prefix. Hardcoded in M3; set from
    /// MapResponse.Node.Addresses in M7.
    pub local_ip: Ipv4Cidr,
    /// In-tunnel MTU. v1 default 1280.
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

pub struct Stack {
    pub(crate) iface: Mutex<Interface>,
    pub(crate) sockets: Mutex<SocketSet<'static>>,
    pub(crate) handles: Arc<HandleRegistry>,
    pub(crate) wake: Arc<(Mutex<bool>, Condvar)>,
    shutdown: Arc<AtomicBool>,
    poll_join: Mutex<Option<JoinHandle<()>>>,
    /// Hold the wg-engine alive for the lifetime of the Stack. Dropped
    /// after the poll thread joins (Drop runs fields in declaration order).
    _engine: Mutex<Option<wg_engine::EngineRunning>>,
}

impl Stack {
    pub fn start(
        cfg: StackConfig,
        engine: wg_engine::EngineRunning,
    ) -> Result<Arc<Stack>, NetstackError> {
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

        let handles = Arc::new(HandleRegistry::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let wake = Arc::clone(&engine.rx_notify);

        let stack: Arc<Stack> = Arc::new(Stack {
            iface: Mutex::new(iface),
            sockets: Mutex::new(SocketSet::new(Vec::new())),
            handles: Arc::clone(&handles),
            wake: Arc::clone(&wake),
            shutdown: Arc::clone(&shutdown),
            poll_join: Mutex::new(None),
            _engine: Mutex::new(Some(engine)),
        });

        let stack_for_thread = Arc::clone(&stack);
        let join = std::thread::Builder::new()
            .name("netstack-poll".into())
            .stack_size(256 * 1024)
            .spawn(move || poll::run(stack_for_thread, device))
            .map_err(NetstackError::Io)?;

        *stack.poll_join.lock() = Some(join);

        info!(local_ip = %cfg.local_ip, "netstack started");
        Ok(stack)
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        crate::poll::poke(&self.wake);
        if let Some(j) = self.poll_join.lock().take() {
            let _ = j.join();
        }
    }

    pub(crate) fn shutdown_flag(&self) -> &AtomicBool {
        &self.shutdown
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        crate::poll::poke(&self.wake);
        if let Some(j) = self.poll_join.lock().take() {
            let _ = j.join();
        }
    }
}
