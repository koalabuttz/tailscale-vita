//! Spike: confirm `smoltcp` (the userspace TCP/IP stack we plan to use
//! inside the WireGuard tunnel) cross-compiles for `armv7-sony-vita-newlibeabihf`,
//! and that we can implement its `phy::Device` trait to drive packets in
//! and out of an arbitrary transport.
//!
//! Implements an "in-memory" Device whose tx/rx are just two queues, then
//! attaches a smoltcp Interface and a UDP socket and confirms the API
//! shape compiles. Doesn't try to do a real handshake — that's Phase 2.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpCidr, Ipv4Address, Ipv4Cidr};

mod logger;

macro_rules! log {
    ($($arg:tt)*) => { logger::log_line(&format!($($arg)*)) };
}

#[derive(Clone, Default)]
struct InMemoryDevice {
    rx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    mtu: usize,
}

impl InMemoryDevice {
    fn new(mtu: usize) -> Self {
        Self { rx: Default::default(), tx: Default::default(), mtu }
    }

    fn inject_rx(&self, pkt: Vec<u8>) {
        self.rx.lock().unwrap().push_back(pkt);
    }

    fn drain_tx(&self) -> Vec<Vec<u8>> {
        self.tx.lock().unwrap().drain(..).collect()
    }
}

struct RxToken(Vec<u8>);
impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct TxToken {
    tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
}
impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.tx.lock().unwrap().push_back(buf);
        r
    }
}

impl Device for InMemoryDevice {
    type RxToken<'a> = RxToken where Self: 'a;
    type TxToken<'a> = TxToken where Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ip;
        caps
    }

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.lock().unwrap().pop_front()?;
        Some((RxToken(pkt), TxToken { tx: self.tx.clone() }))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken { tx: self.tx.clone() })
    }
}

fn main() {
    logger::init("ux0:/data/spike-4.log");
    log!("smoltcp-compile spike: starting");

    let mut device = InMemoryDevice::new(1280);
    let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::now());

    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(100, 64, 0, 1), 10)))
            .ok();
    });

    let mut sockets = SocketSet::new(vec![]);

    let udp_rx_buffer = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; 8],
        vec![0u8; 4096],
    );
    let udp_tx_buffer = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; 8],
        vec![0u8; 4096],
    );
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);
    let udp_handle = sockets.add(udp_socket);

    {
        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        socket.bind(9999).unwrap();
        log!("smoltcp UDP socket bound to :9999");
    }

    iface.poll(Instant::now(), &mut device, &mut sockets);

    let drained = device.drain_tx();
    log!(
        "smoltcp init OK: stack polled, {} tx packets queued",
        drained.len()
    );

    device.inject_rx(vec![0x45, 0x00, 0x00, 0x14]);
    iface.poll(Instant::now(), &mut device, &mut sockets);
    log!("smoltcp poll after rx inject: OK (packet was malformed; expected drop)");

    log!("smoltcp-compile spike: done; sleeping 5s");
    thread::sleep(Duration::from_secs(5));
}
