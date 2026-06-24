use std::collections::VecDeque;
use std::sync::Arc;

use vita_sync::Mutex;
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use vita_log::trace;

/// smoltcp `phy::Device` implementation that bridges to wg-engine's
/// tun_rx / tun_tx queues. Both directions use **try_lock** so the app
/// thread (smoltcp poll loop) never blocks waiting on the wg_engine
/// thread holding the same `Arc<Mutex<VecDeque>>`.
///
/// On try_lock contention, `receive` returns `None` (smoltcp polls again
/// next tick) and `TxToken::consume` silently drops the packet (smoltcp
/// retransmits via TCP machinery).
pub struct WgDevice {
    rx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    mtu: usize,
}

impl WgDevice {
    pub fn new(
        rx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        mtu: usize,
    ) -> Self {
        Self { rx, tx, mtu }
    }
}

pub struct WgRxToken {
    buf: Vec<u8>,
}

impl phy::RxToken for WgRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf)
    }
}

pub struct WgTxToken<'a> {
    tx: &'a Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl<'a> phy::TxToken for WgTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        match self.tx.try_lock() {
            Some(mut q) => q.push_back(buf),
            None => trace!(n = len, "WgDevice tx try_lock contention; dropped"),
        }
        r
    }
}

impl Device for WgDevice {
    type RxToken<'a>
        = WgRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = WgTxToken<'a>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c.max_burst_size = Some(1);
        c
    }

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut rx = self.rx.try_lock()?;
        let pkt = rx.pop_front()?;
        Some((WgRxToken { buf: pkt }, WgTxToken { tx: &self.tx }))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken { tx: &self.tx })
    }
}
