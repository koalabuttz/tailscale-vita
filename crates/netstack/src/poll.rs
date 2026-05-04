use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use parking_lot::{Condvar, Mutex};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use tracing::{info, trace};

use crate::device::WgDevice;
use crate::StackInner;

const MAX_SLEEP: Duration = Duration::from_millis(250);

pub fn run(inner: Arc<StackInner>, mut device: WgDevice) {
    info!("netstack poll loop starting");

    while !inner.shutdown.load(Ordering::Relaxed) {
        let result = {
            let mut iface = inner.iface.lock();
            let mut sockets = inner.sockets.lock();
            iface.poll(SmolInstant::from(StdInstant::now()), &mut device, &mut *sockets)
        };
        if matches!(result, smoltcp::iface::PollResult::SocketStateChanged) {
            trace!("netstack iface.poll: socket state changed");
        }

        notify_handles(&inner);

        let delay = {
            let mut iface = inner.iface.lock();
            let sockets = inner.sockets.lock();
            iface
                .poll_delay(SmolInstant::from(StdInstant::now()), &sockets)
                .map(|d| Duration::from_micros(d.total_micros() as u64))
                .unwrap_or(MAX_SLEEP)
                .min(MAX_SLEEP)
        };

        let (lock, cv) = &*inner.wake;
        let mut woke = lock.lock();
        if !*woke {
            let _ = cv.wait_for(&mut woke, delay);
        }
        *woke = false;
    }

    info!("netstack poll loop exiting");
}

fn notify_handles(inner: &StackInner) {
    let snapshot = inner.handles.snapshot();
    if snapshot.is_empty() {
        return;
    }
    let mut sockets = inner.sockets.lock();
    for (handle, slot) in snapshot {
        let (can_recv, can_send, established, active) = tcp_state(&mut sockets, handle);
        let mut last = slot.last_state.lock();
        let changed = can_recv != last.can_recv
            || can_send != last.can_send
            || established != last.established
            || active != last.active;
        if changed {
            let mut ev = slot.event.lock();
            ev.merge_from(can_recv, can_send, established, active);
            slot.cv.notify_all();
        }
        last.can_recv = can_recv;
        last.can_send = can_send;
        last.established = established;
        last.active = active;
    }
}

fn tcp_state(
    sockets: &mut SocketSet<'static>,
    handle: SocketHandle,
) -> (bool, bool, bool, bool) {
    use smoltcp::socket::Socket;
    let sock = match sockets.iter_mut().find(|(h, _)| *h == handle).map(|(_, s)| s) {
        Some(s) => s,
        None => return (false, false, false, false),
    };
    if let Socket::Tcp(s) = sock {
        let can_recv = s.can_recv() || s.recv_queue() > 0;
        let can_send = s.can_send();
        let established = matches!(s.state(), tcp::State::Established);
        let active = s.is_active();
        (can_recv, can_send, established, active)
    } else {
        (false, false, false, false)
    }
}

pub fn poke(wake: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, cv) = &**wake;
    *lock.lock() = true;
    cv.notify_all();
}
