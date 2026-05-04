use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use parking_lot::{Condvar, Mutex};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use tracing::{info, trace};

use crate::device::WgDevice;
use crate::Stack;

/// Maximum wake interval: even if no work is pending, the poll loop wakes
/// every 250 ms to stay responsive to new socket registrations and
/// pending state changes.
const MAX_SLEEP: Duration = Duration::from_millis(250);

pub fn run(stack: Arc<Stack>, mut device: WgDevice) {
    info!("netstack poll loop starting");

    while !stack.shutdown_flag().load(Ordering::Relaxed) {
        // 1. iface.poll. Drains rx from device, ACKs, retransmits, etc.
        let result = {
            let mut iface = stack.iface.lock();
            let mut sockets = stack.sockets.lock();
            iface.poll(SmolInstant::from(StdInstant::now()), &mut device, &mut *sockets)
        };
        if matches!(result, smoltcp::iface::PollResult::SocketStateChanged) {
            trace!("netstack iface.poll: socket state changed");
        }

        // 2. Walk handle registry, edge-detect socket state changes, fire Condvars.
        notify_handles(&stack);

        // 3. Compute next deadline.
        let delay = {
            let mut iface = stack.iface.lock();
            let sockets = stack.sockets.lock();
            iface
                .poll_delay(SmolInstant::from(StdInstant::now()), &sockets)
                .map(|d| Duration::from_micros(d.total_micros() as u64))
                .unwrap_or(MAX_SLEEP)
                .min(MAX_SLEEP)
        };

        // 4. Park on Condvar until something interesting happens.
        let (lock, cv) = &*stack.wake;
        let mut woke = lock.lock();
        if !*woke {
            let _ = cv.wait_for(&mut woke, delay);
        }
        *woke = false;
    }

    info!("netstack poll loop exiting");
}

fn notify_handles(stack: &Stack) {
    let snapshot = stack.handles.snapshot();
    if snapshot.is_empty() {
        return;
    }
    let mut sockets = stack.sockets.lock();
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

/// Convenience: poke the poll loop to do an iteration immediately.
pub fn poke(wake: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, cv) = &**wake;
    *lock.lock() = true;
    cv.notify_all();
}

