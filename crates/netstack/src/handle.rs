use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::{Condvar, Mutex};
use smoltcp::iface::SocketHandle;

/// Edge-triggered event bitset for one socket. The poll loop sets bits
/// after `iface.poll` based on socket-state deltas; consumers (TcpStream
/// `read`/`write`, TcpListener `accept`, etc.) wait on the Condvar and
/// then read+clear the relevant bit.
#[derive(Debug, Default, Clone, Copy)]
pub struct HandleEvent {
    /// Socket has bytes to recv (or peer FIN means recv() will return Ok(0)).
    pub readable: bool,
    /// Socket can accept more bytes for send.
    pub writable: bool,
    /// Socket is no longer active (FIN'd or RST'd both directions).
    pub closed: bool,
    /// Socket transitioned to Established (used by listener accept).
    pub became_established: bool,
}

impl HandleEvent {
    pub fn merge_from(&mut self, can_recv: bool, can_send: bool, established: bool, active: bool) {
        if can_recv {
            self.readable = true;
        }
        if can_send {
            self.writable = true;
        }
        if !active {
            self.closed = true;
        }
        if established {
            self.became_established = true;
        }
    }
}

/// One slot in the per-handle registry. The `Condvar` is what blocking
/// callers (`TcpStream::read`, `accept`, etc.) park on.
pub struct HandleSlot {
    pub event: Mutex<HandleEvent>,
    pub cv: Condvar,
    /// Last seen state, for edge detection.
    pub last_state: Mutex<LastState>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LastState {
    pub can_recv: bool,
    pub can_send: bool,
    pub established: bool,
    pub active: bool,
}

impl HandleSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            event: Mutex::new(HandleEvent::default()),
            cv: Condvar::new(),
            last_state: Mutex::new(LastState::default()),
        })
    }

    /// Wait for any of the given conditions, up to `deadline`. Returns the
    /// drained event bits at wakeup (cleared in-place).
    pub fn wait_until<F: Fn(&HandleEvent) -> bool>(
        &self,
        deadline: std::time::Instant,
        cond: F,
    ) -> HandleEvent {
        let mut g = self.event.lock();
        while !cond(&g) && std::time::Instant::now() < deadline {
            let timeout = deadline.saturating_duration_since(std::time::Instant::now());
            let _ = self.cv.wait_for(&mut g, timeout);
        }
        let drained = *g;
        *g = HandleEvent::default();
        drained
    }

    /// Wait forever for the given condition.
    pub fn wait_forever<F: Fn(&HandleEvent) -> bool>(&self, cond: F) -> HandleEvent {
        let mut g = self.event.lock();
        while !cond(&g) {
            self.cv.wait(&mut g);
        }
        let drained = *g;
        *g = HandleEvent::default();
        drained
    }
}

/// Registry of per-handle slots. Owned by the Stack; cloneable Arc handles
/// distributed to TcpStream/TcpListener/UdpSocket.
pub struct HandleRegistry {
    slots: Mutex<HashMap<SocketHandle, Arc<HandleSlot>>>,
}

impl HandleRegistry {
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, handle: SocketHandle) -> Arc<HandleSlot> {
        let slot = HandleSlot::new();
        self.slots.lock().insert(handle, Arc::clone(&slot));
        slot
    }

    pub fn unregister(&self, handle: SocketHandle) {
        self.slots.lock().remove(&handle);
    }

    pub fn snapshot(&self) -> Vec<(SocketHandle, Arc<HandleSlot>)> {
        self.slots
            .lock()
            .iter()
            .map(|(h, s)| (*h, Arc::clone(s)))
            .collect()
    }
}

impl Default for HandleRegistry {
    fn default() -> Self {
        Self::new()
    }
}
