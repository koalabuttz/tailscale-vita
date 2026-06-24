use std::collections::VecDeque;
use std::sync::Arc;

use vita_sync::{Condvar, Mutex};

/// A single-producer-single-consumer-style queue with a Condvar wakeup
/// for the consumer side. Internally a `Mutex<VecDeque<T>>` so multiple
/// pushers/poppers are still safe (it's not actually SPSC, just convenient).
///
/// In M2 this is unused — the wg_engine pump polls on a 50ms recv timeout.
/// In M3+ smoltcp pushes outbound IP packets here, and the wg_engine wakes
/// on the Condvar to drain them promptly instead of waiting for the next
/// poll cycle.
pub struct NotifyQueue<T> {
    inner: Mutex<VecDeque<T>>,
    cv: Condvar,
}

impl<T> NotifyQueue<T> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        })
    }

    pub fn push(&self, item: T) {
        self.inner.lock().push_back(item);
        self.cv.notify_one();
    }

    pub fn try_pop(&self) -> Option<T> {
        self.inner.lock().pop_front()
    }

    pub fn drain_into(&self, out: &mut Vec<T>) -> usize {
        let mut g = self.inner.lock();
        let n = g.len();
        out.extend(g.drain(..));
        n
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

impl<T> Default for NotifyQueue<T>
where
    T: 'static,
{
    fn default() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        }
    }
}
