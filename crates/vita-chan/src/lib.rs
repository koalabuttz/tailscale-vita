//! SUPRX-safe bounded/unbounded channels.
//!
//! Replaces `crossbeam-channel` on the Vita target, where
//! crossbeam's thread-local registry crashes inside the SUPRX
//! (same pthread chain as `vita-sync` documents — see that crate
//! and `docs/SUPRX-PTHREAD-INVESTIGATION.md`).
//!
//! ## API
//!
//! Mirrors the subset of `crossbeam_channel` the workspace uses:
//!
//! - [`bounded`] / [`unbounded`] return `(Sender, Receiver)`.
//! - [`Sender`] supports `send`, `try_send`, `send_timeout`.
//! - [`Receiver`] supports `recv`, `try_recv`, `recv_timeout`.
//! - Drop semantics: dropping the last `Sender` makes pending
//!   `recv()`s return `RecvError`. Dropping the last `Receiver`
//!   makes future `send()`s return `SendError(value)`.
//! - Clone: both `Sender` and `Receiver` are cheap `Arc`-clones,
//!   matching crossbeam's multi-producer/multi-consumer model.
//!
//! ## Design
//!
//! - Inner state: `Arc<Shared<T>>` shared by all senders/receivers.
//! - `Shared` holds: `vita_sync::Mutex<VecDeque<T>>` queue,
//!   `vita_sync::Condvar` for not-empty (recv wakeups),
//!   `vita_sync::Condvar` for not-full (send wakeups when bounded),
//!   `AtomicUsize` sender + receiver counts.
//! - `bounded(0)` reserves capacity 1 internally (rendezvous-style
//!   isn't supported; close enough for our use cases).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vita_sync::{Condvar, Mutex};

/// Result of a `send` when the receiver side is fully dropped.
#[derive(Debug)]
pub struct SendError<T>(pub T);

impl<T> std::fmt::Display for SendError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("send on closed channel")
    }
}

impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

/// Result of a `try_send`.
#[derive(Debug)]
pub enum TrySendError<T> {
    /// Bounded channel is at capacity; caller can retry.
    Full(T),
    /// Receiver side fully dropped.
    Disconnected(T),
}

impl<T> std::fmt::Display for TrySendError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrySendError::Full(_) => f.write_str("send on full channel"),
            TrySendError::Disconnected(_) => f.write_str("send on closed channel"),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for TrySendError<T> {}

/// Result of a blocking `recv` when all senders are dropped + queue
/// is empty.
#[derive(Debug)]
pub struct RecvError;

impl std::fmt::Display for RecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("recv on closed channel")
    }
}

impl std::error::Error for RecvError {}

/// Result of a `try_recv`.
#[derive(Debug, PartialEq, Eq)]
pub enum TryRecvError {
    /// Queue is empty but senders still exist; caller can retry.
    Empty,
    /// All senders dropped and queue is empty.
    Disconnected,
}

impl std::fmt::Display for TryRecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TryRecvError::Empty => f.write_str("empty channel"),
            TryRecvError::Disconnected => f.write_str("recv on closed channel"),
        }
    }
}

impl std::error::Error for TryRecvError {}

/// Result of a `recv_timeout`.
#[derive(Debug, PartialEq, Eq)]
pub enum RecvTimeoutError {
    /// Timeout elapsed before an item arrived.
    Timeout,
    /// All senders dropped and queue is empty.
    Disconnected,
}

impl std::fmt::Display for RecvTimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvTimeoutError::Timeout => f.write_str("recv timeout"),
            RecvTimeoutError::Disconnected => f.write_str("recv on closed channel"),
        }
    }
}

impl std::error::Error for RecvTimeoutError {}

struct Shared<T> {
    /// `None` capacity means unbounded.
    cap: Option<usize>,
    queue: Mutex<VecDeque<T>>,
    not_empty: Condvar,
    not_full: Condvar,
    sender_count: AtomicUsize,
    receiver_count: AtomicUsize,
}

impl<T> Shared<T> {
    fn new(cap: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            cap,
            queue: Mutex::new(VecDeque::new()),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            sender_count: AtomicUsize::new(1),
            receiver_count: AtomicUsize::new(1),
        })
    }

    fn is_full(&self, len: usize) -> bool {
        match self.cap {
            Some(c) => len >= c,
            None => false,
        }
    }
}

// ============================================================
// Sender / Receiver
// ============================================================

pub struct Sender<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Sender<T> {
    /// Block until the item is enqueued. Returns `SendError(value)`
    /// if all receivers have dropped.
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        let mut g = self.shared.queue.lock();
        loop {
            if self.shared.receiver_count.load(Ordering::Acquire) == 0 {
                return Err(SendError(value));
            }
            if !self.shared.is_full(g.len()) {
                g.push_back(value);
                drop(g);
                self.shared.not_empty.notify_one();
                return Ok(());
            }
            g = self.shared.not_full.wait(g);
        }
    }

    /// Non-blocking. Returns `TrySendError::Full(value)` if at
    /// capacity, `Disconnected(value)` if no receivers.
    pub fn try_send(&self, value: T) -> Result<(), TrySendError<T>> {
        let mut g = self.shared.queue.lock();
        if self.shared.receiver_count.load(Ordering::Acquire) == 0 {
            return Err(TrySendError::Disconnected(value));
        }
        if self.shared.is_full(g.len()) {
            return Err(TrySendError::Full(value));
        }
        g.push_back(value);
        drop(g);
        self.shared.not_empty.notify_one();
        Ok(())
    }

    /// Block up to `dur`. On timeout, returns the value in
    /// `TrySendError::Full`. On disconnect, returns the value in
    /// `TrySendError::Disconnected`.
    pub fn send_timeout(&self, value: T, dur: Duration) -> Result<(), TrySendError<T>> {
        let mut g = self.shared.queue.lock();
        let mut value = Some(value);
        let mut remaining = dur;
        loop {
            if self.shared.receiver_count.load(Ordering::Acquire) == 0 {
                return Err(TrySendError::Disconnected(value.take().unwrap()));
            }
            if !self.shared.is_full(g.len()) {
                g.push_back(value.take().unwrap());
                drop(g);
                self.shared.not_empty.notify_one();
                return Ok(());
            }
            if remaining.is_zero() {
                return Err(TrySendError::Full(value.take().unwrap()));
            }
            let start = std::time::Instant::now();
            let (g2, res) = self.shared.not_full.wait_timeout(g, remaining);
            g = g2;
            if res.timed_out() {
                remaining = Duration::ZERO;
            } else {
                let elapsed = start.elapsed();
                remaining = remaining.checked_sub(elapsed).unwrap_or(Duration::ZERO);
            }
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.shared.sender_count.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        if self.shared.sender_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Last sender — wake any blocked receivers so they see
            // disconnect.
            self.shared.not_empty.notify_all();
        }
    }
}

pub struct Receiver<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Receiver<T> {
    /// Block until an item is available. Returns `Err(RecvError)`
    /// if all senders are dropped and the queue is drained.
    pub fn recv(&self) -> Result<T, RecvError> {
        let mut g = self.shared.queue.lock();
        loop {
            if let Some(v) = g.pop_front() {
                drop(g);
                self.shared.not_full.notify_one();
                return Ok(v);
            }
            if self.shared.sender_count.load(Ordering::Acquire) == 0 {
                return Err(RecvError);
            }
            g = self.shared.not_empty.wait(g);
        }
    }

    /// Non-blocking.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut g = self.shared.queue.lock();
        if let Some(v) = g.pop_front() {
            drop(g);
            self.shared.not_full.notify_one();
            return Ok(v);
        }
        if self.shared.sender_count.load(Ordering::Acquire) == 0 {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    /// Block up to `dur` for an item.
    pub fn recv_timeout(&self, dur: Duration) -> Result<T, RecvTimeoutError> {
        let mut g = self.shared.queue.lock();
        let mut remaining = dur;
        loop {
            if let Some(v) = g.pop_front() {
                drop(g);
                self.shared.not_full.notify_one();
                return Ok(v);
            }
            if self.shared.sender_count.load(Ordering::Acquire) == 0 {
                return Err(RecvTimeoutError::Disconnected);
            }
            if remaining.is_zero() {
                return Err(RecvTimeoutError::Timeout);
            }
            let start = std::time::Instant::now();
            let (g2, res) = self.shared.not_empty.wait_timeout(g, remaining);
            g = g2;
            if res.timed_out() {
                remaining = Duration::ZERO;
            } else {
                let elapsed = start.elapsed();
                remaining = remaining.checked_sub(elapsed).unwrap_or(Duration::ZERO);
            }
        }
    }

    /// Approximate queue length. Not strictly consistent under
    /// concurrent producers — useful for diagnostics only.
    pub fn len(&self) -> usize {
        self.shared.queue.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        self.shared.receiver_count.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        if self.shared.receiver_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.not_full.notify_all();
        }
    }
}

// ============================================================
// Constructors
// ============================================================

/// Create a bounded channel with the given capacity. Capacity 0 is
/// treated as 1 (no true rendezvous semantics on this implementation).
pub fn bounded<T>(cap: usize) -> (Sender<T>, Receiver<T>) {
    let cap = cap.max(1);
    let shared = Shared::new(Some(cap));
    (
        Sender {
            shared: Arc::clone(&shared),
        },
        Receiver { shared },
    )
}

/// Create an unbounded channel. Sends never block on capacity.
pub fn unbounded<T>() -> (Sender<T>, Receiver<T>) {
    let shared = Shared::new(None);
    (
        Sender {
            shared: Arc::clone(&shared),
        },
        Receiver { shared },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::time::Instant;

    #[test]
    fn send_recv_round_trip() {
        let (tx, rx) = unbounded::<u32>();
        tx.send(7).unwrap();
        assert_eq!(rx.recv().unwrap(), 7);
    }

    #[test]
    fn bounded_blocks_send_when_full() {
        let (tx, rx) = bounded::<u32>(1);
        tx.send(1).unwrap();
        // Second send must block until receiver drains.
        let drained = Arc::new(AtomicUsize::new(0));
        let dr = Arc::clone(&drained);
        let h = thread::spawn(move || {
            tx.send(2).unwrap();
            dr.fetch_add(1, Ordering::SeqCst);
        });
        // give the sender a head start
        thread::sleep(Duration::from_millis(20));
        assert_eq!(drained.load(Ordering::SeqCst), 0);
        let _ = rx.recv().unwrap();
        h.join().unwrap();
        assert_eq!(drained.load(Ordering::SeqCst), 1);
        assert_eq!(rx.recv().unwrap(), 2);
    }

    #[test]
    fn try_send_returns_full() {
        let (tx, _rx) = bounded::<u32>(1);
        tx.send(1).unwrap();
        match tx.try_send(2) {
            Err(TrySendError::Full(v)) => assert_eq!(v, 2),
            other => panic!("expected Full, got {other:?}"),
        }
    }

    #[test]
    fn try_recv_returns_empty_then_disconnected() {
        let (tx, rx) = unbounded::<u32>();
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        drop(tx);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn recv_returns_err_after_all_senders_drop() {
        let (tx, rx) = unbounded::<u32>();
        let tx2 = tx.clone();
        let h = thread::spawn(move || rx.recv());
        thread::sleep(Duration::from_millis(20));
        drop(tx);
        drop(tx2);
        match h.join().unwrap() {
            Err(RecvError) => (),
            Ok(_) => panic!("expected RecvError"),
        }
    }

    #[test]
    fn send_returns_err_after_all_receivers_drop() {
        let (tx, rx) = unbounded::<u32>();
        drop(rx);
        match tx.send(1) {
            Err(SendError(1)) => (),
            other => panic!("expected SendError(1), got {other:?}"),
        }
    }

    #[test]
    fn recv_timeout_times_out() {
        let (_tx, rx) = unbounded::<u32>();
        let start = Instant::now();
        match rx.recv_timeout(Duration::from_millis(30)) {
            Err(RecvTimeoutError::Timeout) => (),
            other => panic!("expected Timeout, got {other:?}"),
        }
        assert!(start.elapsed() >= Duration::from_millis(25));
    }

    #[test]
    fn mpmc_stress() {
        let (tx, rx) = unbounded::<u32>();
        let mut handles = vec![];
        for _ in 0..4 {
            let tx = tx.clone();
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    tx.send(i).unwrap();
                }
            }));
        }
        drop(tx);
        let recv_count = Arc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            let rx = rx.clone();
            let recv_count = Arc::clone(&recv_count);
            handles.push(thread::spawn(move || {
                while rx.recv().is_ok() {
                    recv_count.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        drop(rx);
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(recv_count.load(Ordering::Relaxed), 400);
    }
}
