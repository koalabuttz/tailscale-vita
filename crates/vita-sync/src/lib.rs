//! Synchronization primitives that work in both eboot (std::sync
//! backend) and SUPRX (SCE kernel primitives backend) contexts on
//! the Vita.
//!
//! ## Why this exists
//!
//! The SUPRX has a statically-linked copy of libpthread + newlib that
//! conflicts with the eboot's copy. `pthread_init` is never called
//! in the SUPRX (its `_start` doesn't run), so any pthread API call
//! crashes silently. Rust's `std::sync::Mutex`, `RwLock`, `OnceLock`
//! all use pthread primitives on the Vita target — they crash too.
//!
//! See `docs/SUPRX-PTHREAD-INVESTIGATION.md` (M15-A) and the M15-A2
//! deferral notes in `memory/m11_suprx_loader_findings.md` for the
//! full root-cause analysis. M15-A3 S1 shipped the first proof:
//! `info!()` from inside the SUPRX now lands in `vita.log`.
//!
//! ## Design
//!
//! - `cfg(target_os = "vita")` → SCE backend. Each primitive lazily
//!   creates its SCE kernel object on first use; subsequent calls
//!   are direct sceKernel{Lock,Unlock,Wait,Signal}* syscalls. No
//!   pthread involvement.
//! - `cfg(not(target_os = "vita"))` → std::sync wrapper. Tests +
//!   host_diagnostic keep working unchanged.
//!
//! The API mirrors `parking_lot` / `std::sync` for the subset we
//! use across the workspace, so migration is mostly mechanical
//! `parking_lot::Mutex` → `vita_sync::Mutex` etc.
//!
//! ## Primitives (S2)
//!
//! - `Mutex<T>` with `lock()` / `try_lock()` → `MutexGuard`
//! - `RwLock<T>` with `read()` / `write()` / `try_*` → guards
//! - `OnceLock<T>` with `get()` / `set()` / `get_or_init()`
//! - `Once` (no value) with `call_once(f)`
//! - `Condvar` paired with `Mutex` for `wait` / `wait_timeout` /
//!   `notify_one` / `notify_all`

#![cfg_attr(target_os = "vita", allow(unused))]

#[cfg(target_os = "vita")]
mod vita;
#[cfg(target_os = "vita")]
pub use vita::{Condvar, Mutex, MutexGuard, Once, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, WaitTimeoutResult};

#[cfg(not(target_os = "vita"))]
mod host;
#[cfg(not(target_os = "vita"))]
pub use host::{Condvar, Mutex, MutexGuard, Once, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, WaitTimeoutResult};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn mutex_roundtrip() {
        let m = Mutex::new(42);
        {
            let g = m.lock();
            assert_eq!(*g, 42);
        }
        let g = m.lock();
        assert_eq!(*g, 42);
    }

    #[test]
    fn mutex_mutation() {
        let m = Mutex::new(0u32);
        for _ in 0..5 {
            let mut g = m.lock();
            *g += 1;
        }
        assert_eq!(*m.lock(), 5);
    }

    #[test]
    fn mutex_threaded_increment() {
        let m = Arc::new(Mutex::new(0u32));
        let mut handles = vec![];
        for _ in 0..8 {
            let m = Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let mut g = m.lock();
                    *g += 1;
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*m.lock(), 800);
    }

    #[test]
    fn mutex_try_lock_succeeds_when_unlocked() {
        let m = Mutex::new(7);
        let g = m.try_lock().expect("should succeed");
        assert_eq!(*g, 7);
    }

    #[test]
    fn oncelock_set_once() {
        let cell: OnceLock<String> = OnceLock::new();
        assert!(cell.get().is_none());
        cell.set("first".to_string()).unwrap();
        assert_eq!(cell.get().map(String::as_str), Some("first"));
        assert!(cell.set("second".to_string()).is_err());
    }

    #[test]
    fn oncelock_get_or_init() {
        let cell: OnceLock<i32> = OnceLock::new();
        let v = cell.get_or_init(|| 99);
        assert_eq!(*v, 99);
        let v = cell.get_or_init(|| panic!("should not re-init"));
        assert_eq!(*v, 99);
    }

    #[test]
    fn rwlock_concurrent_readers() {
        let lock = Arc::new(RwLock::new(0u32));
        let mut handles = vec![];
        for _ in 0..4 {
            let lock = Arc::clone(&lock);
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let g = lock.read();
                    let _ = *g;
                }
            }));
        }
        // Concurrent writer.
        let writer_lock = Arc::clone(&lock);
        handles.push(std::thread::spawn(move || {
            for _ in 0..50 {
                let mut g = writer_lock.write();
                *g += 1;
            }
        }));
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*lock.read(), 50);
    }

    #[test]
    fn rwlock_write_excludes_read() {
        let lock = RwLock::new(0u32);
        let w = lock.write();
        assert!(lock.try_read().is_none(), "write should block read");
        drop(w);
        assert!(lock.try_read().is_some());
    }

    #[test]
    fn once_call_once_runs_only_once() {
        let once = Once::new();
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        for _ in 0..3 {
            let counter = Arc::clone(&counter);
            once.call_once(|| {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn once_concurrent_call_once() {
        let once = Arc::new(Once::new());
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut handles = vec![];
        for _ in 0..8 {
            let once = Arc::clone(&once);
            let counter = Arc::clone(&counter);
            handles.push(std::thread::spawn(move || {
                once.call_once(|| {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                });
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn condvar_notify_one_wakes_waiter() {
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let waiter_pair = Arc::clone(&pair);
        let waiter = std::thread::spawn(move || {
            let (m, cv) = &*waiter_pair;
            let mut g = m.lock();
            while !*g {
                g = cv.wait(g);
            }
            *g
        });

        std::thread::sleep(Duration::from_millis(20));
        {
            let (m, cv) = &*pair;
            *m.lock() = true;
            cv.notify_one();
        }
        assert!(waiter.join().unwrap());
    }

    #[test]
    fn condvar_wait_timeout_returns() {
        let pair = (Mutex::new(false), Condvar::new());
        let g = pair.0.lock();
        let (g, res) = pair.1.wait_timeout(g, Duration::from_millis(20));
        drop(g);
        assert!(res.timed_out());
    }
}
