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
//! full root-cause analysis.
//!
//! ## Design
//!
//! - `cfg(target_os = "vita")` → SCE backend. `Mutex<T>` lazily
//!   creates an `sceKernelCreateMutex` on first lock; subsequent
//!   locks call `sceKernelLockMutex`. No pthread involvement.
//! - `cfg(not(target_os = "vita"))` → std::sync wrapper. Tests +
//!   host_diagnostic keep working unchanged.
//!
//! The API mirrors `parking_lot` / `std::sync` for the subset we
//! use across the workspace, so migration is mostly mechanical
//! `parking_lot::Mutex` → `vita_sync::Mutex`.
//!
//! ## What's included (S1 vertical slice)
//!
//! - `Mutex<T>` with `lock()` / `try_lock()` → MutexGuard
//! - `OnceLock<T>` with `get()` / `set()` / `get_or_init()`
//!
//! S2 will add `RwLock<T>`, `Once`, `Condvar`.

#![cfg_attr(target_os = "vita", allow(unused))]

#[cfg(target_os = "vita")]
mod vita;
#[cfg(target_os = "vita")]
pub use vita::{Mutex, MutexGuard, OnceLock};

#[cfg(not(target_os = "vita"))]
mod host;
#[cfg(not(target_os = "vita"))]
pub use host::{Mutex, MutexGuard, OnceLock};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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
        // Spawn threads (via std::thread on host) that each increment
        // a shared counter behind vita_sync::Mutex.
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
        // Second set fails.
        assert!(cell.set("second".to_string()).is_err());
    }

    #[test]
    fn oncelock_get_or_init() {
        let cell: OnceLock<i32> = OnceLock::new();
        let v = cell.get_or_init(|| 99);
        assert_eq!(*v, 99);
        // Second call returns cached value, doesn't re-run init.
        let v = cell.get_or_init(|| panic!("should not re-init"));
        assert_eq!(*v, 99);
    }
}
