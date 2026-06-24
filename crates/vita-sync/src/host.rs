//! Host backend: thin wrappers around `std::sync`. Used on x86_64
//! Linux for unit tests + host_diagnostic. The eboot path *does*
//! see this code via `target_os != "vita"` builds for tests; on the
//! actual Vita target (both eboot and SUPRX), `vita.rs` is selected.

use std::sync::{
    Condvar as StdCondvar, Mutex as StdMutex, MutexGuard as StdMutexGuard,
    Once as StdOnce, OnceLock as StdOnceLock, PoisonError, RwLock as StdRwLock,
    RwLockReadGuard as StdRwLockReadGuard, RwLockWriteGuard as StdRwLockWriteGuard,
};
use std::time::Duration;

// ============================================================
// Mutex
// ============================================================

/// Drop-in replacement for `parking_lot::Mutex<T>`.
///
/// Diverges from `std::sync::Mutex` in one way: `lock()` never returns
/// `Err`. We unwrap poison errors internally — matches parking_lot's
/// semantics (no poisoning). Code that relies on Mutex poisoning
/// should be reworked, but no caller in this workspace does.
pub struct Mutex<T> {
    inner: StdMutex<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: StdMutex::new(value),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        MutexGuard {
            inner: self.inner.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        match self.inner.try_lock() {
            Ok(g) => Some(MutexGuard { inner: g }),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(p)) => Some(MutexGuard {
                inner: p.into_inner(),
            }),
        }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.try_lock() {
            Some(g) => f.debug_struct("Mutex").field("value", &*g).finish(),
            None => f.debug_struct("Mutex").field("value", &"<locked>").finish(),
        }
    }
}

pub struct MutexGuard<'a, T> {
    inner: StdMutexGuard<'a, T>,
}

impl<T> std::ops::Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> std::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

// ============================================================
// RwLock
// ============================================================

/// Drop-in replacement for `parking_lot::RwLock<T>`.
///
/// Same poisoning behaviour as `Mutex`: poisoning is silently
/// converted to a regular lock, matching `parking_lot`.
pub struct RwLock<T> {
    inner: StdRwLock<T>,
}

unsafe impl<T: Send> Send for RwLock<T> {}
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: StdRwLock::new(value),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        RwLockReadGuard {
            inner: self.inner.read().unwrap_or_else(PoisonError::into_inner),
        }
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        RwLockWriteGuard {
            inner: self.inner.write().unwrap_or_else(PoisonError::into_inner),
        }
    }

    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        match self.inner.try_read() {
            Ok(g) => Some(RwLockReadGuard { inner: g }),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(p)) => {
                Some(RwLockReadGuard { inner: p.into_inner() })
            }
        }
    }

    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        match self.inner.try_write() {
            Ok(g) => Some(RwLockWriteGuard { inner: g }),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(p)) => {
                Some(RwLockWriteGuard { inner: p.into_inner() })
            }
        }
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

pub struct RwLockReadGuard<'a, T> {
    inner: StdRwLockReadGuard<'a, T>,
}

impl<T> std::ops::Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

pub struct RwLockWriteGuard<'a, T> {
    inner: StdRwLockWriteGuard<'a, T>,
}

impl<T> std::ops::Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> std::ops::DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

// ============================================================
// OnceLock<T>
// ============================================================

/// Drop-in replacement for `std::sync::OnceLock<T>`. Same API.
pub struct OnceLock<T> {
    inner: StdOnceLock<T>,
}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            inner: StdOnceLock::new(),
        }
    }

    pub fn get(&self) -> Option<&T> {
        self.inner.get()
    }

    pub fn set(&self, value: T) -> Result<(), T> {
        self.inner.set(value)
    }

    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
        self.inner.get_or_init(f)
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Once (no value)
// ============================================================

/// Drop-in replacement for `std::sync::Once`.
pub struct Once {
    inner: StdOnce,
}

impl Once {
    pub const fn new() -> Self {
        Self {
            inner: StdOnce::new(),
        }
    }

    pub fn call_once<F: FnOnce()>(&self, f: F) {
        self.inner.call_once(f);
    }

    pub fn is_completed(&self) -> bool {
        self.inner.is_completed()
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Condvar
// ============================================================

pub struct Condvar {
    inner: StdCondvar,
}

impl Condvar {
    pub const fn new() -> Self {
        Self {
            inner: StdCondvar::new(),
        }
    }

    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        let inner = self.inner.wait(guard.inner).unwrap_or_else(PoisonError::into_inner);
        MutexGuard { inner }
    }

    pub fn wait_timeout<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        dur: Duration,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult) {
        let (inner, res) = self
            .inner
            .wait_timeout(guard.inner, dur)
            .unwrap_or_else(PoisonError::into_inner);
        (
            MutexGuard { inner },
            WaitTimeoutResult {
                timed_out: res.timed_out(),
            },
        )
    }

    pub fn notify_one(&self) {
        self.inner.notify_one();
    }

    pub fn notify_all(&self) {
        self.inner.notify_all();
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct WaitTimeoutResult {
    timed_out: bool,
}

impl WaitTimeoutResult {
    pub fn timed_out(&self) -> bool {
        self.timed_out
    }
}
