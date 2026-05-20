//! Host backend: thin wrappers around `std::sync`. Used on x86_64
//! Linux for unit tests + host_diagnostic. The eboot path *does*
//! see this code via `target_os != "vita"` builds for tests; on the
//! actual Vita target (both eboot and SUPRX), `vita.rs` is selected.

use std::sync::{
    Mutex as StdMutex, MutexGuard as StdMutexGuard, OnceLock as StdOnceLock, PoisonError,
};

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
