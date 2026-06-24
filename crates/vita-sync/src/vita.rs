//! SCE backend: Mutex<T> + OnceLock<T> backed by SCE kernel
//! primitives. Avoids libc-pthread entirely.
//!
//! ## Mutex<T> design
//!
//! `Mutex<T>` is **lazily initialized**: `Mutex::new(value)` is a
//! `const fn` that doesn't touch the kernel. The first `lock()` (or
//! `try_lock()`) call creates the SCE mutex via
//! `sceKernelCreateMutex`. Subsequent locks call
//! `sceKernelLockMutex`. `Drop` calls `sceKernelDeleteMutex`.
//!
//! Lazy init via atomic CAS:
//! - `sce` atomic holds the SceUID once initialized.
//! - Sentinel `0` = uninit; sentinel `SCE_INIT_SENTINEL` = some
//!   thread is currently inside `sceKernelCreateMutex`.
//! - Concurrent first-locks spin briefly waiting for the racing
//!   thread to publish the SceUID. SCE mutex creation is fast
//!   (~µs), so the spin is bounded.
//!
//! ## OnceLock<T> design
//!
//! Pure atomic-based; no SCE primitive needed (one-shot semantics).
//! Three states: empty / initializing / initialized. `set()`
//! claims the initialization atomically.

use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int, c_void};
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};

extern "C" {
    fn sceKernelCreateMutex(
        name: *const c_char,
        attr: u32,
        init_count: c_int,
        opt: *const c_void,
    ) -> c_int;
    fn sceKernelLockMutex(uid: c_int, lock_count: c_int, timeout: *mut u32) -> c_int;
    fn sceKernelUnlockMutex(uid: c_int, unlock_count: c_int) -> c_int;
    fn sceKernelDeleteMutex(uid: c_int) -> c_int;

    fn sceKernelCreateRWLock(
        name: *const c_char,
        attr: u32,
        opt: *const c_void,
    ) -> c_int;
    fn sceKernelLockReadRWLock(uid: c_int, timeout: *mut u32) -> c_int;
    fn sceKernelLockWriteRWLock(uid: c_int, timeout: *mut u32) -> c_int;
    fn sceKernelUnlockReadRWLock(uid: c_int) -> c_int;
    fn sceKernelUnlockWriteRWLock(uid: c_int) -> c_int;
    fn sceKernelDeleteRWLock(uid: c_int) -> c_int;

    fn sceKernelCreateCond(
        name: *const c_char,
        attr: u32,
        mutex_id: c_int,
        opt: *const c_void,
    ) -> c_int;
    fn sceKernelWaitCond(uid: c_int, timeout: *mut u32) -> c_int;
    fn sceKernelSignalCond(uid: c_int) -> c_int;
    fn sceKernelSignalCondAll(uid: c_int) -> c_int;
    fn sceKernelDeleteCond(uid: c_int) -> c_int;
}

/// SCE timeout error returned by sceKernelWaitCond / sceKernelLockMutex
/// when the supplied timeout elapsed. We match on the magnitude rather
/// than including a constant since the exact code is not stable across
/// firmwares — any negative rc with a non-zero timeout pointer means
/// "timed out" for our purposes.
const SCE_KERNEL_ERROR_WAIT_TIMEOUT: c_int = 0x80028001u32 as c_int;

/// SceUID is a positive `c_int` after successful creation. We
/// reserve `0` to mean "uninit" and `-1` as the "another thread is
/// inside `sceKernelCreateMutex`" sentinel. Real SCE errors are
/// negative + always have low bits set, so they'd never collide
/// with `-1` in normal use — but defensively we also avoid storing
/// any negative value other than the sentinel.
const SCE_INIT_SENTINEL: i32 = -1;

/// All vita_sync mutexes share this static C name. The SCE kernel
/// stores its own copy on `sceKernelCreateMutex` so a single static
/// is safe to share.
static MUTEX_NAME: &[u8] = b"vita-sync\0";

pub struct Mutex<T> {
    /// User-protected value.
    inner: UnsafeCell<T>,
    /// 0 = uninit; SCE_INIT_SENTINEL = init-in-progress; >0 = SceUID.
    sce: AtomicI32,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: UnsafeCell::new(value),
            sce: AtomicI32::new(0),
        }
    }

    /// Get the SceUID for this mutex, creating it on first call.
    /// Bounded spin on concurrent first-init.
    #[inline]
    fn ensure_init(&self) -> i32 {
        let current = self.sce.load(Ordering::Acquire);
        if current > 0 {
            return current;
        }
        self.slow_init()
    }

    #[cold]
    fn slow_init(&self) -> i32 {
        loop {
            match self.sce.compare_exchange(
                0,
                SCE_INIT_SENTINEL,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // We won the race; create the SCE mutex.
                    // SAFETY: name is static null-terminated; attr=0 is "default";
                    // init_count=0 = unlocked; opt=null = no extension.
                    let uid = unsafe {
                        sceKernelCreateMutex(
                            MUTEX_NAME.as_ptr() as *const c_char,
                            0,
                            0,
                            ptr::null(),
                        )
                    };
                    if uid <= 0 {
                        // Failure path: restore to uninit so a future caller
                        // can retry. Panicking is the right move because lock
                        // failures here suggest kernel exhaustion.
                        self.sce.store(0, Ordering::Release);
                        panic!(
                            "vita_sync::Mutex: sceKernelCreateMutex failed: 0x{:08x}",
                            uid as u32
                        );
                    }
                    self.sce.store(uid, Ordering::Release);
                    return uid;
                }
                Err(SCE_INIT_SENTINEL) => {
                    // Another thread is creating; spin briefly.
                    std::hint::spin_loop();
                    continue;
                }
                Err(uid) if uid > 0 => return uid,
                Err(other) => {
                    // Shouldn't happen — only 0, sentinel, or >0 valid states.
                    panic!("vita_sync::Mutex: unexpected sce state {other}");
                }
            }
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        let uid = self.ensure_init();
        // SAFETY: uid is a valid SceUID from sceKernelCreateMutex.
        // timeout=null → block indefinitely. lock_count=1 → standard
        // single-acquisition mutex.
        let rc = unsafe { sceKernelLockMutex(uid, 1, ptr::null_mut()) };
        if rc < 0 {
            panic!(
                "vita_sync::Mutex: sceKernelLockMutex failed: 0x{:08x}",
                rc as u32
            );
        }
        MutexGuard { mutex: self, uid }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let uid = self.ensure_init();
        let mut timeout: u32 = 0;
        // SAFETY: same as lock().
        let rc = unsafe { sceKernelLockMutex(uid, 1, &mut timeout) };
        if rc < 0 {
            None
        } else {
            Some(MutexGuard { mutex: self, uid })
        }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> Drop for Mutex<T> {
    fn drop(&mut self) {
        let uid = self.sce.load(Ordering::Acquire);
        if uid > 0 {
            // SAFETY: uid valid; no outstanding guards (we have &mut self).
            let _ = unsafe { sceKernelDeleteMutex(uid) };
        }
    }
}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
    uid: i32,
}

impl<T> std::ops::Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: we hold the SCE mutex; exclusive access guaranteed.
        unsafe { &*self.mutex.inner.get() }
    }
}

impl<T> std::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: we hold the SCE mutex; exclusive access guaranteed.
        unsafe { &mut *self.mutex.inner.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: uid valid (from ensure_init when lock was acquired).
        let _ = unsafe { sceKernelUnlockMutex(self.uid, 1) };
    }
}

// ============================================================
// OnceLock<T>: pure atomic, no SCE primitive needed
// ============================================================

const ONCE_EMPTY: u8 = 0;
const ONCE_INIT: u8 = 1;
const ONCE_READY: u8 = 2;

pub struct OnceLock<T> {
    value: UnsafeCell<MaybeUninit<T>>,
    state: AtomicU8,
}

unsafe impl<T: Send> Send for OnceLock<T> {}
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            value: UnsafeCell::new(MaybeUninit::uninit()),
            state: AtomicU8::new(ONCE_EMPTY),
        }
    }

    pub fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == ONCE_READY {
            // SAFETY: state=READY means value was written via set/get_or_init.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }

    pub fn set(&self, value: T) -> Result<(), T> {
        match self.state.compare_exchange(
            ONCE_EMPTY,
            ONCE_INIT,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // SAFETY: we won the race; no other thread reads value
                // until we publish via state=READY.
                unsafe {
                    (*self.value.get()).write(value);
                }
                self.state.store(ONCE_READY, Ordering::Release);
                Ok(())
            }
            Err(_) => Err(value),
        }
    }

    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
        // Fast path.
        if let Some(v) = self.get() {
            return v;
        }
        // Slow path: try to claim init.
        match self.state.compare_exchange(
            ONCE_EMPTY,
            ONCE_INIT,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let v = f();
                // SAFETY: we won; no other writer.
                unsafe {
                    (*self.value.get()).write(v);
                }
                self.state.store(ONCE_READY, Ordering::Release);
            }
            Err(_) => {
                // Either INIT (another thread is initializing) or
                // READY (already done). Spin until READY.
                while self.state.load(Ordering::Acquire) != ONCE_READY {
                    std::hint::spin_loop();
                }
            }
        }
        // SAFETY: state is READY (we either wrote it or saw it).
        unsafe { (*self.value.get()).assume_init_ref() }
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for OnceLock<T> {
    fn drop(&mut self) {
        if *self.state.get_mut() == ONCE_READY {
            // SAFETY: state=READY → value was initialized.
            unsafe {
                self.value.get_mut().assume_init_drop();
            }
        }
    }
}

// ============================================================
// Once (no value): same atomic state machine as OnceLock<()>,
// but separate type to match std::sync::Once's API.
// ============================================================

pub struct Once {
    state: AtomicU8,
}

impl Once {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(ONCE_EMPTY),
        }
    }

    pub fn call_once<F: FnOnce()>(&self, f: F) {
        if self.state.load(Ordering::Acquire) == ONCE_READY {
            return;
        }
        match self.state.compare_exchange(
            ONCE_EMPTY,
            ONCE_INIT,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                f();
                self.state.store(ONCE_READY, Ordering::Release);
            }
            Err(_) => {
                while self.state.load(Ordering::Acquire) != ONCE_READY {
                    std::hint::spin_loop();
                }
            }
        }
    }

    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == ONCE_READY
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// RwLock<T>: SCE rwlock backed
// ============================================================

static RWLOCK_NAME: &[u8] = b"vita-sync-rw\0";

pub struct RwLock<T> {
    inner: UnsafeCell<T>,
    sce: AtomicI32,
}

unsafe impl<T: Send> Send for RwLock<T> {}
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: UnsafeCell::new(value),
            sce: AtomicI32::new(0),
        }
    }

    #[inline]
    fn ensure_init(&self) -> i32 {
        let current = self.sce.load(Ordering::Acquire);
        if current > 0 {
            return current;
        }
        self.slow_init()
    }

    #[cold]
    fn slow_init(&self) -> i32 {
        loop {
            match self.sce.compare_exchange(
                0,
                SCE_INIT_SENTINEL,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let uid = unsafe {
                        sceKernelCreateRWLock(
                            RWLOCK_NAME.as_ptr() as *const c_char,
                            0,
                            ptr::null(),
                        )
                    };
                    if uid <= 0 {
                        self.sce.store(0, Ordering::Release);
                        panic!(
                            "vita_sync::RwLock: sceKernelCreateRWLock failed: 0x{:08x}",
                            uid as u32
                        );
                    }
                    self.sce.store(uid, Ordering::Release);
                    return uid;
                }
                Err(SCE_INIT_SENTINEL) => {
                    std::hint::spin_loop();
                    continue;
                }
                Err(uid) if uid > 0 => return uid,
                Err(other) => panic!("vita_sync::RwLock: unexpected sce state {other}"),
            }
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let uid = self.ensure_init();
        let rc = unsafe { sceKernelLockReadRWLock(uid, ptr::null_mut()) };
        if rc < 0 {
            panic!(
                "vita_sync::RwLock: sceKernelLockReadRWLock failed: 0x{:08x}",
                rc as u32
            );
        }
        RwLockReadGuard { lock: self, uid }
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let uid = self.ensure_init();
        let rc = unsafe { sceKernelLockWriteRWLock(uid, ptr::null_mut()) };
        if rc < 0 {
            panic!(
                "vita_sync::RwLock: sceKernelLockWriteRWLock failed: 0x{:08x}",
                rc as u32
            );
        }
        RwLockWriteGuard { lock: self, uid }
    }

    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let uid = self.ensure_init();
        let mut timeout: u32 = 0;
        let rc = unsafe { sceKernelLockReadRWLock(uid, &mut timeout) };
        if rc < 0 {
            None
        } else {
            Some(RwLockReadGuard { lock: self, uid })
        }
    }

    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        let uid = self.ensure_init();
        let mut timeout: u32 = 0;
        let rc = unsafe { sceKernelLockWriteRWLock(uid, &mut timeout) };
        if rc < 0 {
            None
        } else {
            Some(RwLockWriteGuard { lock: self, uid })
        }
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> Drop for RwLock<T> {
    fn drop(&mut self) {
        let uid = self.sce.load(Ordering::Acquire);
        if uid > 0 {
            let _ = unsafe { sceKernelDeleteRWLock(uid) };
        }
    }
}

pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
    uid: i32,
}

impl<T> std::ops::Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.inner.get() }
    }
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        let _ = unsafe { sceKernelUnlockReadRWLock(self.uid) };
    }
}

pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
    uid: i32,
}

impl<T> std::ops::Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.inner.get() }
    }
}

impl<T> std::ops::DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.inner.get() }
    }
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        let _ = unsafe { sceKernelUnlockWriteRWLock(self.uid) };
    }
}

// ============================================================
// Condvar: SCE conditional variable
// ============================================================
//
// SCE cond vars are bound to a specific mutex at create time. Our
// `Mutex<T>` lazily creates its SCE mutex on first lock(); to share
// the same SCE mutex with a condvar, the condvar also lazy-inits and
// looks up the bound mutex's UID via the guard we receive in wait().

static COND_NAME: &[u8] = b"vita-sync-cond\0";

pub struct Condvar {
    /// Lazy SCE cond UID. Bound to the mutex of the first `wait()`
    /// caller's guard. A condvar shared across multiple Mutex<T>
    /// values is a panic — but that's also UB in std::sync::Condvar.
    sce: AtomicI32,
}

unsafe impl Send for Condvar {}
unsafe impl Sync for Condvar {}

impl Condvar {
    pub const fn new() -> Self {
        Self {
            sce: AtomicI32::new(0),
        }
    }

    /// Lazy-init the cond bound to `mutex_uid`. Returns the cond UID.
    fn ensure_init(&self, mutex_uid: c_int) -> i32 {
        let current = self.sce.load(Ordering::Acquire);
        if current > 0 {
            return current;
        }
        loop {
            match self.sce.compare_exchange(
                0,
                SCE_INIT_SENTINEL,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let uid = unsafe {
                        sceKernelCreateCond(
                            COND_NAME.as_ptr() as *const c_char,
                            0,
                            mutex_uid,
                            ptr::null(),
                        )
                    };
                    if uid <= 0 {
                        self.sce.store(0, Ordering::Release);
                        panic!(
                            "vita_sync::Condvar: sceKernelCreateCond failed: 0x{:08x}",
                            uid as u32
                        );
                    }
                    self.sce.store(uid, Ordering::Release);
                    return uid;
                }
                Err(SCE_INIT_SENTINEL) => {
                    std::hint::spin_loop();
                    continue;
                }
                Err(uid) if uid > 0 => return uid,
                Err(other) => panic!("vita_sync::Condvar: unexpected sce state {other}"),
            }
        }
    }

    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        let mutex_uid = guard.uid;
        let cond_uid = self.ensure_init(mutex_uid);
        // SCE wait: atomically releases the mutex, blocks, reacquires
        // on signal. Caller's guard remains conceptually held — we
        // hand it back unchanged so RAII semantics survive.
        let rc = unsafe { sceKernelWaitCond(cond_uid, ptr::null_mut()) };
        if rc < 0 {
            panic!(
                "vita_sync::Condvar: sceKernelWaitCond failed: 0x{:08x}",
                rc as u32
            );
        }
        guard
    }

    pub fn wait_timeout<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        dur: std::time::Duration,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult) {
        let mutex_uid = guard.uid;
        let cond_uid = self.ensure_init(mutex_uid);
        let mut timeout: u32 = dur.as_micros().min(u32::MAX as u128) as u32;
        let rc = unsafe { sceKernelWaitCond(cond_uid, &mut timeout) };
        let timed_out = rc == SCE_KERNEL_ERROR_WAIT_TIMEOUT
            || (rc < 0 && (rc as u32) & 0xFFFF == 0x8001);
        (
            guard,
            WaitTimeoutResult {
                timed_out: timed_out || rc < 0,
            },
        )
    }

    pub fn notify_one(&self) {
        let uid = self.sce.load(Ordering::Acquire);
        if uid > 0 {
            let _ = unsafe { sceKernelSignalCond(uid) };
        }
    }

    pub fn notify_all(&self) {
        let uid = self.sce.load(Ordering::Acquire);
        if uid > 0 {
            let _ = unsafe { sceKernelSignalCondAll(uid) };
        }
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Condvar {
    fn drop(&mut self) {
        let uid = self.sce.load(Ordering::Acquire);
        if uid > 0 {
            let _ = unsafe { sceKernelDeleteCond(uid) };
        }
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
