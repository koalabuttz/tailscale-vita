//! SCE backend: spawn threads via `sceKernelCreateThread` +
//! `sceKernelStartThread`, joinable via `sceKernelWaitThreadEnd`.
//!
//! Closure marshalling: boxed (`Box<dyn FnOnce() + Send + 'static>`)
//! then leaked into a raw pointer. The pointer value is passed via
//! `sceKernelStartThread`'s `argp` (the kernel copies `arg_len` bytes
//! into thread-local args storage). Thread entry recovers the pointer
//! from its args, re-Box's it, calls the closure, and exits.
//!
//! Drop / detach: the entry calls `sceKernelExitThread` (NOT
//! exit-and-delete), so the thread handle remains valid for
//! `sceKernelWaitThreadEnd` afterwards. `join()` then waits + deletes.
//! Detached threads (JoinHandle dropped without join) leak their SCE
//! handle until the surrounding process exits — fine in practice
//! because every workspace spawn site joins in Drop.
//!
//! ## ⚠ Known SUPRX limitation (2026-06-24)
//!
//! Spawning via this crate from inside a SUPRX **and then performing
//! any heap allocation from the spawned thread** crashes the SUPRX
//! on hardware. The thread starts and can call SCE syscalls, but the
//! first `Box::new` (or anything that touches `taipool_alloc`) faults.
//! Cause isn't fully understood — possibly the `Box<dyn FnOnce>`
//! invocation pattern leaves the allocator state in a bad spot for
//! that thread. The eboot path is unaffected.
//!
//! Workaround used by `vita-log`: spawn the writer thread via raw
//! `sceKernelCreateThread`, with the entry function as a plain
//! `extern "C" fn` and arguments handed off through a static slot
//! (no boxed closure). See `vita-log/src/lib.rs::raw_spawn_writer`.

use std::ffi::{c_char, c_int, c_void, CString};
use std::io;
use std::ptr;

// Note: no `#[link]` attribute. The SCE stub libs
// (SceKernelThreadMgr_stub_weak etc.) get linked by the SUPRX's
// CMakeLists.txt at final-link time; cargo just compiles the
// staticlib with these as unresolved-but-undefined references.
extern "C" {
    fn sceKernelCreateThread(
        name: *const c_char,
        entry: unsafe extern "C" fn(u32, *mut c_void) -> i32,
        init_priority: c_int,
        stack_size: u32,
        attr: u32,
        cpu_affinity_mask: c_int,
        option: *const c_void,
    ) -> c_int;
    fn sceKernelStartThread(thid: c_int, arg_len: u32, argp: *mut c_void) -> c_int;
    fn sceKernelExitThread(status: c_int) -> c_int;
    fn sceKernelWaitThreadEnd(
        thid: c_int,
        status: *mut c_int,
        timeout: *mut u32,
    ) -> c_int;
    fn sceKernelDeleteThread(thid: c_int) -> c_int;
}

/// Stack size when caller didn't specify. Matches the most common
/// value across the workspace (magicsock, derp, netstack, runtime).
const DEFAULT_STACK: usize = 256 * 1024;

/// Thread priority. 0x40 matches vitacompanion + the existing
/// bootstrap thread pattern in `tailscale-vita-rt`. Lower = higher
/// priority (Vita's scheduler is reverse-order). 0x40 is sufficient
/// for background daemon work.
const DEFAULT_PRIORITY: c_int = 0x40;

/// Type-erased boxed closure marshalled into the SCE thread.
type BoxedClosure = Box<dyn FnOnce() + Send + 'static>;

pub struct Handle(c_int);

/// SCE thread entry-point wrapper. Recovers the boxed closure from
/// `argp`, invokes it, then exits via `sceKernelExitThread` so
/// `sceKernelWaitThreadEnd` can still complete after the thread
/// finishes (necessary for `JoinHandle::join`).
///
/// Caller (sceKernelStartThread) passes `arg_len = sizeof(pointer)`
/// and `argp` pointing at a location holding the BoxedClosure pointer.
/// The kernel copies `arg_len` bytes from `argp` into thread-local
/// storage; this function reads the pointer back out.
unsafe extern "C" fn thread_entry(_arg_len: u32, argp: *mut c_void) -> i32 {
    // Materialize this SCE thread's newlib per-thread _REENT (TLS slot
    // 0x89) BEFORE running any Rust std code. libc malloc/free/errno (and
    // anything std does that touches them) deref the calling thread's
    // _REENT, but a raw sceKernelCreateThread thread has none until it's
    // touched. __getreent() self-heals (module_start ran _init_vita_reent,
    // so _newlib_reent_mutex exists). Without this, the FIRST std alloc /
    // errno on a spawned worker faults — the exact M15-A3 S6 crash class.
    // Every worker the runtime spawns (magicsock, wg pump, derp, netstack
    // poll, event loop, listener) goes through here, so this one touch
    // makes them all std-ready.
    unsafe {
        extern "C" {
            fn __getreent() -> *mut c_void;
        }
        let _ = __getreent();
    }
    // Set up this worker's pthread-OSAL control block (pspThreadData +
    // cancel eventflag). Needed before any std::sync::Condvar /
    // thread::park / tokio block_on that WAITS, since pthread_cond's
    // pte_osSemaphoreCancellablePend derefs it (NULL on a raw SCE thread
    // => abort). pte_osInit() materializes it; OSAL-only, not the crashing
    // full pthread_init. (S6/S7 finding.)
    unsafe {
        extern "C" {
            fn pte_osInit() -> i32;
        }
        let _ = pte_osInit();
    }
    // Read the boxed-closure pointer from the args buffer. argp is
    // a pointer to a copy of a `*mut BoxedClosure` value.
    let boxed_ptr: *mut BoxedClosure = unsafe { *(argp as *const *mut BoxedClosure) };
    // SAFETY: we leaked exactly one Box in `spawn`; reclaim it.
    let boxed: Box<BoxedClosure> = unsafe { Box::from_raw(boxed_ptr) };
    // Inner Box → FnOnce. Move out + call, CONTAINED: panic=unwind is the
    // staticlib profile, so a panic escaping this `extern "C"` frame is ARM
    // EHABI UB / scheduler corruption. catch_unwind makes the Builder::spawn
    // contract ("on panic the thread simply exits") real for every worker.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (*boxed)()));
    // Exit (NOT delete) so a pending join can wake up.
    unsafe { sceKernelExitThread(0) };
    0
}

pub fn spawn<F>(
    name: Option<String>,
    stack_size: Option<usize>,
    f: F,
) -> io::Result<Handle>
where
    F: FnOnce() + Send + 'static,
{
    let cname = CString::new(name.unwrap_or_else(|| "vita-thread".to_string()))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in thread name"))?;
    let stack: u32 = stack_size
        .unwrap_or(DEFAULT_STACK)
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "stack_size too large for u32"))?;

    let boxed: BoxedClosure = Box::new(f);
    let leaked: *mut BoxedClosure = Box::into_raw(Box::new(boxed));

    let thid = unsafe {
        sceKernelCreateThread(
            cname.as_ptr(),
            thread_entry,
            DEFAULT_PRIORITY,
            stack,
            0,
            0,
            ptr::null(),
        )
    };
    if thid < 0 {
        // Reclaim the closure box to avoid leak on failed create.
        // SAFETY: nothing else has access to `leaked` yet.
        drop(unsafe { Box::from_raw(leaked) });
        return Err(io::Error::other(format!(
            "sceKernelCreateThread failed: 0x{:08x}",
            thid as u32
        )));
    }

    // Pass the pointer value through argp. The kernel copies
    // `arg_len` bytes from our local `leaked_value` into the
    // thread's args buffer; thread_entry reads it back out.
    let leaked_value: *mut BoxedClosure = leaked;
    let arg_len = std::mem::size_of::<*mut BoxedClosure>() as u32;
    let argp = &leaked_value as *const *mut BoxedClosure as *mut c_void;

    let rc = unsafe { sceKernelStartThread(thid, arg_len, argp) };
    if rc < 0 {
        // The thread was created but won't run — reclaim closure,
        // delete the SCE handle.
        drop(unsafe { Box::from_raw(leaked) });
        let _ = unsafe { sceKernelDeleteThread(thid) };
        return Err(io::Error::other(format!(
            "sceKernelStartThread failed: 0x{:08x}",
            rc as u32
        )));
    }

    Ok(Handle(thid))
}

pub fn join(h: Handle) -> io::Result<()> {
    let mut status: c_int = 0;
    // `timeout = null` means wait indefinitely.
    let rc = unsafe { sceKernelWaitThreadEnd(h.0, &mut status, ptr::null_mut()) };
    if rc < 0 {
        return Err(io::Error::other(format!(
            "sceKernelWaitThreadEnd failed: 0x{:08x}",
            rc as u32
        )));
    }
    // Best-effort delete; ignore failures (handle might already be
    // gone if the thread raced).
    let _ = unsafe { sceKernelDeleteThread(h.0) };
    Ok(())
}

/// Non-blocking finished check. Uses `sceKernelWaitThreadEnd` with a
/// zero timeout — returns immediately. SCE_KERNEL_ERROR_WAIT_TIMEOUT
/// (or any negative rc) means "still running"; rc >= 0 means exited.
pub fn is_finished(h: &Handle) -> bool {
    let mut status: c_int = 0;
    let mut timeout: u32 = 0;
    // SAFETY: h.0 is a valid thid we created; status/timeout are
    // stack locals.
    let rc = unsafe { sceKernelWaitThreadEnd(h.0, &mut status, &mut timeout) };
    rc >= 0
}

/// Sleep current thread for `dur`. Uses `sceKernelDelayThread`
/// (microsecond resolution). Pure SCE primitive — no pthread.
pub fn sleep(dur: std::time::Duration) {
    extern "C" {
        fn sceKernelDelayThread(delay_usec: u32) -> c_int;
    }
    // Saturate at u32::MAX microseconds (~71 minutes). Callers
    // wanting longer waits should loop themselves.
    let usecs = dur.as_micros().min(u32::MAX as u128) as u32;
    // SAFETY: no preconditions other than caller is a thread.
    let _ = unsafe { sceKernelDelayThread(usecs) };
}
