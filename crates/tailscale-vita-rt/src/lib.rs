//! tailscale-vita-rt — Phase 1C: Rust staticlib with taipool-backed
//! global allocator.
//!
//! The C SUPRX shim (crates/tailscale-vita-plugin) calls
//! `taipool_init(N)` in `module_start` BEFORE invoking any Rust code,
//! then calls `ts_vita_rt_hello`. From that point on, every Rust
//! allocation (Box, Vec, String, …) routes through `TaipoolAllocator`,
//! which calls back into `taipool_alloc` / `taipool_free`.
//!
//! Phase 1D will add a Rust-spawned thread for the runtime body.
//! Phase 2 wires `tailscale-vita::Runtime` through.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{c_char, c_int, c_void};
use core::ptr;

// ---------------- SCE / taipool FFI ----------------

extern "C" {
    fn sceClibPrintf(fmt: *const c_char, ...) -> c_int;
    fn sceIoOpen(path: *const c_char, flag: c_int, mode: c_int) -> c_int;
    fn sceIoWrite(fd: c_int, buf: *const c_void, len: u32) -> c_int;
    fn sceIoClose(fd: c_int) -> c_int;

    fn taipool_alloc(size: usize) -> *mut c_void;
    fn taipool_free(ptr: *mut c_void);
    fn taipool_get_free_space() -> usize;

    // Phase 1D thread API.
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
    fn sceKernelDelayThread(delay_us: u32) -> c_int;
    fn sceKernelExitDeleteThread(status: c_int) -> c_int;
    fn sceKernelGetProcessTimeWide() -> u64;
}

const SCE_O_WRONLY: c_int = 0x0002;
const SCE_O_CREAT: c_int = 0x0200;
const SCE_O_TRUNC: c_int = 0x0400;
const SCE_MODE: c_int = 0o666;

const RUST_HELLO_PATH: &core::ffi::CStr = c"ux0:data/tailscale-vita/rust-hello.txt";
const THREAD_HELLO_PATH: &core::ffi::CStr = c"ux0:data/tailscale-vita/thread-hello.txt";

/// Phase 1D iteration count. The thread overwrites
/// `thread-hello.txt` once per second; after `THREAD_ITERS` it exits
/// cleanly. Keep small so an FTP-poll over the 5-second window can
/// see the counter advance.
const THREAD_ITERS: u32 = 5;
const THREAD_TICK_US: u32 = 1_000_000;
const THREAD_STACK: u32 = 64 * 1024;
const THREAD_PRIORITY: c_int = 0x40;

// ---------------- Global allocator ----------------

/// Wraps taipool. taipool_alloc returns 4-byte-aligned blocks (ARM
/// libc malloc convention) but Rust types frequently require 8/16-byte
/// alignment — so we over-allocate, manually align, and stash the
/// raw pointer one usize before the aligned pointer for `free`.
///
/// Layout invariants:
///   raw         = taipool_alloc(size + align + sizeof(usize))
///   user_ptr    = align_up(raw + sizeof(usize), align)
///   prefix     := *(user_ptr - sizeof(usize)) = raw
struct TaipoolAllocator;

const PREFIX: usize = core::mem::size_of::<usize>();

unsafe impl GlobalAlloc for TaipoolAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(PREFIX);
        let total = match layout
            .size()
            .checked_add(align)
            .and_then(|s| s.checked_add(PREFIX))
        {
            Some(t) => t,
            None => return ptr::null_mut(),
        };

        // SAFETY: extern C call. Returns null on OOM, which we propagate.
        let raw = unsafe { taipool_alloc(total) } as usize;
        if raw == 0 {
            return ptr::null_mut();
        }
        let user = (raw + PREFIX + align - 1) & !(align - 1);
        // SAFETY: `user - PREFIX` is within the [raw, raw+total) region
        // and aligned to usize (since align >= PREFIX and user is align-aligned).
        unsafe {
            *((user - PREFIX) as *mut usize) = raw;
        }
        user as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: `ptr` was produced by our `alloc`, so the prefix
        // word holds the original taipool-returned pointer.
        let raw = unsafe { *((ptr as usize - PREFIX) as *const usize) };
        unsafe { taipool_free(raw as *mut c_void) };
    }
}

#[global_allocator]
static ALLOCATOR: TaipoolAllocator = TaipoolAllocator;

// `alloc::handle_alloc_error` calls this when allocation fails.
// The default unstable handler isn't available in no_std without the
// `alloc_error_handler` feature — we provide a stable one ourselves.
#[cfg(not(test))]
#[no_mangle]
extern "C" fn rust_oom() -> ! {
    unsafe {
        sceClibPrintf(c"[ts-vita] rust OOM (taipool exhausted)\n".as_ptr());
    }
    loop {
        core::hint::spin_loop();
    }
}

// ---------------- Phase 1C entry point ----------------

/// Phase 1C: prove the global allocator works by exercising
/// `String`, `Vec`, and friends. Writes a heap-built message to
/// rust-hello.txt and returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ts_vita_rt_hello() -> c_int {
    // SAFETY: each block calls into FFI with valid pointers + sizes.
    unsafe {
        sceClibPrintf(
            c"[ts-vita] ts_vita_rt_hello() entry; taipool_free=%u bytes\n".as_ptr(),
            taipool_get_free_space() as u32,
        );

        // Heap-built message — proves allocator + UTF-8 + reallocation.
        let mut msg = String::from("hello from rust + taipool ");
        msg.push_str("(global allocator OK, ");
        let mut numbers: Vec<u8> = Vec::with_capacity(4);
        numbers.push(1);
        numbers.push(2);
        numbers.push(3);
        numbers.push(4);
        // Force a realloc to exercise dealloc.
        numbers.shrink_to_fit();
        let sum: u32 = numbers.iter().map(|&n| n as u32).sum();
        // Push digits without using format_args!/write! (those need
        // intermediate alloc but should work; this is a smaller test).
        msg.push_str("sum=");
        push_u32(&mut msg, sum);
        msg.push_str(")\n");

        let fd = sceIoOpen(
            RUST_HELLO_PATH.as_ptr(),
            SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC,
            SCE_MODE,
        );
        if fd < 0 {
            sceClibPrintf(
                c"[ts-vita] sceIoOpen(rust-hello.txt) -> %d\n".as_ptr(),
                fd,
            );
            return fd;
        }
        let written = sceIoWrite(
            fd,
            msg.as_ptr() as *const c_void,
            msg.len() as u32,
        );
        let _ = sceIoClose(fd);

        sceClibPrintf(
            c"[ts-vita] ts_vita_rt_hello() done; taipool_free=%u bytes after\n".as_ptr(),
            taipool_get_free_space() as u32,
        );

        if written < 0 {
            return written;
        }
        0
    }
}

fn push_u32(s: &mut String, mut n: u32) {
    if n == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0usize;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        s.push(buf[i] as char);
    }
}

fn push_u64(s: &mut String, mut n: u64) {
    if n == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        s.push(buf[i] as char);
    }
}

// ---------------- Phase 1D: spawn a Rust-owned worker thread ----------------

/// SCE thread entry. Called by `sceKernelStartThread` on a fresh
/// worker thread. Loops `THREAD_ITERS` times, sleeping
/// `THREAD_TICK_US` between writes; each iteration overwrites
/// `thread-hello.txt` with the current iter + the SCE process clock.
/// Exits the thread cleanly on completion (exit status 0).
unsafe extern "C" fn rust_thread_main(_args: u32, _argp: *mut c_void) -> i32 {
    // SAFETY: every FFI call passes static C strings or local
    // buffers. Allocations route through the taipool global allocator
    // which the C side initialised before launching us.
    unsafe {
        sceClibPrintf(c"[ts-vita] rust thread alive\n".as_ptr());

        for iter in 1..=THREAD_ITERS {
            let t = sceKernelGetProcessTimeWide();

            let mut msg = String::with_capacity(64);
            msg.push_str("rust thread iter=");
            push_u32(&mut msg, iter);
            msg.push_str(" t_us=");
            push_u64(&mut msg, t);
            if iter == THREAD_ITERS {
                msg.push_str(" done");
            }
            msg.push('\n');

            let fd = sceIoOpen(
                THREAD_HELLO_PATH.as_ptr(),
                SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC,
                SCE_MODE,
            );
            if fd >= 0 {
                sceIoWrite(fd, msg.as_ptr() as *const c_void, msg.len() as u32);
                sceIoClose(fd);
            }

            sceKernelDelayThread(THREAD_TICK_US);
        }

        sceClibPrintf(c"[ts-vita] rust thread exiting cleanly\n".as_ptr());
        sceKernelExitDeleteThread(0)
    }
}

/// Spawn the worker thread. Returns the SCE thread id (>0) on
/// success, or a negative SCE error on failure. The thread runs
/// asynchronously — `module_start` returns immediately after this.
#[no_mangle]
pub unsafe extern "C" fn ts_vita_rt_start_thread() -> c_int {
    // SAFETY: name + entry are static; arg/option are null. Any
    // failure is logged and surfaced as a negative return.
    unsafe {
        let thid = sceKernelCreateThread(
            c"ts-vita-rt".as_ptr(),
            rust_thread_main,
            THREAD_PRIORITY,
            THREAD_STACK,
            0,
            0,
            core::ptr::null(),
        );
        if thid < 0 {
            sceClibPrintf(
                c"[ts-vita] sceKernelCreateThread -> %d\n".as_ptr(),
                thid,
            );
            return thid;
        }
        let rc = sceKernelStartThread(thid, 0, core::ptr::null_mut());
        if rc < 0 {
            sceClibPrintf(
                c"[ts-vita] sceKernelStartThread(thid=%d) -> %d\n".as_ptr(),
                thid,
                rc,
            );
            return rc;
        }
        sceClibPrintf(
            c"[ts-vita] rust thread spawned, thid=%d\n".as_ptr(),
            thid,
        );
        thid
    }
}

// ---------------- no_std plumbing ----------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        sceClibPrintf(c"[ts-vita] rust staticlib panicked\n".as_ptr());
    }
    loop {
        core::hint::spin_loop();
    }
}
