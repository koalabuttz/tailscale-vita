//! tailscale-vita-rt — Phase 2 SUPRX bridge to `tailscale-vita::Runtime`.
//!
//! Module-load flow (in C `module_start`, see crates/tailscale-vita-plugin):
//!
//!   1. `taipool_init(N)` — backs Rust's `#[global_allocator]`.
//!   2. `ts_vita_rt_start()` — installs vita-log, spawns the bootstrap
//!      thread (`ts-vita-rt-bootstrap`), returns immediately so
//!      `module_start` can return SCE_KERNEL_START_SUCCESS.
//!   3. Inside the bootstrap thread (wrapped in `catch_unwind`):
//!      `run_runtime()` waits 3s for SceShell's net stack to settle,
//!      loads `Config`, brings up `Runtime`, binds a `TcpListener` on
//!      the tailnet IP:port, spawns a worker thread for
//!      `Runtime::run_event_loop`, then runs the accept loop until
//!      `ts_vita_rt_stop` flips `SHUTDOWN`.
//!   4. `ts_vita_rt_stop()` — flips `SHUTDOWN`, joins the bootstrap
//!      thread (which has already cleanly torn down listener +
//!      runtime).
//!
//! `TaipoolAllocator` is the same Phase 1C allocator with the
//! over-alloc-+-prefix-pointer alignment trick (taipool returns
//! 4-byte-aligned blocks, Rust Layout demands up to 16).

use std::alloc::{GlobalAlloc, Layout};
use std::ffi::{c_char, c_int, c_void};
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use vita_chan::{bounded, TryRecvError};
use vita_log::{error, info, warn};

use netstack::TcpListener;
use tailscale_vita::{Config, ConfigError, Runtime};
use vita_log::LogError;

mod handler;

const CONFIG_PATH: &str = "ux0:/data/tailscale-vita/config.toml";
const ACCEPT_POLL: Duration = Duration::from_millis(500);
const NET_SETTLE: Duration = Duration::from_secs(3);

// ---------------- Diagnostic trace (matches main.c's TRACE_PATH) ----------------
//
// Phase 2 bring-up: write checkpoint markers via raw sceIo before
// touching any Rust-runtime machinery (vita-log, std::thread, etc.)
// so we can tell from FTP how far we got. Direct FFI, no allocations.

extern "C" {
    fn sceIoOpen(path: *const c_char, flag: i32, mode: i32) -> i32;
    fn sceIoWrite(fd: i32, buf: *const c_void, len: u32) -> i32;
    fn sceIoClose(fd: i32) -> i32;

    // Phase 2 std::thread::spawn from extern "C" context turns out to
    // be broken (Phase 2 risk #14 hit on hardware 2026-05-05). Bootstrap
    // the runtime thread via the SCE thread API instead — same approach
    // that worked in Phase 1D.
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
    fn sceKernelExitDeleteThread(status: c_int) -> c_int;

    // Phase 2 diagnostic: try pthread_create directly. If this works
    // from SCE-bootstrap context, we know pthread is functional and
    // std::thread::spawn's wrapper is the issue. If it crashes too,
    // pthread itself isn't initialized from non-pthread parent
    // threads and we need a different bootstrap path.
    fn pthread_create(
        thread: *mut usize,
        attr: *const c_void,
        start_routine: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> c_int;
    fn pthread_join(thread: usize, retval: *mut *mut c_void) -> c_int;
}

unsafe extern "C" fn pthread_smoke_target(_arg: *mut c_void) -> *mut c_void {
    trace("pt-target: hello from pthread-direct child");
    ptr::null_mut()
}

// M15-A2: pthread_init/_init_vita_reent extern decls deleted —
// the SUPRX no longer calls into libc-pthread at all. See
// docs/SUPRX-PTHREAD-INVESTIGATION.md for why. Thread spawning is
// now routed through the `vita-thread` crate (sceKernelCreateThread
// directly). libpthread is still linked to satisfy compile-time
// symbol resolution for std::thread types appearing in compiled
// Rust code, but no runtime path enters it.

const SCE_O_WRONLY: i32 = 0x0002;
const SCE_O_CREAT: i32 = 0x0200;
const SCE_O_APPEND: i32 = 0x0100;

fn trace(msg: &str) {
    let path = c"ux0:data/tailscale-vita/phase2-trace.txt".as_ptr();
    // SAFETY: path is static C-string. Best-effort write; ignore errors.
    unsafe {
        let fd = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0o666);
        if fd >= 0 {
            let _ = sceIoWrite(fd, msg.as_ptr() as *const c_void, msg.len() as u32);
            let _ = sceIoWrite(fd, b"\n".as_ptr() as *const c_void, 1);
            let _ = sceIoClose(fd);
        }
    }
}

// ---------------- Global allocator (Phase 1C, kept) ----------------

extern "C" {
    fn taipool_alloc(size: usize) -> *mut c_void;
    fn taipool_free(ptr: *mut c_void);
}

const PREFIX: usize = std::mem::size_of::<usize>();

struct TaipoolAllocator;

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
        // SAFETY: extern C alloc; null-checked.
        let raw = unsafe { taipool_alloc(total) } as usize;
        if raw == 0 {
            return ptr::null_mut();
        }
        let user = (raw + PREFIX + align - 1) & !(align - 1);
        // SAFETY: `user - PREFIX` lies in [raw, raw+total) and is
        // usize-aligned (align >= PREFIX, user is align-aligned).
        unsafe {
            *((user - PREFIX) as *mut usize) = raw;
        }
        user as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: ptr was produced by our `alloc` so the prefix word
        // holds the original taipool pointer.
        let raw = unsafe { *((ptr as usize - PREFIX) as *const usize) };
        unsafe { taipool_free(raw as *mut c_void) };
    }
}

// S7: Rust's Global allocator is now newlib's System (malloc/free/memalign),
// NOT the hand-rolled TaipoolAllocator. TaipoolAllocator's prefix-pointer
// scheme corrupted under toml's allocation pattern (taipool_free crash on a
// zeroed prefix word). newlib's heap + malloc are now initialised in
// module_start (_init_vita_heap/_init_vita_malloc) and proven working
// (thread_local/tokio ran on System), so unifying ALL allocation (Rust
// Global + std::alloc::System + C libc) on one tested newlib heap removes
// the custom-allocator bug class. TaipoolAllocator is kept below but unused.
#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

// ---------------- Runtime entry points (Phase 2B) ----------------

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// SCE-thread entry point: this is the bootstrap thread that owns the
/// rest of the runtime startup (vita-log init, Runtime::up, listener,
/// accept loop). We came here from sceKernelStartThread, scheduled
/// from `ts_vita_rt_start` after the C side had already initialised
/// taipool. Phase 2 lesson: spawning std::thread directly from FFI
/// context fails — vita_log::init's writer-thread spawn returns
/// LogError::Open(io::Error). A SCE-spawned thread that THEN calls
/// std::thread::Builder works fine (verified in Phase 1D for the
/// thread-spawn case; here we extend the pattern to vita-log).
unsafe extern "C" fn bootstrap_main(_args: u32, _argp: *mut c_void) -> i32 {
    trace("rb1: bootstrap thread entry");

    // PERMANENT raw-sceIo panic hook. std's default backtrace machinery
    // (gimli/addr2line) crashes in taipool_free in this SUPRX (S6), so this
    // is the ONLY working panic diagnostic — it traces message+location
    // directly, and fires at panic time regardless of whether unwinding
    // works. Keep it for the life of the plugin.
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<no loc>".to_string());
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("<non-str payload>");
        trace(&format!("PANIC at {}: {}", loc, msg));
    }));
    trace("rb-hook: panic hook installed");

    // Materialize THIS thread's newlib _REENT (TLS slot 0x89) before any
    // libc call. The bootstrap thread is a raw sceKernelCreateThread spawn
    // (not via vita_thread, which touches reent in its trampoline), and
    // run_runtime's first acts — Config::load (std::fs), OsRng/getentropy,
    // std::sync::Mutex, Instant::now — all deref _REENT. Without this it
    // regresses to the pre-S6 crash. __getreent self-heals (module_start
    // ran _init_vita_reent). [S7 must-fix #2 — was in the deleted run_probe.]
    unsafe {
        extern "C" {
            fn __getreent() -> *mut c_void;
        }
        let _ = __getreent();
    }
    trace("rb-reent: bootstrap reent touched");

    // Set up THIS thread's pthread-OSAL control block (pspThreadData with a
    // cancellation eventflag). pte_osSemaphoreCancellablePend — the
    // pthread_cond/park path std (and thus tokio's block_on) uses when it
    // WAITS for I/O — derefs it; on a raw SCE thread it's NULL => data abort
    // (the register-step crash). pte_osInit() materializes it (proven in the
    // S6 spike, v5). This is the OSAL init only, NOT the crashing full
    // pthread_init. Idempotent enough: one call per thread, sets its slot.
    unsafe {
        extern "C" {
            fn pte_osInit() -> i32;
        }
        let _ = pte_osInit();
    }
    trace("rb-pte: pte_osInit done (thread parkable)");

    // One-shot probe: does ARM EHABI unwinding actually work in this
    // -nostartfiles SUPRX? If catch_unwind contains this panic we get
    // "uw-ok" and the panic boundaries (here + vita_thread) are real; if
    // unwinding is broken the process dies at the panic (the hook's PANIC
    // line is the last marker) and we'd switch to panic="abort".
    let uw = std::panic::catch_unwind(|| panic!("unwind-probe"));
    trace(if uw.is_err() {
        "uw-ok: unwinding works (panic contained)"
    } else {
        "uw-BAD: catch_unwind returned Ok (impossible)"
    });

    // S7: run the REAL runtime, contained. run_runtime does Config::load ->
    // Runtime::up (register over Noise+h2 on a tokio current-thread rt) ->
    // TcpListener::bind -> spawn event-loop worker -> accept loop.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run_runtime));

    trace("rb-end: run_runtime returned; exiting bootstrap");

    // SAFETY: extern C call to exit cleanly.
    unsafe { sceKernelExitDeleteThread(0) }
}

/// C entry point: spawn the bootstrap thread via the SCE thread API
/// and return. Called from `module_start` AFTER `taipool_init`
/// succeeded. Returns 0 on success, negative SCE error on failure.
#[no_mangle]
pub unsafe extern "C" fn ts_vita_rt_start() -> i32 {
    trace("r1: ts_vita_rt_start entry");

    SHUTDOWN.store(false, Ordering::SeqCst);

    trace("r2: pre-sceKernelCreateThread");
    // SAFETY: name + entry are statics; arg/option null. Negative
    // return = SCE error code, propagated to C.
    let thid = unsafe {
        sceKernelCreateThread(
            c"ts-vita-rt-boot".as_ptr(),
            bootstrap_main,
            0x40,            // priority (matches vitacompanion)
            // S7: 4 MB stack. The bootstrap thread runs the whole
            // synchronous bring-up on one stack — toml/serde parsing
            // (very stack-heavy), then rustls + h2 + Noise handshakes
            // (big cert/frame buffers). The old 256 KB overflowed in
            // toml::from_str (hard abort, no panic) where the eboot's
            // ~1 MB main thread does not. Generous here; tune later.
            4 * 1024 * 1024, // stack
            0,
            0,
            ptr::null(),
        )
    };
    if thid < 0 {
        trace("r3: sceKernelCreateThread failed");
        return thid;
    }

    trace("r4: pre-sceKernelStartThread");
    // SAFETY: thid is valid (just created); no args.
    let rc = unsafe { sceKernelStartThread(thid, 0, ptr::null_mut()) };
    if rc < 0 {
        trace("r5: sceKernelStartThread failed");
        return rc;
    }

    trace("r6: spawn ok; returning 0");
    0
}

/// C entry point: signal shutdown. Called from `module_stop`. The
/// bootstrap thread polls `SHUTDOWN` and exits via
/// `sceKernelExitDeleteThread`; we don't explicitly join it here
/// because we use SCE threads (no JoinHandle). Best-effort: by the
/// time module_stop runs, the SUPRX is being torn down anyway.
#[no_mangle]
pub unsafe extern "C" fn ts_vita_rt_stop() {
    trace("rs1: ts_vita_rt_stop entry");
    SHUTDOWN.store(true, Ordering::SeqCst);
}

// ---------------- Runtime body (Phase 2C) ----------------

/// Bootstrap-thread body. Mirrors `crates/tailscale-vita-demo::run`
/// but driven by `SHUTDOWN` instead of a wall-clock deadline.
fn run_runtime() {
    trace("rr1: run_runtime entry");
    info!("suprx.runtime.start");

    // One-shot WG data-plane crypto self-test, BEFORE any network setup so it's
    // fully isolated (no sockets, no peers) and runs even if the control plane
    // never comes up. Collapses the data-plane bug fork: VERDICT=
    // AEAD_NONEMPTY_MISCOMPILE (on-device crypto) vs CRYPTO_OK_NETWORK_SUSPECT
    // (UDP egress). See memory wg_dataplane_peer_session_bug.
    trace(&format!("wgst: {}", tailscale_vita::wg_selftest_line()));

    // Mirror vitacompanion's pattern: SUPRX is injected before
    // SceShell's network stack is fully ready. 3s pause keeps us out
    // of `sceNetCtlInetGetState`-races.
    trace("rr2: pre-NET_SETTLE sleep");
    std::thread::sleep(NET_SETTLE);
    trace("rr3: post-NET_SETTLE sleep");

    let cfg = match Config::load_or_template(Path::new(CONFIG_PATH)) {
        Ok(c) => { trace("rr4: config load Ok"); c }
        Err(ConfigError::TemplateWritten { path }) => {
            trace("rr4: config template written");
            warn!(path = %path, "suprx: config template written; fill auth_key + relaunch");
            return;
        }
        Err(e) => {
            trace("rr4: config load FAILED");
            error!(error = %e, "suprx: config load failed");
            return;
        }
    };
    info!(
        control_url = %cfg.control_url,
        hostname = %cfg.hostname,
        demo_port = cfg.demo_port,
        listener_pool_size = cfg.listener_pool_size,
        suprx_host_only = cfg.suprx_host_only,
        "suprx.config.loaded"
    );

    // M18: an empty auth_key is no longer an abort — it means
    // interactive (QR) login. Runtime::up publishes NeedsLogin + the
    // AuthURL into the snapshot and long-polls until the user approves.

    let port = cfg.demo_port;
    let pool = cfg.listener_pool_size;

    trace("rr5: pre-Runtime::up");
    let mut runtime = match Runtime::up(cfg) {
        Ok(r) => { trace("rr6: Runtime::up Ok"); r }
        Err(e) => {
            trace("rr6: Runtime::up FAILED");
            error!(error = %e, "suprx: runtime.up failed");
            return;
        }
    };
    info!("suprx.runtime.up");

    let listener = match TcpListener::bind(runtime.netstack(), port, pool) {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "suprx: listener bind failed");
            runtime.shutdown();
            return;
        }
    };
    info!(port, pool, "suprx.listen");

    // Worker thread for run_event_loop — same two-thread shape as the
    // demo. The worker owns `runtime` (so it can call `shutdown()` on
    // exit); the bootstrap thread runs the accept loop.
    let (stop_tx, stop_rx) = bounded::<()>(1);
    let worker = vita_thread::Builder::new()
        .name("ts-vita-rt-event")
        .stack_size(256 * 1024)
        .spawn(move || {
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(move || {
                let stats = runtime.run_event_loop(|| match stop_rx.try_recv() {
                    Ok(()) | Err(TryRecvError::Disconnected) => true,
                    Err(TryRecvError::Empty) => false,
                });
                match stats {
                    Ok(s) => info!(?s, "suprx.runtime.exit"),
                    Err(e) => error!(error = %e, "suprx.runtime.exit.error"),
                }
                runtime.shutdown();
            }));
            if outcome.is_err() {
                error!("suprx: event-loop worker panicked");
            }
        })
        .expect("spawn ts-vita-rt-event worker");

    // Accept loop, exits when ts_vita_rt_stop flips SHUTDOWN.
    let mut accept_count: u32 = 0;
    while !SHUTDOWN.load(Ordering::Relaxed) {
        match listener.accept_timeout(ACCEPT_POLL) {
            Ok((stream, peer)) => {
                accept_count += 1;
                info!(%peer, count = accept_count, "suprx.accept");
                handler::serve(stream, peer);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(e) => {
                warn!(error = %e, "suprx.accept.error");
                break;
            }
        }
    }

    let _ = stop_tx.send(());
    let _ = worker.join();
    drop(listener);
    info!(accept_count, "suprx.runtime.shutdown");
}
