//! File-mirrored logger for tailscale-vita on PSVita.
//!
//! Vita has no console; `println!` goes to a sink that nothing reads.
//! `vita_log::init()` writes events to `ux0:data/tailscale-vita/vita.log`
//! (rotated at 10 MiB, last 3 kept).
//!
//! ## Why we don't use `tracing-subscriber`
//!
//! tracing-subscriber uses `thread_local!` internally for span
//! context and the dispatcher cache. On the Vita target,
//! `thread_local!` falls back to pthread_getspecific/setspecific,
//! which crash in the SUPRX context (uninit libpthread state).
//! M15-A2 hardware verification hit this crash 2026-05-13. See
//! `docs/SUPRX-PTHREAD-INVESTIGATION.md` and the M15-A2 deferral
//! notes in `memory/m11_suprx_loader_findings.md`.
//!
//! M15-A3 replaces tracing-subscriber with our own minimal logger:
//! - `vita_log::info!` / `warn!` / `error!` / `debug!` / `trace!`
//!   macros that format and enqueue messages.
//! - A dedicated writer thread (spawned via raw `sceKernelCreateThread`
//!   in `raw_spawn_writer`) drains the queue and writes via SCE I/O.
//! - Queue is a `vita_sync::Mutex<VecDeque<String>>` — no pthread
//!   primitives.
//!
//! ## Vita gotchas surfaced during S1 bring-up (2026-06-24)
//!
//! 1. **Path form**: sceIoOpen with `"ux0:/data/..."` (leading slash
//!    after the mount prefix) silently accepts writes that never
//!    persist. Always use `"ux0:data/..."`.
//! 2. **Filename `log.txt`**: writes to that specific filename in
//!    `ux0:data/tailscale-vita/` did not persist (likely tied to the
//!    historic 40 MiB of `log.txt.{0..3}` left there from the
//!    M1–M10 tracing-subscriber path). We use `vita.log` instead.
//! 3. **Append-only fds**: opening `O_WRONLY|O_CREAT` without
//!    `O_APPEND` produced fds that report write success but never
//!    flushed data to disk. `O_APPEND` works reliably.
//! 4. **vita-thread closure trampoline crashes the SUPRX**: spawning
//!    via `vita_thread::Builder::spawn` (which boxes the closure and
//!    invokes a `Box<dyn FnOnce>` from the SCE-spawned thread) faults
//!    on the first allocation. The writer thread is spawned via raw
//!    `sceKernelCreateThread` instead, with cfg passed through a
//!    static slot (`WRITER_CFG`).
//! 5. **Cross-thread alloc → dealloc**: `TaipoolAllocator` is not
//!    safe for the bootstrap thread to allocate a `String` and the
//!    writer thread to free it. Writer leaks drained `String`s after
//!    writing (workaround in `writer.rs`).
//!
//! ## Macro API
//!
//! Drop-in compatible with the most common `tracing` forms:
//! - `info!("plain message")`
//! - `info!("formatted: {}", x)`
//! - `info!(key = %expr, "msg")` — `%expr` formats via Display
//! - `info!(key = ?expr, "msg")` — `?expr` formats via Debug
//! - `info!(key = expr, "msg")` — formats via Display
//! - Combinations of the above.
//!
//! Field names are formatted inline (`key=value message`) — we
//! lose tracing's structured-JSON semantics but the log file stays
//! human-readable, which is what we need on Vita.

mod error;
mod io;
mod macros;
mod timestamp;
mod writer;

pub use error::LogError;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use vita_sync::{Mutex, OnceLock};

/// Total events dropped due to queue overflow since process start.
pub static LOGS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Initialization guard. `init()` is idempotent — a second call
/// returns `LogError::AlreadyInitialized`.
static INIT: OnceLock<()> = OnceLock::new();

/// Global filter level. Set by `init_with_config`. Events below
/// this level are dropped at the macro entry point.
static FILTER_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Bounded queue of pending log lines. The writer thread drains it.
/// We use a vita_sync::Mutex (SCE-backed on Vita target) to avoid
/// the thread_local!/parking_lot dependencies of crossbeam-channel.
static QUEUE: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

/// Max in-flight log lines. Beyond this, new events are dropped
/// (LOGS_DROPPED incremented).
const QUEUE_CAP: usize = 1024;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogConfig {
    pub path: String,
    pub filter: String,
    pub rotate_bytes: u64,
    pub keep_files: u8,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            path: "ux0:data/tailscale-vita/vita.log".into(),
            filter: "info".into(),
            rotate_bytes: 10 * 1024 * 1024,
            keep_files: 3,
        }
    }
}

/// Initialize with default config. Idempotent.
pub fn init() -> Result<(), LogError> {
    init_with_config(LogConfig::default())
}

/// Initialize with a custom config. Idempotent.
pub fn init_with_config(cfg: LogConfig) -> Result<(), LogError> {
    if INIT.get().is_some() {
        return Err(LogError::AlreadyInitialized);
    }
    if let Some(parent) = std::path::Path::new(&cfg.path).parent() {
        if let Some(parent_str) = parent.to_str() {
            io::mkdir_p(parent_str).map_err(LogError::Open)?;
        }
    }

    // Parse filter string. Just the level prefix for now; tracing's
    // per-target filter syntax (e.g., "info,h2=warn") is out of
    // scope for S1.
    let level = match cfg.filter.as_str().split(',').next().unwrap_or("info") {
        "error" => Level::Error,
        "warn" => Level::Warn,
        "info" => Level::Info,
        "debug" => Level::Debug,
        "trace" => Level::Trace,
        _ => Level::Info,
    };
    FILTER_LEVEL.store(level as u8, Ordering::Release);

    // Install the queue *before* spawning the writer, so any racing
    // emit call sees a valid queue (else it'd drop the event).
    let _ = QUEUE.set(Mutex::new(VecDeque::with_capacity(QUEUE_CAP)));

    let writer_cfg = cfg.clone();
    raw_spawn_writer(writer_cfg).map_err(LogError::Open)?;

    let _ = INIT.set(());
    Ok(())
}

/// On Vita, spawn the writer thread via raw `sceKernelCreateThread`
/// rather than through `vita_thread::Builder::spawn`. The latter
/// uses a `Box<dyn FnOnce>` trampoline, and invoking it from a
/// SCE-spawned thread crashes the SUPRX on the first allocation
/// the closure performs (verified 2026-06-24). Cfg is handed off
/// via a static slot to avoid the closure capture entirely.
#[cfg(target_os = "vita")]
static mut WRITER_CFG: Option<LogConfig> = None;

#[cfg(target_os = "vita")]
unsafe extern "C" fn raw_writer_entry(
    _args: u32,
    _argp: *mut std::ffi::c_void,
) -> i32 {
    let cfg = unsafe {
        WRITER_CFG
            .take()
            .unwrap_or_else(LogConfig::default)
    };
    // Catch any panic before it crosses the extern "C" boundary (UB).
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        writer::run(cfg);
    }));
    extern "C" {
        fn sceKernelExitDeleteThread(status: i32) -> i32;
    }
    unsafe { sceKernelExitDeleteThread(0) }
}

#[cfg(target_os = "vita")]
fn raw_spawn_writer(cfg: LogConfig) -> std::io::Result<()> {
    use std::ffi::{c_char, c_int, c_void};
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
    }
    // SAFETY: writer-thread spawn is one-shot at init; no other
    // writer racing with us. The take() in raw_writer_entry runs
    // after sceKernelStartThread (an SCE memory barrier).
    unsafe {
        WRITER_CFG = Some(cfg);
    }
    let thid = unsafe {
        sceKernelCreateThread(
            c"vita-log".as_ptr(),
            raw_writer_entry,
            0x40,
            256 * 1024,
            0,
            0,
            std::ptr::null(),
        )
    };
    if thid < 0 {
        return Err(std::io::Error::other(format!(
            "sceKernelCreateThread failed: 0x{:08x}",
            thid as u32
        )));
    }
    let rc = unsafe { sceKernelStartThread(thid, 0, std::ptr::null_mut()) };
    if rc < 0 {
        return Err(std::io::Error::other(format!(
            "sceKernelStartThread failed: 0x{:08x}",
            rc as u32
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "vita"))]
fn raw_spawn_writer(cfg: LogConfig) -> std::io::Result<()> {
    std::thread::spawn(move || writer::run(cfg));
    Ok(())
}

/// Internal entry point invoked by the `info!`/`warn!`/... macros.
/// Hidden from docs.
#[doc(hidden)]
pub fn __emit(level: Level, file: &'static str, line: u32, args: std::fmt::Arguments<'_>) {
    if (level as u8) > FILTER_LEVEL.load(Ordering::Relaxed) {
        return;
    }
    let queue = match QUEUE.get() {
        Some(q) => q,
        None => return, // init() hasn't run; silently drop.
    };
    let line_text = format!(
        "{} {} {}:{} {}",
        timestamp::format(),
        level.as_str(),
        short_file(file),
        line,
        args
    );
    let mut q = queue.lock();
    if q.len() >= QUEUE_CAP {
        LOGS_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    q.push_back(line_text);
}

/// Best-effort flush: yields + sleeps so the writer can drain.
pub fn flush() {
    vita_thread::sleep(std::time::Duration::from_millis(50));
}

// ============================================================
// Helpers
// ============================================================

/// Strip leading `crates/<crate>/src/` prefix so log lines stay
/// short. Falls back to the full path.
fn short_file(file: &str) -> &str {
    if let Some(idx) = file.find("/src/") {
        &file[idx + "/src/".len()..]
    } else {
        file
    }
}
