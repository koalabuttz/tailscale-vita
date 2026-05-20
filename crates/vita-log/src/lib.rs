//! File-mirrored logger for tailscale-vita on PSVita.
//!
//! Vita has no console; `println!` goes to a sink that nothing reads.
//! `vita_log::init()` writes events to `ux0:/data/tailscale-vita/log.txt`
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
//! - A dedicated writer thread (spawned via `vita_thread`) drains
//!   the queue and writes to the log file via `std::fs`.
//! - Queue is a `vita_sync::Mutex<VecDeque<String>>` — no pthread
//!   primitives.
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
//! lose tracing's structured-JSON semantics but log.txt stays
//! human-readable, which is what we need on Vita.

mod error;
mod macros;
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
            path: "ux0:/data/tailscale-vita/log.txt".into(),
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
        std::fs::create_dir_all(parent).map_err(LogError::Open)?;
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
    vita_thread::Builder::new()
        .name("vita-log")
        .stack_size(256 * 1024)
        .spawn(move || writer::run(writer_cfg))
        .map_err(LogError::Open)?;

    let _ = INIT.set(());
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
        now_iso8601_short(),
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

fn now_iso8601_short() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "?".into())
}

/// Strip leading `crates/<crate>/src/` prefix so log lines stay
/// short. Falls back to the full path.
fn short_file(file: &str) -> &str {
    if let Some(idx) = file.find("/src/") {
        &file[idx + "/src/".len()..]
    } else {
        file
    }
}
