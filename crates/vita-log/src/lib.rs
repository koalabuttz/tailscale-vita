//! File-mirrored `tracing` subscriber for tailscale-vita on PSVita.
//!
//! Vita has no console; `println!` goes to a sink that nothing reads.
//! `vita_log::init()` writes structured `tracing` events to
//! `ux0:/data/tailscale-vita/log.txt` (rotated at 10 MiB, last 3 kept)
//! and optionally mirrors to stdout for emulator runs.
//!
//! Producer threads never block on slow Vita-FS writes: the file layer
//! pushes formatted events onto a bounded `crossbeam-channel` (cap 1024)
//! drained by a dedicated `vita-log` writer thread. On overflow, events
//! are dropped and a `WARN` line is emitted with the running count.

use std::sync::atomic::AtomicU64;
use std::sync::OnceLock;

mod error;
mod panic;
mod writer;

pub use error::LogError;

/// Total events dropped due to channel overflow since process start.
/// Reset to 0 each time the writer thread emits a WARN summary line.
pub static LOGS_DROPPED: AtomicU64 = AtomicU64::new(0);

static INIT: OnceLock<()> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct LogConfig {
    /// File path. Default: `ux0:/data/tailscale-vita/log.txt`.
    pub path: String,
    /// `tracing-subscriber` filter expression (e.g. `"info,h2=warn"`).
    /// Default: `$TS_VITA_LOG` if set, else `"info"`.
    pub filter: String,
    /// Rotate when this size is exceeded. Default 10 MiB.
    pub rotate_bytes: u64,
    /// Number of rotated files kept. Default 3 (so total disk = 4 × rotate_bytes).
    pub keep_files: u8,
    /// Mirror events to stdout. Useful in Vita3K and on dev hosts.
    pub stdout_mirror: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            path: "ux0:/data/tailscale-vita/log.txt".into(),
            filter: std::env::var("TS_VITA_LOG").unwrap_or_else(|_| "info".into()),
            rotate_bytes: 10 * 1024 * 1024,
            keep_files: 3,
            stdout_mirror: true,
        }
    }
}

/// Initialize the global tracing subscriber with default config.
/// Idempotent: a second call returns `LogError::AlreadyInitialized`.
pub fn init() -> Result<(), LogError> {
    init_with_config(LogConfig::default())
}

/// Initialize with a custom `LogConfig`.
pub fn init_with_config(cfg: LogConfig) -> Result<(), LogError> {
    if INIT.get().is_some() {
        return Err(LogError::AlreadyInitialized);
    }

    if let Some(parent) = std::path::Path::new(&cfg.path).parent() {
        std::fs::create_dir_all(parent).map_err(LogError::Open)?;
    }

    let (tx, rx) = crossbeam_channel::bounded::<Vec<u8>>(1024);

    let writer_path = std::path::PathBuf::from(&cfg.path);
    let writer_cfg = cfg.clone();
    std::thread::Builder::new()
        .name("vita-log".into())
        .stack_size(256 * 1024)
        .spawn(move || writer::run(rx, writer_path, writer_cfg))
        .map_err(LogError::Open)?;

    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    let targets: Targets = cfg
        .filter
        .parse()
        .map_err(|e: tracing_subscriber::filter::ParseError| {
            LogError::InvalidFilter(e.to_string())
        })?;

    let make_writer = writer::ChannelMakeWriter::new(tx);

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(make_writer)
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .with_filter(targets.clone());

    let stdout_layer = if cfg.stdout_mirror {
        Some(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .with_filter(targets),
        )
    } else {
        None
    };

    let subscriber = tracing_subscriber::Registry::default()
        .with(file_layer)
        .with(stdout_layer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| LogError::Subscriber(e.to_string()))?;

    panic::install_panic_hook();
    let _ = INIT.set(());

    tracing::info!(path = %cfg.path, "log initialized");
    Ok(())
}

/// Best-effort flush. Yields, sleeps briefly to let the writer drain.
/// The writer flushes after every batch already.
pub fn flush() {
    std::thread::yield_now();
    std::thread::sleep(std::time::Duration::from_millis(10));
}
