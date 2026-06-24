//! Writer thread: drains the global queue, writes lines via the
//! backend-gated `io` module (SCE-direct on Vita, `std::fs` on host),
//! handles rotation. Spawned via raw `sceKernelCreateThread`
//! in `lib::raw_spawn_writer`.
//!
//! See `lib.rs`'s top-of-file notes for the Vita-specific gotchas
//! (path form, filename, O_APPEND-only fds, cross-thread alloc).

use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::io::{self, File};
use crate::{LogConfig, LOGS_DROPPED, QUEUE};

/// Writer poll cadence. The queue is mutex-protected (no condvar in
/// S1), so we poll. 20 ms is fine for log throughput.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) fn run(cfg: LogConfig) {
    let mut state = match WriterState::open(cfg) {
        Some(s) => s,
        None => return,
    };

    // Run-start marker so each new vita.log session is recognisable.
    // Append-only opens preserve content across runs.
    state.write_line("=== vita-log start ===\n");
    state.reopen_append();

    loop {
        // Drain queue under one lock.
        let drained: Vec<String> = {
            let queue = match QUEUE.get() {
                Some(q) => q,
                None => return,
            };
            let mut q = queue.lock();
            if q.is_empty() {
                Vec::new()
            } else {
                q.drain(..).collect()
            }
        };

        if drained.is_empty() {
            vita_thread::sleep(POLL_INTERVAL);
            continue;
        }

        for line in drained {
            state.write_line(&line);
            // `line` drops here, freeing it on the writer thread. This is
            // safe now: the SUPRX `#[global_allocator]` is `std::alloc::System`
            // (newlib's single global, `__malloc_lock`-protected heap), so a
            // String allocated on the producer thread frees fine here. The old
            // `mem::forget` workaround existed only for taipool, whose
            // alloc/free heap-identity split (System memalign vs taipool free)
            // crashed cross-thread frees — that allocator was dropped in
            // M15-A3 S7. Forgetting instead leaked every drained line at the
            // log-emission rate (~835 KB/s on hardware → 32 MB OOM in ~40 s).
        }

        let dropped = LOGS_DROPPED.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let line = format!("vita_log: dropped {} events\n", dropped);
            state.write_line(&line);
        }

        // Close+reopen forces the kernel to flush metadata so external
        // readers observe the new size. `sceIoSyncByFd` alone does not
        // suffice (verified 2026-06-24 on FTPVita).
        state.reopen_append();
    }
}

struct WriterState {
    cfg: LogConfig,
    file: File,
    bytes_written: u64,
}

impl WriterState {
    fn reopen_append(&mut self) {
        if let Ok(f) = io::File::open_append(&self.cfg.path) {
            self.file = f; // Drop closes the old fd via sceIoClose.
        }
    }

    fn open(cfg: LogConfig) -> Option<Self> {
        // Append-only: the historical "truncate on each run" path was
        // dropped because SCE_O_TRUNC raced with the first
        // sceIoWrite (SCE_KERNEL_ERROR_ERROR), and opening without
        // O_APPEND produced fds that swallowed writes (Vita quirks
        // documented in `lib.rs`).
        let file = io::File::open_append(&cfg.path).ok()?;
        Some(Self {
            cfg,
            file,
            bytes_written: 0,
        })
    }

    fn write_line(&mut self, line: &str) {
        if self.file.write_all(line.as_bytes()).is_err() {
            return;
        }
        if !line.ends_with('\n') {
            let _ = self.file.write_all(b"\n");
            self.bytes_written += 1;
        }
        self.bytes_written += line.len() as u64;
        if self.bytes_written >= self.cfg.rotate_bytes {
            self.rotate();
        }
    }

    fn rotate(&mut self) {
        let path = self.cfg.path.clone();
        let keep = self.cfg.keep_files as usize;
        for i in (1..=keep).rev() {
            let from = numbered(&path, i - 1);
            let to = numbered(&path, i);
            let _ = io::remove(&to);
            let _ = io::rename(&from, &to);
        }
        let zero = numbered(&path, 0);
        let _ = io::remove(&zero);
        let _ = io::rename(&path, &zero);
        if let Ok(f) = io::File::open_append(&path) {
            self.file = f;
            self.bytes_written = 0;
        }
    }
}

fn numbered(path: &str, idx: usize) -> String {
    format!("{}.{}", path, idx)
}
