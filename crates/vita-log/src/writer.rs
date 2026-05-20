//! Writer thread: drains the global queue, writes lines to the log
//! file, handles rotation. Spawned via `vita_thread::Builder` so
//! it uses an SCE thread on Vita target (no pthread).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::{LogConfig, LOGS_DROPPED, QUEUE};

/// Writer poll cadence. The queue is mutex-protected (no condvar in
/// S1), so we poll. 20 ms is fine for log throughput.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) fn run(cfg: LogConfig) {
    let path = PathBuf::from(&cfg.path);
    let mut state = match WriterState::open(path, cfg) {
        Some(s) => s,
        None => return,
    };

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
        }
        let _ = state.file.flush();

        let dropped = LOGS_DROPPED.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let line = format!("vita_log: dropped {} events\n", dropped);
            state.write_line(&line);
            let _ = state.file.flush();
        }
    }
}

struct WriterState {
    path: PathBuf,
    cfg: LogConfig,
    file: File,
    bytes_written: u64,
}

impl WriterState {
    fn open(path: PathBuf, cfg: LogConfig) -> Option<Self> {
        // Truncate on init: each run gets a fresh log. Rotate-on-size
        // applies within a run (when bytes_written exceeds rotate_bytes).
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .ok()?;
        Some(Self {
            path,
            cfg,
            file,
            bytes_written: 0,
        })
    }

    fn write_line(&mut self, line: &str) {
        if self.file.write_all(line.as_bytes()).is_err() {
            return;
        }
        // Newline if the caller didn't include one.
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
        let _ = self.file.flush();
        let path = &self.path;
        let keep = self.cfg.keep_files as usize;
        for i in (1..=keep).rev() {
            let from = numbered(path, i - 1);
            let to = numbered(path, i);
            let _ = std::fs::remove_file(&to);
            let _ = std::fs::rename(&from, &to);
        }
        let zero = numbered(path, 0);
        let _ = std::fs::remove_file(&zero);
        let _ = std::fs::rename(path, &zero);
        if let Ok(f) = OpenOptions::new().create(true).append(true).open(path) {
            self.file = f;
            self.bytes_written = 0;
        }
    }
}

fn numbered(path: &Path, idx: usize) -> PathBuf {
    let mut p = path.to_path_buf();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("log.txt");
    p.set_file_name(format!("{}.{}", name, idx));
    p
}
