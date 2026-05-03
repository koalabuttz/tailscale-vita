use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use crossbeam_channel::{Receiver, Sender, TrySendError};
use tracing_subscriber::fmt::MakeWriter;

use crate::{LogConfig, LOGS_DROPPED};

pub(crate) struct ChannelWriter {
    tx: Sender<Vec<u8>>,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.tx.try_send(buf.to_vec()) {
            Ok(()) => Ok(buf.len()),
            Err(TrySendError::Full(_)) => {
                LOGS_DROPPED.fetch_add(1, Ordering::Relaxed);
                Ok(buf.len())
            }
            Err(TrySendError::Disconnected(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "vita-log writer thread is gone",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct ChannelMakeWriter {
    tx: Sender<Vec<u8>>,
}

impl ChannelMakeWriter {
    pub fn new(tx: Sender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl<'a> MakeWriter<'a> for ChannelMakeWriter {
    type Writer = ChannelWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ChannelWriter {
            tx: self.tx.clone(),
        }
    }
}

pub(crate) fn run(rx: Receiver<Vec<u8>>, path: PathBuf, cfg: LogConfig) {
    let mut state = WriterState::open(path, cfg);
    while let Ok(chunk) = rx.recv() {
        state.write_chunk(&chunk);
        while let Ok(more) = rx.try_recv() {
            state.write_chunk(&more);
        }
        let _ = state.file.flush();

        let dropped = LOGS_DROPPED.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let line = format!(
                "{} WARN  vita_log dropped log events count={}\n",
                now_iso8601(),
                dropped,
            );
            state.write_chunk(line.as_bytes());
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
    fn open(path: PathBuf, cfg: LogConfig) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|e| {
                eprintln!("vita-log: cannot open {}: {}", path.display(), e);
                File::create(std::env::temp_dir().join("vita-log-fallback.txt"))
                    .expect("vita-log fallback file create failed")
            });
        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Self {
            path,
            cfg,
            file,
            bytes_written,
        }
    }

    fn write_chunk(&mut self, chunk: &[u8]) {
        if self.file.write_all(chunk).is_err() {
            return;
        }
        self.bytes_written += chunk.len() as u64;
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

fn now_iso8601() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "?".into())
}
