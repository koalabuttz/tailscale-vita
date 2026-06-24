//! Plan A: drive the `h2` crate (async, but without an async I/O reactor)
//! by wrapping our sync `NoiseStream<ControlStream>` in an `AsyncRead +
//! AsyncWrite` adapter. A dedicated `noise_pump` thread does the actual
//! blocking I/O; the adapter's `poll_*` methods exchange bytes with that
//! thread via two `Mutex<VecDeque<u8>>`s.
//!
//! See `M5a-DECISION.md` for why we picked this over a hand-rolled HTTP/2
//! client.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use vita_thread::JoinHandle;
use std::time::Duration;

use vita_sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use vita_log::{debug, trace, warn};

use crate::control_stream::ControlStream;
use crate::record::NoiseStream;

/// Bytes that the pump's read direction polls for at a time.
const READ_TICK: Duration = Duration::from_millis(20);

/// Maximum bytes pump will drain from `tx_buf` per loop iteration before
/// re-checking the rx side. Keeps a busy writer from starving reads.
const TX_DRAIN_MAX: usize = 16 * 1024;

pub struct IoCore {
    /// The underlying sync stream + Noise framer. Held only by the pump
    /// thread (other threads exchange bytes via `rx_buf` / `tx_buf`).
    noise: Mutex<Option<NoiseStream<ControlStream>>>,
    /// Plaintext bytes already drained from inbound records, ready for
    /// `poll_read`.
    rx_buf: Mutex<VecDeque<u8>>,
    /// Plaintext bytes the caller wants written. Pump drains and frames.
    tx_buf: Mutex<VecDeque<u8>>,
    /// Stored at most-recent `poll_read` Pending.
    rx_waker: Mutex<Option<Waker>>,
    /// Stored at most-recent `poll_write` Pending (rare — we usually
    /// accept writes immediately).
    tx_waker: Mutex<Option<Waker>>,
    /// Set when the pump observes EOF/error, or shutdown is requested.
    closed: AtomicBool,
    /// First fatal error observed by pump.
    err: Mutex<Option<io::Error>>,
}

impl IoCore {
    fn fail(&self, e: io::Error) {
        let mut g = self.err.lock();
        if g.is_none() {
            *g = Some(e);
        }
        self.closed.store(true, Ordering::Release);
        self.wake_rx();
        self.wake_tx();
    }

    fn wake_rx(&self) {
        if let Some(w) = self.rx_waker.lock().take() {
            w.wake();
        }
    }

    fn wake_tx(&self) {
        if let Some(w) = self.tx_waker.lock().take() {
            w.wake();
        }
    }

    fn current_err(&self) -> Option<io::Error> {
        self.err
            .lock()
            .as_ref()
            .map(|e| io::Error::new(e.kind(), e.to_string()))
    }
}

/// Tokio AsyncRead/AsyncWrite adapter handed to `h2::client::handshake`.
pub struct AsyncNoiseStream {
    pub(crate) core: Arc<IoCore>,
    /// Pump-thread join handle. Held by the parent of `AsyncNoiseStream`
    /// (typically the `Http2Conn`) so it can be joined on shutdown.
    pub(crate) pump_join: Option<JoinHandle>,
}

impl AsyncNoiseStream {
    pub fn spawn(stream: NoiseStream<ControlStream>) -> Self {
        let core = Arc::new(IoCore {
            noise: Mutex::new(Some(stream)),
            rx_buf: Mutex::new(VecDeque::with_capacity(8192)),
            tx_buf: Mutex::new(VecDeque::with_capacity(8192)),
            rx_waker: Mutex::new(None),
            tx_waker: Mutex::new(None),
            closed: AtomicBool::new(false),
            err: Mutex::new(None),
        });
        let core_for_thread = Arc::clone(&core);
        let pump_join = vita_thread::Builder::new()
            .name("noise-pump")
            .stack_size(256 * 1024)
            .spawn(move || pump(core_for_thread))
            .expect("spawn noise-pump thread");
        Self {
            core,
            pump_join: Some(pump_join),
        }
    }

    pub fn shutdown(&mut self) {
        self.core.closed.store(true, Ordering::Release);
        self.core.wake_rx();
        self.core.wake_tx();
        if let Some(j) = self.pump_join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for AsyncNoiseStream {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn pump(core: Arc<IoCore>) {
    debug!("noise-pump starting");
    // Take ownership of the NoiseStream from the core, run, put back on exit.
    let mut noise = match core.noise.lock().take() {
        Some(s) => s,
        None => {
            warn!("noise-pump: no NoiseStream available");
            return;
        }
    };

    // Set a short read timeout so we can alternate read/write and notice shutdown.
    if let Err(e) = set_read_timeout(&noise, READ_TICK) {
        core.fail(e);
        return;
    }

    let mut read_buf = vec![0u8; 8192];
    while !core.closed.load(Ordering::Acquire) {
        // 1) Drain tx_buf -> noise.write_all
        let chunk = {
            let mut g = core.tx_buf.lock();
            let take = std::cmp::min(g.len(), TX_DRAIN_MAX);
            let v: Vec<u8> = g.drain(..take).collect();
            v
        };
        if !chunk.is_empty() {
            if let Err(e) = noise.write_all(&chunk) {
                core.fail(e);
                break;
            }
            if let Err(e) = noise.flush() {
                core.fail(e);
                break;
            }
            trace!(n = chunk.len(), "noise-pump tx drained");
            core.wake_tx();
        }

        // 2) Try one read with short timeout. WouldBlock/TimedOut means
        //    "no data right now, loop again".
        match noise.read(&mut read_buf) {
            Ok(0) => {
                trace!("noise-pump: eof on read");
                core.fail(io::Error::new(io::ErrorKind::UnexpectedEof, "noise eof"));
                break;
            }
            Ok(n) => {
                core.rx_buf.lock().extend(read_buf[..n].iter().copied());
                trace!(n, "noise-pump rx pushed");
                core.wake_rx();
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                // No bytes available now; loop to check tx + shutdown again.
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                core.fail(e);
                break;
            }
            Err(e) => {
                core.fail(e);
                break;
            }
        }
    }

    debug!("noise-pump exiting");
    *core.noise.lock() = Some(noise);
}

fn set_read_timeout(noise: &NoiseStream<ControlStream>, t: Duration) -> io::Result<()> {
    noise.set_read_timeout(Some(t))
}

impl AsyncRead for AsyncNoiseStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let core = &self.core;

        // First, try to drain rx_buf without storing a waker.
        {
            let mut g = core.rx_buf.lock();
            if !g.is_empty() {
                drain_into_readbuf(&mut g, buf);
                return Poll::Ready(Ok(()));
            }
        }

        // Empty. Are we closed with an error?
        if core.closed.load(Ordering::Acquire) {
            // Pump is gone. Surface the error if we have one; else treat as EOF.
            return match core.current_err() {
                Some(e) if e.kind() != io::ErrorKind::UnexpectedEof => Poll::Ready(Err(e)),
                _ => Poll::Ready(Ok(())), // EOF (ReadBuf untouched -> reader sees 0)
            };
        }

        // Store waker, then RECHECK rx_buf to avoid the lost-wakeup race.
        *core.rx_waker.lock() = Some(cx.waker().clone());
        {
            let mut g = core.rx_buf.lock();
            if !g.is_empty() {
                drain_into_readbuf(&mut g, buf);
                return Poll::Ready(Ok(()));
            }
        }
        Poll::Pending
    }
}

fn drain_into_readbuf(q: &mut VecDeque<u8>, buf: &mut ReadBuf<'_>) {
    let n = std::cmp::min(buf.remaining(), q.len());
    let initialized = buf.initialize_unfilled_to(n);
    for slot in initialized.iter_mut().take(n) {
        *slot = q.pop_front().unwrap();
    }
    buf.advance(n);
}

impl AsyncWrite for AsyncNoiseStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let core = &self.core;
        if core.closed.load(Ordering::Acquire) {
            if let Some(e) = core.current_err() {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "noise closed")));
        }
        // Append the entire buffer to tx_buf. Pump drains in TX_DRAIN_MAX
        // chunks. h2 calls poll_write with already-modest buffers.
        core.tx_buf.lock().extend(buf.iter().copied());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // We need the pump to actually push tx_buf out before reporting flushed.
        let core = &self.core;
        if core.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(core
                .current_err()
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "noise closed"))));
        }
        if core.tx_buf.lock().is_empty() {
            return Poll::Ready(Ok(()));
        }
        *core.tx_waker.lock() = Some(cx.waker().clone());
        // Recheck after storing waker.
        if core.tx_buf.lock().is_empty() {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.core.closed.store(true, Ordering::Release);
        self.core.wake_rx();
        self.core.wake_tx();
        Poll::Ready(Ok(()))
    }
}
