//! Noise transport-mode framer over a generic blocking `Read + Write`
//! stream (typically `TcpStream` after the HTTP/1.1 upgrade).
//!
//! Wire format per record: `1 B msgType=0x04 || 2 B BE len || ChaCha20-Poly1305 ciphertext`.
//! Each `Read` call drains decrypted bytes from an internal plaintext
//! buffer, refilling by reading + decrypting one record at a time.
//! Each `Write` call splits its caller's buffer into chunks of
//! `NOISE_MAX_RECORD_PAYLOAD` and frames each as one record.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use crate::control_stream::ControlStream;
use std::time::Duration;

use crate::noise::{NoiseTransport, NOISE_MAX_RECORD_PAYLOAD};

const MSG_TYPE_RECORD: u8 = 0x04;
const HEADER_LEN: usize = 3; // 1 B msgType + 2 B BE len

pub struct NoiseStream<S: Read + Write> {
    inner: S,
    noise: NoiseTransport,
    /// Plaintext bytes ready for the caller's `read()`.
    rx_plain: VecDeque<u8>,
    /// Single inbound-record assembly buffer (reused across reads).
    rx_buf: Vec<u8>,
    /// Reusable record-write buffer.
    tx_buf: Vec<u8>,
    /// Set after we observe an EOF on the inner stream.
    eof: bool,
}

impl<S: Read + Write> NoiseStream<S> {
    pub fn new(inner: S, noise: NoiseTransport, leftover: Vec<u8>) -> Self {
        let mut rx_buf = Vec::with_capacity(HEADER_LEN + 65536);
        rx_buf.extend_from_slice(&leftover);
        Self {
            inner,
            noise,
            rx_plain: VecDeque::with_capacity(8192),
            rx_buf,
            tx_buf: Vec::with_capacity(HEADER_LEN + 65536),
            eof: false,
        }
    }

    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.noise.handshake_hash
    }
}

impl NoiseStream<ControlStream> {
    /// Configure the underlying TCP stream's read timeout. Used by the
    /// async-IO pump thread (`async_io.rs`) to alternate read/write
    /// without busy-spinning. Works for both plain and TLS-wrapped
    /// streams (TLS calls down to the underlying TcpStream's setsockopt).
    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(t)
    }
}

impl<S: Read + Write> NoiseStream<S> {

    /// Pull bytes from the inner stream into `rx_buf` until at least
    /// `required` total bytes are present, OR EOF.
    fn fill_until(&mut self, required: usize) -> io::Result<()> {
        let mut tmp = [0u8; 4096];
        while self.rx_buf.len() < required {
            if self.eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "noise stream eof mid-record",
                ));
            }
            match self.inner.read(&mut tmp) {
                Ok(0) => {
                    self.eof = true;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "noise stream eof mid-record",
                    ));
                }
                Ok(n) => self.rx_buf.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Decrypt one full record off the front of `rx_buf` and append the
    /// plaintext to `rx_plain`. Caller must ensure at least HEADER_LEN
    /// bytes are present.
    fn drain_one_record(&mut self) -> io::Result<()> {
        if self.rx_buf.len() < HEADER_LEN {
            self.fill_until(HEADER_LEN)?;
        }
        if self.rx_buf[0] != MSG_TYPE_RECORD {
            return Err(io::Error::other(format!(
                "noise: unexpected msg type {:#x}",
                self.rx_buf[0]
            )));
        }
        let len = u16::from_be_bytes([self.rx_buf[1], self.rx_buf[2]]) as usize;
        let total = HEADER_LEN + len;
        self.fill_until(total)?;

        vita_log::trace!(record_len = len, "noise.record.decrypt");

        let mut out = Vec::with_capacity(len);
        self.noise
            .decrypt_record(&self.rx_buf[HEADER_LEN..total], &mut out)
            .map_err(|e| io::Error::other(format!("noise decrypt: {e}")))?;

        // Drain consumed bytes from rx_buf front.
        self.rx_buf.drain(..total);
        self.rx_plain.extend(out);
        Ok(())
    }
}

impl<S: Read + Write> Read for NoiseStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rx_plain.is_empty() {
            self.drain_one_record()?;
        }
        let n = std::cmp::min(buf.len(), self.rx_plain.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.rx_plain.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl<S: Read + Write> Write for NoiseStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Split caller's buf into max-sized records; encrypt each and write.
        let mut total_in = 0usize;
        for chunk in buf.chunks(NOISE_MAX_RECORD_PAYLOAD) {
            self.tx_buf.clear();
            self.noise
                .write_record(chunk, &mut self.tx_buf)
                .map_err(|e| io::Error::other(format!("noise encrypt: {e}")))?;
            self.inner.write_all(&self.tx_buf)?;
            total_in += chunk.len();
        }
        Ok(total_in)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
