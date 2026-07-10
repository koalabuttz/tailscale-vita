//! Purpose-built, **streaming** HTTP/1.1 for the Taildrop PUT surface.
//!
//! Modeled on the M14 LocalAPI reader (`tailscale-vita/src/localapi/http.rs`)
//! but with one load-bearing difference: that reader buffers the WHOLE
//! request (head + body) in a ≤ 8 KB `Vec`, which is fatal here — Taildrop
//! bodies are MBs. So we split the two:
//!
//! - [`read_head`] reads only up to the `\r\n\r\n` terminator (capped at
//!   [`MAX_HEAD_BYTES`]) and hands back any body bytes that arrived in the
//!   same read as `leftover`.
//! - [`stream_body`] then pipes exactly `Content-Length` bytes from
//!   `leftover` + the socket through a caller-supplied sink (→ `vita_fs`)
//!   in [`BODY_CHUNK`]-sized pieces, never holding the whole body in RAM.
//!
//! Both are generic over `R: Read` / `W: Write` so the logic is unit-tested
//! with in-memory cursors; in production `R`/`W` is a `netstack::TcpStream`
//! (which impls `std::io::Read + Write`).

use std::io::{self, ErrorKind, Read, Write};

use vita_log::trace;

/// Max bytes buffered while reading the request HEAD (request line +
/// headers). The body is NOT counted here — it streams to disk. 8 KB is
/// vastly more than any Taildrop PUT head; a slow-loris that never sends
/// `\r\n\r\n` trips this instead of growing unbounded.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;

/// Body streaming chunk size. 32 KB trades syscall/`vita_fs::append`
/// overhead against per-connection RAM (one such buffer on the heap).
pub const BODY_CHUNK: usize = 32 * 1024;

/// Max HTTP headers parsed per request.
const MAX_HEADERS: usize = 32;

/// Parsed request head. The body is streamed separately via [`stream_body`].
pub struct RequestHead {
    pub method: String,
    /// Request target with any `?query` stripped — Taildrop v1 ignores
    /// query params (resume offsets) and always treats a PUT as
    /// full-from-zero.
    pub path: String,
    /// `Content-Length`, or `None` if the header was absent (→ 411 at the
    /// handler). Parsed as `u64` so a multi-GB claim doesn't overflow
    /// before the `max_size` check.
    pub content_length: Option<u64>,
    /// Body bytes already pulled off the socket by the read that found the
    /// header terminator. The handler must write these before streaming
    /// the rest.
    pub leftover: Vec<u8>,
}

/// Failure modes reading a request. The inner detail on `Io`/`BadRequest`
/// is surfaced through the derived `Debug` in the handler's `warn!(?e)`
/// logs; the dead-code lint doesn't count a Debug-only read, hence the
/// allow. The handler matches on the *variant* (not the payload) to pick a
/// status code.
#[derive(Debug)]
#[allow(dead_code)]
pub enum HttpError {
    /// Underlying socket error → 500.
    Io(io::Error),
    /// Malformed request head → 400.
    BadRequest(&'static str),
    /// Head exceeded [`MAX_HEAD_BYTES`] before a terminator → 400.
    HeadTooLarge,
    /// Body ended (EOF/timeout) before `Content-Length` bytes arrived → 400.
    Incomplete,
}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read + parse the request head, up to and including `\r\n\r\n`. Body
/// bytes co-read with the terminator come back in [`RequestHead::leftover`].
/// Caps the head at [`MAX_HEAD_BYTES`].
pub fn read_head<R: Read>(r: &mut R) -> Result<RequestHead, HttpError> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end;
    loop {
        if buf.len() >= MAX_HEAD_BYTES {
            return Err(HttpError::HeadTooLarge);
        }
        let n = match r.read(&mut tmp) {
            Ok(0) => return Err(HttpError::BadRequest("eof before head end")),
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                return Err(HttpError::BadRequest("head read timeout"));
            }
            Err(e) => return Err(e.into()),
        };
        buf.extend_from_slice(&tmp[..n]);
        // Scan only the freshly read tail (+3 overlap for a terminator
        // split across two reads).
        let scan_start = buf.len().saturating_sub(n + 3);
        if let Some(idx) = find_crlfcrlf(&buf[scan_start..]) {
            header_end = scan_start + idx;
            break;
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&buf[..header_end + 4]) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(HttpError::BadRequest("incomplete head")),
        Err(_) => return Err(HttpError::BadRequest("malformed head")),
    }
    let method = req
        .method
        .ok_or(HttpError::BadRequest("missing method"))?
        .to_string();
    let target = req.path.ok_or(HttpError::BadRequest("missing path"))?;
    let path = target.split('?').next().unwrap_or(target).to_string();
    let content_length = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let leftover = buf[header_end + 4..].to_vec();

    trace!(
        method,
        path,
        cl = content_length.unwrap_or(0),
        "peerapi.head"
    );
    Ok(RequestHead {
        method,
        path,
        content_length,
        leftover,
    })
}

/// Stream exactly `content_length` body bytes — first from `initial`
/// (bytes co-read with the head), then from `r` — handing each chunk to
/// `write_chunk`. Returns the total written (== `content_length` on
/// success). Never holds more than `initial.len()` + [`BODY_CHUNK`] in RAM.
///
/// If `initial` is longer than `content_length` (a client that pipelined
/// past the advertised length) we honor only `content_length` and stop.
/// A short read (EOF/timeout before the full length) is [`HttpError::Incomplete`].
pub fn stream_body<R, F>(
    r: &mut R,
    initial: &[u8],
    content_length: u64,
    mut write_chunk: F,
) -> Result<u64, HttpError>
where
    R: Read,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let mut remaining = content_length;

    if !initial.is_empty() && remaining > 0 {
        let take = (initial.len() as u64).min(remaining) as usize;
        write_chunk(&initial[..take])?;
        remaining -= take as u64;
    }

    let mut tmp = vec![0u8; BODY_CHUNK];
    while remaining > 0 {
        let want = (tmp.len() as u64).min(remaining) as usize;
        let n = match r.read(&mut tmp[..want]) {
            Ok(0) => return Err(HttpError::Incomplete),
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                return Err(HttpError::Incomplete);
            }
            Err(e) => return Err(e.into()),
        };
        write_chunk(&tmp[..n])?;
        remaining -= n as u64;
    }
    Ok(content_length)
}

/// Write a bodyless HTTP/1.1 response with `status` (`Content-Length: 0`,
/// `Connection: close`). Taildrop replies carry no body — success is a
/// bare `200`, every error a bare status code. Generic over `W: Write`.
pub fn write_response<W: Write>(w: &mut W, status: u16) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        reason = reason_phrase(status),
    );
    w.write_all(head.as_bytes())?;
    w.flush()
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn find_crlfcrlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_head_parses_put_and_strips_query() {
        let raw =
            b"PUT /v0/put/hi.txt?offset=0 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        let mut cur = Cursor::new(raw.to_vec());
        let head = read_head(&mut cur).unwrap();
        assert_eq!(head.method, "PUT");
        assert_eq!(head.path, "/v0/put/hi.txt"); // query dropped
        assert_eq!(head.content_length, Some(5));
        assert_eq!(head.leftover, b"hello"); // body co-read with the head
    }

    #[test]
    fn read_head_missing_content_length_is_none() {
        let raw = b"PUT /v0/put/x HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut cur = Cursor::new(raw.to_vec());
        let head = read_head(&mut cur).unwrap();
        assert_eq!(head.content_length, None);
        assert!(head.leftover.is_empty());
    }

    #[test]
    fn stream_body_reassembles_leftover_plus_socket() {
        // 3 bytes came in with the head; the rest streams off the socket.
        let mut cur = Cursor::new(b"defghij".to_vec());
        let mut sink = Vec::new();
        let n = stream_body(&mut cur, b"abc", 10, |c| {
            sink.extend_from_slice(c);
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 10);
        assert_eq!(sink, b"abcdefghij");
    }

    #[test]
    fn stream_body_honors_content_length_over_pipelined_initial() {
        // Head read pulled in 5 bytes but Content-Length is only 3.
        let mut cur = Cursor::new(Vec::new());
        let mut sink = Vec::new();
        let n = stream_body(&mut cur, b"abcXX", 3, |c| {
            sink.extend_from_slice(c);
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 3);
        assert_eq!(sink, b"abc");
    }

    #[test]
    fn stream_body_chunks_large_body() {
        // Body bigger than one BODY_CHUNK → multiple sink calls, exact total.
        let body = vec![7u8; BODY_CHUNK * 2 + 1234];
        let mut cur = Cursor::new(body.clone());
        let mut total = 0u64;
        let mut calls = 0;
        let n = stream_body(&mut cur, b"", body.len() as u64, |c| {
            total += c.len() as u64;
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, body.len() as u64);
        assert_eq!(total, body.len() as u64);
        assert!(calls >= 3, "expected chunked delivery, got {calls} calls");
    }

    #[test]
    fn stream_body_eof_before_length_is_incomplete() {
        let mut cur = Cursor::new(b"ab".to_vec());
        let err = stream_body(&mut cur, b"", 10, |_| Ok(()));
        assert!(matches!(err, Err(HttpError::Incomplete)));
    }

    #[test]
    fn write_response_shape() {
        let mut out = Vec::new();
        write_response(&mut out, 200).unwrap();
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }
}
