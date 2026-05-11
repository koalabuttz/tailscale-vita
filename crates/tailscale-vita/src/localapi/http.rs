//! Minimal HTTP/1.1 request reader + response writer for the M14
//! LocalAPI. Hand-rolled because the workspace has no server crate
//! (httparse is parse-only, hyper et al. are too heavy for Vita's
//! memory budget). Mirrors the pattern in
//! `crates/tailscale-vita-demo/src/handler.rs` — read until
//! `\r\n\r\n`, dispatch, write response, close.
//!
//! Scope: enough to serve a small read-only API. No keep-alive, no
//! chunked transfer, no large bodies (POST bodies are bounded to 8 KB).

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use tracing::trace;

/// Max bytes we'll buffer for a single request (head + small body).
/// Generous enough for any LocalAPI body we plan to accept; small
/// enough that a slow-loris client can't OOM us.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// Per-request read/write timeout. Localhost has no excuse to be
/// slow.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// Max number of HTTP headers parsed per request. Way more than
/// any reasonable client sends.
const MAX_HEADERS: usize = 32;

/// Parsed LocalAPI request. Only the fields we need: method, path,
/// query, body. Headers are deliberately discarded — LocalAPI is
/// loopback-only and doesn't need to consult Host, Auth, etc.
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    /// Request body bytes after the `\r\n\r\n` header terminator.
    pub body: Vec<u8>,
}

/// Failure modes when reading a request. The server treats parse
/// errors as 400 Bad Request and IO errors as a closed connection.
#[derive(Debug)]
pub enum RequestError {
    Io(std::io::Error),
    BadRequest(&'static str),
    TooLarge,
}

impl From<std::io::Error> for RequestError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read one HTTP/1.1 request off the stream. Stops at `\r\n\r\n` for
/// the header terminator; reads `Content-Length` more bytes for the
/// body (cap [`MAX_REQUEST_BYTES`] total).
pub fn read_request(stream: &mut TcpStream) -> Result<Request, RequestError> {
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    let header_end;
    loop {
        if buf.len() >= MAX_REQUEST_BYTES {
            return Err(RequestError::TooLarge);
        }
        let n = match stream.read(&mut tmp) {
            Ok(0) => return Err(RequestError::BadRequest("eof before headers")),
            Ok(n) => n,
            Err(e)
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                return Err(RequestError::BadRequest("read timeout"));
            }
            Err(e) => return Err(e.into()),
        };
        buf.extend_from_slice(&tmp[..n]);
        // Scan only over the freshly extended portion (plus 3 bytes of
        // overlap to catch a CRLFCRLF split across reads).
        let scan_start = buf.len().saturating_sub(n + 3);
        if let Some(idx) = find_crlfcrlf(&buf[scan_start..]) {
            header_end = scan_start + idx;
            break;
        }
    }

    // Parse the request line + headers using httparse.
    let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers_buf);
    match req.parse(&buf[..header_end + 4]) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(RequestError::BadRequest("incomplete request line"));
        }
        Err(_) => return Err(RequestError::BadRequest("malformed request")),
    }
    let method = req
        .method
        .ok_or(RequestError::BadRequest("missing method"))?
        .to_string();
    let target = req
        .path
        .ok_or(RequestError::BadRequest("missing path"))?
        .to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };

    // Read body if Content-Length present.
    let content_length: usize = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    let already_have = buf.len().saturating_sub(body_start);
    let mut body = buf[body_start..].to_vec();
    if content_length > already_have {
        let needed = content_length - already_have;
        if body_start + content_length > MAX_REQUEST_BYTES {
            return Err(RequestError::TooLarge);
        }
        let mut remaining = needed;
        while remaining > 0 {
            let cap = tmp.len().min(remaining);
            let n = match stream.read(&mut tmp[..cap]) {
                Ok(0) => return Err(RequestError::BadRequest("eof before body end")),
                Ok(n) => n,
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock
                        || e.kind() == ErrorKind::TimedOut =>
                {
                    return Err(RequestError::BadRequest("body read timeout"));
                }
                Err(e) => return Err(e.into()),
            };
            body.extend_from_slice(&tmp[..n]);
            remaining = remaining.saturating_sub(n);
        }
    } else if content_length < already_have {
        // Trailing pipelined request — we don't support pipelining.
        // Truncate to advertised length.
        body.truncate(content_length);
    }

    trace!(method, path, query_len = query.len(), body_len = body.len(), "localapi.req");
    Ok(Request {
        method,
        path,
        query,
        body,
    })
}

/// Write an HTTP/1.1 response. `body_json` is sent as
/// `application/json` with `Content-Length` set and `Connection: close`.
pub fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    body_json: &[u8],
) -> std::io::Result<()> {
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    let reason = reason_phrase(status);
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body_json.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body_json)?;
    stream.flush()?;
    Ok(())
}

/// Write a small error response with a JSON body `{error: msg}`.
pub fn write_error(
    stream: &mut TcpStream,
    status: u16,
    msg: &str,
) -> std::io::Result<()> {
    // Hand-rolled JSON to avoid pulling serde_json for a 1-key object.
    // (We use serde_json elsewhere but trivial-error path can be tight.)
    let escaped = escape_json_string(msg);
    let body = format!("{{\"error\":\"{escaped}\"}}");
    write_json_response(stream, status, body.as_bytes())
}

fn find_crlfcrlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Parse `key=val&key2=val2` query strings. Doesn't URL-decode values
/// (LocalAPI clients don't send escaped characters in addr=... or
/// ip=... params). Returns the first matching value or None.
pub fn query_get<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_get_finds_value() {
        let q = "addr=100.64.0.1&type=disco";
        assert_eq!(query_get(q, "addr"), Some("100.64.0.1"));
        assert_eq!(query_get(q, "type"), Some("disco"));
        assert_eq!(query_get(q, "missing"), None);
    }

    #[test]
    fn query_get_empty_string() {
        assert_eq!(query_get("", "addr"), None);
    }

    #[test]
    fn escape_json_string_handles_special_chars() {
        assert_eq!(escape_json_string("plain"), "plain");
        assert_eq!(escape_json_string("a\"b"), "a\\\"b");
        assert_eq!(escape_json_string("a\nb"), "a\\nb");
        assert_eq!(escape_json_string("a\\b"), "a\\\\b");
        // Control char.
        assert_eq!(escape_json_string("a\x01b"), "a\\u0001b");
    }

    #[test]
    fn find_crlfcrlf_locates_terminator() {
        assert_eq!(
            find_crlfcrlf(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"),
            Some(23)
        );
        assert_eq!(find_crlfcrlf(b"no terminator here"), None);
    }
}
