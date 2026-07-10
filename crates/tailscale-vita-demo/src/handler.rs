//! One-shot HTTP/1.1 handler for the demo's tailnet-facing HTTP echo.
//!
//! Default response: `200 OK / hello from vita\n` — sufficient for
//! `curl http://100.x.y.z:8080/`.
//!
//! M14 Stage 5: when the request path starts with `/api/`, the
//! handler proxies to the loopback LocalAPI server
//! (`127.0.0.1:41112`) and returns its JSON response. Lets us verify
//! LocalAPI end-to-end from a tailnet peer (the Vita has no shell;
//! we can't curl loopback locally). Path mapping:
//!
//! - `GET  /api/status`     → `GET  /localapi/v0/status`
//! - `GET  /api/whois?addr=...` → `GET /localapi/v0/whois?addr=...`
//! - `GET  /api/health`     → `GET  /localapi/v0/health`
//! - `GET  /api/netmap`     → `GET  /localapi/v0/netmap`
//! - `GET  /api/ping?ip=...`→ `GET  /localapi/v0/ping?ip=...`
//! The proxy deliberately exposes only read-only LocalAPI GETs. Lifecycle
//! controls stay loopback-only; a tailnet peer must never be able to turn the
//! demo server into `/logout`, `/down`, or `/up`.

use std::io::{ErrorKind, Read as _, Write};
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::time::Duration;

use netstack::tcp::TcpStream;
use vita_log::{info, warn};

const DEFAULT_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
                          Content-Type: text/plain\r\n\
                          Content-Length: 16\r\n\
                          Connection: close\r\n\
                          \r\n\
                          hello from vita\n";

const LOCALAPI_ADDR: &str = "127.0.0.1:41112";

const READ_TIMEOUT: Duration = Duration::from_secs(3);
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REQ_HEAD: usize = 8 * 1024;
const PROXY_MAX_RESPONSE: usize = 256 * 1024;

pub fn serve(mut stream: TcpStream, peer: SocketAddr) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

    let mut head = Vec::with_capacity(512);
    let mut buf = [0u8; 256];
    while head.len() < MAX_REQ_HEAD {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                break;
            }
            Err(e) => {
                warn!(%peer, error = %e, "demo.handler.read.error");
                return;
            }
        }
    }

    // Parse just enough of the request line to decide if this is an
    // `/api/...` proxy hit. Cheap: split first line by spaces.
    let api_path = head.split(|&b| b == b'\n').next().and_then(|first_line| {
        let line = std::str::from_utf8(first_line).ok()?;
        let mut parts = line.split_whitespace();
        let method = parts.next()?;
        let target = parts.next()?;
        if let Some(rest) = target.strip_prefix("/api/") {
            Some((method.to_string(), rest.to_string()))
        } else {
            None
        }
    });

    let response: Vec<u8> = match api_path {
        Some((method, rest)) => match proxy_to_localapi(&method, &rest) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(%peer, error = %e, "demo.api.proxy.failed");
                proxy_error_response(&e)
            }
        },
        None => DEFAULT_RESPONSE.to_vec(),
    };

    if let Err(e) = stream.write_all(&response) {
        warn!(%peer, error = %e, "demo.handler.write.error");
        return;
    }
    let _ = stream.flush();
    info!(%peer, head_bytes = head.len(), body_bytes = response.len(), "demo.served");
}

/// Forward a `/api/<rest>` request to `127.0.0.1:41112/localapi/v0/<rest>`
/// and return the upstream's raw HTTP response bytes (which we'll
/// stream back to the tailnet client as-is). Returns an error string
/// if the loopback dial fails (LocalAPI disabled / bind failed / crashed).
fn proxy_to_localapi(method: &str, rest: &str) -> Result<Vec<u8>, String> {
    if method != "GET" {
        return Err("only read-only GET LocalAPI proxying is allowed".into());
    }
    let path = rest.split('?').next().unwrap_or(rest);
    if !matches!(path, "status" | "whois" | "health" | "netmap" | "ping") {
        return Err("LocalAPI endpoint is not exposed through the demo proxy".into());
    }
    // Build a minimal upstream request.
    let upstream_req = format!(
        "{method} /localapi/v0/{rest} HTTP/1.1\r\n\
         Host: localhost:41112\r\n\
         Connection: close\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    let mut conn = StdTcpStream::connect(LOCALAPI_ADDR).map_err(|e| format!("connect: {e}"))?;
    conn.set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    conn.set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|e| format!("set_write_timeout: {e}"))?;
    conn.write_all(upstream_req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    conn.flush().map_err(|e| format!("flush: {e}"))?;
    let mut response = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    loop {
        if response.len() >= PROXY_MAX_RESPONSE {
            return Err("upstream response too large".into());
        }
        match conn.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                return Err(format!("read timeout: {e}"));
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(response)
}

fn proxy_error_response(err: &str) -> Vec<u8> {
    let body = format!("{{\"error\":\"proxy: {err}\"}}\n");
    let mut resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    )
    .into_bytes();
    resp.extend_from_slice(body.as_bytes());
    resp
}
