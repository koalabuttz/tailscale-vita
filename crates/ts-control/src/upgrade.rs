//! HTTP/1.1 `Upgrade: tailscale-control-protocol` dance for the TS2021
//! control endpoint.
//!
//! Flow (per Tailscale's `controlhttp` package):
//!
//! 1. TCP-connect to `<server_url>` (or TLS to port 443 for production
//!    Tailscale; Headscale dev runs cleartext).
//! 2. Write a `POST /ts2021` request with:
//!    - `Connection: Upgrade`
//!    - `Upgrade: tailscale-control-protocol`
//!    - `X-Tailscale-Handshake: <base64 of init envelope>`
//! 3. Read a `101 Switching Protocols` response back via `httparse`.
//! 4. Drain any trailing bytes that came in the same TCP read (typically
//!    none) and return them along with the still-open socket.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use httparse::Status;
use tracing::{debug, warn};

use crate::control_stream::{wrap_tls, ControlStream};
use crate::url as urlmod;
use crate::ControlError;

/// Handle on the upgraded socket. M5 wraps this with a `NoiseStream`
/// adapter (record framer); the rest of the control client never reads
/// directly. M14 generalised from `TcpStream` to `ControlStream` so we
/// can carry either cleartext (Headscale dev) or TLS-wrapped (real
/// `controlplane.tailscale.com`) sockets through the same pipeline.
pub struct UpgradedSocket {
    pub tcp: ControlStream,
    /// Bytes that arrived after the `\r\n\r\n` of the 101 response in the
    /// same `read()` syscall. Almost always empty for well-behaved servers.
    pub leftover: Vec<u8>,
}

const UPGRADE_TOKEN: &str = "tailscale-control-protocol";
const HANDSHAKE_HEADER: &str = "X-Tailscale-Handshake";
const PATH: &str = "/ts2021";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Open a fresh connection to `server_url` (TLS-wrapped if `https://`)
/// and perform the HTTP/1.1 upgrade. `handshake_b64` is the
/// base64-encoded init envelope produced by
/// `NoiseHandshaker::build_init_header()`.
pub fn dial_and_upgrade(
    server_url: &str,
    handshake_b64: &str,
) -> Result<UpgradedSocket, ControlError> {
    let parsed = urlmod::parse(server_url)?;
    let scheme: &str = &parsed.scheme;
    let tls = match scheme {
        "http" => false,
        "https" => true,
        _ => {
            return Err(ControlError::Url(
                "control_url scheme must be http or https",
            ))
        }
    };
    let host = parsed.host;
    let port = parsed.port;

    let host_header = format!("{host}:{port}");
    debug!(host = %host, port, tls, "control.upgrade.dial");

    let host_for_resolve: &str = &host;
    let addr = (host_for_resolve, port)
        .to_socket_addrs()
        .map_err(|e| ControlError::Transport(format!("resolve {host}:{port}: {e}")))?
        .next()
        .ok_or_else(|| ControlError::Transport(format!("no addrs for {host}:{port}")))?;

    let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    tcp.set_read_timeout(Some(READ_TIMEOUT))?;
    tcp.set_write_timeout(Some(READ_TIMEOUT))?;
    tcp.set_nodelay(true)?;

    let mut stream = if tls {
        wrap_tls(tcp, &host)?
    } else {
        ControlStream::Plain(tcp)
    };

    let req = format!(
        "POST {PATH} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: {UPGRADE_TOKEN}\r\n\
         {HANDSHAKE_HEADER}: {handshake_b64}\r\n\
         User-Agent: tailscale-vita/0.1\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let leftover = read_101(&mut stream, &addr)?;
    debug!(leftover = leftover.len(), "control.upgrade.complete");
    Ok(UpgradedSocket {
        tcp: stream,
        leftover,
    })
}

/// Read the `101 Switching Protocols` response off `tcp`. Returns any
/// trailing bytes that came in the same read after `\r\n\r\n`.
fn read_101(tcp: &mut ControlStream, addr: &SocketAddr) -> Result<Vec<u8>, ControlError> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    let mut header_end: Option<usize> = None;

    while header_end.is_none() {
        if buf.len() > 16 * 1024 {
            return Err(ControlError::Transport(format!(
                "upgrade response > 16 KiB without complete headers ({addr})"
            )));
        }
        let n = tcp.read(&mut tmp)?;
        if n == 0 {
            return Err(ControlError::Transport(format!(
                "upgrade response closed before complete headers ({addr})"
            )));
        }
        buf.extend_from_slice(&tmp[..n]);
        // Look for the first \r\n\r\n
        if let Some(pos) = find_header_terminator(&buf) {
            header_end = Some(pos + 4);
        }
    }

    let header_end = header_end.unwrap();
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let parse_n = match resp.parse(&buf[..header_end])? {
        Status::Complete(n) => n,
        Status::Partial => {
            return Err(ControlError::Transport(
                "upgrade: httparse partial after locating \\r\\n\\r\\n (impossible)".into(),
            ))
        }
    };

    let status = resp
        .code
        .ok_or_else(|| ControlError::Transport("upgrade: missing status code".into()))?;
    if status != 101 {
        let reason = resp.reason.unwrap_or("");
        let body_preview = String::from_utf8_lossy(&buf[parse_n..]).to_string();
        return Err(ControlError::Http {
            status,
            body: format!(
                "expected 101 Switching Protocols, got {status} {reason}; body={body_preview}"
            ),
        });
    }

    let leftover = buf[header_end..].to_vec();
    if !leftover.is_empty() {
        warn!(
            n = leftover.len(),
            "upgrade: server sent {} bytes after 101 headers in the same read",
            leftover.len()
        );
    }
    Ok(leftover)
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_terminator() {
        assert_eq!(find_header_terminator(b"\r\n\r\n"), Some(0));
        assert_eq!(find_header_terminator(b"hi\r\n\r\nrest"), Some(2));
        assert_eq!(find_header_terminator(b"nope"), None);
    }
}
