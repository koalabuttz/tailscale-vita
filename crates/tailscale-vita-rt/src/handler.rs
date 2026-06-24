//! One-shot HTTP/1.1 handler. Lifted verbatim from
//! `crates/tailscale-vita-demo/src/handler.rs` with the trace event
//! prefix renamed (`demo.*` → `suprx.*`). If this stays this thin we
//! should refactor it into a shared crate during Phase 3.

use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::time::Duration;

use netstack::tcp::TcpStream;
use vita_log::{info, warn};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
                          Content-Type: text/plain\r\n\
                          Content-Length: 16\r\n\
                          Connection: close\r\n\
                          \r\n\
                          hello from vita\n";

const READ_TIMEOUT: Duration = Duration::from_secs(3);
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REQ_HEAD: usize = 8 * 1024;

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
            Err(e)
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => {
                warn!(%peer, error = %e, "suprx.handler.read.error");
                return;
            }
        }
    }

    if let Err(e) = stream.write_all(RESPONSE) {
        warn!(%peer, error = %e, "suprx.handler.write.error");
        return;
    }
    let _ = stream.flush();
    info!(
        %peer,
        head_bytes = head.len(),
        body_bytes = 16,
        "suprx.served"
    );
}
