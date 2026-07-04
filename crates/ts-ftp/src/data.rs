//! PASV data-channel helpers: bind a single-use data listener (rotating
//! through the configured port range) and format the `227` reply.

use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};

use netstack::{StackHandle, TcpListener};

/// Bind a fresh single-use data listener, advancing the *shared* `next`
/// cursor through `[lo, hi]` (inclusive). Tries every port in the range once
/// before giving up — a port may still be in TIME_WAIT from a prior transfer.
///
/// `next` is shared across ALL sessions (an `Arc<AtomicU16>` in `Ctx`), not
/// reset per session. This matters because the common client is one-shot
/// (connect → single transfer → disconnect): with a per-session cursor every
/// transfer reused `lo`, so the configured range was inert and rapid same-port
/// reuse collided with the prior data connection's lingering TIME_WAIT socket
/// — the intermittent "data connection never establishes" fault (BUG A,
/// 2026-07-04). A shared cursor spreads consecutive transfers across the whole
/// range, giving each port the rest of the range as TIME_WAIT clearance.
pub(crate) fn bind_passive(
    stack: &StackHandle,
    next: &AtomicU16,
    lo: u16,
    hi: u16,
) -> io::Result<(TcpListener, u16)> {
    let span = hi.saturating_sub(lo).saturating_add(1).max(1);
    let mut last_err = None;
    for _ in 0..span {
        // Atomically claim the current port and advance the shared cursor.
        // Single-threaded today (serial sessions), but the CAS keeps it correct
        // if the accept loop ever gains concurrency.
        let port = loop {
            let cur = next.load(Ordering::Relaxed);
            let claimed = cur.clamp(lo, hi);
            let advanced = if claimed >= hi { lo } else { claimed + 1 };
            if next
                .compare_exchange_weak(cur, advanced, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break claimed;
            }
        };
        match TcpListener::bind_handle(stack, port, 1) {
            Ok(l) => return Ok((l, port)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("no passive port available")))
}

/// Format the `227` reply body: `Entering Passive Mode (h1,h2,h3,h4,p1,p2).`
/// where the host bytes are the tailnet IP and `p1,p2` encode the port.
pub(crate) fn format_227(ip: Ipv4Addr, port: u16) -> String {
    let o = ip.octets();
    format!(
        "Entering Passive Mode ({},{},{},{},{},{}).",
        o[0],
        o[1],
        o[2],
        o[3],
        port >> 8,
        port & 0xff
    )
}

/// Format the `229` reply body for `EPSV`: `Entering Extended Passive Mode
/// (|||PORT|)` — port only, no host. Because it omits the address, it works
/// regardless of which address the client reached us on, sidestepping the
/// PASV host-IP problem entirely for EPSV-capable clients.
pub(crate) fn format_229(port: u16) -> String {
    format!("Entering Extended Passive Mode (|||{port}|)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pasv_227_encoding() {
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        // 30000 = 0x7530 -> 117, 48. The host bytes are the *tailnet* IP
        // (our node's address, the one the control connection arrived on),
        // never a LAN IP.
        assert_eq!(
            format_227(ip, 30000),
            "Entering Passive Mode (100,64,0,7,117,48)."
        );
    }

    #[test]
    fn epsv_229_encoding() {
        assert_eq!(
            format_229(30000),
            "Entering Extended Passive Mode (|||30000|)"
        );
        assert_eq!(
            format_229(21),
            "Entering Extended Passive Mode (|||21|)"
        );
    }
}
