//! Per-connection Taildrop PUT handler. Runs on its own bounded thread
//! (spawned by the accept loop), one request per connection, then closes.
//!
//! Flow: read head → route (`PUT /v0/put/<name>` only) → sanitize name →
//! enforce `Content-Length` / `max_size` → stream the body to
//! `<name>.partial` → move to a collision-free final name with a
//! verify-after-rename guard (`vita_fs::rename` is non-atomic). Any failure
//! after the partial exists best-effort removes it.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use netstack::tcp::TcpStream;
use vita_log::{info, warn};

use crate::http::{self, HttpError};
use crate::name;
use crate::{Ctx, TaildropReport};

/// URL prefix for the Taildrop PUT surface (`tailscale file cp` targets
/// `/v0/put/<url-escaped-name>`).
const PUT_PREFIX: &str = "/v0/put/";

/// Read/write timeout on the connection. A stalled sender frees its thread
/// slot instead of pinning it — the body read re-arms this per chunk, so a
/// live-but-slow transfer keeps going while a truly dead one trips it.
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Handle one accepted connection. Never panics out (the accept loop also
/// wraps this in `catch_unwind`, but we keep the socket writes inside so a
/// client always gets a status line).
pub(crate) fn handle(mut stream: TcpStream, peer: SocketAddr, ctx: &Ctx) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let head = match http::read_head(&mut stream) {
        Ok(h) => h,
        Err(e) => {
            // Malformed/oversized/socket-dead head → 400 and move on.
            warn!(%peer, ?e, "peerapi.head.error");
            let _ = http::write_response(&mut stream, 400);
            return;
        }
    };

    // Surface is PUT-only.
    if !head.method.eq_ignore_ascii_case("PUT") {
        warn!(%peer, method = %head.method, "peerapi.method.rejected");
        let _ = http::write_response(&mut stream, 405);
        return;
    }

    // Route + sanitize the filename from /v0/put/<escaped-name>.
    let escaped = match head.path.strip_prefix(PUT_PREFIX) {
        Some(s) => s,
        None => {
            warn!(%peer, path = %head.path, "peerapi.path.unrecognized");
            let _ = http::write_response(&mut stream, 400);
            return;
        }
    };
    let name = match name::sanitize_filename(escaped) {
        Ok(n) => n,
        Err(e) => {
            warn!(%peer, escaped, ?e, "peerapi.name.rejected");
            let _ = http::write_response(&mut stream, 400);
            report(
                ctx,
                peer,
                escaped.to_string(),
                0,
                format!("rejected: {e:?}"),
            );
            return;
        }
    };

    // Content-Length is mandatory; enforce max_size BEFORE reading a byte.
    let content_length = match head.content_length {
        Some(cl) => cl,
        None => {
            warn!(%peer, name, "peerapi.length.required");
            let _ = http::write_response(&mut stream, 411);
            return;
        }
    };
    if content_length > ctx.cfg.max_size {
        warn!(%peer, name, content_length, max = ctx.cfg.max_size, "peerapi.too_big");
        let _ = http::write_response(&mut stream, 413);
        report(ctx, peer, name, content_length, "rejected: too_big".into());
        return;
    }
    let _reservation = match reserve_in_flight(ctx, content_length) {
        Some(reservation) => reservation,
        None => {
            warn!(%peer, name, content_length, "peerapi.in_flight_limit");
            let _ = http::write_response(&mut stream, 503);
            report(
                ctx,
                peer,
                name,
                content_length,
                "rejected: in_flight_limit".into(),
            );
            return;
        }
    };

    // v1 auth posture: the tailnet ACL is the boundary — accept any peer
    // that reached us (same stance as ts-ftp). We just LOG the source addr
    // (a tailnet IP, post-WG-decap) on every PUT.
    info!(%peer, name, content_length, "peerapi.put.begin");

    let dir = Path::new(&ctx.cfg.dir);
    let partial_id = ctx.partial_seq.fetch_add(1, Ordering::Relaxed);
    let partial = dir.join(format!(".taildrop-{partial_id:016x}.partial"));

    // Truncate-create the .partial so it starts empty AND exists even when
    // the body is 0 bytes (a legit empty file streams zero chunks, so
    // `append` would never run and `finalize`'s rename would have no
    // source). A create failure here is an I/O error → 500.
    if let Err(e) = vita_fs::write(&partial, b"") {
        warn!(%peer, name, error = %e, "peerapi.partial.create_failed");
        let _ = http::write_response(&mut stream, 500);
        report(ctx, peer, name, 0, "error: partial create".into());
        return;
    }
    // Stream the body → <name>.partial, appending each chunk.
    let written = match http::stream_body(&mut stream, &head.leftover, content_length, |chunk| {
        vita_fs::append(&partial, chunk)
    }) {
        Ok(n) => n,
        Err(e) => {
            let _ = vita_fs::remove_file(&partial);
            // I/O error to disk → 500; truncated body from the peer → 400.
            let status = match e {
                HttpError::Io(_) => 500,
                _ => 400,
            };
            warn!(%peer, name, ?e, status, "peerapi.body.error");
            let _ = http::write_response(&mut stream, status);
            report(ctx, peer, name, 0, format!("error: body ({status})"));
            return;
        }
    };

    // Move .partial → collision-free final name, verifying the (non-atomic)
    // rename landed.
    let finalized = {
        let _lock = ctx.finalize_lock.lock();
        finalize(dir, &partial, &name, written)
    };
    match finalized {
        Ok(final_name) => {
            info!(%peer, name = %final_name, bytes = written, "peerapi.put.ok");
            let _ = http::write_response(&mut stream, 200);
            report(ctx, peer, final_name, written, "ok".into());
        }
        Err(e) => {
            let _ = vita_fs::remove_file(&partial);
            warn!(%peer, name, error = %e, "peerapi.finalize.failed");
            let _ = http::write_response(&mut stream, 500);
            report(ctx, peer, name, written, "error: finalize".into());
        }
    }
}

/// Move `partial` to a collision-free final name under `dir`, then VERIFY
/// the destination landed. `vita_fs::rename` is remove-then-rename
/// (NON-atomic — see `config_edit.rs`), so a mid-rename failure can lose
/// the file; we can't rewrite a streamed multi-MB body from RAM (we never
/// held it), so a lost destination is a hard error (the sender's PUT gets a
/// 500 and retries the whole file). Returns the final name on success.
fn finalize(dir: &Path, partial: &Path, name: &str, expect_bytes: u64) -> io::Result<String> {
    let existing = dir_names(dir);
    let final_name = name::next_free_name(name, &existing).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "taildrop name collision limit reached",
        )
    })?;
    let dest = dir.join(&final_name);

    vita_fs::rename(partial, &dest)?;

    // Verify: the destination must now exist and hold at least the bytes we
    // streamed (a legit 0-byte file passes `>= 0`). A missing/short entry
    // means the non-atomic rename dropped it.
    match entry_size(dir, &final_name) {
        Some(size) if size >= expect_bytes => Ok(final_name),
        other => Err(io::Error::other(format!(
            "rename verify failed for {final_name:?}: got {other:?}, expected >= {expect_bytes}"
        ))),
    }
}

/// Reservation released automatically on every connection exit, including
/// short reads and disk failures.
struct InFlightReservation<'a> {
    used: &'a std::sync::atomic::AtomicU64,
    bytes: u64,
}

impl Drop for InFlightReservation<'_> {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

fn reserve_in_flight(ctx: &Ctx, bytes: u64) -> Option<InFlightReservation<'_>> {
    let mut current = ctx.in_flight_bytes.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(bytes)?;
        if next > ctx.cfg.max_size {
            return None;
        }
        match ctx.in_flight_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(InFlightReservation {
                    used: &ctx.in_flight_bytes,
                    bytes,
                });
            }
            Err(observed) => current = observed,
        }
    }
}

/// Names currently in `dir`. An unreadable dir yields an empty set — treat
/// that as "no known collisions" so a first-ever drop into a just-created
/// dir still writes (the verify step still catches a genuinely broken dir).
fn dir_names(dir: &Path) -> HashSet<String> {
    vita_fs::read_dir(dir)
        .map(|entries| entries.into_iter().map(|e| e.name).collect())
        .unwrap_or_default()
}

/// Size of a non-dir entry named `name` in `dir`, or `None` if absent.
/// vita_fs has no single-file stat, so we scan `read_dir`.
fn entry_size(dir: &Path, name: &str) -> Option<u64> {
    vita_fs::read_dir(dir)
        .ok()?
        .into_iter()
        .find(|e| e.name == name && !e.is_dir)
        .map(|e| e.size)
}

/// Hand a terminal outcome to the runtime-installed sink (if any) so it can
/// surface recent drops in its snapshot. Best-effort; never blocks.
fn report(ctx: &Ctx, peer: SocketAddr, name: String, size: u64, status: String) {
    if let Some(sink) = &ctx.sink {
        sink(TaildropReport {
            name,
            size,
            sender: peer.to_string(),
            status,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises the real on-disk write path (vita_fs host backend =
    // std::fs): truncate-create .partial → append → finalize (rename +
    // verify) → collision-rename. Proves the streaming-to-disk + move
    // machinery works without a live TcpStream (the HTTP framing is covered
    // by http.rs's generic-over-Read tests).
    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ts-peerapi-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn stream_to_partial(dir: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        let partial = dir.join(format!("{name}.partial"));
        vita_fs::write(&partial, b"").unwrap();
        for chunk in body.chunks(4) {
            vita_fs::append(&partial, chunk).unwrap();
        }
        partial
    }

    #[test]
    fn finalize_moves_partial_to_final() {
        let dir = tmp_dir("fin");
        let partial = stream_to_partial(&dir, "hello.txt", b"hello world");
        let final_name = finalize(&dir, &partial, "hello.txt", 11).unwrap();
        assert_eq!(final_name, "hello.txt");
        assert_eq!(
            std::fs::read(dir.join("hello.txt")).unwrap(),
            b"hello world"
        );
        assert!(!partial.exists(), ".partial should be consumed by the move");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_avoids_collision() {
        let dir = tmp_dir("col");
        std::fs::write(dir.join("hello.txt"), b"pre-existing").unwrap();
        let partial = stream_to_partial(&dir, "hello.txt", b"new bytes");
        let final_name = finalize(&dir, &partial, "hello.txt", 9).unwrap();
        assert_eq!(final_name, "hello (1).txt");
        // Original untouched; new file under the collision-free name.
        assert_eq!(
            std::fs::read(dir.join("hello.txt")).unwrap(),
            b"pre-existing"
        );
        assert_eq!(
            std::fs::read(dir.join("hello (1).txt")).unwrap(),
            b"new bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_handles_empty_file() {
        let dir = tmp_dir("empty");
        // 0-byte body: truncate-create leaves an empty .partial, no appends.
        let partial = stream_to_partial(&dir, "empty.dat", b"");
        let final_name = finalize(&dir, &partial, "empty.dat", 0).unwrap();
        assert_eq!(final_name, "empty.dat");
        assert_eq!(std::fs::read(dir.join("empty.dat")).unwrap(), b"");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
