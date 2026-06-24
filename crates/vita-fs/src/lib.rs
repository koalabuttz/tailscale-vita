//! Backend-gated whole-file I/O for tailscale-vita.
//!
//! ## Why this exists
//!
//! `std::fs` on the Vita target routes through newlib stdio, which
//! needs a per-thread `_REENT` set up by `crt0`. The SUPRX bootstrap
//! thread (raw `sceKernelCreateThread`, no crt0) has no `_REENT`, so
//! any `std::fs` call from it faults — the same crash that forced
//! `vita-log` onto raw `sceIo`. `vita-fs` gives the runtime's state
//! files (config TOML, persistent keys, server-key cache, map session
//! state) the same raw-`sceIo` treatment so `Runtime::up` can run in
//! the SUPRX. See `docs/SUPRX-PTHREAD-INVESTIGATION.md` and the M15-A3
//! S6 audit notes in `memory/m11_suprx_loader_findings.md`.
//!
//! - `cfg(target_os = "vita")` → SCE backend (`sceIoOpen`/`Read`/
//!   `Write`/`Mkdir`/`Remove`/`Rename`). Used on BOTH eboot and SUPRX
//!   — sceIo works in either, and avoids newlib entirely.
//! - `cfg(not(target_os = "vita"))` → `std::fs` delegation for host
//!   tests + `host_diagnostic`.
//!
//! ## Vita gotchas baked in (from the vita-log S1 bring-up)
//!
//! - **Path form**: `"ux0:/data/..."` (leading slash after the device
//!   prefix) silently loses writes. The SCE backend normalizes it to
//!   `"ux0:data/..."`, so callers can keep passing the slash form that
//!   works under newlib on the eboot.
//! - **`O_APPEND`**: sceIo writes only commit reliably with `O_APPEND`;
//!   `write` removes any existing file first, then create+appends, so a
//!   fresh full-file write still lands.
//!
//! API mirrors the `std::fs` free functions the runtime uses, taking
//! `&Path`, so migration is `std::fs::X(p)` → `vita_fs::X(p)`. A missing
//! file yields an `io::Error` whose `kind()` is `NotFound`, matching
//! `std::fs` (callers branch on this).

use std::io;
use std::path::Path;

#[cfg(target_os = "vita")]
mod vita;
#[cfg(target_os = "vita")]
use vita as imp;

#[cfg(not(target_os = "vita"))]
mod host;
#[cfg(not(target_os = "vita"))]
use host as imp;

/// Read the entire file into a byte vector. `NotFound` if absent.
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    imp::read(path)
}

/// Read the entire file as UTF-8. `NotFound` if absent,
/// `InvalidData` if not valid UTF-8.
pub fn read_to_string(path: &Path) -> io::Result<String> {
    let bytes = imp::read(path)?;
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "file is not valid UTF-8"))
}

/// Write `data` to `path`, replacing any existing content. NOT atomic
/// on its own — callers wanting atomicity write to a tmp path then
/// [`rename`].
pub fn write(path: &Path, data: &[u8]) -> io::Result<()> {
    imp::write(path, data)
}

/// Create `path` and all missing parents. Idempotent.
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    imp::create_dir_all(path)
}

/// Remove a file. Missing file is NOT an error (matches the common
/// best-effort `let _ = remove_file(..)` usage).
pub fn remove_file(path: &Path) -> io::Result<()> {
    imp::remove_file(path)
}

/// Rename `from` to `to`. On Vita, `to` is removed first if present
/// (newlib/sceIo `rename` can fail when the target exists).
pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
    imp::rename(from, to)
}
