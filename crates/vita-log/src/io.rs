//! Backend-gated file I/O for vita-log.
//!
//! On Vita target: raw SCE I/O syscalls (sceIoOpen/Write/Close/Rename/
//! Remove/Mkdir). These bypass newlib's I/O wrappers, which require a
//! per-thread `_REENT` set up by `pthread_create`. Our SUPRX runtime
//! spawns threads via `sceKernelCreateThread` directly (see
//! `vita_thread`), so those threads have no `_REENT` and crash inside
//! any `std::fs` call. The SCE syscalls don't touch `_REENT`.
//!
//! On host: thin wrapper around `std::fs` — same surface, std impls.

use std::io;

#[cfg(target_os = "vita")]
mod sce;
#[cfg(target_os = "vita")]
use sce as imp;

#[cfg(not(target_os = "vita"))]
mod std_io;
#[cfg(not(target_os = "vita"))]
use std_io as imp;

/// Opaque file handle.
pub(crate) struct File(imp::File);

impl File {
    /// Open for write, create if missing, truncate to zero.
    pub(crate) fn open_truncate(path: &str) -> io::Result<Self> {
        imp::open_truncate(path).map(Self)
    }

    /// Open for write, create if missing, append at end.
    pub(crate) fn open_append(path: &str) -> io::Result<Self> {
        imp::open_append(path).map(Self)
    }

    pub(crate) fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        imp::write_all(&mut self.0, buf)
    }
}

/// Best-effort mkdir of `path`. Returns Ok if it now exists (whether
/// we created it or it already did). On Vita, single-level only — the
/// caller is expected to pass an existing parent (ux0:/data is always
/// present, ux0:/data/tailscale-vita gets created here if missing).
pub(crate) fn mkdir_p(path: &str) -> io::Result<()> {
    imp::mkdir(path)
}

pub(crate) fn rename(from: &str, to: &str) -> io::Result<()> {
    imp::rename(from, to)
}

pub(crate) fn remove(path: &str) -> io::Result<()> {
    imp::remove(path)
}
