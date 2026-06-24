//! SCE I/O backend: raw kernel syscalls, no newlib involvement.

use std::ffi::{c_char, c_int, c_void, CString};
use std::io;

extern "C" {
    fn sceIoOpen(path: *const c_char, flag: c_int, mode: c_int) -> c_int;
    fn sceIoWrite(fd: c_int, buf: *const c_void, len: u32) -> c_int;
    fn sceIoClose(fd: c_int) -> c_int;
    fn sceIoMkdir(path: *const c_char, mode: c_int) -> c_int;
    fn sceIoRename(from: *const c_char, to: *const c_char) -> c_int;
    fn sceIoRemove(path: *const c_char) -> c_int;
    fn sceIoSyncByFd(fd: c_int, flag: c_int) -> c_int;
}

const SCE_O_WRONLY: c_int = 0x0002;
const SCE_O_CREAT: c_int = 0x0200;
const SCE_O_APPEND: c_int = 0x0100;

/// SCE "already exists" errno. mkdir returns this when the directory
/// is already present — we treat it as success.
const SCE_ERROR_ERRNO_EEXIST: c_int = 0x80010011u32 as c_int;

pub(super) struct File {
    fd: c_int,
}

impl Drop for File {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: fd was returned by sceIoOpen.
            let _ = unsafe { sceIoClose(self.fd) };
        }
    }
}

fn c(path: &str) -> io::Result<CString> {
    CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))
}

fn err_from_sce(code: c_int, op: &'static str) -> io::Error {
    io::Error::other(format!("{op} failed: 0x{:08x}", code as u32))
}

/// On Vita, "truncate" is effectively `open_append` — see `vita-log`'s
/// top-of-file notes for the Vita I/O quirks that forced this. The
/// host backend honors the name (it truncates).
pub(super) fn open_truncate(path: &str) -> io::Result<File> {
    open_append(path)
}

pub(super) fn open_append(path: &str) -> io::Result<File> {
    let cp = c(path)?;
    // SAFETY: path is null-terminated; flags + mode are constants.
    let fd = unsafe { sceIoOpen(cp.as_ptr(), SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0o666) };
    if fd < 0 {
        return Err(err_from_sce(fd, "sceIoOpen(append)"));
    }
    Ok(File { fd })
}

pub(super) fn write_all(file: &mut File, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: fd is a valid SCE fd; buf is a valid byte slice.
        let n = unsafe { sceIoWrite(file.fd, buf.as_ptr() as *const c_void, buf.len() as u32) };
        if n < 0 {
            return Err(err_from_sce(n, "sceIoWrite"));
        }
        if n == 0 {
            return Err(io::Error::other("sceIoWrite returned 0"));
        }
        buf = &buf[n as usize..];
    }
    // Best-effort: nudge the kernel to flush. Doesn't make data visible
    // to FTP on its own (verified 2026-06-24) — close+reopen in the
    // writer loop is the actual flush barrier — but cheap and harmless.
    // SAFETY: fd is valid.
    unsafe {
        let _ = sceIoSyncByFd(file.fd, 0);
    }
    Ok(())
}

pub(super) fn mkdir(path: &str) -> io::Result<()> {
    let cp = c(path)?;
    // SAFETY: path is null-terminated.
    let rc = unsafe { sceIoMkdir(cp.as_ptr(), 0o777) };
    if rc < 0 && rc != SCE_ERROR_ERRNO_EEXIST {
        return Err(err_from_sce(rc, "sceIoMkdir"));
    }
    Ok(())
}

pub(super) fn rename(from: &str, to: &str) -> io::Result<()> {
    let cf = c(from)?;
    let ct = c(to)?;
    let rc = unsafe { sceIoRename(cf.as_ptr(), ct.as_ptr()) };
    if rc < 0 {
        return Err(err_from_sce(rc, "sceIoRename"));
    }
    Ok(())
}

pub(super) fn remove(path: &str) -> io::Result<()> {
    let cp = c(path)?;
    let rc = unsafe { sceIoRemove(cp.as_ptr()) };
    if rc < 0 {
        return Err(err_from_sce(rc, "sceIoRemove"));
    }
    Ok(())
}
