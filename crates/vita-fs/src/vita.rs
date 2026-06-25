//! SCE I/O backend: raw kernel syscalls, no newlib `_REENT`.

use std::ffi::{c_char, c_int, c_void, CString};
use std::io;
use std::path::Path;

extern "C" {
    fn sceIoOpen(path: *const c_char, flag: c_int, mode: c_int) -> c_int;
    fn sceIoRead(fd: c_int, buf: *mut c_void, len: u32) -> c_int;
    fn sceIoWrite(fd: c_int, buf: *const c_void, len: u32) -> c_int;
    fn sceIoClose(fd: c_int) -> c_int;
    fn sceIoMkdir(path: *const c_char, mode: c_int) -> c_int;
    fn sceIoRemove(path: *const c_char) -> c_int;
    fn sceIoRename(from: *const c_char, to: *const c_char) -> c_int;
    fn sceIoSyncByFd(fd: c_int, flag: c_int) -> c_int;
    fn sceIoDopen(path: *const c_char) -> c_int;
    fn sceIoDread(fd: c_int, dir: *mut SceIoDirent) -> c_int;
    fn sceIoDclose(fd: c_int) -> c_int;
}

/// `SceIoStat` (0x58 bytes) — kernel file-status struct. We only read
/// `st_attr` (dir bit) and `st_size`; timestamps are opaque 16-byte
/// `SceDateTime`s we never decode. Layout per
/// `vitasdk .../psp2common/kernel/iofilemgr.h`.
#[repr(C)]
struct SceIoStat {
    st_mode: i32,         // 0x00
    st_attr: u32,         // 0x04  SCE_SO_IF* attribute bits
    st_size: i64,         // 0x08
    st_ctime: [u8; 16],   // 0x10  SceDateTime
    st_atime: [u8; 16],   // 0x20  SceDateTime
    st_mtime: [u8; 16],   // 0x30  SceDateTime
    st_private: [u32; 6], // 0x40
}

/// `SceIoDirent` (0x160 bytes) — one directory entry filled by
/// `sceIoDread`. `d_name` is a NUL-terminated C string (≤255 + NUL).
#[repr(C)]
struct SceIoDirent {
    d_stat: SceIoStat,      // 0x00
    d_name: [c_char; 256],  // 0x58
    d_private: *mut c_void, // 0x158
    dummy: c_int,           // 0x15C
}

/// `st_attr` directory test: `(attr & SCE_SO_IFMT) == SCE_SO_IFDIR`.
const SCE_SO_IFMT: u32 = 0x0038;
const SCE_SO_IFDIR: u32 = 0x0010;

const SCE_O_RDONLY: c_int = 0x0001;
const SCE_O_WRONLY: c_int = 0x0002;
const SCE_O_CREAT: c_int = 0x0200;
const SCE_O_APPEND: c_int = 0x0100;

const SCE_ERRNO_ENOENT: c_int = 0x80010002u32 as c_int;
const SCE_ERRNO_EEXIST: c_int = 0x80010011u32 as c_int;

const READ_CHUNK: usize = 8 * 1024;

/// Normalize a path string for sceIo: drop a single `/` immediately
/// after the device prefix (`"ux0:/data" -> "ux0:data"`). The leading
/// slash silently breaks sceIo writes (vita-log S1 finding); newlib on
/// the eboot tolerated it, so callers still pass it.
fn norm(path: &Path) -> io::Result<String> {
    let s = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 path"))?;
    if let Some(colon) = s.find(':') {
        if s.as_bytes().get(colon + 1) == Some(&b'/') {
            let mut t = String::with_capacity(s.len() - 1);
            t.push_str(&s[..=colon]);
            t.push_str(&s[colon + 2..]);
            return Ok(t);
        }
    }
    Ok(s.to_string())
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))
}

fn sce_err(code: c_int, op: &'static str) -> io::Error {
    io::Error::other(format!("{op} failed: 0x{:08x}", code as u32))
}

pub(super) fn read(path: &Path) -> io::Result<Vec<u8>> {
    let cp = cstr(&norm(path)?)?;
    // SAFETY: cp is null-terminated; RDONLY open.
    let fd = unsafe { sceIoOpen(cp.as_ptr(), SCE_O_RDONLY, 0) };
    if fd < 0 {
        if fd == SCE_ERRNO_ENOENT {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        return Err(sce_err(fd, "sceIoOpen(read)"));
    }
    let mut out = Vec::new();
    let mut buf = [0u8; READ_CHUNK];
    loop {
        // SAFETY: fd valid; buf is a valid writable slice.
        let n = unsafe { sceIoRead(fd, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
        if n < 0 {
            unsafe { sceIoClose(fd) };
            return Err(sce_err(n, "sceIoRead"));
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { sceIoClose(fd) };
    Ok(out)
}

pub(super) fn write(path: &Path, data: &[u8]) -> io::Result<()> {
    let cp = cstr(&norm(path)?)?;
    // Clear existing content, then create+append. O_APPEND is required
    // for sceIo writes to actually commit (vita-log S1 finding); remove
    // first so the append starts from an empty file.
    let _ = unsafe { sceIoRemove(cp.as_ptr()) };
    // SAFETY: cp null-terminated; flags/mode constants.
    let fd = unsafe { sceIoOpen(cp.as_ptr(), SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0o666) };
    if fd < 0 {
        return Err(sce_err(fd, "sceIoOpen(write)"));
    }
    let mut buf = data;
    while !buf.is_empty() {
        // SAFETY: fd valid; buf valid slice.
        let n = unsafe { sceIoWrite(fd, buf.as_ptr() as *const c_void, buf.len() as u32) };
        if n <= 0 {
            unsafe { sceIoClose(fd) };
            return Err(sce_err(n, "sceIoWrite"));
        }
        buf = &buf[n as usize..];
    }
    // SAFETY: fd valid. Best-effort sync, then close (close flushes).
    unsafe {
        let _ = sceIoSyncByFd(fd, 0);
        sceIoClose(fd);
    }
    Ok(())
}

pub(super) fn create_dir_all(path: &Path) -> io::Result<()> {
    let s = norm(path)?;
    // mkdir each cumulative level after the device prefix, ignoring
    // "already exists". For our paths (ux0:data/tailscale-vita) the
    // ux0:data parent always exists, so this is usually one mkdir.
    let colon = s.find(':').map(|c| c + 1).unwrap_or(0);
    let bytes = s.as_bytes();
    let mut i = colon;
    while i <= s.len() {
        let at_sep = i == s.len() || bytes[i] == b'/';
        if at_sep && i > colon {
            let sub = &s[..i];
            let csub = cstr(sub)?;
            // SAFETY: csub null-terminated.
            let rc = unsafe { sceIoMkdir(csub.as_ptr(), 0o777) };
            if rc < 0 && rc != SCE_ERRNO_EEXIST {
                // Parent likely already exists; tolerate and continue.
                // A genuine failure surfaces on the subsequent open/write.
            }
        }
        i += 1;
    }
    Ok(())
}

pub(super) fn remove_file(path: &Path) -> io::Result<()> {
    let cp = cstr(&norm(path)?)?;
    // SAFETY: cp null-terminated.
    let rc = unsafe { sceIoRemove(cp.as_ptr()) };
    if rc < 0 && rc != SCE_ERRNO_ENOENT {
        return Err(sce_err(rc, "sceIoRemove"));
    }
    Ok(())
}

pub(super) fn rename(from: &Path, to: &Path) -> io::Result<()> {
    let cf = cstr(&norm(from)?)?;
    let ct = cstr(&norm(to)?)?;
    // sceIo rename can fail if the target exists; remove it first.
    let _ = unsafe { sceIoRemove(ct.as_ptr()) };
    // SAFETY: both null-terminated.
    let rc = unsafe { sceIoRename(cf.as_ptr(), ct.as_ptr()) };
    if rc < 0 {
        return Err(sce_err(rc, "sceIoRename"));
    }
    Ok(())
}

pub(super) fn read_dir(path: &Path) -> io::Result<Vec<super::DirEntry>> {
    let cp = cstr(&norm(path)?)?;
    // SAFETY: cp is null-terminated.
    let fd = unsafe { sceIoDopen(cp.as_ptr()) };
    if fd < 0 {
        if fd == SCE_ERRNO_ENOENT {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        return Err(sce_err(fd, "sceIoDopen"));
    }
    let mut out = Vec::new();
    loop {
        // Zeroed is valid: repr(C) POD, d_private becomes null (unused).
        let mut dirent: SceIoDirent = unsafe { std::mem::zeroed() };
        // SAFETY: fd valid; dirent is a valid writable SceIoDirent.
        let rc = unsafe { sceIoDread(fd, &mut dirent) };
        if rc < 0 {
            unsafe { sceIoDclose(fd) };
            return Err(sce_err(rc, "sceIoDread"));
        }
        if rc == 0 {
            break; // no more entries
        }
        // SAFETY: the kernel NUL-terminates d_name within the 256-byte buffer.
        let name = unsafe { std::ffi::CStr::from_ptr(dirent.d_name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        if name == "." || name == ".." {
            continue;
        }
        let is_dir = (dirent.d_stat.st_attr & SCE_SO_IFMT) == SCE_SO_IFDIR;
        let size = if is_dir { 0 } else { dirent.d_stat.st_size.max(0) as u64 };
        out.push(super::DirEntry { name, is_dir, size });
    }
    unsafe { sceIoDclose(fd) };
    Ok(out)
}
