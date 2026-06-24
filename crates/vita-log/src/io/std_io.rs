//! Host I/O backend: thin wrappers around std::fs.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

pub(super) struct File {
    inner: fs::File,
}

pub(super) fn open_truncate(path: &str) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map(|inner| File { inner })
}

pub(super) fn open_append(path: &str) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(|inner| File { inner })
}

pub(super) fn write_all(file: &mut File, buf: &[u8]) -> io::Result<()> {
    file.inner.write_all(buf)
}

pub(super) fn mkdir(path: &str) -> io::Result<()> {
    fs::create_dir_all(Path::new(path))
}

pub(super) fn rename(from: &str, to: &str) -> io::Result<()> {
    fs::rename(from, to)
}

pub(super) fn remove(path: &str) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
