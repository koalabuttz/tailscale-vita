//! Host backend: delegate to `std::fs`. Used for unit tests +
//! host_diagnostic on x86_64.

use std::io;
use std::path::Path;

pub(super) fn read(path: &Path) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

pub(super) fn write(path: &Path, data: &[u8]) -> io::Result<()> {
    std::fs::write(path, data)
}

pub(super) fn create_dir_all(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

pub(super) fn remove_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub(super) fn rename(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::rename(from, to)
}
