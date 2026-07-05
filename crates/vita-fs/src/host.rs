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

pub(super) fn append(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(data)
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

pub(super) fn read_dir(path: &Path) -> io::Result<Vec<super::DirEntry>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        let is_dir = meta.is_dir();
        out.push(super::DirEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir,
            size: if is_dir { 0 } else { meta.len() },
        });
    }
    Ok(out)
}
