use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use vita_sync::Mutex;

use crate::types::MachinePublic;
use crate::ControlError;

/// Serialize `bytes` to `path` via tmp+rename to be atomic against
/// power loss / unsafe-shutdown on Vita's vfat. The lock prevents
/// simultaneous writers from racing on the same path.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ControlError> {
    static WRITE_LOCK: Mutex<()> = Mutex::new(());
    let _g = WRITE_LOCK.lock();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = make_tmp_path(path);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    // Vita newlib `rename` may fail if the target exists; remove first.
    let _ = std::fs::remove_file(path);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn make_tmp_path(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    p.set_file_name(format!("{name}.tmp.{}", std::process::id()));
    p
}

/// Read pinned server pubkey from disk, or persist `seen` and return it.
/// Returns `Err(ServerKeyChanged)` if a pin exists and differs.
pub fn pin_or_load_server_key(
    dir: &Path,
    seen: &MachinePublic,
) -> Result<MachinePublic, ControlError> {
    let path = dir.join("server-key.bin");
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut pinned = [0u8; 32];
            pinned.copy_from_slice(&bytes);
            if pinned == seen.0 {
                Ok(*seen)
            } else {
                Err(ControlError::ServerKeyChanged)
            }
        }
        Ok(_) => {
            // Wrong length. Treat like missing; overwrite.
            atomic_write(&path, &seen.0)?;
            Ok(*seen)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            atomic_write(&path, &seen.0)?;
            Ok(*seen)
        }
        Err(e) => Err(ControlError::Io(e)),
    }
}
