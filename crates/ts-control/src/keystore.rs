//! Persistent Curve25519 keypairs for the three Tailscale identities:
//! `MachineKey` (Noise static), `NodeKey` (WG static; matches the
//! `nodekey:<hex>` registered with the control plane and the WG pubkey
//! used by M2/M8), and `DiscoKey` (placeholder — generated and
//! persisted but never used in DERP-only v1; the server requires it
//! set in `MapRequest`).
//!
//! Files: `<dir>/{machine,node,disco}.priv` — 32 raw bytes each, no
//! envelope. Same atomic-rename pattern as M4's `server-key.bin`.
//! Pubs are derived from privs on every load via x25519 scalar*basepoint.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use rand_core::OsRng;
use tracing::info;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::persist::atomic_write;
use crate::types::{
    DiscoPrivate, DiscoPublic, MachinePrivate, MachinePublic, NodePrivate, NodePublic,
};
use crate::ControlError;

const MACHINE_FILE: &str = "machine.priv";
const NODE_FILE: &str = "node.priv";
const DISCO_FILE: &str = "disco.priv";

pub struct KeyStore {
    pub machine_priv: MachinePrivate,
    pub machine_pub: MachinePublic,
    pub node_priv: NodePrivate,
    pub node_pub: NodePublic,
    pub disco_priv: DiscoPrivate,
    pub disco_pub: DiscoPublic,
}

impl KeyStore {
    /// Load all three priv keys from `dir`, generating any that are
    /// missing or wrong-sized. Atomic-write fresh keys on first
    /// generation. Pubs are derived deterministically from privs.
    pub fn load_or_generate(dir: &Path) -> Result<Self, ControlError> {
        let machine_priv_bytes = load_or_generate_priv(dir, MACHINE_FILE)?;
        let node_priv_bytes = load_or_generate_priv(dir, NODE_FILE)?;
        let disco_priv_bytes = load_or_generate_priv(dir, DISCO_FILE)?;

        let machine_pub_bytes = derive_pub(&machine_priv_bytes);
        let node_pub_bytes = derive_pub(&node_priv_bytes);
        let disco_pub_bytes = derive_pub(&disco_priv_bytes);

        let ks = KeyStore {
            machine_priv: MachinePrivate(machine_priv_bytes),
            machine_pub: MachinePublic(machine_pub_bytes),
            node_priv: NodePrivate(node_priv_bytes),
            node_pub: NodePublic(node_pub_bytes),
            disco_priv: DiscoPrivate(disco_priv_bytes),
            disco_pub: DiscoPublic(disco_pub_bytes),
        };

        let mpub = ks.machine_pub.to_mkey_string();
        let npub = ks.node_pub.to_nodekey_string();
        let dpub = ks.disco_pub.to_discokey_string();
        info!(
            machine_pub = %mpub,
            node_pub = %npub,
            disco_pub = %dpub,
            "control.keystore.loaded"
        );
        Ok(ks)
    }
}

/// Read 32 bytes from `dir/file`. On NotFound or wrong length,
/// generate a fresh Curve25519 secret and persist atomically.
fn load_or_generate_priv(dir: &Path, file: &str) -> Result<[u8; 32], ControlError> {
    let path = dir.join(file);
    match fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        }
        Ok(_) => generate_and_persist(&path),
        Err(e) if e.kind() == ErrorKind::NotFound => generate_and_persist(&path),
        Err(e) => Err(ControlError::Io(e)),
    }
}

fn generate_and_persist(path: &Path) -> Result<[u8; 32], ControlError> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let bytes = secret.to_bytes();
    atomic_write(path, &bytes)?;
    info!(path = %path.display(), "control.keystore.generated");
    Ok(bytes)
}

fn derive_pub(priv_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*priv_bytes);
    PublicKey::from(&secret).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn deterministic_pub_from_priv() {
        let bytes = [0x42u8; 32];
        let p1 = derive_pub(&bytes);
        let p2 = derive_pub(&bytes);
        assert_eq!(p1, p2);
        // x25519 clamps the secret, so the result is well-defined and
        // not all-zeros for a non-zero priv.
        assert_ne!(p1, [0u8; 32]);
    }

    #[test]
    fn load_or_generate_idempotent() {
        let dir = env::temp_dir().join(format!("vita-ks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let a = KeyStore::load_or_generate(&dir).unwrap();
        let b = KeyStore::load_or_generate(&dir).unwrap();

        assert_eq!(a.machine_pub.0, b.machine_pub.0);
        assert_eq!(a.node_pub.0, b.node_pub.0);
        assert_eq!(a.disco_pub.0, b.disco_pub.0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
