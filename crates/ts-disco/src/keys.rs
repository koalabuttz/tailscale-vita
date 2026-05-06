//! Minimal key newtypes used by Disco wire structs.
//!
//! Tailscale's reference implementation (`tailscale-rs::ts_keys`) lives in
//! its own crate with macros + prefix-string formatting + many derives.
//! For M12 we only need the on-the-wire byte representation + conversions
//! to `crypto_box`, so we inline three thin wrappers here. The full
//! string-prefix formatting (e.g., `discokey:abcd…`) lives in
//! `ts-control`'s types module — convert with `From<[u8; 32]>` at the
//! crate boundary.

use crypto_box::{PublicKey as BoxPublic, SecretKey as BoxSecret};

/// 32-byte X25519 public key used as the Disco identity. Wire-encoded
/// directly into the [`Header`][crate::Header]'s `sender_pub` field.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct DiscoPublicKey(pub [u8; 32]);

impl From<[u8; 32]> for DiscoPublicKey {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<DiscoPublicKey> for [u8; 32] {
    fn from(k: DiscoPublicKey) -> Self {
        k.0
    }
}

impl From<&DiscoPublicKey> for BoxPublic {
    fn from(k: &DiscoPublicKey) -> Self {
        BoxPublic::from(k.0)
    }
}

impl From<DiscoPublicKey> for BoxPublic {
    fn from(k: DiscoPublicKey) -> Self {
        BoxPublic::from(k.0)
    }
}

/// 32-byte X25519 private key. NOT zerocopy-derived — only the public
/// half goes on the wire; the private half stays in memory.
pub struct DiscoPrivateKey([u8; 32]);

impl DiscoPrivateKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> DiscoPublicKey {
        DiscoPublicKey(BoxSecret::from(self.0).public_key().to_bytes())
    }

    /// Generate a fresh private key from the OS RNG. Always available
    /// (rand_core's OsRng + getrandom feature is in our workspace deps).
    pub fn random() -> Self {
        use rand_core::RngCore;
        let mut b = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut b);
        Self(b)
    }
}

impl From<&DiscoPrivateKey> for BoxSecret {
    fn from(k: &DiscoPrivateKey) -> Self {
        BoxSecret::from(k.0)
    }
}

impl Drop for DiscoPrivateKey {
    fn drop(&mut self) {
        for b in &mut self.0 {
            *b = 0;
        }
    }
}

/// 32-byte X25519 public key for WireGuard / Node identity, embedded in
/// the [`Ping`][crate::Ping] message body so receivers can correlate
/// disco identity → node identity.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct NodePublicKey(pub [u8; 32]);

impl From<[u8; 32]> for NodePublicKey {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<NodePublicKey> for [u8; 32] {
    fn from(k: NodePublicKey) -> Self {
        k.0
    }
}
