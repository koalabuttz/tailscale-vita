use crate::ControlError;

pub const MKEY_PREFIX: &str = "mkey:";
pub const NODEKEY_PREFIX: &str = "nodekey:";
pub const DISCOKEY_PREFIX: &str = "discokey:";

/// Server's Noise static public key (Curve25519). 32 raw bytes; serialized
/// as `mkey:<64hex>`.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct MachinePublic(pub [u8; 32]);

impl MachinePublic {
    pub fn from_mkey_str(s: &str) -> Result<Self, ControlError> {
        let s = s.trim();
        let hex = s.strip_prefix(MKEY_PREFIX).unwrap_or(s);
        if hex.len() != 64 {
            return Err(ControlError::BadServerKey {
                reason: "expected 64 hex chars after mkey: prefix",
            });
        }
        let mut out = [0u8; 32];
        decode_hex(hex, &mut out)?;
        Ok(Self(out))
    }

    pub fn to_mkey_string(&self) -> String {
        format!("{}{}", MKEY_PREFIX, encode_hex(&self.0))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for MachinePublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MachinePublic({})", self.to_mkey_string())
    }
}

impl std::fmt::Display for MachinePublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_mkey_string())
    }
}

/// Our local Noise static private key. M5+.
pub struct MachinePrivate(pub [u8; 32]);

impl Drop for MachinePrivate {
    fn drop(&mut self) {
        for b in &mut self.0 {
            *b = 0;
        }
    }
}

/// WireGuard pubkey (== Tailscale NodeKey). 32 raw bytes; serialized as
/// `nodekey:<64hex>`. Same wire format as MachinePublic but different
/// semantic role.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct NodePublic(pub [u8; 32]);

impl NodePublic {
    pub fn from_nodekey_str(s: &str) -> Result<Self, ControlError> {
        let hex = s.trim().strip_prefix(NODEKEY_PREFIX).unwrap_or(s.trim());
        if hex.len() != 64 {
            return Err(ControlError::BadServerKey {
                reason: "expected 64 hex chars in nodekey",
            });
        }
        let mut out = [0u8; 32];
        decode_hex(hex, &mut out)?;
        Ok(Self(out))
    }

    pub fn to_nodekey_string(&self) -> String {
        format!("{}{}", NODEKEY_PREFIX, encode_hex(&self.0))
    }
}

pub struct NodePrivate(pub [u8; 32]);

impl Drop for NodePrivate {
    fn drop(&mut self) {
        for b in &mut self.0 {
            *b = 0;
        }
    }
}

/// Tailscale "disco" key (used for direct-path discovery). v1 generates
/// it but never uses it — the server requires it set in MapRequest.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct DiscoPublic(pub [u8; 32]);

impl DiscoPublic {
    pub fn to_discokey_string(&self) -> String {
        format!("{}{}", DISCOKEY_PREFIX, encode_hex(&self.0))
    }
}

pub struct DiscoPrivate(pub [u8; 32]);

impl Drop for DiscoPrivate {
    fn drop(&mut self) {
        for b in &mut self.0 {
            *b = 0;
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn decode_hex(hex: &str, out: &mut [u8]) -> Result<(), ControlError> {
    if hex.len() != out.len() * 2 {
        return Err(ControlError::BadServerKey {
            reason: "hex length mismatch",
        });
    }
    for (i, byte_out) in out.iter_mut().enumerate() {
        let s = &hex[i * 2..i * 2 + 2];
        *byte_out = u8::from_str_radix(s, 16).map_err(|_| ControlError::BadServerKey {
            reason: "non-hex character",
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_machine_pub() {
        let bytes = [0x12u8; 32];
        let mk = MachinePublic(bytes);
        let s = mk.to_mkey_string();
        assert!(s.starts_with("mkey:"));
        assert_eq!(s.len(), "mkey:".len() + 64);
        let parsed = MachinePublic::from_mkey_str(&s).unwrap();
        assert_eq!(parsed.0, bytes);
    }

    #[test]
    fn lenient_no_prefix() {
        let bytes = [0x42u8; 32];
        let hex = "42".repeat(32);
        let parsed = MachinePublic::from_mkey_str(&hex).unwrap();
        assert_eq!(parsed.0, bytes);
    }

    #[test]
    fn rejects_short_hex() {
        assert!(MachinePublic::from_mkey_str("mkey:dead").is_err());
    }

    #[test]
    fn rejects_bad_hex() {
        let s = format!("mkey:{}", "Z".repeat(64));
        assert!(MachinePublic::from_mkey_str(&s).is_err());
    }
}
