use crate::ControlError;

/// Generate a fresh `(MachinePrivate, MachinePublic)` pair using snow's
/// default-resolver RNG. Suitable for ephemeral M5 demos; the real
/// `KeyStore` (M6) persists these keys to disk so they survive restart.
pub fn generate_machine_keypair() -> Result<(MachinePrivate, MachinePublic), ControlError> {
    use snow::Builder;
    let pattern = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("static pattern parses");
    let kp = Builder::new(pattern)
        .generate_keypair()
        .map_err(|e| ControlError::Transport(format!("snow keygen: {e}")))?;
    if kp.private.len() != 32 || kp.public.len() != 32 {
        return Err(ControlError::Transport(
            "snow returned non-32-byte keypair".into(),
        ));
    }
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&kp.private);
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&kp.public);
    Ok((MachinePrivate(priv_bytes), MachinePublic(pub_bytes)))
}

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

// =============================================================================
// M7: /machine/map wire types
//
// Mirrors `tailcfg.MapRequest` / `tailcfg.MapResponse` and friends. Field
// names match Go's default JSON-tag behavior (capitalized struct field name
// used verbatim) via explicit `#[serde(rename = "...")]` per field. We
// only declare fields we actually consume; everything else is dropped on
// the floor by serde (no-op).
// =============================================================================

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub(crate) struct MapRequestWire {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "Compress")]
    pub compress: String, // "" — Headscale gzips the HTTP layer regardless
    #[serde(rename = "NodeKey")]
    pub node_key: String, // "nodekey:<hex>"
    #[serde(rename = "DiscoKey")]
    pub disco_key: String, // "discokey:<hex>"
    #[serde(rename = "Hostinfo")]
    pub hostinfo: MapHostinfoWire,
    #[serde(rename = "Stream")]
    pub stream: bool,
    #[serde(rename = "OmitPeers")]
    pub omit_peers: bool,
    #[serde(rename = "ReadOnly")]
    pub read_only: bool,
    #[serde(rename = "Endpoints")]
    pub endpoints: Vec<String>, // empty for v1 (no magicsock)
    #[serde(rename = "MapSessionHandle")]
    pub map_session_handle: String,
    #[serde(rename = "MapSessionSeq")]
    pub map_session_seq: i64,
}

#[derive(Serialize)]
pub(crate) struct MapHostinfoWire {
    #[serde(rename = "IPNVersion")]
    pub ipn_version: String,
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "OS")]
    pub os: String,
    #[serde(rename = "OSVersion")]
    pub os_version: String,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct MapResponseWire {
    #[serde(rename = "MapSessionHandle", default)]
    pub map_session_handle: String,
    #[serde(rename = "Seq", default)]
    pub seq: i64,
    #[serde(rename = "KeepAlive", default)]
    pub keep_alive: bool,
    #[serde(rename = "Node", default)]
    pub node: Option<NodeWire>,
    #[serde(rename = "DERPMap", default)]
    pub derp_map: Option<DerpMapWire>,
    #[serde(rename = "Peers", default)]
    pub peers: Option<Vec<NodeWire>>,
    #[serde(rename = "PeersChanged", default)]
    pub peers_changed: Option<Vec<NodeWire>>,
    #[serde(rename = "PeersRemoved", default)]
    pub peers_removed: Option<Vec<i64>>,
    #[serde(rename = "PeersChangedPatch", default)]
    pub peers_changed_patch: Option<Vec<PeerChangeWire>>,
    #[serde(rename = "Domain", default)]
    pub domain: String,
    #[serde(rename = "ControlTime", default)]
    pub control_time: Option<String>,
    // DNSConfig, PacketFilter, ClientVersion, etc. are parsed-and-dropped
    // by serde (no fields). v1 doesn't consume them.
}

#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct NodeWire {
    #[serde(rename = "ID", default)]
    pub id: i64,
    #[serde(rename = "StableID", default)]
    pub stable_id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Key", default)]
    pub key: String, // "nodekey:<hex>"
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: String, // "discokey:<hex>"
    #[serde(rename = "Addresses", default)]
    pub addresses: Vec<String>, // "100.64.0.1/32"
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Vec<String>,
    #[serde(rename = "HomeDERP", default)]
    pub home_derp: u16,
    #[serde(rename = "DERP", default)]
    pub derp_legacy: String, // "127.3.3.40:<region>"
    #[serde(rename = "Online", default)]
    pub online: Option<bool>,
    /// M12: peer's advertised direct-path candidates ("ip:port" strings;
    /// IPv4 or "[v6]:port"). Headscale forwards what each peer sent in
    /// its `MapRequest.Endpoints`.
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Vec<String>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct DerpMapWire {
    #[serde(rename = "Regions", default)]
    pub regions: HashMap<String, DerpRegionWire>,
    // HomeParams ignored for v1
}

#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct DerpRegionWire {
    #[serde(rename = "RegionID", default)]
    pub region_id: u16,
    #[serde(rename = "RegionCode", default)]
    pub region_code: String,
    #[serde(rename = "RegionName", default)]
    pub region_name: String,
    #[serde(rename = "Nodes", default)]
    pub nodes: Vec<DerpNodeWire>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct DerpNodeWire {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "RegionID", default)]
    pub region_id: u16,
    #[serde(rename = "HostName", default)]
    pub hostname: String,
    #[serde(rename = "IPv4", default)]
    pub ipv4: String,
    #[serde(rename = "IPv6", default)]
    pub ipv6: String,
    #[serde(rename = "DERPPort", default)]
    pub derp_port: u16,
    #[serde(rename = "STUNPort", default)]
    pub stun_port: i32,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct PeerChangeWire {
    #[serde(rename = "NodeID", default)]
    pub node_id: i64,
    #[serde(rename = "Key", default)]
    pub key: Option<String>,
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: Option<String>,
    #[serde(rename = "HomeDERP", default)]
    pub home_derp: Option<u16>,
    #[serde(rename = "DERPRegion", default)]
    pub derp_region_legacy: Option<u16>,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Option<Vec<String>>,
    #[serde(rename = "Online", default)]
    pub online: Option<bool>,
    #[serde(rename = "LastSeen", default)]
    pub last_seen: Option<String>,
    #[serde(rename = "KeyExpiry", default)]
    pub key_expiry: Option<String>,
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

    #[test]
    fn map_request_serializes_with_session_seq_and_handle() {
        let req = MapRequestWire {
            version: 90,
            compress: String::new(),
            node_key: "nodekey:01".repeat(32),
            disco_key: "discokey:02".repeat(32),
            hostinfo: MapHostinfoWire {
                ipn_version: "tailscale-vita/0.1.0".into(),
                hostname: "vita".into(),
                os: "linux".into(),
                os_version: "vita-3.74".into(),
            },
            stream: true,
            omit_peers: false,
            read_only: false,
            endpoints: vec![],
            map_session_handle: "abc123".into(),
            map_session_seq: 42,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["Version"], 90);
        assert_eq!(v["Stream"], true);
        assert_eq!(v["OmitPeers"], false);
        assert_eq!(v["MapSessionSeq"], 42);
        assert_eq!(v["MapSessionHandle"], "abc123");
        assert_eq!(v["Hostinfo"]["IPNVersion"], "tailscale-vita/0.1.0");
        assert!(v["Endpoints"].is_array());
        assert_eq!(v["Endpoints"].as_array().unwrap().len(), 0);
        // M14 verification: top-level DiscoKey is the canonical place
        // (matches upstream tailcfg.MapRequest.DiscoKey, JSON-encoded
        // as the MarshalText form `"discokey:<hex>"`). Pixel9a's
        // netmap entry on Headscale 0.26 had a non-zero disco_key
        // populated from MapRequest, so the wire path works at this
        // shape — kept this assertion to guard against regressions.
        assert!(v["DiscoKey"].as_str().unwrap().starts_with("discokey:"));
    }

    #[test]
    fn map_response_keepalive_parses() {
        let body = br#"{"KeepAlive":true}"#;
        let resp: MapResponseWire = serde_json::from_slice(body).unwrap();
        assert!(resp.keep_alive);
        assert_eq!(resp.seq, 0);
    }

    #[test]
    fn map_response_full_node_parses() {
        let body = br#"{
            "Seq": 5,
            "Node": {
                "ID": 1,
                "Name": "vita.example.com",
                "Key": "nodekey:e3faa33ff4008f822e0957d41bc1d83c5ba97f362239253e298f64b39a4cda51",
                "Addresses": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
                "HomeDERP": 0
            },
            "Peers": [],
            "Domain": "example.com"
        }"#;
        let resp: MapResponseWire = serde_json::from_slice(body).unwrap();
        assert_eq!(resp.seq, 5);
        assert_eq!(resp.domain, "example.com");
        let node = resp.node.unwrap();
        assert_eq!(node.id, 1);
        assert_eq!(node.addresses.len(), 2);
        assert_eq!(node.addresses[0], "100.64.0.1/32");
    }

    #[test]
    fn peer_change_optional_fields_parse() {
        let body = br#"{"NodeID": 7, "Online": true, "HomeDERP": 5}"#;
        let pc: PeerChangeWire = serde_json::from_slice(body).unwrap();
        assert_eq!(pc.node_id, 7);
        assert_eq!(pc.online, Some(true));
        assert_eq!(pc.home_derp, Some(5));
        assert!(pc.key.is_none());
    }
}
