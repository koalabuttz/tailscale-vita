use crate::ControlError;
use serde::de::Deserializer;

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
pub const NLKEY_PREFIX: &str = "nlpub:";

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

/// Tailnet-Lock public key. Modern (capver ≥ ~120) Tailscale registers
/// expect this even when TKA is disabled — upstream tailscale-rs sends
/// `nl_key: Some(<NLPublic>)` unconditionally. Same Curve25519 wire
/// shape as NodePublic / DiscoPublic, but serialized as `nlpub:<hex>`.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct NLPublic(pub [u8; 32]);

impl NLPublic {
    pub fn to_nlkey_string(&self) -> String {
        format!("{}{}", NLKEY_PREFIX, encode_hex(&self.0))
    }
}

pub struct NLPrivate(pub [u8; 32]);

impl Drop for NLPrivate {
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

/// serde helper: accept JSON `null` as `T::default()` (e.g. an empty
/// `Vec`). Tailscale at capver≥138 returns some sequence-shaped fields
/// as JSON `null` rather than `[]`; the default `Vec<T>` deserializer
/// rejects null with "invalid type: null, expected a sequence". Apply
/// via `#[serde(default, deserialize_with = "null_or_default")]`.
fn null_or_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let opt = Option::<T>::deserialize(de)?;
    Ok(opt.unwrap_or_default())
}

#[derive(Serialize)]
pub(crate) struct MapRequestWire {
    #[serde(rename = "Version")]
    pub version: u32,
    /// "zstd" or "" (no compression). `omitzero` semantics — empty
    /// string is dropped from the wire.
    #[serde(rename = "Compress", skip_serializing_if = "String::is_empty")]
    pub compress: String,
    /// Upstream Go's controlclient sets `KeepAlive: true` on every
    /// streaming MapRequest. Tells the server to inject KeepAlive
    /// frames to keep the long-poll alive across NAT timeouts.
    #[serde(rename = "KeepAlive", skip_serializing_if = "std::ops::Not::not")]
    pub keep_alive: bool,
    #[serde(rename = "NodeKey")]
    pub node_key: String, // "nodekey:<hex>"
    #[serde(rename = "DiscoKey")]
    pub disco_key: String, // "discokey:<hex>"
    /// Field order matches Go's `tailcfg.MapRequest` (Stream serializes
    /// before Hostinfo).
    #[serde(rename = "Stream", skip_serializing_if = "std::ops::Not::not")]
    pub stream: bool,
    #[serde(rename = "Hostinfo")]
    pub hostinfo: MapHostinfoWire,
    #[serde(rename = "OmitPeers", skip_serializing_if = "std::ops::Not::not")]
    pub omit_peers: bool,
    #[serde(rename = "ReadOnly", skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
    #[serde(rename = "Endpoints", skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// M14E: parallel array describing each `Endpoints[i]`'s type
    /// (`tailcfg.EndpointType`: 0=Unknown, 1=Local, 2=STUN,
    /// 3=Portmapped, 4=STUN4LocalPort, 5=ExplicitConf). Upstream Go
    /// `controlclient/direct.go` always sends the two arrays as a
    /// matched pair; missing this is suspected to make the server
    /// classify our endpoints as "untyped" → drop them. `omitempty`
    /// behavior preserves backwards compat (Headscale tolerates absent).
    #[serde(rename = "EndpointTypes", skip_serializing_if = "Vec::is_empty")]
    pub endpoint_types: Vec<u8>,
    /// M14I: only serialize when non-empty. Upstream Go uses
    /// `json:",omitzero"` on this field; empty handle ⇒ "client is
    /// starting a fresh session" (server allocates a new one).
    /// Sending an arbitrary client-generated handle with `Seq=0` looks
    /// to the server like "I want to resume session X starting at
    /// seq=0", which is nonsense if the server has no record of session
    /// X — suspected silent-reject for state writes.
    #[serde(rename = "MapSessionHandle", skip_serializing_if = "String::is_empty")]
    pub map_session_handle: String,
    /// M14I: same — `omitzero` semantics. Only meaningful when
    /// resuming an existing session (paired with non-empty handle).
    #[serde(rename = "MapSessionSeq", skip_serializing_if = "is_zero_i64")]
    pub map_session_seq: i64,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// Mirrors `tailcfg.Hostinfo` on the wire. All fields are
/// `Option<...>` (Hostname excepted) and serde drops `None`s — callers
/// pick which fields to populate.
#[derive(Serialize)]
pub(crate) struct MapHostinfoWire {
    #[serde(rename = "IPNVersion", skip_serializing_if = "Option::is_none")]
    pub ipn_version: Option<String>,
    /// `App` identifies the client variant (e.g. `tailscale-vita/...`).
    /// Tsrs sends it; required for our DiscoKey-commit path on real
    /// Tailscale (Phase 11 bisection — TBD whether load-bearing).
    #[serde(rename = "App", skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(rename = "BackendLogID", skip_serializing_if = "Option::is_none")]
    pub backend_log_id: Option<String>,
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "OS", skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(rename = "OSVersion", skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(rename = "NetInfo", skip_serializing_if = "Option::is_none")]
    pub net_info: Option<NetInfoWire>,
    /// M20 (Taildrop): services this node offers on the tailnet. Control
    /// propagates these into every peer's netmap; `tailscale file cp <f>
    /// vita:` reports "no targets" unless we advertise a `peerapi4`
    /// entry here. `None` (the default) omits the field entirely, so a
    /// services-less MapRequest is byte-identical to the pre-M20 body —
    /// control is strict about the Hostinfo envelope shape (TS2021
    /// lesson), so we don't want to send an empty `[]` either.
    #[serde(rename = "Services", skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ServiceWire>>,
}

/// One `Hostinfo.Services` entry — a service this node offers, advertised
/// to peers via the netmap. Wire shape mirrors Tailscale's
/// `tailcfg.Service`: `{"Proto":"peerapi4","Port":8098,
/// "Description":"peerapi"}`. PascalCase tags are load-bearing.
#[derive(Serialize)]
pub(crate) struct ServiceWire {
    /// e.g. `"peerapi4"` (Taildrop over IPv4). Our netstack is v4-only,
    /// so we never advertise `peerapi6`.
    #[serde(rename = "Proto")]
    pub proto: String,
    /// TCP port the service listens on at our tailnet IP.
    #[serde(rename = "Port")]
    pub port: u16,
    /// Free-text label; Tailscale uses `"peerapi"` for the Taildrop
    /// endpoint.
    #[serde(rename = "Description")]
    pub description: String,
}

#[derive(Serialize, Default)]
pub(crate) struct NetInfoWire {
    /// 0 means "client hasn't picked a home region yet"; perfectly
    /// valid for first MapRequest.
    #[serde(rename = "PreferredDERP")]
    pub preferred_derp: i32,
    #[serde(rename = "LinkType")]
    pub link_type: String,
    #[serde(rename = "WorkingUDP", skip_serializing_if = "Option::is_none")]
    pub working_udp: Option<bool>,
    #[serde(rename = "WorkingIPv6", skip_serializing_if = "Option::is_none")]
    pub working_ipv6: Option<bool>,
    #[serde(rename = "HavePortMap", skip_serializing_if = "std::ops::Not::not")]
    pub have_port_map: bool,
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
    /// M19 identity card: display profiles for the users owning `Node`
    /// and `Peers`. **Delta**, not a full set — since CapVer 5 control
    /// sends only new/changed profiles per frame, so `netmap` upserts
    /// rather than replaces (a no-change frame carries an empty/`null`
    /// list, which must not blank the accumulated map). CapVer≥138
    /// serializes the empty case as JSON `null` — reuse `null_or_default`.
    #[serde(rename = "UserProfiles", default, deserialize_with = "null_or_default")]
    pub user_profiles: Vec<UserProfileWire>,
    #[serde(rename = "ControlTime", default)]
    pub control_time: Option<String>,
    /// `PacketFilter` is destination-side access control. A nil/absent value
    /// in a map delta means unchanged (tailcfg map-version contract).
    #[serde(
        rename = "PacketFilter",
        default,
        deserialize_with = "deserialize_packet_filter"
    )]
    pub packet_filter: PacketFilterWire,
    // DNSConfig, ClientVersion, etc. are parsed-and-dropped by serde.
}

#[derive(Default, Debug, Clone)]
pub(crate) enum PacketFilterWire {
    /// Field omitted from this delta frame; retain the previous policy.
    #[default]
    Missing,
    Rules(Vec<FilterRuleWire>),
}

fn deserialize_packet_filter<'de, D>(d: D) -> Result<PacketFilterWire, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<FilterRuleWire>>::deserialize(d)?
        .map(PacketFilterWire::Rules)
        .unwrap_or(PacketFilterWire::Missing))
}

/// Wire form of tailcfg.FilterRule after control has expanded policy aliases.
#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct FilterRuleWire {
    #[serde(rename = "SrcIPs", default)]
    pub src_ips: Vec<String>,
    #[serde(rename = "DstPorts", default)]
    pub dst_ports: Vec<NetPortRangeWire>,
    #[serde(rename = "IPProto", default)]
    pub ip_proto: Vec<u8>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct NetPortRangeWire {
    #[serde(rename = "IP", default)]
    pub ip: String,
    #[serde(rename = "Ports", default)]
    pub ports: PortRangeWire,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct PortRangeWire {
    #[serde(rename = "First", default)]
    pub first: u16,
    #[serde(rename = "Last", default)]
    pub last: u16,
}

/// Mirrors `tailcfg.UserProfile` — the display identity for a user that
/// owns one or more nodes. M19 resolves our own `Node.User` against
/// these to show a human login name in the dashboard identity card.
#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct UserProfileWire {
    #[serde(rename = "ID", default)]
    pub id: i64,
    #[serde(rename = "LoginName", default)]
    pub login_name: String,
    #[serde(rename = "DisplayName", default)]
    pub display_name: String,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub(crate) struct NodeWire {
    #[serde(rename = "ID", default)]
    pub id: i64,
    #[serde(rename = "StableID", default)]
    pub stable_id: String,
    /// M19: server-assigned user ID owning this node. Resolved against
    /// `MapResponse.UserProfiles` to display a human login name. Tagged
    /// nodes point this at a tag pseudo-user with no human profile.
    /// `0` = unset/omitted.
    #[serde(rename = "User", default)]
    pub user: i64,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Key", default)]
    pub key: String, // "nodekey:<hex>"
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: String, // "discokey:<hex>"
    #[serde(rename = "Addresses", default, deserialize_with = "null_or_default")]
    pub addresses: Vec<String>, // "100.64.0.1/32"
    #[serde(rename = "AllowedIPs", default, deserialize_with = "null_or_default")]
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
    #[serde(rename = "Endpoints", default, deserialize_with = "null_or_default")]
    pub endpoints: Vec<String>,
    /// M15-B (ACL UX): tags the server has assigned to this node, e.g.
    /// `["tag:vita"]`. Server-computed from the auth-key + tailnet ACL
    /// policy. When this Vita's own NodeWire has an empty `tags` field,
    /// the runtime emits a one-shot warning that we have full tailnet
    /// access — encourages users to re-issue with `--tags=tag:vita` and
    /// write an ACL.
    #[serde(rename = "Tags", default, deserialize_with = "null_or_default")]
    pub tags: Vec<String>,
    /// RFC3339 key-expiry (tailcfg `Node.KeyExpiry`). Present on the
    /// self Node and every peer; long-standing field, not CapVer-gated.
    /// M17-B surfaces the SELF value as the "node dropping off soon"
    /// warning. Zero value (`0001-01-01T00:00:00Z`) = expiry disabled.
    #[serde(rename = "KeyExpiry", default)]
    pub key_expiry: Option<String>,
    /// RFC3339 last-seen (tailcfg `Node.LastSeen`, `*time.Time`).
    /// Typically populated only for offline/idle peers; None/omitted
    /// for currently-online peers. M17-B shows it in peer detail.
    #[serde(rename = "LastSeen", default)]
    pub last_seen: Option<String>,
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
    #[serde(rename = "Nodes", default, deserialize_with = "null_or_default")]
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
            keep_alive: true,
            node_key: "nodekey:01".repeat(32),
            disco_key: "discokey:02".repeat(32),
            hostinfo: MapHostinfoWire {
                ipn_version: Some("tailscale-vita/0.1.0".into()),
                app: None,
                backend_log_id: Some("test-backend-log".into()),
                hostname: "vita".into(),
                os: Some("linux".into()),
                os_version: Some("vita-3.74".into()),
                net_info: Some(NetInfoWire::default()),
                services: None,
            },
            stream: true,
            omit_peers: false,
            read_only: false,
            endpoints: vec![],
            endpoint_types: vec![],
            map_session_handle: "abc123".into(),
            map_session_seq: 42,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["Version"], 90);
        assert_eq!(v["Stream"], true);
        // M14J: OmitPeers/ReadOnly default-false → omitted from wire
        // (matches upstream Go `omitzero`). Their absence here
        // proves the skip_serializing_if is wired correctly.
        assert!(v.get("OmitPeers").is_none());
        assert!(v.get("ReadOnly").is_none());
        // Empty Compress/Endpoints from this test fixture → omitted.
        // (Production sends Compress="zstd" and a populated Endpoints
        // vec — see map.rs::build_map_request.)
        assert!(v.get("Endpoints").is_none());
        assert!(v.get("Compress").is_none());
        assert_eq!(v["MapSessionSeq"], 42);
        assert_eq!(v["MapSessionHandle"], "abc123");
        assert_eq!(v["Hostinfo"]["IPNVersion"], "tailscale-vita/0.1.0");
        // M14 verification: top-level DiscoKey is the canonical place
        // (matches upstream tailcfg.MapRequest.DiscoKey, JSON-encoded
        // as the MarshalText form `"discokey:<hex>"`). Pixel9a's
        // netmap entry on Headscale 0.26 had a non-zero disco_key
        // populated from MapRequest, so the wire path works at this
        // shape — kept this assertion to guard against regressions.
        assert!(v["DiscoKey"].as_str().unwrap().starts_with("discokey:"));
        // M14E: empty EndpointTypes is omitted from the wire
        // (skip_serializing_if = "Vec::is_empty"), preserving
        // backwards-compat with Headscale and earlier capvers.
        assert!(v.get("EndpointTypes").is_none());
    }

    #[test]
    fn hostinfo_services_serializes_exact_shape() {
        // M20: a Taildrop-advertising Hostinfo carries a single
        // `peerapi4` Service. Assert the EXACT wire keys/values control
        // expects — a malformed Hostinfo can break the map stream.
        let hi = MapHostinfoWire {
            ipn_version: None,
            app: None,
            backend_log_id: None,
            hostname: "vita".into(),
            os: None,
            os_version: None,
            net_info: None,
            services: Some(vec![ServiceWire {
                proto: "peerapi4".into(),
                port: 8098,
                description: "peerapi".into(),
            }]),
        };
        let v = serde_json::to_value(&hi).unwrap();
        let svc = &v["Services"][0];
        assert_eq!(svc["Proto"], "peerapi4");
        assert_eq!(svc["Port"], 8098);
        assert_eq!(svc["Description"], "peerapi");
        // Exact wire bytes: serialize the STRUCT (not via `to_value`,
        // which alphabetizes keys) so field order + PascalCase are
        // asserted as they hit the wire. No lowercase serde leakage.
        let s = serde_json::to_string(&hi).unwrap();
        assert!(
            s.contains(r#""Services":[{"Proto":"peerapi4","Port":8098,"Description":"peerapi"}]"#),
            "unexpected Services shape: {s}"
        );
    }

    #[test]
    fn hostinfo_services_none_omits_field() {
        // `None` must drop the field ENTIRELY (not emit `"Services":null`
        // or `[]`) so the pre-M20 body shape is preserved byte-for-byte.
        let hi = MapHostinfoWire {
            ipn_version: None,
            app: None,
            backend_log_id: None,
            hostname: "vita".into(),
            os: None,
            os_version: None,
            net_info: None,
            services: None,
        };
        let v = serde_json::to_value(&hi).unwrap();
        assert!(v.get("Services").is_none());
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
    fn node_wire_tags_present() {
        let body = br#"{"ID":1,"Name":"v","Tags":["tag:vita","tag:portable"]}"#;
        let n: NodeWire = serde_json::from_slice(body).unwrap();
        assert_eq!(n.tags, vec!["tag:vita".to_string(), "tag:portable".into()]);
    }

    #[test]
    fn node_wire_tags_absent_defaults_to_empty() {
        // Untagged auth-key produces a node record with no Tags field.
        // M15-B uses this absence to trigger the registration-time
        // ACL warning.
        let body = br#"{"ID":1,"Name":"v"}"#;
        let n: NodeWire = serde_json::from_slice(body).unwrap();
        assert!(n.tags.is_empty());
    }

    #[test]
    fn node_wire_tags_null_defaults_to_empty() {
        // Some control-plane implementations emit `"Tags": null`
        // instead of omitting the field. `null_or_default` handles
        // this (same pattern as Addresses/AllowedIPs/Endpoints).
        let body = br#"{"ID":1,"Name":"v","Tags":null}"#;
        let n: NodeWire = serde_json::from_slice(body).unwrap();
        assert!(n.tags.is_empty());
    }

    #[test]
    fn node_wire_user_parses() {
        // M19: Node.User carries the owning user's ID for identity-card
        // resolution; absent → 0 (unset).
        let n: NodeWire = serde_json::from_slice(br#"{"ID":1,"User":42}"#).unwrap();
        assert_eq!(n.user, 42);
        let n2: NodeWire = serde_json::from_slice(br#"{"ID":1}"#).unwrap();
        assert_eq!(n2.user, 0);
    }

    #[test]
    fn user_profile_wire_parses() {
        let body = br#"{"ID":42,"LoginName":"dave@example.com","DisplayName":"Dave"}"#;
        let up: UserProfileWire = serde_json::from_slice(body).unwrap();
        assert_eq!(up.id, 42);
        assert_eq!(up.login_name, "dave@example.com");
        assert_eq!(up.display_name, "Dave");
    }

    #[test]
    fn map_response_user_profiles_parse() {
        let body = br#"{"UserProfiles":[{"ID":1,"LoginName":"a@b"},{"ID":2,"LoginName":"c@d"}]}"#;
        let resp: MapResponseWire = serde_json::from_slice(body).unwrap();
        assert_eq!(resp.user_profiles.len(), 2);
        assert_eq!(resp.user_profiles[0].id, 1);
        assert_eq!(resp.user_profiles[1].login_name, "c@d");
    }

    #[test]
    fn map_response_user_profiles_null_defaults_to_empty() {
        // CapVer≥138 serializes the empty sequence as JSON `null`;
        // `null_or_default` maps it to an empty Vec (same pattern as
        // Peers/Addresses) rather than a deserialize error.
        let body = br#"{"UserProfiles":null}"#;
        let resp: MapResponseWire = serde_json::from_slice(body).unwrap();
        assert!(resp.user_profiles.is_empty());
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
