//! `RuntimeSnapshot` — JSON-friendly cross-thread view of the running
//! tailnet client. Published by the event loop on every `MapEvent`
//! (and after lifecycle / peer-region changes); read by M14 LocalAPI
//! handlers running on a dedicated thread.
//!
//! Why a snapshot vs. direct state access: the live `NetMap` lives
//! inside `MapClient` which is consumed by `run_event_loop`. The
//! LocalAPI server thread can't reach it without coupling. An
//! `Arc<RwLock<RuntimeSnapshot>>` lets the event loop publish a fresh
//! copy at a single point per cycle, and any number of readers (HTTP
//! handlers, debug tooling) snapshot cheaply with bounded lock time.
//!
//! Field shapes match the LocalAPI JSON we serve out — keep these
//! types and their `serde` impls in lockstep with consumer
//! expectations (the future LiveArea UI parses them directly).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::lifecycle::OnlineState;

/// Top-level published runtime state. Cheap to clone; small enough to
/// hand out by value when needed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeSnapshot {
    /// Unix time the snapshot was last refreshed by the event loop.
    pub updated_at_unix: u64,
    /// Unix time the runtime started. Used by `/localapi/v0/health`
    /// to compute uptime without an extra clock plumbing path.
    pub started_at_unix: u64,
    /// Hostname this runtime registered as. Surfaced for UI display.
    pub hostname: String,
    /// Our tailnet addresses (typically a single /32 like
    /// `100.127.67.49/32`).
    pub our_addrs: Vec<AllowedIpView>,
    /// Current lifecycle state (Connecting / Online / Degraded /
    /// Offline / AuthFailed / SecurityFailed).
    pub lifecycle: OnlineState,
    /// Human-readable explanation when `lifecycle` is fatal.
    pub fatal_reason: Option<String>,
    /// M18: the control-plane `AuthURL` to display (as a QR + text) when
    /// `lifecycle == NeedsLogin`. The user scans it on a phone and
    /// approves the node; `Runtime::up`'s wait-loop then long-polls
    /// until authorized and clears this. `None` outside interactive
    /// login.
    #[serde(default)]
    pub auth_url: Option<String>,
    /// Peer count for quick sanity-check reads.
    pub peer_count: usize,
    /// Our chosen DERP home region (legacy field, see netmap.rs).
    pub derp_home_region: u16,
    /// DERP regions currently connected. Empty during cold start.
    pub alive_derp_regions: Vec<u16>,
    /// Our magicsock UDP bind (typically `0.0.0.0:41641`).
    pub magic_local: SocketAddr,
    /// Our public-mapped UDP endpoint discovered via STUN (Stage-3
    /// netcheck). `None` until netcheck completes.
    pub public_endpoint: Option<SocketAddr>,
    /// M15-B: ACL posture as the server computed it for our node.
    /// LocalAPI consumers (and the future LiveArea UI) display this
    /// prominently so users notice when their Vita has full tailnet
    /// access (the load-bearing security boundary in
    /// `memory/vita_threat_model.md`).
    pub acl: AclSummary,
    /// M17-B: our own node's RFC3339 key-expiry. `None` if the server
    /// omitted it; `0001-…` zero value means expiry disabled. The
    /// dashboard warns before this passes (a silent tailnet drop-off).
    #[serde(default)]
    pub our_key_expiry: Option<String>,
    /// M19 identity card: the tailnet's domain (e.g. `example.com`),
    /// from `MapResponse.Domain`. `None` until the first full map. Read
    /// from persistent NetMap state on every publish so the 3 s
    /// full-replace republish can't blank it.
    #[serde(default)]
    pub tailnet_domain: Option<String>,
    /// M19 identity card: our own login name (e.g. `dave@example.com`),
    /// resolved from `UserProfiles` + `Node.User`. `None` for tagged
    /// nodes (no human user) or before the profile lands — the UI falls
    /// back to the hostname.
    #[serde(default)]
    pub user_login: Option<String>,
    /// M19: true while an interactive login is running (between the
    /// user's `/login-interactive` and the authorized response). With
    /// `lifecycle == NeedsLogin` + `auth_url` it drives the dashboard's
    /// three full-screen login modes (spinner / QR / logged-out).
    #[serde(default)]
    pub login_in_progress: bool,
    /// Per-peer view, keyed by node-key hex.
    pub peers: HashMap<String, PeerView>,
}

/// What scope the server has granted this Vita on the tailnet. When
/// `has_tags=false`, the auth-key wasn't tagged and the device can
/// reach every peer + service the ACL allows for untagged nodes —
/// which on most personal tailnets is "everything." UIs should
/// surface this in a high-visibility way (red badge in LiveArea, etc.).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AclSummary {
    /// Tags assigned to our node, e.g. `["tag:vita"]`. Empty when
    /// untagged.
    pub tags: Vec<String>,
    /// Convenience: `!tags.is_empty()`. Lets JSON consumers branch
    /// without scanning the array. Mirrors upstream Tailscale's
    /// `tailscale status --json` "TagsSet" boolean.
    pub has_tags: bool,
}

/// Per-peer info LocalAPI consumers see. Constructed by merging
/// `PeerSnapshot` (from netmap) with magicsock's direct-path state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerView {
    /// Full 64-char hex node-key (sans `nodekey:` prefix).
    pub node_key_hex: String,
    /// Stable server-assigned numeric ID (helpful for cross-referencing
    /// with `tailscale debug netmap` output on other devices).
    pub node_id: i64,
    /// Peer hostname.
    pub name: String,
    /// Peer's last-known online state per control plane.
    pub online: bool,
    /// The peer's primary tailnet IP, when it has one /32 entry. None
    /// for peers whose only `allowed_ips` are CIDR routes (rare).
    pub tailscale_ip: Option<Ipv4Addr>,
    /// Verbose dotted-quad/CIDR form of every advertised allowed_ip.
    pub allowed_ips: Vec<String>,
    /// Peer's home DERP region ID. 0 means unassigned (legacy DERP
    /// field on the peer carries the actual home).
    pub home_derp: u16,
    /// Direct-path UDP endpoint candidates the peer advertised in
    /// MapRequest.Endpoints. Empty for pre-M12 peers.
    pub endpoints: Vec<String>,
    /// Whether we currently have an alive Disco path to this peer.
    pub direct_path_alive: bool,
    /// Which of the peer's endpoints answered our last Disco ping (if
    /// any). Useful for diagnosing "they advertised 5 endpoints; which
    /// one actually worked?".
    pub direct_path_endpoint: Option<SocketAddr>,
    /// Last-measured RTT on the alive path, milliseconds. None when
    /// no alive path exists.
    pub direct_path_rtt_ms: Option<u64>,
    /// M17-B: RFC3339 last-seen; usually only set for offline peers.
    #[serde(default)]
    pub last_seen: Option<String>,
    /// M17-B: RFC3339 key-expiry (`0001-…` = expiry disabled).
    #[serde(default)]
    pub key_expiry: Option<String>,
}

/// Wire-friendly form of `ts_control::AllowedIp`. Kept as `addr` +
/// `prefix` rather than collapsed to a string so JSON consumers can
/// route on either independently.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowedIpView {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl RuntimeSnapshot {
    /// Pre-`up()` placeholder. Useful so `Runtime::snapshot()` can
    /// hand out a non-None value during the brief window between
    /// `Runtime::up` setup and the first event-loop publish.
    pub fn empty(hostname: String, magic_local: SocketAddr) -> Self {
        Self {
            updated_at_unix: now_unix(),
            started_at_unix: now_unix(),
            hostname,
            our_addrs: Vec::new(),
            lifecycle: OnlineState::Connecting,
            fatal_reason: None,
            auth_url: None,
            peer_count: 0,
            derp_home_region: 0,
            alive_derp_regions: Vec::new(),
            magic_local,
            public_endpoint: None,
            acl: AclSummary::default(),
            our_key_expiry: None,
            tailnet_domain: None,
            user_login: None,
            login_in_progress: false,
            peers: HashMap::new(),
        }
    }
}

/// Format a 32-byte node-key as 64 lowercase hex chars. Used for both
/// snapshot map keys and `PeerView.node_key_hex`.
pub fn node_key_hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Wall-clock unix seconds. Returns 0 if the system clock is before
/// the epoch (impossible in practice; defensive).
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_serializes_to_json() {
        let snap = RuntimeSnapshot::empty(
            "vita".into(),
            "0.0.0.0:41641".parse().unwrap(),
        );
        let json = serde_json::to_string(&snap).expect("snapshot serialize");
        // Spot-check a couple of fields are present.
        assert!(json.contains("\"hostname\":\"vita\""));
        assert!(json.contains("\"lifecycle\":\"Connecting\""));
        assert!(json.contains("\"peer_count\":0"));
    }

    #[test]
    fn snapshot_identity_fields_default_when_absent() {
        // SUPRX and eboot are versioned independently; a snapshot JSON
        // written by an older binary (no M19 identity fields) must still
        // parse thanks to `#[serde(default)]`.
        let json = r#"{
            "updated_at_unix": 1,
            "started_at_unix": 1,
            "hostname": "vita",
            "our_addrs": [],
            "lifecycle": "Connecting",
            "fatal_reason": null,
            "peer_count": 0,
            "derp_home_region": 0,
            "alive_derp_regions": [],
            "magic_local": "0.0.0.0:41641",
            "public_endpoint": null,
            "acl": {"tags": [], "has_tags": false},
            "peers": {}
        }"#;
        let snap: RuntimeSnapshot = serde_json::from_str(json).expect("parse legacy snapshot");
        assert_eq!(snap.tailnet_domain, None);
        assert_eq!(snap.user_login, None);
        assert!(!snap.login_in_progress);
    }

    #[test]
    fn snapshot_serializes_identity_fields() {
        let mut snap = RuntimeSnapshot::empty(
            "vita".into(),
            "0.0.0.0:41641".parse().unwrap(),
        );
        snap.tailnet_domain = Some("example.com".into());
        snap.user_login = Some("dave@example.com".into());
        snap.login_in_progress = true;
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"tailnet_domain\":\"example.com\""));
        assert!(json.contains("\"user_login\":\"dave@example.com\""));
        assert!(json.contains("\"login_in_progress\":true"));
    }

    #[test]
    fn node_key_hex_is_64_lowercase_chars() {
        let bytes = [0xAB; 32];
        let s = node_key_hex(&bytes);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(s.starts_with("abababab"));
    }

    #[test]
    fn peer_view_serializes_with_expected_fields() {
        let peer = PeerView {
            node_key_hex: "ab".repeat(32),
            node_id: 42,
            name: "phone".into(),
            online: true,
            tailscale_ip: Some(Ipv4Addr::new(100, 64, 0, 5)),
            allowed_ips: vec!["100.64.0.5/32".into()],
            home_derp: 12,
            endpoints: vec!["166.198.24.1:29944".into()],
            direct_path_alive: true,
            direct_path_endpoint: Some("166.198.24.1:29944".parse().unwrap()),
            direct_path_rtt_ms: Some(68),
            last_seen: None,
            key_expiry: Some("2027-01-15T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&peer).unwrap();
        assert!(json.contains("\"name\":\"phone\""));
        assert!(json.contains("\"direct_path_alive\":true"));
        assert!(json.contains("\"direct_path_rtt_ms\":68"));
        assert!(json.contains("\"tailscale_ip\":\"100.64.0.5\""));
    }
}
