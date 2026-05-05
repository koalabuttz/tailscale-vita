//! In-memory netmap state, updated by `MapResponse` frames.
//!
//! `apply` merges a non-keepalive `MapResponseWire` into the local
//! `NetMap` and returns a `NetMapDelta` describing the changes for
//! the demo to push into `wg-engine`. The demo never sees the wire
//! types directly — only the typed snapshots.
//!
//! Delta semantics:
//!
//! - `Peers` (full set) → clear, replace.
//! - `PeersChanged` → upsert.
//! - `PeersRemoved` (NodeID list) → look up via `id_to_key`, drop.
//! - `PeersChangedPatch` (sparse) → apply per-field updates onto
//!   existing peers; emit a `RekeyedPeer` if `Key` changed (caller
//!   must drop the old `Tunn` and create a new one).
//! - `Node` → record our own tailnet addresses.
//! - `DERPMap` → replace wholesale.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use tracing::{debug, info, warn};

use crate::types::{DerpMapWire, MapResponseWire, NodeWire, PeerChangeWire};

/// 32 raw bytes — the binary form of a `nodekey:<hex>` value.
pub type NodeKeyBytes = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedIp {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Clone, Debug)]
pub struct PeerSnapshot {
    pub node_id: i64,
    pub node_key: NodeKeyBytes,
    pub disco_key: Option<NodeKeyBytes>,
    pub name: String,
    pub allowed_ips: Vec<AllowedIp>,
    pub home_derp: u16,
    pub online: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerpRegionSnapshot {
    pub region_id: u16,
    pub region_code: String,
    pub region_name: String,
    pub nodes: Vec<DerpNodeSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerpNodeSnapshot {
    pub name: String,
    pub region_id: u16,
    pub hostname: String,
    pub ipv4: String,
    pub ipv6: String,
    pub derp_port: u16,
    pub stun_port: i32,
}

#[derive(Default)]
pub struct NetMap {
    pub our_addrs: Vec<AllowedIp>,
    pub peers: HashMap<NodeKeyBytes, PeerSnapshot>,
    /// Secondary index: server-assigned NodeID → NodeKey. Lets us
    /// resolve `PeersRemoved` and `PeersChangedPatch` entries (which
    /// reference NodeID) back to a peer.
    pub id_to_key: HashMap<i64, NodeKeyBytes>,
    pub derp_regions: HashMap<u16, DerpRegionSnapshot>,
    pub last_seq: i64,
    pub session_handle: String,
    pub domain: String,
}

#[derive(Clone, Debug)]
pub struct RekeyedPeer {
    pub old_key: NodeKeyBytes,
    pub snapshot: PeerSnapshot,
}

#[derive(Default, Debug)]
pub struct NetMapDelta {
    pub upserted: Vec<PeerSnapshot>,
    pub removed: Vec<NodeKeyBytes>,
    pub rekeyed: Vec<RekeyedPeer>,
    pub our_addrs_changed: bool,
    pub derp_map_changed: bool,
    pub patches_applied: usize,
    pub patches_skipped_unknown_node_id: usize,
    pub seq: i64,
}

impl NetMap {
    /// Apply a non-keepalive `MapResponse`. Caller MUST short-circuit
    /// on `keep_alive=true` before invoking this.
    pub(crate) fn apply(&mut self, resp: &MapResponseWire) -> NetMapDelta {
        let mut delta = NetMapDelta::default();

        if resp.seq > self.last_seq {
            self.last_seq = resp.seq;
        }
        delta.seq = self.last_seq;
        if !resp.map_session_handle.is_empty() {
            self.session_handle = resp.map_session_handle.clone();
        }
        if !resp.domain.is_empty() {
            self.domain = resp.domain.clone();
        }

        if let Some(node) = &resp.node {
            let new_addrs = parse_addrs(&node.addresses);
            if !new_addrs.is_empty() && new_addrs != self.our_addrs {
                info!(addrs = ?new_addrs, "control.map.our_addrs.set");
                self.our_addrs = new_addrs;
                delta.our_addrs_changed = true;
            }
        }

        if let Some(dmap) = &resp.derp_map {
            self.derp_regions = parse_derp_regions(dmap);
            info!(
                region_count = self.derp_regions.len(),
                "control.map.derp_map.set"
            );
            delta.derp_map_changed = true;
        }

        if let Some(peers) = &resp.peers {
            // Full set replace: every peer not in the new list is
            // implicitly removed.
            let new_keys: HashMap<NodeKeyBytes, ()> = peers
                .iter()
                .filter_map(|n| parse_nodekey(&n.key).map(|k| (k, ())))
                .collect();
            let old_keys: Vec<NodeKeyBytes> = self.peers.keys().copied().collect();
            for old in old_keys {
                if !new_keys.contains_key(&old) {
                    self.peers.remove(&old);
                    delta.removed.push(old);
                }
            }
            // Rebuild id_to_key from scratch since IDs may have shifted.
            self.id_to_key.clear();
            for n in peers {
                if let Some(snap) = node_to_snapshot(n) {
                    self.id_to_key.insert(snap.node_id, snap.node_key);
                    self.peers.insert(snap.node_key, snap.clone());
                    delta.upserted.push(snap);
                }
            }
        }

        if let Some(peers_changed) = &resp.peers_changed {
            for n in peers_changed {
                if let Some(snap) = node_to_snapshot(n) {
                    self.id_to_key.insert(snap.node_id, snap.node_key);
                    self.peers.insert(snap.node_key, snap.clone());
                    delta.upserted.push(snap);
                }
            }
        }

        if let Some(removed_ids) = &resp.peers_removed {
            for id in removed_ids {
                if let Some(key) = self.id_to_key.remove(id) {
                    self.peers.remove(&key);
                    delta.removed.push(key);
                }
            }
        }

        if let Some(patches) = &resp.peers_changed_patch {
            for patch in patches {
                self.apply_patch(patch, &mut delta);
            }
        }

        debug!(
            seq = delta.seq,
            upserted = delta.upserted.len(),
            removed = delta.removed.len(),
            rekeyed = delta.rekeyed.len(),
            patches = delta.patches_applied,
            "control.map.delta"
        );
        delta
    }

    fn apply_patch(&mut self, patch: &PeerChangeWire, delta: &mut NetMapDelta) {
        let Some(&node_key) = self.id_to_key.get(&patch.node_id) else {
            warn!(node_id = patch.node_id, "control.map.patch.unknown_node_id");
            delta.patches_skipped_unknown_node_id += 1;
            return;
        };
        let Some(peer) = self.peers.get_mut(&node_key) else {
            warn!(node_id = patch.node_id, "control.map.patch.missing_peer");
            delta.patches_skipped_unknown_node_id += 1;
            return;
        };

        // Rekey: NodeKey rotation. Old `Tunn` is invalid; emit a
        // RekeyedPeer event so the demo can drop+create.
        if let Some(new_key_str) = &patch.key {
            if let Some(new_key) = parse_nodekey(new_key_str) {
                if new_key != node_key {
                    let mut new_peer = peer.clone();
                    new_peer.node_key = new_key;
                    apply_patch_fields(&mut new_peer, patch);
                    let old_key = node_key;
                    self.peers.remove(&old_key);
                    self.id_to_key.insert(new_peer.node_id, new_key);
                    self.peers.insert(new_key, new_peer.clone());
                    delta.rekeyed.push(RekeyedPeer {
                        old_key,
                        snapshot: new_peer,
                    });
                    delta.patches_applied += 1;
                    return;
                }
            }
        }

        apply_patch_fields(peer, patch);
        delta.patches_applied += 1;
        delta.upserted.push(peer.clone());
    }
}

fn apply_patch_fields(peer: &mut PeerSnapshot, patch: &PeerChangeWire) {
    if let Some(home) = patch.home_derp {
        peer.home_derp = home;
    } else if let Some(legacy) = patch.derp_region_legacy {
        peer.home_derp = legacy;
    }
    if let Some(disco) = &patch.disco_key {
        if let Some(d) = parse_nodekey_with_prefix(disco, "discokey:") {
            peer.disco_key = Some(d);
        }
    }
    if let Some(online) = patch.online {
        peer.online = online;
    }
    // endpoints / last_seen / key_expiry: v1 doesn't consume.
}

fn node_to_snapshot(n: &NodeWire) -> Option<PeerSnapshot> {
    let node_key = parse_nodekey(&n.key)?;
    let disco_key = if n.disco_key.is_empty() {
        None
    } else {
        parse_nodekey_with_prefix(&n.disco_key, "discokey:")
    };
    let allowed_ips = parse_addrs(&n.allowed_ips);
    let home_derp = if n.home_derp != 0 {
        n.home_derp
    } else {
        parse_legacy_derp(&n.derp_legacy).unwrap_or(0)
    };
    Some(PeerSnapshot {
        node_id: n.id,
        node_key,
        disco_key,
        name: n.name.clone(),
        allowed_ips,
        home_derp,
        online: n.online.unwrap_or(false),
    })
}

fn parse_nodekey(s: &str) -> Option<NodeKeyBytes> {
    parse_nodekey_with_prefix(s, "nodekey:")
}

fn parse_nodekey_with_prefix(s: &str, prefix: &str) -> Option<NodeKeyBytes> {
    let hex = s.strip_prefix(prefix).unwrap_or(s);
    decode_hex_32(hex)
}

fn decode_hex_32(hex: &str) -> Option<NodeKeyBytes> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let s = hex.get(i * 2..i * 2 + 2)?;
        *b = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

fn parse_addrs(addrs: &[String]) -> Vec<AllowedIp> {
    addrs.iter().filter_map(|a| parse_ipv4_cidr(a)).collect()
}

fn parse_ipv4_cidr(s: &str) -> Option<AllowedIp> {
    let (ip, prefix) = s.split_once('/')?;
    let addr: Ipv4Addr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some(AllowedIp { addr, prefix })
}

/// Legacy DERP magic string `"127.3.3.40:<region>"` (used by older capvers
/// before the `HomeDERP` int field). Returns the region.
fn parse_legacy_derp(s: &str) -> Option<u16> {
    let (_, port) = s.rsplit_once(':')?;
    port.parse().ok()
}

fn parse_derp_regions(dmap: &DerpMapWire) -> HashMap<u16, DerpRegionSnapshot> {
    dmap.regions
        .values()
        .map(|r| {
            let nodes = r
                .nodes
                .iter()
                .map(|n| DerpNodeSnapshot {
                    name: n.name.clone(),
                    region_id: n.region_id,
                    hostname: n.hostname.clone(),
                    ipv4: n.ipv4.clone(),
                    ipv6: n.ipv6.clone(),
                    derp_port: n.derp_port,
                    stun_port: n.stun_port,
                })
                .collect();
            (
                r.region_id,
                DerpRegionSnapshot {
                    region_id: r.region_id,
                    region_code: r.region_code.clone(),
                    region_name: r.region_name.clone(),
                    nodes,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MapResponseWire, NodeWire, PeerChangeWire};

    fn node(id: i64, hex_byte: u8, addr: &str) -> NodeWire {
        NodeWire {
            id,
            name: format!("peer-{id}"),
            key: format!("nodekey:{}", format!("{:02x}", hex_byte).repeat(32)),
            addresses: vec![format!("{addr}/32")],
            allowed_ips: vec![format!("{addr}/32")],
            home_derp: 1,
            ..Default::default()
        }
    }

    fn key_bytes(byte: u8) -> NodeKeyBytes {
        [byte; 32]
    }

    #[test]
    fn apply_full_peers_replace() {
        let mut nm = NetMap::default();
        let resp = MapResponseWire {
            seq: 1,
            peers: Some(vec![node(1, 0x11, "100.64.0.2"), node(2, 0x22, "100.64.0.3")]),
            ..Default::default()
        };
        let delta = nm.apply(&resp);
        assert_eq!(delta.upserted.len(), 2);
        assert_eq!(nm.peers.len(), 2);
        assert!(nm.peers.contains_key(&key_bytes(0x11)));
        assert!(nm.peers.contains_key(&key_bytes(0x22)));
    }

    #[test]
    fn apply_full_peers_replace_drops_old() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponseWire {
            peers: Some(vec![node(1, 0x11, "100.64.0.2"), node(2, 0x22, "100.64.0.3")]),
            ..Default::default()
        });
        let delta = nm.apply(&MapResponseWire {
            peers: Some(vec![node(2, 0x22, "100.64.0.3")]),
            ..Default::default()
        });
        assert_eq!(nm.peers.len(), 1);
        assert_eq!(delta.removed, vec![key_bytes(0x11)]);
        assert_eq!(delta.upserted.len(), 1);
    }

    #[test]
    fn apply_peers_changed_upsert() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponseWire {
            peers: Some(vec![node(1, 0x11, "100.64.0.2")]),
            ..Default::default()
        });
        let delta = nm.apply(&MapResponseWire {
            peers_changed: Some(vec![node(2, 0x22, "100.64.0.3")]),
            ..Default::default()
        });
        assert_eq!(nm.peers.len(), 2);
        assert_eq!(delta.upserted.len(), 1);
        assert_eq!(delta.upserted[0].node_id, 2);
    }

    #[test]
    fn apply_peers_removed_drops() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponseWire {
            peers: Some(vec![node(1, 0x11, "100.64.0.2"), node(2, 0x22, "100.64.0.3")]),
            ..Default::default()
        });
        let delta = nm.apply(&MapResponseWire {
            peers_removed: Some(vec![1]),
            ..Default::default()
        });
        assert_eq!(delta.removed, vec![key_bytes(0x11)]);
        assert_eq!(nm.peers.len(), 1);
        assert!(nm.peers.contains_key(&key_bytes(0x22)));
    }

    #[test]
    fn apply_patch_home_derp_change() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponseWire {
            peers: Some(vec![node(7, 0x77, "100.64.0.7")]),
            ..Default::default()
        });
        let delta = nm.apply(&MapResponseWire {
            peers_changed_patch: Some(vec![PeerChangeWire {
                node_id: 7,
                home_derp: Some(42),
                ..Default::default()
            }]),
            ..Default::default()
        });
        assert_eq!(delta.patches_applied, 1);
        assert_eq!(nm.peers[&key_bytes(0x77)].home_derp, 42);
    }

    #[test]
    fn apply_patch_rekey_swaps_node_key() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponseWire {
            peers: Some(vec![node(7, 0x77, "100.64.0.7")]),
            ..Default::default()
        });
        let new_key = format!("nodekey:{}", "ab".repeat(32));
        let delta = nm.apply(&MapResponseWire {
            peers_changed_patch: Some(vec![PeerChangeWire {
                node_id: 7,
                key: Some(new_key.clone()),
                ..Default::default()
            }]),
            ..Default::default()
        });
        assert_eq!(delta.rekeyed.len(), 1);
        assert_eq!(delta.rekeyed[0].old_key, key_bytes(0x77));
        assert_eq!(delta.rekeyed[0].snapshot.node_key, [0xabu8; 32]);
        assert!(!nm.peers.contains_key(&key_bytes(0x77)));
        assert!(nm.peers.contains_key(&[0xabu8; 32]));
        assert_eq!(nm.id_to_key[&7], [0xabu8; 32]);
    }

    #[test]
    fn apply_patch_unknown_node_id_warns_and_skips() {
        let mut nm = NetMap::default();
        let delta = nm.apply(&MapResponseWire {
            peers_changed_patch: Some(vec![PeerChangeWire {
                node_id: 999,
                home_derp: Some(5),
                ..Default::default()
            }]),
            ..Default::default()
        });
        assert_eq!(delta.patches_applied, 0);
        assert_eq!(delta.patches_skipped_unknown_node_id, 1);
    }

    #[test]
    fn apply_records_our_addrs_from_node() {
        let mut nm = NetMap::default();
        let resp = MapResponseWire {
            node: Some(NodeWire {
                id: 1,
                addresses: vec!["100.64.0.1/32".into(), "fd7a:115c:a1e0::1/128".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let delta = nm.apply(&resp);
        assert!(delta.our_addrs_changed);
        // IPv6 is filtered out; only IPv4 makes it through parse_ipv4_cidr.
        assert_eq!(nm.our_addrs.len(), 1);
        assert_eq!(nm.our_addrs[0].addr, Ipv4Addr::new(100, 64, 0, 1));
    }

    #[test]
    fn apply_seq_advances_monotonically() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponseWire {
            seq: 5,
            ..Default::default()
        });
        assert_eq!(nm.last_seq, 5);
        nm.apply(&MapResponseWire {
            seq: 3,
            ..Default::default()
        });
        // Older seqs don't reset us.
        assert_eq!(nm.last_seq, 5);
    }

    #[test]
    fn parse_legacy_derp_works() {
        assert_eq!(parse_legacy_derp("127.3.3.40:5"), Some(5));
        assert_eq!(parse_legacy_derp(""), None);
    }
}
