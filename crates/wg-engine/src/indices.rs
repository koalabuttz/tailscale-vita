use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use vita_sync::RwLock;

use crate::peer::{Ipv4Cidr, Peer};

/// Three-index lookup of peers, mirroring Cloudflare's `device::Device`
/// pattern (see `boringtun/src/device/mod.rs:148`):
///
/// - `by_pubkey` for upserts and broadcast (handshake-init dispatch).
/// - `by_idx` for O(1) inbound dispatch via `receiver_idx >> 8`.
/// - `by_ip` for outbound dispatch via longest-prefix-match on the
///   plaintext IPv4 destination.
///
/// Per the lock-ordering invariant in PLAN-V1.md §"Cross-cutting decisions",
/// these are acquired together (read-only) at the top of any pump
/// iteration and dropped before the inner `Peer.tunn` lock is taken.
pub struct Indices {
    pub by_pubkey: RwLock<HashMap<[u8; 32], Arc<Peer>>>,
    pub by_idx: RwLock<HashMap<u32, Arc<Peer>>>,
    pub by_ip: RwLock<AllowedIps>,
}

impl Indices {
    pub fn new() -> Self {
        Self {
            by_pubkey: RwLock::new(HashMap::new()),
            by_idx: RwLock::new(HashMap::new()),
            by_ip: RwLock::new(AllowedIps::new()),
        }
    }

    pub fn insert(&self, peer: Arc<Peer>) {
        self.by_pubkey
            .write()
            .insert(peer.pubkey, Arc::clone(&peer));
        self.by_idx
            .write()
            .insert(peer.our_index, Arc::clone(&peer));
        self.by_ip.write().insert_peer(&peer);
    }

    pub fn remove(&self, pubkey: &[u8; 32]) {
        if let Some(peer) = self.by_pubkey.write().remove(pubkey) {
            self.by_idx.write().remove(&peer.our_index);
            self.by_ip.write().remove_peer(&peer);
        }
    }

    pub fn count(&self) -> usize {
        self.by_pubkey.read().len()
    }
}

impl Default for Indices {
    fn default() -> Self {
        Self::new()
    }
}

/// Longest-prefix-match for AllowedIPs. Stored as a `Vec` sorted
/// descending by prefix length; lookup is O(N) but N ≤ 8 in v1
/// (one peer × a handful of advertised CIDRs).
pub struct AllowedIps {
    entries: Vec<(Ipv4Cidr, Arc<Peer>)>,
}

impl AllowedIps {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn insert_peer(&mut self, peer: &Arc<Peer>) {
        for cidr in &peer.allowed_ips {
            self.entries.push((*cidr, Arc::clone(peer)));
        }
        // Sort by prefix length descending so longest-match wins on first hit.
        self.entries.sort_by(|a, b| b.0.prefix.cmp(&a.0.prefix));
    }

    pub fn remove_peer(&mut self, peer: &Arc<Peer>) {
        let target = peer.pubkey;
        self.entries.retain(|(_, p)| p.pubkey != target);
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<Arc<Peer>> {
        self.entries
            .iter()
            .find(|(cidr, _)| cidr.contains(ip))
            .map(|(_, p)| Arc::clone(p))
    }
}

impl Default for AllowedIps {
    fn default() -> Self {
        Self::new()
    }
}
