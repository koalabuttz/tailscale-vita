//! Multi-peer BoringTun host for tailscale-vita.
//!
//! M2 wires this against `UdpTransport` and a hand-crafted ICMP test
//! harness; M3 plugs it into smoltcp via `Arc<Mutex<VecDeque<Vec<u8>>>>`
//! shared with `EngineRunning`; M8 swaps `UdpTransport` for `DerpTransport`.
//!
//! The hot loop lives in `pump.rs`. Public API is `Engine::new` →
//! `Engine::start` → drain `EngineRunning.tun_rx` / push to `tun_tx`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use vita_thread::JoinHandle;

use arc_swap::ArcSwap;
use boringtun::noise::Tunn;
use vita_sync::{Condvar, Mutex};
use vita_log::info;

mod config;
mod dispatch;
pub mod icmp;
mod indices;
mod peer;
mod pump;
mod queue;
mod transport;

mod error;

pub use config::{build_engine_inputs, decode_priv_key, decode_pub_key, read_wg_toml, WgToml};
pub use error::WgError;
pub use peer::{DirectPathHint, Ipv4Cidr, Peer, PeerConfig, PeerStats, TransportAddr};
pub use transport::{NoopTransport, Transport, UdpTransport};

use indices::Indices;

/// Caller-supplied engine configuration.
pub struct EngineConfig {
    pub our_static_secret: x25519_dalek::StaticSecret,
    /// In-tunnel MTU. v1 default 1280.
    pub mtu: usize,
    pub peers: Vec<PeerConfig>,
}

impl EngineConfig {
    pub fn from_wg_toml(toml: &WgToml) -> Result<Self, WgError> {
        let (secret, peers) = build_engine_inputs(toml)?;
        Ok(Self {
            our_static_secret: secret,
            mtu: 1280,
            peers,
        })
    }
}

/// Shared engine state. Cheap to clone (it's `Arc<Inner>`-shaped via the
/// `Arc<Indices>` interior). Construct once at startup; `start` spawns
/// the pump thread driving a `Transport`.
pub struct Engine {
    indices: Arc<Indices>,
    next_idx: AtomicU32,
    our_static_secret: x25519_dalek::StaticSecret,
}

impl Engine {
    /// Build an engine with the given peer set. Each peer gets a fresh
    /// `Tunn` instance; on `start`, the pump primes the handshake init
    /// for any peer with a known transport address.
    pub fn new(cfg: EngineConfig) -> Result<Self, WgError> {
        let indices = Arc::new(Indices::new());
        let next_idx = AtomicU32::new(1);
        let engine = Self {
            indices,
            next_idx,
            our_static_secret: cfg.our_static_secret,
        };
        for peer_cfg in cfg.peers {
            engine.upsert_peer(peer_cfg)?;
        }
        Ok(engine)
    }

    /// Add or replace a peer entry by pubkey. Allocates a fresh
    /// `our_index` and a fresh `Tunn`. If the pubkey already exists, the
    /// old peer is removed and replaced.
    pub fn upsert_peer(&self, cfg: PeerConfig) -> Result<(), WgError> {
        let pubkey_bytes: [u8; 32] = *cfg.pubkey.as_bytes();
        // Drop any existing entry with this pubkey first.
        self.indices.remove(&pubkey_bytes);

        let our_index = self.next_idx.fetch_add(1, Ordering::Relaxed);
        let tunn = Tunn::new(
            self.our_static_secret.clone(),
            cfg.pubkey,
            cfg.preshared_key,
            cfg.persistent_keepalive_secs,
            our_index,
            None,
        );

        let peer = Arc::new(Peer {
            pubkey: pubkey_bytes,
            our_index,
            allowed_ips: cfg.allowed_ips,
            transport_addr: ArcSwap::from(Arc::new(cfg.initial_endpoint)),
            tunn: Mutex::new(tunn),
            stats: Mutex::new(PeerStats::default()),
        });

        self.indices.insert(peer);
        Ok(())
    }

    pub fn remove_peer(&self, pubkey: &x25519_dalek::PublicKey) {
        self.indices.remove(pubkey.as_bytes());
    }

    pub fn set_endpoint(&self, pubkey: &x25519_dalek::PublicKey, endpoint: TransportAddr) {
        if let Some(peer) = self.indices.by_pubkey.read().get(pubkey.as_bytes()).cloned() {
            peer.set_transport_addr(endpoint);
        }
    }

    pub fn peer_stats(&self, pubkey: &x25519_dalek::PublicKey) -> Option<PeerStats> {
        self.indices
            .by_pubkey
            .read()
            .get(pubkey.as_bytes())
            .map(|p| *p.stats.lock())
    }

    /// Snapshot peer count. Cheap (single read-lock + len). Used by M7
    /// to verify that the netmap delta stream has populated the engine.
    pub fn peer_count(&self) -> usize {
        self.indices.by_pubkey.read().len()
    }

    /// Spawn the pump thread driving `transport`. Returns an `EngineRunning`
    /// with the rx/tx queues for callers to interact with the tunnel.
    ///
    /// Takes `&self` so the caller keeps the `Engine` alive after start —
    /// M7's control thread needs to call `upsert_peer` / `remove_peer`
    /// based on `MapResponse` deltas.
    pub fn start<T: Transport + 'static>(
        &self,
        transport: T,
    ) -> Result<EngineRunning, WgError> {
        self.start_with_hint(transport, None)
    }

    /// Like [`Engine::start`], with an optional [`DirectPathHint`] oracle
    /// the pump consults at send time. M12 wires `MagicSocketCtl` here.
    pub fn start_with_hint<T: Transport + 'static>(
        &self,
        transport: T,
        direct_path_hint: Option<Arc<dyn DirectPathHint>>,
    ) -> Result<EngineRunning, WgError> {
        let transport = Arc::new(transport);
        let tun_rx_q = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
        let tun_tx_q = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
        let rx_notify = Arc::new((Mutex::new(false), Condvar::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let join = {
            let indices = Arc::clone(&self.indices);
            let transport = Arc::clone(&transport);
            let tun_rx_q = Arc::clone(&tun_rx_q);
            let tun_tx_q = Arc::clone(&tun_tx_q);
            let rx_notify = Arc::clone(&rx_notify);
            let shutdown = Arc::clone(&shutdown);
            let hint = direct_path_hint.clone();
            vita_thread::Builder::new()
                .name("wg_engine")
                .stack_size(256 * 1024)
                .spawn(move || {
                    pump::run(
                        indices,
                        transport,
                        hint,
                        tun_rx_q,
                        tun_tx_q,
                        rx_notify,
                        shutdown,
                    )
                })
                .map_err(WgError::Io)?
        };

        info!(
            peers = self.indices.count(),
            direct_hint = direct_path_hint.is_some(),
            "wg-engine started"
        );

        Ok(EngineRunning {
            tun_rx: tun_rx_q,
            tun_tx: tun_tx_q,
            rx_notify,
            shutdown,
            join: Some(join),
        })
    }
}

/// Handle to a running engine. Drop or call `shutdown` to stop.
pub struct EngineRunning {
    /// Decapsulated plaintext IPv4 packets from peers. Drain to consume.
    pub tun_rx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Plaintext IPv4 packets to encapsulate and send. Push to send.
    pub tun_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Wakes whenever `tun_rx` gets a new packet. M3 smoltcp wakeup hook.
    pub rx_notify: Arc<(Mutex<bool>, Condvar)>,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle>,
}

impl EngineRunning {
    /// Signal shutdown and join the pump thread.
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for EngineRunning {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}
