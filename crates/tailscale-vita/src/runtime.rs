//! `Runtime` — the long-running tailnet client. Owns the Noise tunnel,
//! HTTP/2 conn, WG engine, DERP transport, netstack, and `MapClient`,
//! and exposes a small public API for embedding apps:
//!
//! - `Runtime::up(config)` — blocks: fetch_server_key → KeyStore →
//!   Noise+h2 → register → engine + DerpTransport + Stack + MapClient.
//!   Returns once register has succeeded; the first MapResponse arrives
//!   inside `run_event_loop`.
//! - `runtime.netstack()` — for binding TcpListeners.
//! - `runtime.lifecycle()` — read current `OnlineState`.
//! - `runtime.run_event_loop(should_stop)` — drives MapClient + DERP
//!   plumbing + lifecycle. Returns when `should_stop` returns true OR
//!   the tunnel dies.
//! - `runtime.shutdown()` — drops in the right order.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use smoltcp::wire::Ipv4Cidr as SmolIpv4Cidr;
use tracing::{info, warn};

use netstack::{Stack, StackConfig};
use ts_control::async_io::AsyncNoiseStream;
use ts_control::http2::Http2Conn;
use ts_control::record::NoiseStream;
use ts_control::{KeyStore, MapClient, MapEvent, NetMap};
use ts_derp::{DerpMap, DerpNodeAddr, DerpTransport, DerpTransportCtl};
use wg_engine::{Engine, EngineConfig, Ipv4Cidr, PeerConfig, TransportAddr};

use crate::config::Config;
use crate::error::RuntimeError;
use crate::lifecycle::{LifecycleTracker, OnlineState};
use crate::proto::{consume_early_payload, hex_short, read_server_response};

pub struct Runtime {
    config: Config,
    state_dir: PathBuf,
    derp_ctl: DerpTransportCtl,
    engine: Arc<Engine>,
    /// `None` after `shutdown()` has consumed it. Held in `Option` so
    /// `shutdown` can take it; runtime field access through
    /// `self.stack` panics if shutdown has already been called.
    stack: Option<Stack>,
    map: Option<MapClient>,
    lifecycle: Mutex<LifecycleTracker>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RunStats {
    pub snapshots: u32,
    pub keepalives: u32,
    pub control_errors: u32,
    pub final_lifecycle: OnlineState,
    pub final_peer_count: usize,
    pub final_alive_regions: usize,
}

impl Default for OnlineState {
    fn default() -> Self {
        OnlineState::Connecting
    }
}

impl Runtime {
    /// Block until the v1 control plane is up: fetch server key, load
    /// keystore, complete Noise+HTTP/2 handshake, register, spin up
    /// engine + DerpTransport + Stack + MapClient.
    pub fn up(config: Config) -> Result<Self, RuntimeError> {
        let state_dir = PathBuf::from(&config.state_dir);
        let host_authority = config.host_authority();

        info!(
            control_url = %config.control_url,
            hostname = %config.hostname,
            "runtime.up.start"
        );

        // 1. Fetch server's Noise pubkey.
        let server_pub = ts_control::fetch_server_key(&config.control_url, config.capver)?;
        info!(server_pub = %server_pub, "control.key.received");

        // 2. KeyStore — persistent machine/node/disco keys.
        let ks = KeyStore::load_or_generate(&state_dir)?;

        // 3-5. Noise IK handshake + h2 over the Noise tunnel. Lifted
        // verbatim from the M9 demo's run().
        info!("starting Noise IK handshake");
        let mut hs = ts_control::NoiseHandshaker::new(&ks.machine_priv, &server_pub)?;
        let header_b64 = hs.build_init_header()?;
        info!(b64_len = header_b64.len(), "control.noise.init.built");

        let mut upgraded = ts_control::upgrade::dial_and_upgrade(&config.control_url, &header_b64)?;
        info!(leftover = upgraded.leftover.len(), "control.upgrade.101");

        let server_response = read_server_response(&mut upgraded)?;
        let nt = hs.finalize(&server_response)?;
        info!(
            handshake_hash = %hex_short(&nt.handshake_hash),
            "control.noise.handshake.complete"
        );

        let leftover = upgraded.leftover;
        let mut noise_stream = NoiseStream::new(upgraded.tcp, nt, leftover);
        consume_early_payload(&mut noise_stream)?;

        let async_stream = AsyncNoiseStream::spawn(noise_stream);
        info!("opening HTTP/2 over Noise");
        let mut conn = Http2Conn::open(async_stream)?;
        info!("control.http2.handshake.complete");

        // 6. Register using config.auth_key directly (M10 — no separate
        //    auth-key.txt file). User pastes the Headscale preauth key
        //    into config.toml.
        let auth_key = config.auth_key.trim();
        info!(len = auth_key.len(), "control.auth_key.loaded");

        let outcome = ts_control::register(
            &mut conn,
            auth_key,
            &ks.node_pub,
            &config.hostname,
            &host_authority,
        )?;
        info!(
            machine_authorized = outcome.machine_authorized,
            node_key_expired = outcome.node_key_expired,
            "control.register.ok"
        );

        // 8. DerpTransport + Engine + Stack.
        // Same 32 priv bytes serve WG identity AND DERP NaCl-box ECDH
        // (verified in spike-05).
        let our_secret = x25519_dalek::StaticSecret::from(ks.node_priv.0);
        let (derp_transport, derp_ctl) =
            DerpTransport::new(ks.node_priv.0, ks.node_pub.0, config.max_derp_conns);

        let engine = Arc::new(Engine::new(EngineConfig {
            our_static_secret: our_secret,
            mtu: 1280,
            peers: vec![],
        })?);
        let engine_running = engine.start(derp_transport)?;
        info!("wg-engine: pump running with DerpTransport");

        let stack = Stack::start(StackConfig::new(), engine_running)?;
        info!("netstack: poll thread running (no local IP yet)");

        // 9. MapClient.
        let map = MapClient::start(
            conn,
            ks.node_pub,
            ks.disco_pub,
            config.hostname.clone(),
            host_authority.clone(),
            state_dir.clone(),
        )?;
        info!("control.map.started");

        Ok(Self {
            config,
            state_dir,
            derp_ctl,
            engine,
            stack: Some(stack),
            map: Some(map),
            lifecycle: Mutex::new(LifecycleTracker::new()),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Borrowed access to the netstack so the demo can bind a
    /// TcpListener on the tailnet IP:port.
    pub fn netstack(&self) -> &Stack {
        self.stack
            .as_ref()
            .expect("runtime: netstack accessed after shutdown")
    }

    pub fn lifecycle(&self) -> OnlineState {
        self.lifecycle.lock().state()
    }

    pub fn engine_peer_count(&self) -> usize {
        self.engine.peer_count()
    }

    pub fn alive_derp_regions(&self) -> Vec<u16> {
        self.derp_ctl.alive_regions()
    }

    /// Drive the MapClient + DERP plumbing + lifecycle until
    /// `should_stop` returns true. Each iteration polls one `MapEvent`
    /// with a 2 s timeout.
    pub fn run_event_loop<F>(&mut self, mut should_stop: F) -> Result<RunStats, RuntimeError>
    where
        F: FnMut() -> bool,
    {
        let stack = self
            .stack
            .as_ref()
            .ok_or_else(|| RuntimeError::Internal("runtime stack already shut down".into()))?;
        let mut map = self
            .map
            .take()
            .ok_or_else(|| RuntimeError::Internal("runtime map_client already taken".into()))?;

        let mut snapshots = 0u32;
        let mut keepalives = 0u32;
        let mut control_errors = 0u32;
        let mut derp_map_set = false;
        let mut local_addrs_set = false;

        while !should_stop() {
            let event = match map.next_event(Duration::from_secs(2)) {
                Ok(e) => e,
                Err(e) => {
                    control_errors += 1;
                    warn!(error = %e, "control.map.error");
                    self.lifecycle.lock().record_control_reconnect();
                    // v1: continue the loop. M11+ adds real reconnect.
                    continue;
                }
            };
            let now = Instant::now();

            match event {
                MapEvent::Snapshot(snap) => {
                    snapshots += 1;
                    self.lifecycle.lock().record_map_event(now);

                    if !derp_map_set && snap.derp_region_count > 0 {
                        let derp_map = build_derp_map(map.netmap());
                        self.derp_ctl.set_derp_map(derp_map.clone());
                        match self.derp_ctl.pick_and_set_home(&derp_map) {
                            Ok(home) => info!(
                                home,
                                regions = derp_map.regions.len(),
                                "derp.home.selected"
                            ),
                            Err(e) => warn!(error = %e, "derp.home.selection.failed"),
                        }
                        derp_map_set = true;
                    }

                    if !local_addrs_set && !snap.our_addrs.is_empty() {
                        let local_cidrs: Vec<SmolIpv4Cidr> = snap
                            .our_addrs
                            .iter()
                            .map(|a| SmolIpv4Cidr::new(a.addr, a.prefix))
                            .collect();
                        info!(
                            addrs = ?local_cidrs,
                            "netstack.local_addrs.from_mapresponse"
                        );
                        stack.set_local_addrs(local_cidrs);
                        local_addrs_set = true;
                    }

                    push_delta_to_engine(&self.engine, &snap, self.derp_ctl.home_region());
                }
                MapEvent::KeepAlive { seq } => {
                    keepalives += 1;
                    self.lifecycle.lock().record_map_event(now);
                    info!(seq, count = keepalives, "control.map.keepalive");
                }
                MapEvent::Idle => {}
            }

            // Proxy DERP rx signal until a real per-rx hook lands.
            if !self.derp_ctl.alive_regions().is_empty() {
                self.lifecycle.lock().record_derp_rx(now);
            }
            self.lifecycle.lock().tick(
                now,
                self.engine.peer_count(),
                self.derp_ctl.alive_regions().len(),
            );
        }

        // Map drops here — terminating the long-poll cleanly.
        drop(map);

        Ok(RunStats {
            snapshots,
            keepalives,
            control_errors,
            final_lifecycle: self.lifecycle.lock().state(),
            final_peer_count: self.engine.peer_count(),
            final_alive_regions: self.derp_ctl.alive_regions().len(),
        })
    }

    /// Graceful teardown. Closes DERP conns, drops the netstack
    /// (which joins poll thread + wg-engine pump). Idempotent — safe
    /// to call from `Drop`.
    pub fn shutdown(mut self) {
        info!("runtime.shutdown.requested");
        // DERP first so conns close cleanly.
        self.derp_ctl.shutdown();
        // Drop map (if we never ran the event loop).
        self.map = None;
        // Stack drop joins netstack poll + engine pump.
        let _ = self.stack.take();
        info!("runtime.shutdown.complete");
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // If the demo neglected to call shutdown(), do it now (in field
        // drop order, this is implicit, but we want the explicit order:
        // derp first, then map, then stack).
        self.derp_ctl.shutdown();
        self.map = None;
        let _ = self.stack.take();
    }
}

/// Translate ts-control's `NetMap.derp_regions` into ts-derp's
/// `DerpMap` shape. Both HashMap<u16, region-info> but with different
/// node types — copy field-by-field. Lifted verbatim from M9 demo.
fn build_derp_map(nm: &NetMap) -> DerpMap {
    let mut regions = std::collections::HashMap::with_capacity(nm.derp_regions.len());
    for (region_id, region) in &nm.derp_regions {
        let nodes: Vec<DerpNodeAddr> = region
            .nodes
            .iter()
            .map(|n| DerpNodeAddr {
                region_id: n.region_id,
                name: n.name.clone(),
                hostname: n.hostname.clone(),
                ipv4: n.ipv4.clone(),
                ipv6: n.ipv6.clone(),
                derp_port: n.derp_port,
            })
            .collect();
        regions.insert(*region_id, nodes);
    }
    DerpMap { regions }
}

fn push_delta_to_engine(
    engine: &Engine,
    snap: &ts_control::NetMapSnapshot,
    our_home: u16,
) {
    let delta = &snap.delta;
    info!(
        seq = snap.seq,
        peer_count = snap.peer_count,
        derp_regions = snap.derp_region_count,
        upserted = delta.upserted.len(),
        removed = delta.removed.len(),
        rekeyed = delta.rekeyed.len(),
        patches = delta.patches_applied,
        "control.map.netmap"
    );

    for p in &delta.upserted {
        let allowed_ips: Vec<Ipv4Cidr> = p
            .allowed_ips
            .iter()
            .map(|a| Ipv4Cidr {
                addr: a.addr,
                prefix: a.prefix,
            })
            .collect();
        let pubkey = x25519_dalek::PublicKey::from(p.node_key);
        let region = if p.home_derp != 0 {
            p.home_derp
        } else {
            our_home
        };
        let initial_endpoint = if region != 0 {
            Some(TransportAddr::Derp {
                region,
                peer_pubkey: p.node_key,
            })
        } else {
            None
        };
        if let Err(e) = engine.upsert_peer(PeerConfig {
            pubkey,
            preshared_key: None,
            persistent_keepalive_secs: Some(25),
            allowed_ips,
            initial_endpoint,
        }) {
            warn!(error = %e, node_id = p.node_id, "control.map.peer.upsert.failed");
        } else {
            info!(
                node_id = p.node_id,
                allowed_ips = ?p.allowed_ips,
                home_derp = p.home_derp,
                routed_via_region = region,
                "control.map.peer.upsert"
            );
        }
    }

    for k in &delta.removed {
        let pubkey = x25519_dalek::PublicKey::from(*k);
        engine.remove_peer(&pubkey);
        info!(?k, "control.map.peer.remove");
    }

    for r in &delta.rekeyed {
        let old = x25519_dalek::PublicKey::from(r.old_key);
        engine.remove_peer(&old);
        let allowed_ips: Vec<Ipv4Cidr> = r
            .snapshot
            .allowed_ips
            .iter()
            .map(|a| Ipv4Cidr {
                addr: a.addr,
                prefix: a.prefix,
            })
            .collect();
        let new_pubkey = x25519_dalek::PublicKey::from(r.snapshot.node_key);
        let region = if r.snapshot.home_derp != 0 {
            r.snapshot.home_derp
        } else {
            our_home
        };
        let initial_endpoint = if region != 0 {
            Some(TransportAddr::Derp {
                region,
                peer_pubkey: r.snapshot.node_key,
            })
        } else {
            None
        };
        let _ = engine.upsert_peer(PeerConfig {
            pubkey: new_pubkey,
            preshared_key: None,
            persistent_keepalive_secs: Some(25),
            allowed_ips,
            initial_endpoint,
        });
        info!(node_id = r.snapshot.node_id, "control.map.peer.rekeyed");
    }
}
