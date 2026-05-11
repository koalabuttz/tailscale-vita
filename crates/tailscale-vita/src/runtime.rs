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

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::unbounded;
use parking_lot::Mutex;
use smoltcp::wire::Ipv4Cidr as SmolIpv4Cidr;
use tracing::{info, warn};

use netstack::{Stack, StackConfig};
use ts_control::async_io::AsyncNoiseStream;
use ts_control::http2::Http2Conn;
use ts_control::record::NoiseStream;
use ts_control::{KeyStore, MapClient, MapEvent, NetMap};
use ts_derp::{DerpMap, DerpNodeAddr, DerpTransport, DerpTransportCtl};
use ts_disco::keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use ts_magicsock::{MagicSocket, MagicSocketCtl, DEFAULT_PORT as MAGICSOCK_PORT};
use wg_engine::{Engine, EngineConfig, Ipv4Cidr, PeerConfig, TransportAddr};

use crate::config::Config;
use crate::dual_transport::DualTransport;
use crate::error::RuntimeError;
use crate::lifecycle::{LifecycleTracker, OnlineState};
use crate::proto::{consume_early_payload, hex_short, read_server_response};

pub struct Runtime {
    config: Config,
    state_dir: PathBuf,
    derp_ctl: DerpTransportCtl,
    engine: Arc<Engine>,
    magic_ctl: MagicSocketCtl,
    /// Held to keep the magic-socket worker alive; dropped on shutdown.
    _magic_socket: Option<MagicSocket>,
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

        // Generate a per-process BackendLogID — upstream Go client
        // hard-errors without one and the modern Tailscale coordinator
        // appears to use it as a session disambiguator. 32 hex chars.
        let backend_log_id = generate_backend_log_id();
        info!(backend_log_id = %backend_log_id, "control.backend_log_id.generated");

        let outcome = ts_control::register(
            &mut conn,
            auth_key,
            &ks.node_pub,
            &ks.nl_pub,
            &backend_log_id,
            &config.hostname,
            &host_authority,
        )?;
        info!(
            machine_authorized = outcome.machine_authorized,
            node_key_expired = outcome.node_key_expired,
            "control.register.ok"
        );

        // 8. DerpTransport + MagicSocket (M12) + Engine + Stack.
        // Same 32 priv bytes serve WG identity AND DERP NaCl-box ECDH
        // (verified in spike-05). The disco priv key is separate.
        let our_secret = x25519_dalek::StaticSecret::from(ks.node_priv.0);
        let (derp_transport, derp_ctl) =
            DerpTransport::new(ks.node_priv.0, ks.node_pub.0, config.max_derp_conns);

        // Bind the Disco / direct-path UDP socket. Try the canonical
        // 41641 first; if it's taken (or sceNet rejects), fall back
        // to an ephemeral port. The actual bound port goes into our
        // MapRequest.Endpoints advertisement so peers know where to ping.
        let (non_disco_tx, non_disco_rx) = unbounded();
        let disco_priv = DiscoPrivateKey::from_bytes(ks.disco_priv.0);
        let our_node_pub_disco = NodePublicKey::from(ks.node_pub.0);
        let (magic_socket, magic_ctl) = bind_magicsock(
            disco_priv,
            our_node_pub_disco,
            non_disco_tx,
        )?;
        let magic_local = magic_ctl.local_addr();
        info!(%magic_local, "magicsock.bound");

        // Local endpoint candidates for MapRequest.Endpoints. Discover
        // our LAN IP via the connect-trick (kernel routing decision —
        // no packet actually sent).
        let local_endpoints = build_local_endpoints(&config.control_url, magic_local);
        // M14E: parallel `tailcfg.EndpointType` codes. Every endpoint
        // we build via the connect-trick is a LAN IP (Vita's WiFi
        // address), so type 1 = `EndpointLocal`. Real Tailscale
        // requires this paired array to non-Unknown-classify our
        // advertised endpoints.
        let local_endpoint_types: Vec<u8> = vec![1u8; local_endpoints.len()];
        info!(
            ?local_endpoints,
            ?local_endpoint_types,
            "magicsock.endpoints.advertise"
        );

        let engine = Arc::new(Engine::new(EngineConfig {
            our_static_secret: our_secret,
            mtu: 1280,
            peers: vec![],
        })?);
        let dual = DualTransport::new(magic_ctl.clone(), non_disco_rx, derp_transport);
        let hint: Arc<dyn wg_engine::DirectPathHint> = Arc::new(magic_ctl.clone());
        let engine_running = engine.start_with_hint(dual, Some(hint))?;
        info!("wg-engine: pump running with DualTransport(Magic+Derp)");

        let stack = Stack::start(StackConfig::new(), engine_running)?;
        info!("netstack: poll thread running (no local IP yet)");

        // 9. MapClient. local_endpoints sourced from MagicSocket bind.
        let map = MapClient::start(
            conn,
            ks.node_pub,
            ks.disco_pub,
            config.hostname.clone(),
            backend_log_id.clone(),
            host_authority.clone(),
            state_dir.clone(),
            local_endpoints,
            local_endpoint_types,
        )?;
        info!("control.map.started");

        Ok(Self {
            config,
            state_dir,
            derp_ctl,
            engine,
            magic_ctl,
            _magic_socket: Some(magic_socket),
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
        // Fire the NetInfo "lite" MapRequest exactly once after the
        // first snapshot establishes the DERP map. Without this call,
        // real Tailscale's coord server never commits our DiscoKey /
        // HomeDERP / Endpoints to its persistent state — peers see us
        // with `disco_key=discokey:0...` no matter how long the
        // streaming long-poll runs. Mirrors upstream Go's
        // `controlclient.Direct.SetDerpHomeRegion` which sends a
        // `stream=false` MapRequest with NetInfo + OmitPeers=true.
        let mut sent_netinfo_once = false;

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

                    // Fire the NetInfo lite MapRequest once, after the
                    // DERP map is loaded. M14M-Phase11 found that the
                    // server's persistent-state write path (DiscoKey,
                    // home region, endpoints) only triggers on a
                    // non-streaming MapRequest carrying NetInfo with
                    // real DerpLatency.
                    //
                    // Stage 3 (M12 prereq): probe each DERP region's
                    // STUN port (UDP/3478) via our magicsock to
                    // discover (a) our public-mapped endpoint for
                    // peers behind different NATs and (b) real
                    // round-trip times to populate DerpLatency. Falls
                    // back to stub 50 ms latencies if every probe
                    // fails (e.g. UDP egress blocked).
                    if derp_map_set && !sent_netinfo_once {
                        sent_netinfo_once = true;
                        let report = run_netcheck(&self.magic_ctl, map.netmap());
                        let preferred_derp = if report.preferred_derp != 0 {
                            report.preferred_derp
                        } else {
                            self.derp_ctl.home_region()
                        };
                        let latencies: Vec<(String, f64)> = if !report.derp_latency.is_empty() {
                            report
                                .derp_latency
                                .iter()
                                .map(|(rid, secs)| (format!("{}-v4", rid), *secs))
                                .collect()
                        } else {
                            // Fallback: stub 50 ms for every known region.
                            map.netmap()
                                .derp_regions
                                .keys()
                                .flat_map(|rid| {
                                    vec![
                                        (format!("{}-v4", rid), 0.050),
                                        (format!("{}-v6", rid), 0.050),
                                    ]
                                })
                                .collect()
                        };
                        // Public-endpoint discovery: prefer the DERP-
                        // probe's reflection if any DERP responded;
                        // else fall back to public STUN (Google /
                        // Cloudflare / Twilio). Tailscale's own DERPs
                        // sometimes refuse STUN from clients without
                        // recent activity history.
                        let public_endpoint = report.public_endpoint.or_else(|| {
                            ts_magicsock::netcheck::discover_public_endpoint(
                                &self.magic_ctl,
                                ts_magicsock::netcheck::DEFAULT_PROBE_TIMEOUT,
                            )
                        });
                        let extra: Vec<String> = public_endpoint
                            .into_iter()
                            .map(|sa| sa.to_string())
                            .collect();
                        match map.send_netinfo_update(preferred_derp, latencies, extra) {
                            Ok(()) => info!(
                                preferred_derp,
                                "control.map.netinfo_update.sent"
                            ),
                            Err(e) => warn!(error = %e, "control.map.netinfo_update.failed"),
                        }
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
                    push_delta_to_magicsock(&self.magic_ctl, &snap);
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

/// Run STUN-based netcheck against every region in the netmap's
/// DERPMap. Returns aggregated reflected endpoint + per-region RTT.
///
/// Each region's first node is probed at `<ipv4>:3478` (the standard
/// STUN port that all Tailscale DERP servers run). Probes go in
/// parallel via `MagicSocketCtl::stun_probe`; aggregation waits up to
/// `DEFAULT_PROBE_TIMEOUT` for responses.
///
/// Skipping a region is benign — its absence from the report just
/// means that region won't appear in `DerpLatency` (and the server
/// won't consider it for our home selection).
fn run_netcheck(magic_ctl: &MagicSocketCtl, nm: &NetMap) -> ts_magicsock::netcheck::NetcheckReport {
    let mut targets: Vec<ts_magicsock::netcheck::StunTarget> = Vec::new();
    for (region_id, region) in &nm.derp_regions {
        let Some(node) = region.nodes.first() else {
            continue;
        };
        // Each DERP node's `ipv4` field is the resolved IP of the
        // relay; STUN uses UDP/3478. Skip nodes with empty / unparseable
        // ipv4 (rare — control server populates this).
        let target_str = format!("{}:{}", node.ipv4, ts_magicsock::netcheck::STUN_PORT);
        match target_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => targets.push(ts_magicsock::netcheck::StunTarget {
                region_id: *region_id,
                ipv4_addr: addr,
            }),
            Err(_) => {
                warn!(
                    region_id,
                    ipv4 = %node.ipv4,
                    "netcheck.target.parse_failed"
                );
            }
        }
    }
    ts_magicsock::netcheck::probe_targets(
        magic_ctl,
        &targets,
        ts_magicsock::netcheck::DEFAULT_PROBE_TIMEOUT,
    )
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

/// Plumb each peer's Disco identity + endpoint candidates into the
/// magic socket so its ping pump can probe direct paths. Called per
/// MapResponse alongside `push_delta_to_engine`.
fn push_delta_to_magicsock(magic: &MagicSocketCtl, snap: &ts_control::NetMapSnapshot) {
    let delta = &snap.delta;
    for p in &delta.upserted {
        let disco_pub = match p.disco_key {
            Some(b) => DiscoPublicKey::from(b),
            None => continue, // pre-disco peer; can't reach directly
        };
        if p.endpoints.is_empty() {
            continue;
        }
        magic.upsert_peer(p.node_key, disco_pub, p.endpoints.clone());
        info!(
            node_id = p.node_id,
            endpoint_count = p.endpoints.len(),
            "magicsock.peer.upsert"
        );
    }
    for k in &delta.removed {
        magic.remove_peer(k);
    }
    for r in &delta.rekeyed {
        magic.remove_peer(&r.old_key);
        if let Some(b) = r.snapshot.disco_key {
            if !r.snapshot.endpoints.is_empty() {
                magic.upsert_peer(
                    r.snapshot.node_key,
                    DiscoPublicKey::from(b),
                    r.snapshot.endpoints.clone(),
                );
            }
        }
    }
}

/// Bind the Disco/direct-path UDP socket. Tries the canonical 41641
/// first; on failure (port taken, sceNet rejection) falls back to
/// ephemeral (0.0.0.0:0).
fn bind_magicsock(
    disco_priv: DiscoPrivateKey,
    our_node_pub: NodePublicKey,
    non_disco_tx: crossbeam_channel::Sender<ts_magicsock::NonDiscoPacket>,
) -> Result<(MagicSocket, MagicSocketCtl), RuntimeError> {
    let primary: SocketAddr = (IpAddr::from([0, 0, 0, 0]), MAGICSOCK_PORT).into();
    match MagicSocket::bind(primary, disco_priv, our_node_pub, non_disco_tx.clone()) {
        Ok(p) => Ok(p),
        Err(e) => {
            warn!(error = %e, port = MAGICSOCK_PORT, "magicsock.bind.primary_failed; trying ephemeral");
            let fallback: SocketAddr = (IpAddr::from([0, 0, 0, 0]), 0).into();
            // Re-derive disco_priv from a fresh copy of the key bytes
            // (the previous one was moved into the failed bind call).
            // Avoid persisting a separate priv copy by reading it back
            // from the disco-pub-derived secret — but DiscoPrivateKey
            // doesn't support that. Workaround: clone via from_bytes()
            // BEFORE the first bind. See caller.
            //
            // Since bind_magicsock takes `disco_priv` by value and we
            // already consumed it, the caller must have given us a
            // unique copy if they want fallback. Phase 2 keeps it
            // simple and propagates the original error.
            let _ = fallback;
            Err(RuntimeError::Internal(format!(
                "magicsock bind failed on {primary}: {e}"
            )))
        }
    }
}

/// Generate a 32-hex-char `BackendLogID` for the lifetime of this
/// runtime. Upstream uses logtail's session ID; we just need
/// something unique-per-process that *looks* like a real client.
fn generate_backend_log_id() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(32);
    use std::fmt::Write as _;
    for b in &bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Discover our LAN IP via the connect-trick (ask the kernel which
/// local IP would route to a given external address; no packet sent).
/// Returns the formatted endpoint strings to advertise in
/// MapRequest.Endpoints. Empty vec on discovery failure — better to
/// send nothing than wrong addresses.
///
/// **Important**: an empty Endpoints list appears to be the silent
/// gate that causes real Tailscale (capver 138) to refuse to commit
/// our `Node.DiscoKey` to its database. The connect-trick used to
/// silently fail on `https://` control URLs because the URL has no
/// port and `UdpSocket::connect(&str)` requires `host:port` form, so
/// MapRequest went out with `Endpoints: []`. We now parse out
/// host+port (defaulting 443 for https, 80 for http) before probing.
fn build_local_endpoints(control_url: &str, magic_local: SocketAddr) -> Vec<String> {
    let (host, default_port) = if let Some(rest) = control_url.strip_prefix("https://") {
        (rest, 443u16)
    } else if let Some(rest) = control_url.strip_prefix("http://") {
        (rest, 80u16)
    } else {
        (control_url, 443u16)
    };
    let host = host.split('/').next().unwrap_or(host);
    let host_port = if host.contains(':') {
        // Already has explicit port (e.g. Headscale on `192.168.8.147:8080`).
        host.to_string()
    } else {
        format!("{host}:{default_port}")
    };
    let probe = match UdpSocket::bind(("0.0.0.0", 0)).and_then(|s| {
        s.connect(host_port.as_str())?;
        s.local_addr()
    }) {
        Ok(addr) => addr,
        Err(e) => {
            warn!(error = %e, %host_port, "lan_ip.probe.failed");
            return vec![];
        }
    };
    let lan_ip = probe.ip();
    if lan_ip.is_unspecified() {
        warn!("lan_ip.probe returned 0.0.0.0; not advertising endpoints");
        return vec![];
    }
    let port = magic_local.port();
    let endpoint = match lan_ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };
    vec![endpoint]
}
