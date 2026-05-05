use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use tracing::{error, info, info_span, warn};

use ts_control::async_io::AsyncNoiseStream;
use ts_control::http2::Http2Conn;
use ts_control::record::NoiseStream;
use ts_control::{ControlError, KeyStore, MapClient, MapEvent, NetMap};
use ts_derp::{DerpMap, DerpNodeAddr, DerpTransport};
use wg_engine::{Engine, EngineConfig, Ipv4Cidr, PeerConfig, TransportAddr};

use netstack::{Stack, StackConfig};
use smoltcp::wire::Ipv4Cidr as SmolIpv4Cidr;

mod lifecycle;
use lifecycle::LifecycleTracker;

const HEADSCALE_URL: &str = "http://192.168.8.147:8080";
const HEADSCALE_HOST: &str = "192.168.8.147:8080";
const CAPVER: u32 = 90;
const SERVER_RESP_LEN: usize = 51;

fn main() {
    if let Err(e) = vita_log::init() {
        eprintln!("vita-log init failed: {e}");
        return;
    }
    let _span = info_span!(
        "startup",
        milestone = "M9",
        build = env!("BUILD_TIMESTAMP"),
        build_unix = env!("BUILD_UNIX"),
    )
    .entered();
    info!(build = env!("BUILD_TIMESTAMP"), "binary build timestamp");

    if let Err(e) = run() {
        error!(error = %e, "M9 demo failed");
    }
    vita_log::flush();
    thread::sleep(Duration::from_secs(1));
}

const STATE_DIR: &str = "ux0:/data/tailscale-vita";
const AUTH_KEY_FILE: &str = "auth-key.txt";

fn run() -> Result<(), ControlError> {
    info!(headscale = HEADSCALE_URL, capver = CAPVER, "fetching Noise pubkey");
    let server_pub = ts_control::fetch_server_key(HEADSCALE_URL, CAPVER)?;
    info!(pub = %server_pub, "control.key.received");

    let state_dir = Path::new(STATE_DIR);
    let ks = KeyStore::load_or_generate(state_dir)?;

    info!("starting Noise IK handshake");
    let mut hs = ts_control::NoiseHandshaker::new(&ks.machine_priv, &server_pub)?;
    let header_b64 = hs.build_init_header()?;
    info!(b64_len = header_b64.len(), "control.noise.init.built");

    let mut upgraded = ts_control::upgrade::dial_and_upgrade(HEADSCALE_URL, &header_b64)?;
    info!(leftover = upgraded.leftover.len(), "control.upgrade.101");

    let server_response = read_server_response(&mut upgraded)?;
    let nt = hs.finalize(&server_response)?;
    let hash_hex = hex_short(&nt.handshake_hash);
    info!(handshake_hash = %hash_hex, "control.noise.handshake.complete");

    // Wrap the upgraded TCP socket in our NoiseStream framer.
    let leftover = upgraded.leftover;
    let mut noise_stream = NoiseStream::new(upgraded.tcp, nt, leftover);

    // Consume Tailscale's EarlyPayload (5 B magic + u32_be length + JSON)
    // before handing the stream to h2. Required for protocolVersion >= 49.
    consume_early_payload(&mut noise_stream)?;

    let async_stream = AsyncNoiseStream::spawn(noise_stream);

    info!("opening HTTP/2 over Noise");
    let mut conn = Http2Conn::open(async_stream)?;
    info!("control.http2.handshake.complete");

    let auth_key_path = state_dir.join(AUTH_KEY_FILE);
    let auth_key_raw = std::fs::read_to_string(&auth_key_path).map_err(|e| {
        ControlError::Transport(format!(
            "auth-key read failed at {}: {e}",
            auth_key_path.display()
        ))
    })?;
    let auth_key = auth_key_raw.trim();
    info!(
        path = %auth_key_path.display(),
        len = auth_key.len(),
        "control.auth_key.loaded"
    );

    let outcome = ts_control::register(&mut conn, auth_key, &ks.node_pub, "vita", HEADSCALE_HOST)?;
    info!(
        machine_authorized = outcome.machine_authorized,
        node_key_expired = outcome.node_key_expired,
        "control.register.ok"
    );

    // ---- M8/M9: spawn engine + DerpTransport + netstack, drive the map ----

    // Both wg-engine's WG static_public AND ts-derp's NaCl-box ECDH derive
    // from the same 32 priv bytes (proven by spike-05). One key, three uses.
    let our_secret = x25519_dalek::StaticSecret::from(ks.node_priv.0);

    let (derp_transport, derp_ctl) = DerpTransport::new(ks.node_priv.0, ks.node_pub.0, /*cap=*/ 8);

    let engine = Engine::new(EngineConfig {
        our_static_secret: our_secret,
        mtu: 1280,
        peers: vec![],
    })
    .map_err(|e| ControlError::Transport(format!("engine new: {e}")))?;
    let engine_running = engine
        .start(derp_transport)
        .map_err(|e| ControlError::Transport(format!("engine start: {e}")))?;
    info!("wg-engine: pump running with DerpTransport (DerpMap pending)");

    // M9: spin up smoltcp-backed netstack so inbound ICMP echoes get
    // auto-replied (smoltcp 0.12's iface.process_icmpv4 does this for free
    // once iface.ip_addrs contains our 100.64.x.y).
    let stack = Stack::start(StackConfig::new(), engine_running)
        .map_err(|e| ControlError::Transport(format!("netstack start: {e}")))?;
    info!("netstack: poll thread running (no local IP yet)");

    let mut map = MapClient::start(
        conn,
        ks.node_pub,
        ks.disco_pub,
        "vita".into(),
        HEADSCALE_HOST.into(),
        state_dir.to_path_buf(),
    )?;
    info!("control.map.started");

    // The first MapResponse with derp_region_count > 0 is when we pick a
    // home and start dialing. The first MapResponse with our_addrs set
    // is when we hand our tailnet IP to the netstack.
    let demo_window = Duration::from_secs(120);
    let deadline = Instant::now() + demo_window;
    let mut keepalive_count = 0u32;
    let mut snapshot_count = 0u32;
    let mut derp_map_set = false;
    let mut local_addrs_set = false;
    let mut lifecycle = LifecycleTracker::new();

    while Instant::now() < deadline {
        let event = map.next_event(Duration::from_secs(2))?;
        let now = Instant::now();

        match event {
            MapEvent::Snapshot(snap) => {
                snapshot_count += 1;
                lifecycle.record_map_event(now);

                // Wire DERP first time we see regions.
                if !derp_map_set && snap.derp_region_count > 0 {
                    let derp_map = build_derp_map(map.netmap());
                    derp_ctl.set_derp_map(derp_map.clone());
                    match derp_ctl.pick_and_set_home(&derp_map) {
                        Ok(home) => info!(home, regions = derp_map.regions.len(), "derp.home.selected"),
                        Err(e) => warn!(error = %e, "derp.home.selection.failed"),
                    }
                    derp_map_set = true;
                }

                // Wire local IP into smoltcp first time MapResponse has
                // our_addrs. Without this, smoltcp drops inbound packets
                // for 100.64.0.1 and the auto-ICMP-reply never fires.
                if !local_addrs_set && !snap.our_addrs.is_empty() {
                    let local_cidrs: Vec<SmolIpv4Cidr> = snap
                        .our_addrs
                        .iter()
                        .map(|a| SmolIpv4Cidr::new(a.addr, a.prefix))
                        .collect();
                    info!(addrs = ?local_cidrs, "netstack.local_addrs.from_mapresponse");
                    stack.set_local_addrs(local_cidrs);
                    local_addrs_set = true;
                }

                push_delta_to_engine(&engine, &snap, derp_ctl.home_region());
            }
            MapEvent::KeepAlive { seq } => {
                keepalive_count += 1;
                lifecycle.record_map_event(now);
                info!(seq, count = keepalive_count, "control.map.keepalive");
            }
            MapEvent::Idle => {}
        }

        // v1 proxy for "DERP rx" until M10 plumbs a real per-rx hook:
        // any region in the alive set means our DERP path is up.
        if !derp_ctl.alive_regions().is_empty() {
            lifecycle.record_derp_rx(now);
        }

        lifecycle.tick(now, engine.peer_count(), derp_ctl.alive_regions().len());
    }

    info!(
        peer_count = engine.peer_count(),
        snapshots = snapshot_count,
        keepalives = keepalive_count,
        derp_alive_regions = ?derp_ctl.alive_regions(),
        lifecycle_state = ?lifecycle.state(),
        "M9 demo done"
    );
    drop(map);
    derp_ctl.shutdown();
    drop(stack); // joins netstack poll + wg-engine pump
    Ok(())
}

/// Translate ts-control's `NetMap.derp_regions` into ts-derp's `DerpMap`
/// shape. Both are HashMap<u16, region-info> but with different node
/// types — copying field-by-field.
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

fn push_delta_to_engine(engine: &Engine, snap: &ts_control::NetMapSnapshot, our_home: u16) {
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
        // Pick the peer's home DERP if known, else fall back to ours
        // (Tailscale relays bridge between regions, so even cross-region
        //  peers reach each other via either side's home).
        let region = if p.home_derp != 0 { p.home_derp } else { our_home };
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
            // 25 s keepalive so WG keeps the encrypted tunnel alive even
            // when no app traffic flows. Required for M9 ICMP reachability.
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

const EARLY_PAYLOAD_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";

fn consume_early_payload(stream: &mut NoiseStream<TcpStream>) -> Result<(), ControlError> {
    use std::io::Read;
    let mut hdr = [0u8; 9];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| ControlError::Transport(format!("early payload header: {e}")))?;
    if &hdr[..5] != EARLY_PAYLOAD_MAGIC {
        return Err(ControlError::Transport(format!(
            "early payload missing magic; got first 5 bytes = {:02x?}",
            &hdr[..5]
        )));
    }
    let len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
    if len > 64 * 1024 {
        return Err(ControlError::Transport(format!(
            "early payload length absurd: {len}"
        )));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| ControlError::Transport(format!("early payload body: {e}")))?;
    info!(len, body_preview = %String::from_utf8_lossy(&body[..body.len().min(80)]), "control.early_payload");
    Ok(())
}

fn read_server_response(upgraded: &mut ts_control::upgrade::UpgradedSocket) -> Result<Vec<u8>, ControlError> {
    let mut out = std::mem::take(&mut upgraded.leftover);
    let needed = SERVER_RESP_LEN;
    upgraded.tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut tmp = [0u8; 64];
    while out.len() < needed {
        let to_read = (needed - out.len()).min(tmp.len());
        let n = upgraded.tcp.read(&mut tmp[..to_read])?;
        if n == 0 {
            return Err(ControlError::Transport(format!(
                "noise: server closed before sending {needed} bytes"
            )));
        }
        out.extend_from_slice(&tmp[..n]);
    }
    if out.len() > needed {
        // Anything past 51 bytes is the start of the first record stream.
        let extra = out.split_off(needed);
        // Stash that back into the upgraded socket's leftover so NoiseStream
        // can pick it up.
        upgraded.leftover = extra;
    }
    Ok(out)
}

fn hex_short(b: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(16);
    for byte in &b[..8] {
        let _ = write!(s, "{:02x}", byte);
    }
    s
}

// Pull TcpStream into namespace so the Read impl resolves; this is
// needed because we're calling `upgraded.tcp.read(...)` above.
#[allow(dead_code)]
fn _ensure_tcpstream_in_scope(_t: TcpStream) {}
