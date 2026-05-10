//! Phase 9 host-side diagnostic. Runs `ts_control`'s register +
//! streaming-map flow against real Tailscale from x86_64 Linux, in
//! isolation from the Vita platform. If DiscoKey commits when this
//! runs but doesn't when our Vita VPK runs, the bug is
//! Vita-platform-specific (sceNet, armv7 cross-compile artifact, etc).
//! If both fail, the bug is in our `ts_control` Rust code itself.
//!
//! ## Usage
//!
//! ```bash
//! TS_AUTH_KEY="tskey-auth-..." \
//!   RUST_LOG="ts_control=debug,host_diagnostic=info" \
//!   cargo run --release -p ts-control --example host_diagnostic
//! ```
//!
//! Optional env vars:
//! - `TS_CONTROL_URL` — default `https://controlplane.tailscale.com`
//! - `TS_HOSTNAME`    — default `vita-host-diag-<8 random hex>`
//! - `TS_STATE_DIR`   — default `/tmp/ts-control-host-diag`
//! - `TS_RUN_SECS`    — default `15`
//!
//! Drives the same call sequence as
//! `tailscale_vita::runtime::Runtime::up`, minus everything the
//! DiscoKey gate doesn't depend on (magicsock / netstack / DERP /
//! wg-engine). Helpers (`read_server_response`,
//! `consume_early_payload`, `generate_backend_log_id`,
//! `host_authority`) are inlined so the example is self-contained
//! and doesn't pull in `tailscale-vita`'s deps.

use std::io::Read as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rand_core::RngCore as _;
use ts_control::{
    dial_and_upgrade, fetch_server_key, register, AsyncNoiseStream, ControlError, ControlStream,
    Http2Conn, KeyStore, MapClient, MapEvent, NoiseHandshaker, NoiseStream, UpgradedSocket,
};
use tracing::info;

// ----- Inlined copies of helpers from `tailscale-vita::proto` ---------------
//
// Kept here verbatim so the example doesn't need to depend on the
// `tailscale-vita` crate (which would drag in netstack / boringtun /
// ts-derp / etc — none of which the DiscoKey gate is about).

const EARLY_PAYLOAD_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";
const SERVER_RESP_LEN: usize = 51;

fn read_server_response(upgraded: &mut UpgradedSocket) -> Result<Vec<u8>, ControlError> {
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
        let extra = out.split_off(needed);
        upgraded.leftover = extra;
    }
    Ok(out)
}

fn consume_early_payload(stream: &mut NoiseStream<ControlStream>) -> Result<(), ControlError> {
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
    info!(
        len,
        body_preview = %String::from_utf8_lossy(&body[..body.len().min(80)]),
        "control.early_payload"
    );
    Ok(())
}

// ----- Inlined copies from `tailscale-vita::runtime` and `Config` ----------

fn host_authority(control_url: &str) -> String {
    let s = control_url;
    if let Some(rest) = s.strip_prefix("https://") {
        rest.trim_end_matches('/').to_string()
    } else if let Some(rest) = s.strip_prefix("http://") {
        rest.trim_end_matches('/').to_string()
    } else {
        s.trim_end_matches('/').to_string()
    }
}

fn random_hex(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand_core::OsRng.fill_bytes(&mut bytes);
    use std::fmt::Write as _;
    let mut s = String::with_capacity(byte_len * 2);
    for b in &bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

// ----- main ----------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ts_control=info,host_diagnostic=info")),
        )
        .init();

    let auth_key = std::env::var("TS_AUTH_KEY")
        .map_err(|_| "TS_AUTH_KEY env var required (use a reusable+ephemeral tskey-auth-...)")?;
    let control_url = std::env::var("TS_CONTROL_URL")
        .unwrap_or_else(|_| "https://controlplane.tailscale.com".into());
    let hostname = std::env::var("TS_HOSTNAME")
        .unwrap_or_else(|_| format!("vita-host-diag-{}", random_hex(4)));
    let state_dir: PathBuf = std::env::var("TS_STATE_DIR")
        .unwrap_or_else(|_| "/tmp/ts-control-host-diag".into())
        .into();
    let run_secs: u64 = std::env::var("TS_RUN_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);

    std::fs::create_dir_all(&state_dir)?;
    // Wipe any prior run's keys/session so we always test the fresh
    // ephemeral-register path (the path tsrs uses successfully).
    for f in &[
        "machine.priv",
        "node.priv",
        "disco.priv",
        "nl.priv",
        "last_seq",
        "session_handle",
    ] {
        let _ = std::fs::remove_file(state_dir.join(f));
    }

    info!(
        %control_url, %hostname, ?state_dir, run_secs,
        capver = ts_control::CAPVER,
        "host_diagnostic.start"
    );

    let authority = host_authority(&control_url);

    // ---- mirror `Runtime::up` exactly --------------------------------------

    // 1. Fetch server's Noise pubkey.
    let server_pub = fetch_server_key(&control_url, ts_control::CAPVER as u32)?;
    info!(%server_pub, "host_diagnostic.server_key.fetched");

    // 2. Load (or generate-fresh, since we wiped) machine/node/disco/nl keys.
    let ks = KeyStore::load_or_generate(&state_dir)?;
    info!(
        machine_pub = %ks.machine_pub,
        node_pub = %ks.node_pub.to_nodekey_string(),
        disco_pub = %ks.disco_pub.to_discokey_string(),
        nl_pub = %ks.nl_pub.to_nlkey_string(),
        "host_diagnostic.keystore.loaded"
    );

    // 3. Noise IK init header.
    let mut hs = NoiseHandshaker::new(&ks.machine_priv, &server_pub)?;
    let header_b64 = hs.build_init_header()?;

    // 4. HTTP/1.1 upgrade dance + read server's 51-byte Noise response.
    let mut upgraded = dial_and_upgrade(&control_url, &header_b64)?;
    let server_response = read_server_response(&mut upgraded)?;

    // 5. Finalize Noise → transport state, build framed NoiseStream,
    //    consume EarlyPayload before HTTP/2 starts.
    let nt = hs.finalize(&server_response)?;
    let leftover = std::mem::take(&mut upgraded.leftover);
    let mut noise_stream = NoiseStream::new(upgraded.tcp, nt, leftover);
    consume_early_payload(&mut noise_stream)?;

    // 6. Wrap in async adapter + open HTTP/2 over the noise tunnel.
    let async_stream = AsyncNoiseStream::spawn(noise_stream);
    let mut conn = Http2Conn::open(async_stream)?;

    // 7. Register (Ephemeral=true is baked into ts_control::register).
    let backend_log_id = random_hex(16);
    let _outcome = register(
        &mut conn,
        &auth_key,
        &ks.node_pub,
        &ks.nl_pub,
        &backend_log_id,
        &hostname,
        &authority,
    )?;

    // 8. Open the streaming map.
    let mut map = MapClient::start(
        conn,
        ks.node_pub,
        ks.disco_pub,
        hostname,
        backend_log_id,
        authority,
        state_dir,
        Vec::new(), // no advertised endpoints — match tsrs's diagnostic shape
        Vec::new(),
    )?;

    // 9. Loop and log events. The critical line is
    //    `control.map.our_node.recv` (emitted by ts_control::netmap).
    //
    // M14M Phase 11: after the first MapResponse arrives (initial
    // netmap with our_node), send a non-streaming "lite" MapRequest
    // with NetInfo (PreferredDerp + DerpLatency). This is the magic
    // call that tells real Tailscale's coord server to commit DiscoKey
    // / HomeDERP / Endpoints. Without it the streaming long-poll
    // alone doesn't trigger the persistent-state write path on the
    // server — the symptom we've been hunting.
    let deadline = Instant::now() + Duration::from_secs(run_secs);
    let mut sent_netinfo_update = false;
    while Instant::now() < deadline {
        match map.next_event(Duration::from_millis(500))? {
            MapEvent::Snapshot(s) => {
                info!(
                    seq = s.seq,
                    peer_count = s.peer_count,
                    derp_region_count = s.derp_region_count,
                    "host_diagnostic.snapshot"
                );
                if !sent_netinfo_update {
                    sent_netinfo_update = true;
                    info!("host_diagnostic.netinfo_update.start");
                    // host_diagnostic is control-plane-only — no
                    // magicsock and no netcheck; pass stub latencies +
                    // empty extra_endpoints. The Vita runtime does
                    // real STUN-based netcheck.
                    let latencies: Vec<(String, f64)> = vec![
                        ("1-v4".into(), 0.040),
                        ("21-v4".into(), 0.060),
                        ("27-v4".into(), 0.050),
                    ];
                    if let Err(e) = map.send_netinfo_update(1, latencies, Vec::new()) {
                        info!(error = %e, "host_diagnostic.netinfo_update.fail");
                    }
                }
            }
            MapEvent::KeepAlive { seq } => info!(seq, "host_diagnostic.keepalive"),
            MapEvent::Idle => {}
        }
    }

    info!("host_diagnostic.done");
    Ok(())
}
