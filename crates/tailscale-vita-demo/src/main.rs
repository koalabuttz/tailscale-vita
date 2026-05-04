use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use std::sync::Arc;
use tracing::{error, info, info_span, warn};

use wg_engine::icmp::{build_icmp_echo_request, parse_icmp_echo_reply};
use wg_engine::{Engine, EngineConfig, UdpTransport, WgError};

const CONFIG_PATH: &str = "ux0:/data/tailscale-vita/wg.toml";

const ICMP_IDENT: u16 = 0xBEEF;
const NUM_ECHOES: u16 = 5;
const HANDSHAKE_GRACE: Duration = Duration::from_secs(2);
const ECHO_REPLY_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

fn main() {
    if let Err(e) = vita_log::init() {
        eprintln!("vita-log init failed: {e}");
        return;
    }
    let _span = info_span!("startup", milestone = "M2").entered();

    if let Err(e) = run() {
        error!(error = %e, "M2 demo failed");
    }
    vita_log::flush();
    // Sleep so VitaShell exit doesn't truncate the last log flush.
    thread::sleep(Duration::from_secs(1));
}

fn run() -> Result<(), WgError> {
    info!(path = %CONFIG_PATH, "loading wg config");
    let toml = wg_engine::read_wg_toml(Path::new(CONFIG_PATH))?;
    if toml.peer.len() != 1 {
        return Err(WgError::BadPeerCount(toml.peer.len()));
    }

    let our_tunnel_ip: Ipv4Addr = toml
        .our
        .tunnel_ip
        .parse()
        .map_err(|_| WgError::Config(format!("our.tunnel_ip: {}", toml.our.tunnel_ip)))?;

    let cfg = EngineConfig::from_wg_toml(&toml)?;
    let peer_tunnel_ip = cfg
        .peers
        .first()
        .and_then(|p| p.allowed_ips.first())
        .map(|c| c.addr)
        .ok_or_else(|| WgError::Config("peer has no allowed_ips".into()))?;
    let peer_pub = cfg
        .peers
        .first()
        .map(|p| *p.pubkey.as_bytes())
        .expect("peer count checked");

    let our_static_pub = x25519_dalek::PublicKey::from(&cfg.our_static_secret);
    info!(
        our_pub = %short_hex(our_static_pub.as_bytes()),
        peer_pub = %short_hex(&peer_pub),
        our_tunnel_ip = %our_tunnel_ip,
        peer_tunnel_ip = %peer_tunnel_ip,
        "engine configured"
    );

    let transport = UdpTransport::bind("0.0.0.0:0".parse().unwrap())?;
    info!(local = %transport.local_addr()?, "udp transport bound");

    let engine = Engine::new(cfg)?;
    let running = engine.start(transport)?;

    info!(grace_ms = HANDSHAKE_GRACE.as_millis() as u64, "waiting for handshake");
    thread::sleep(HANDSHAKE_GRACE);

    let mut ok = 0u32;
    for seq in 0..NUM_ECHOES {
        let payload = format!("hello-vita-seq-{seq}");
        let req = build_icmp_echo_request(our_tunnel_ip, peer_tunnel_ip, ICMP_IDENT, seq, payload.as_bytes());
        let req_len = req.len();
        running.tun_tx.lock().push_back(req);
        info!(seq, n = req_len, "icmp.echo.request queued");

        if wait_for_reply(&running.tun_rx, seq, ECHO_REPLY_TIMEOUT) {
            ok += 1;
        } else {
            warn!(seq, "icmp.echo.timeout");
        }
        thread::sleep(Duration::from_millis(200));
    }

    info!(ok, total = NUM_ECHOES, "M2 demo done");
    drop(running); // joins the wg_engine thread cleanly
    Ok(())
}

fn wait_for_reply(
    tun_rx: &Arc<Mutex<VecDeque<Vec<u8>>>>,
    expected_seq: u16,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let pkt = tun_rx.lock().pop_front();
        match pkt {
            Some(p) => {
                if let Some(reply) = parse_icmp_echo_reply(&p) {
                    if reply.ident == ICMP_IDENT && reply.seq == expected_seq {
                        info!(
                            seq = reply.seq,
                            from = %reply.src,
                            n = reply.payload.len(),
                            payload = %String::from_utf8_lossy(&reply.payload),
                            "icmp.echo.reply"
                        );
                        return true;
                    } else {
                        warn!(
                            got_seq = reply.seq,
                            got_ident = reply.ident,
                            expected_seq,
                            "icmp.echo.reply.mismatched"
                        );
                    }
                } else {
                    warn!(n = p.len(), "tun_rx: non-ICMP-echo-reply packet");
                }
            }
            None => thread::sleep(POLL_INTERVAL),
        }
    }
    false
}

fn short_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(12);
    for b in &bytes[..bytes.len().min(6)] {
        let _ = write!(s, "{:02x}", b);
    }
    s
}
