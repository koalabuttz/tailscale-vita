use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use smoltcp::wire::Ipv4Cidr;
use tracing::{error, info, info_span, warn};

use netstack::tcp::TcpStream;
use netstack::{Stack, StackConfig};
use wg_engine::{Engine, EngineConfig, UdpTransport, WgError};

const CONFIG_PATH: &str = "ux0:/data/tailscale-vita/wg.toml";

const HTTP_TARGET_PORT: u16 = 8080;
const HANDSHAKE_GRACE: Duration = Duration::from_secs(2);
const HTTP_BODY_DEADLINE: Duration = Duration::from_secs(10);

fn main() {
    if let Err(e) = vita_log::init() {
        eprintln!("vita-log init failed: {e}");
        return;
    }
    let _span = info_span!("startup", milestone = "M3").entered();

    if let Err(e) = run() {
        error!(error = %e, "M3 demo failed");
    }
    vita_log::flush();
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

    info!(
        our_tunnel_ip = %our_tunnel_ip,
        peer_tunnel_ip = %peer_tunnel_ip,
        "configuration loaded"
    );

    let transport = UdpTransport::bind("0.0.0.0:0".parse().unwrap())?;
    info!(local = %transport.local_addr()?, "udp transport bound");

    let engine = Engine::new(cfg)?;
    let engine_running = engine.start(transport)?;

    let oct = our_tunnel_ip.octets();
    let local_cidr = Ipv4Cidr::new(
        smoltcp::wire::Ipv4Address::new(oct[0], oct[1], oct[2], oct[3]),
        24,
    );
    let stack = Stack::start(StackConfig::new(local_cidr), engine_running)
        .map_err(|e| WgError::Config(format!("netstack: {e}")))?;
    info!("netstack ready");

    info!(grace_ms = HANDSHAKE_GRACE.as_millis() as u64, "waiting for handshake");
    thread::sleep(HANDSHAKE_GRACE);

    let target = SocketAddr::V4(SocketAddrV4::new(peer_tunnel_ip, HTTP_TARGET_PORT));
    info!(remote = %target, "connecting via tunnel");
    let stream = TcpStream::connect(&stack, target);
    let mut stream = match stream {
        Ok(s) => {
            info!(remote = %target, "tcp.connected");
            s
        }
        Err(e) => {
            error!(remote = %target, error = %e, "tcp.connect.failed");
            return Ok(());
        }
    };

    let req = b"GET / HTTP/1.0\r\nHost: 10.6.0.1\r\nUser-Agent: tailscale-vita-m3\r\n\r\n";
    if let Err(e) = stream.write_all(req) {
        error!(error = %e, "tcp.write.failed");
        return Ok(());
    }
    info!(n = req.len(), "tcp.request.sent");

    let mut total = 0usize;
    let mut first_line: Option<String> = None;
    let mut accum = Vec::with_capacity(4096);
    let mut buf = [0u8; 1024];
    let deadline = Instant::now() + HTTP_BODY_DEADLINE;
    loop {
        if Instant::now() >= deadline {
            warn!("tcp.read.deadline");
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                info!("tcp.read.eof");
                break;
            }
            Ok(n) => {
                total += n;
                if accum.len() < 4096 {
                    accum.extend_from_slice(&buf[..n.min(4096 - accum.len())]);
                }
                if first_line.is_none() {
                    if let Some(pos) = accum.iter().position(|&b| b == b'\n') {
                        let line = String::from_utf8_lossy(&accum[..pos])
                            .trim_end_matches('\r')
                            .to_string();
                        info!(line = %line, "tcp.response.status");
                        first_line = Some(line);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                warn!("tcp.read.wouldblock");
                break;
            }
            Err(e) => {
                error!(error = %e, "tcp.read.error");
                break;
            }
        }
    }
    info!(total, status = ?first_line, "tcp.session.summary");

    drop(stream);
    info!("M3 demo done");
    drop(stack);
    Ok(())
}
