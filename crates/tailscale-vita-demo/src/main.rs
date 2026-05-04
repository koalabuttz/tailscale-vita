use std::io::Read;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use http::Method;
use tracing::{error, info, info_span, warn};

use ts_control::async_io::AsyncNoiseStream;
use ts_control::http2::Http2Conn;
use ts_control::record::NoiseStream;
use ts_control::{generate_machine_keypair, ControlError};

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
        milestone = "M5",
        build = env!("BUILD_TIMESTAMP"),
        build_unix = env!("BUILD_UNIX"),
    )
    .entered();
    info!(build = env!("BUILD_TIMESTAMP"), "binary build timestamp");

    if let Err(e) = run() {
        error!(error = %e, "M5 demo failed");
    }
    vita_log::flush();
    thread::sleep(Duration::from_secs(1));
}

fn run() -> Result<(), ControlError> {
    info!(headscale = HEADSCALE_URL, capver = CAPVER, "fetching Noise pubkey");
    let server_pub = ts_control::fetch_server_key(HEADSCALE_URL, CAPVER)?;
    info!(pub = %server_pub, "control.key.received");

    let (my_priv, my_pub) = generate_machine_keypair()?;
    info!(my_pub = %my_pub, "control.key.local.generated");

    info!("starting Noise IK handshake");
    let mut hs = ts_control::NoiseHandshaker::new(&my_priv, &server_pub)?;
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

    info!("issuing POST /machine/whoami (expecting 501 from Headscale 0.26)");
    match conn.request(
        Method::POST,
        "/machine/whoami",
        b"{}",
        &[("content-type", "application/json")],
        HEADSCALE_HOST,
    ) {
        Ok(resp) => {
            info!(
                status = resp.status,
                body_len = resp.body.len(),
                first_header = ?resp.headers.first(),
                "control.http2.response"
            );
        }
        Err(e) => warn!(error = %e, "request failed"),
    }

    info!("M5 demo done");
    drop(conn);
    Ok(())
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
