//! DERP handshake: TLS dial → HTTP/1.1 `Upgrade: DERP` → ServerKey →
//! ClientInfo (NaCl box) → ServerInfo (NaCl-box decrypt).
//!
//! See `tailscale.com/derp/derphttp/derphttp_client.go` and
//! `derp/derp_client.go`. The full sequence:
//!
//! ```text
//! C → S  TCP+TLS connect to host:443 (or node.derp_port if set).
//! C → S  GET /derp HTTP/1.1   (Upgrade: DERP)
//! C ← S  HTTP/1.1 101 Switching Protocols
//! C ← S  FrameServerKey  [1 type | 4 len | 8 magic "DERP🔑" | 32 server_pub]
//! C → S  FrameClientInfo [1 type | 4 len | 32 client_pub | 24 nonce |
//!                          NaCl-box(server_pub, client_priv, JSON)]
//! C ← S  FrameServerInfo [1 type | 4 len | 24 nonce |
//!                          NaCl-box(server_priv, client_pub, JSON)]
//! ```
//!
//! After step 5 the connection is a bidirectional DERP frame stream:
//! we send `FrameSendPacket`/`FramePong`/`FrameNotePreferred`, the server
//! sends `FrameRecvPacket`/`FrameKeepAlive`/`FramePing`/`FramePeerGone`/
//! `FrameHealth`/`FrameRestarting`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crypto_box::aead::generic_array::GenericArray;
use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{PublicKey as CbPublic, SalsaBox, SecretKey as CbSecret};
use rand_core::OsRng;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::frame::{read_frame, write_frame, FrameType};
use crate::magic::{DIAL_TIMEOUT, MAGIC, PROTOCOL_VERSION};
use crate::{DerpError, DerpNodeAddr, NodeKeyBytes};

pub type DerpTls = StreamOwned<ClientConnection, TcpStream>;

pub struct DerpHandshakeOutput {
    pub tls: DerpTls,
    pub server_pub: NodeKeyBytes,
    pub server_info: ServerInfoWire,
}

/// Mirrors upstream `tailscale.com/derp/derp.ClientInfo`. Critical: the
/// JSON keys are **mixed-case** — `version` and `meshKey` are lowercase
/// per upstream's explicit `json:"version,omitempty"` /
/// `json:"meshKey,omitempty,omitzero"` tags; `CanAckPings` has no tag so
/// it defaults to PascalCase; `IsProber` has `json:",omitempty"`.
///
/// **Wrong-case here is the M8 bringup bug**: server's `json.Unmarshal`
/// silently leaves `Version=0` if you send `"Version"` (capitalized),
/// then rejects the handshake because `Version != ProtocolVersion`.
#[derive(Serialize, Debug)]
pub struct ClientInfoWire {
    #[serde(rename = "version")]
    pub version: u32,
    #[serde(rename = "meshKey", skip_serializing_if = "String::is_empty")]
    pub mesh_key: String,
    #[serde(rename = "CanAckPings")]
    pub can_ack_pings: bool,
    #[serde(rename = "IsProber", skip_serializing_if = "is_false")]
    pub is_prober: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Deserialize, Debug, Default)]
pub struct ServerInfoWire {
    #[serde(rename = "version", default)]
    pub version: u32,
    #[serde(rename = "TokenBucketBytesPerSecond", default)]
    pub token_bucket_bytes_per_second: i64,
    #[serde(rename = "TokenBucketBytesBurst", default)]
    pub token_bucket_bytes_burst: i64,
}

/// Open one DERP relay connection. Caller is responsible for trying
/// multiple nodes from a region; this function dials a single node.
pub fn dial_and_handshake(
    node: &DerpNodeAddr,
    our_priv: &NodeKeyBytes,
    our_pub: &NodeKeyBytes,
) -> Result<DerpHandshakeOutput, DerpError> {
    let dial_addr = node.dial_addr();
    info!(region = node.region_id, host = %node.hostname, addr = %dial_addr, "derp.dial");
    let tcp = dial_tcp(&dial_addr)?;
    let _ = tcp.set_nodelay(true);

    let mut tls = wrap_tls(tcp, &node.hostname)?;
    info!(region = node.region_id, "derp.tls.handshake.ok");

    write_upgrade_request(&mut tls, &node.hostname)?;
    let leftover = read_upgrade_response(&mut tls)?;
    info!(
        region = node.region_id,
        leftover = leftover.len(),
        "derp.upgrade.101"
    );

    // From now on, reads need to drain `leftover` first, then pull more
    // bytes from the TLS stream.
    let mut br = BufferedRead::new(&mut tls, leftover);

    // -- FrameServerKey --
    let (ty, payload) = read_frame(&mut br)?;
    if ty != FrameType::ServerKey {
        return Err(DerpError::Upgrade(format!(
            "expected ServerKey (0x01), got 0x{:02x}",
            ty as u8
        )));
    }
    if payload.len() < 8 + 32 {
        return Err(DerpError::FrameTooShort {
            ty: "ServerKey",
            len: payload.len(),
            need: 40,
        });
    }
    if &payload[..8] != MAGIC {
        let mut first8 = [0u8; 8];
        first8.copy_from_slice(&payload[..8]);
        return Err(DerpError::BadMagic { first8 });
    }
    let mut server_pub: NodeKeyBytes = [0u8; 32];
    server_pub.copy_from_slice(&payload[8..40]);
    info!(
        server_pub = %short_hex(&server_pub),
        "derp.server_key.received"
    );

    // -- FrameClientInfo --
    let salsa = SalsaBox::new(&CbPublic::from(server_pub), &CbSecret::from(*our_priv));
    let nonce: GenericArray<u8, <SalsaBox as AeadCore>::NonceSize> =
        SalsaBox::generate_nonce(&mut OsRng);
    let client_info = ClientInfoWire {
        version: PROTOCOL_VERSION,
        mesh_key: String::new(),
        can_ack_pings: false,
        is_prober: false,
    };
    let json = serde_json::to_vec(&client_info)?;
    let ciphertext = salsa
        .encrypt(&nonce, json.as_slice())
        .map_err(|e| DerpError::NaclBox(format!("encrypt ClientInfo: {e}")))?;

    let mut frame_payload = Vec::with_capacity(32 + 24 + ciphertext.len());
    frame_payload.extend_from_slice(our_pub);
    frame_payload.extend_from_slice(nonce.as_slice());
    frame_payload.extend_from_slice(&ciphertext);

    // The TLS write side is borrowed; we need to release the BufferedRead's
    // borrow on `tls` first, write, then re-borrow. Since BufferedRead holds
    // `&mut tls`, we just write through *br.inner.
    write_frame(br.inner, FrameType::ClientInfo, &frame_payload)?;
    debug!(
        bytes = 5 + frame_payload.len(),
        "derp.client_info.sent"
    );

    // -- FrameServerInfo --
    let (ty, payload) = read_frame(&mut br)?;
    if ty != FrameType::ServerInfo {
        return Err(DerpError::Upgrade(format!(
            "expected ServerInfo (0x03), got 0x{:02x}",
            ty as u8
        )));
    }
    if payload.len() < 24 + 16 {
        return Err(DerpError::FrameTooShort {
            ty: "ServerInfo",
            len: payload.len(),
            need: 40,
        });
    }
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(&payload[..24]);
    let server_nonce: GenericArray<u8, <SalsaBox as AeadCore>::NonceSize> = nonce_bytes.into();
    let plaintext = salsa
        .decrypt(&server_nonce, &payload[24..])
        .map_err(|e| DerpError::NaclBox(format!("decrypt ServerInfo: {e}")))?;
    let server_info: ServerInfoWire = serde_json::from_slice(&plaintext)?;
    info!(
        version = server_info.version,
        rate_burst = server_info.token_bucket_bytes_burst,
        "derp.server_info.decrypted"
    );

    if server_info.version != 0 && server_info.version != PROTOCOL_VERSION {
        // Older DERP servers (TS prod, mid-2024) sometimes omit version
        // entirely (=0 from default); only warn-fail when it's an
        // explicit non-2 number.
        return Err(DerpError::UnsupportedServerVersion {
            server_version: server_info.version,
            expected: PROTOCOL_VERSION,
        });
    }

    // Drop the BufferedRead, taking ownership of `tls` back. Any leftover
    // bytes (rare; would mean the server pipelined a frame) are ignored —
    // we expect the next read on tls to deliver them.
    if br.has_leftover() {
        warn!(
            leftover = br.remaining(),
            "derp.handshake.unexpected.leftover_after_server_info"
        );
    }
    drop(br);

    Ok(DerpHandshakeOutput {
        tls,
        server_pub,
        server_info,
    })
}

// ---------- TCP / TLS plumbing -------------------------------------------

fn dial_tcp(host_port: &str) -> Result<TcpStream, DerpError> {
    // Resolve via to_socket_addrs — picks first IPv4 (or IPv6) result.
    use std::net::ToSocketAddrs;
    let mut addrs = host_port
        .to_socket_addrs()
        .map_err(|e| DerpError::Io(std::io::Error::new(e.kind(), format!("resolve {host_port}: {e}"))))?;
    let addr = addrs
        .next()
        .ok_or_else(|| DerpError::Internal(format!("no addrs for {host_port}")))?;
    let tcp = TcpStream::connect_timeout(&addr, DIAL_TIMEOUT)?;
    Ok(tcp)
}

fn wrap_tls(tcp: TcpStream, server_name: &str) -> Result<DerpTls, DerpError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name: ServerName<'static> = ServerName::try_from(server_name.to_owned())
        .map_err(|e| DerpError::Tls(format!("bad ServerName: {e}")))?;
    let conn = ClientConnection::new(Arc::new(config), server_name)?;
    Ok(StreamOwned::new(conn, tcp))
}

// ---------- HTTP/1.1 upgrade ---------------------------------------------

fn write_upgrade_request(tls: &mut DerpTls, host: &str) -> Result<(), DerpError> {
    let req = format!(
        "GET /derp HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: DERP\r\n\
         User-Agent: tailscale-vita/0.1.0\r\n\
         \r\n"
    );
    tls.write_all(req.as_bytes())?;
    tls.flush()?;
    Ok(())
}

/// Read the upgrade response head into a buffer; verify status 101;
/// return any bytes that came after the `\r\n\r\n` terminator (the
/// start of the FrameServerKey, possibly).
fn read_upgrade_response(tls: &mut DerpTls) -> Result<Vec<u8>, DerpError> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 256];
    loop {
        let n = tls.read(&mut tmp)?;
        if n == 0 {
            return Err(DerpError::Upgrade(
                "EOF before HTTP/1.1 upgrade response head".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            return parse_upgrade_response(&buf, pos + 4);
        }
        if buf.len() > 16 * 1024 {
            return Err(DerpError::Upgrade(
                "upgrade response head exceeded 16 KiB".into(),
            ));
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_upgrade_response(buf: &[u8], head_end: usize) -> Result<Vec<u8>, DerpError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let parsed = resp.parse(&buf[..head_end])?;
    if !parsed.is_complete() {
        return Err(DerpError::Upgrade(
            "httparse claims response head incomplete despite CRLF-CRLF".into(),
        ));
    }
    let code = resp.code.ok_or_else(|| {
        DerpError::Upgrade("upgrade response missing status code".into())
    })?;
    if code != 101 {
        return Err(DerpError::Upgrade(format!(
            "expected 101 Switching Protocols, got {code}"
        )));
    }
    Ok(buf[head_end..].to_vec())
}

// ---------- Buffered-prefix Read adapter --------------------------------

/// Drains a stashed prefix buffer first, then delegates to the inner
/// reader. Used after the HTTP upgrade so that any bytes that came in
/// the same TLS read as the response head get consumed before the
/// frame reader pulls more bytes from `tls`.
struct BufferedRead<'a, R: Read> {
    inner: &'a mut R,
    leftover: Vec<u8>,
    pos: usize,
}

impl<'a, R: Read> BufferedRead<'a, R> {
    fn new(inner: &'a mut R, leftover: Vec<u8>) -> Self {
        Self {
            inner,
            leftover,
            pos: 0,
        }
    }
    fn has_leftover(&self) -> bool {
        self.pos < self.leftover.len()
    }
    fn remaining(&self) -> usize {
        self.leftover.len().saturating_sub(self.pos)
    }
}

impl<'a, R: Read> Read for BufferedRead<'a, R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.leftover.len() {
            let n = (self.leftover.len() - self.pos).min(out.len());
            out[..n].copy_from_slice(&self.leftover[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(out)
    }
}

fn short_hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(16);
    for byte in &b[..b.len().min(8)] {
        let _ = write!(s, "{:02x}", byte);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffered_read_drains_leftover_then_inner() {
        let inner_data = b"WORLD";
        let mut inner = std::io::Cursor::new(&inner_data[..]);
        let mut br = BufferedRead::new(&mut inner, b"HELLO".to_vec());

        let mut buf = [0u8; 10];
        let n = br.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"HELLO");
        let n = br.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WORLD");
    }

    #[test]
    fn double_crlf_finder() {
        assert_eq!(find_double_crlf(b"HTTP/1.1 101\r\n\r\nBODY"), Some(12));
        assert_eq!(find_double_crlf(b"\r\n\r\n"), Some(0));
        assert_eq!(find_double_crlf(b"no terminator here"), None);
    }

    #[test]
    fn parse_upgrade_response_101() {
        let head = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: DERP\r\n\
                     Connection: Upgrade\r\n\
                     \r\n\
                     EXTRA";
        let pos = find_double_crlf(head).unwrap();
        let leftover = parse_upgrade_response(head, pos + 4).unwrap();
        assert_eq!(&leftover, b"EXTRA");
    }

    #[test]
    fn parse_upgrade_response_rejects_non_101() {
        let head = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let pos = find_double_crlf(head).unwrap();
        let err = parse_upgrade_response(head, pos + 4).unwrap_err();
        match err {
            DerpError::Upgrade(s) => assert!(s.contains("404")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn client_info_serializes_with_mixed_case_per_upstream() {
        let ci = ClientInfoWire {
            version: 2,
            mesh_key: String::new(),
            can_ack_pings: false,
            is_prober: false,
        };
        let v: serde_json::Value = serde_json::to_value(&ci).unwrap();
        // `version` and `meshKey` are LOWERCASE in upstream's json tags.
        assert_eq!(v["version"], 2);
        // mesh_key empty → skipped (matches upstream's omitempty,omitzero).
        assert!(v.get("meshKey").is_none());
        // CanAckPings has no upstream tag → default PascalCase, always emitted.
        assert_eq!(v["CanAckPings"], false);
        // IsProber has json:",omitempty" → skipped when false.
        assert!(v.get("IsProber").is_none());
        // No mistaken capitalized aliases.
        assert!(v.get("Version").is_none());
        assert!(v.get("MeshKey").is_none());
    }

    #[test]
    fn client_info_emits_meshkey_when_set() {
        let ci = ClientInfoWire {
            version: 2,
            mesh_key: "abc".into(),
            can_ack_pings: true,
            is_prober: true,
        };
        let v: serde_json::Value = serde_json::to_value(&ci).unwrap();
        assert_eq!(v["meshKey"], "abc");
        assert_eq!(v["CanAckPings"], true);
        assert_eq!(v["IsProber"], true);
    }

    #[test]
    fn server_info_parses_minimal_and_full() {
        let mini: ServerInfoWire = serde_json::from_slice(br#"{"version":2}"#).unwrap();
        assert_eq!(mini.version, 2);
        let full: ServerInfoWire = serde_json::from_slice(
            br#"{"version":2,"TokenBucketBytesPerSecond":1000000,"TokenBucketBytesBurst":2000000}"#,
        )
        .unwrap();
        assert_eq!(full.version, 2);
        assert_eq!(full.token_bucket_bytes_per_second, 1_000_000);
        assert_eq!(full.token_bucket_bytes_burst, 2_000_000);
    }

    #[test]
    fn nacl_box_round_trip_against_self() {
        // Sanity: encrypt with (peer_pub, our_priv) and decrypt with the
        // same SalsaBox; matches the spike-05 confirmation that crypto_box
        // works on host too.
        use crypto_box::{PublicKey, SecretKey};
        let our = [0xaa; 32];
        let peer = [0xbb; 32];
        let salsa = SalsaBox::new(&PublicKey::from(peer), &SecretKey::from(our));
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let plaintext = b"hello vita";
        let ct = salsa.encrypt(&nonce, &plaintext[..]).unwrap();
        let pt = salsa.decrypt(&nonce, ct.as_slice()).unwrap();
        assert_eq!(pt, plaintext);
    }
}
