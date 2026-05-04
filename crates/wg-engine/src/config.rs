use std::net::SocketAddr;
use std::path::Path;

use base64::Engine as _;
use serde::Deserialize;

use crate::peer::{Ipv4Cidr, PeerConfig, TransportAddr};
use crate::WgError;

/// On-disk schema for `ux0:/data/tailscale-vita/wg.toml`. Used by M2 to
/// configure a single hardcoded peer for the WireGuard handshake test.
/// In M7+ peers will come from MapResponse, not from this file.
#[derive(Deserialize, Debug)]
pub struct WgToml {
    pub our: OurKey,
    #[serde(default)]
    pub peer: Vec<PeerEntry>,
}

#[derive(Deserialize, Debug)]
pub struct OurKey {
    pub private_key_b64: String,
    /// Our tunnel-side IP. M2 hardcodes this; in v1 it comes from
    /// MapResponse.Node.Addresses.
    pub tunnel_ip: String,
}

#[derive(Deserialize, Debug)]
pub struct PeerEntry {
    pub public_key_b64: String,
    #[serde(default)]
    pub preshared_key_b64: Option<String>,
    pub allowed_ips: Vec<String>,
    pub endpoint: String,
    #[serde(default)]
    pub persistent_keepalive_secs: Option<u16>,
}

/// Read and parse `wg.toml`. Returns the raw TOML structure.
pub fn read_wg_toml(path: &Path) -> Result<WgToml, WgError> {
    let content = std::fs::read_to_string(path).map_err(WgError::Io)?;
    toml::from_str::<WgToml>(&content)
        .map_err(|e| WgError::Config(format!("parsing {}: {e}", path.display())))
}

/// Decode a 32-byte WireGuard private key from base64.
pub fn decode_priv_key(b64: &str, field: &'static str) -> Result<[u8; 32], WgError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| WgError::Base64 {
            field,
            reason: e.to_string(),
        })?;
    if bytes.len() != 32 {
        return Err(WgError::Base64 {
            field,
            reason: format!("expected 32 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Same as `decode_priv_key` but for public keys (semantically just a
/// 32-byte blob — same wire format).
pub fn decode_pub_key(b64: &str, field: &'static str) -> Result<[u8; 32], WgError> {
    decode_priv_key(b64, field)
}

/// Resolve a `WgToml` into runtime configs the Engine can consume.
pub fn build_engine_inputs(
    cfg: &WgToml,
) -> Result<(x25519_dalek::StaticSecret, Vec<PeerConfig>), WgError> {
    let priv_bytes = decode_priv_key(&cfg.our.private_key_b64, "our.private_key_b64")?;
    let our_secret = x25519_dalek::StaticSecret::from(priv_bytes);

    let mut peers = Vec::with_capacity(cfg.peer.len());
    for p in &cfg.peer {
        let pub_bytes = decode_pub_key(&p.public_key_b64, "peer.public_key_b64")?;
        let pubkey = x25519_dalek::PublicKey::from(pub_bytes);

        let preshared_key = match &p.preshared_key_b64 {
            Some(s) if !s.is_empty() => Some(decode_priv_key(s, "peer.preshared_key_b64")?),
            _ => None,
        };

        let allowed_ips = p
            .allowed_ips
            .iter()
            .map(|s| Ipv4Cidr::parse(s))
            .collect::<Result<Vec<_>, _>>()?;

        let endpoint: SocketAddr = p
            .endpoint
            .parse()
            .map_err(|_| WgError::BadSocketAddr(p.endpoint.clone()))?;
        let initial_endpoint = Some(TransportAddr::Udp(endpoint));

        peers.push(PeerConfig {
            pubkey,
            preshared_key,
            persistent_keepalive_secs: p.persistent_keepalive_secs,
            allowed_ips,
            initial_endpoint,
        });
    }
    Ok((our_secret, peers))
}
