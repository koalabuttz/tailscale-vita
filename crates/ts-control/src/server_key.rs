use serde::Deserialize;
use tracing::{info, warn};

use crate::types::MachinePublic;
use crate::url as urlmod;
use crate::ControlError;

/// JSON shape of `tailcfg.OverTLSPublicKeyResponse`. Tailscale prod and
/// Headscale both send `publicKey` as `mkey:<hex>`.
#[derive(Deserialize, Debug)]
struct OverTLSPublicKeyResponse {
    #[serde(rename = "publicKey")]
    public_key: String,
    /// Older clients used this; modern Headscale + prod leave it empty.
    #[serde(default, rename = "legacyPublicKey")]
    _legacy_public_key: String,
}

/// Fetch the Noise static public key from a Tailscale-compatible control
/// server. Issues `GET <server_url>/key?v=<capver>`.
///
/// Headscale serves this in cleartext (HTTP); Tailscale prod requires
/// HTTPS. Both code paths route through the same `ureq` agent which
/// handles TLS via rustls + webpki-roots.
///
/// The Vita's outer TLS verification has no special pinning — the inner
/// Noise IK handshake (M5) is what authenticates the server. See
/// PLAN-V1.md §"Cross-cutting decisions".
pub fn fetch_server_key(server_url: &str, capver: u32) -> Result<MachinePublic, ControlError> {
    let parsed = urlmod::parse(server_url)?;
    let url = format!(
        "{}://{}:{}/key?v={capver}",
        parsed.scheme, parsed.host, parsed.port
    );

    info!(url = %url, "control.key.fetching");

    let resp = ureq::get(&url).call().map_err(|e| {
        warn!(error = %e, "control.key.transport.error");
        ControlError::Transport(format!("ureq: {e}"))
    })?;
    let status = resp.status().as_u16();
    if status != 200 {
        let body = resp
            .into_body()
            .read_to_string()
            .unwrap_or_default();
        return Err(ControlError::Http { status, body });
    }
    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| ControlError::Transport(format!("read body: {e}")))?;
    let parsed: OverTLSPublicKeyResponse = serde_json::from_str(&body)?;
    let mk = MachinePublic::from_mkey_str(&parsed.public_key)?;
    info!(key = %mk, "control.key.fetched");
    Ok(mk)
}
