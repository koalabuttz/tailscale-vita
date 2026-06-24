use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use vita_log::{debug, info, warn};

use crate::types::MachinePublic;
use crate::url as urlmod;
use crate::ControlError;

/// How long a fetched server key is reused before refresh. Matches the
/// cadence Go's `controlclient` assumes for rotation (very rare in
/// practice; even legitimate rotations are typically announced days
/// ahead). 1 hour is short enough that a stale cache won't strand us
/// for long, long enough to skip refetch on every reconnect.
pub const SERVER_KEY_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Filenames inside `state_dir` for the cached Noise pub key + metadata.
const KEY_CACHE_FILE: &str = "server.pub";
const KEY_CACHE_META_FILE: &str = "server.pub.meta";

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

/// Cached variant of [`fetch_server_key`]. Reads `state_dir/server.pub`
/// (+ companion `.meta` with the fetch timestamp); returns the cached
/// value if it's younger than [`SERVER_KEY_CACHE_TTL`]. Otherwise
/// re-fetches and overwrites the cache.
///
/// Cache invalidation:
/// - Stale (older than TTL) → refetch.
/// - Missing / unparseable file → refetch silently.
/// - The caller can force a refresh by calling
///   [`invalidate_server_key_cache`] when a downstream Noise handshake
///   fails (covers the legitimate-rotation case where the key changed
///   without warning).
///
/// Cache files are written atomically (write to tmp, rename) so a
/// crash mid-write can't leave a corrupt cache.
pub fn fetch_server_key_cached(
    server_url: &str,
    capver: u32,
    state_dir: &Path,
) -> Result<MachinePublic, ControlError> {
    if let Some(cached) = read_cached_key(state_dir) {
        debug!(key = %cached, "control.key.cache.hit");
        return Ok(cached);
    }
    let fresh = fetch_server_key(server_url, capver)?;
    if let Err(e) = write_cached_key(state_dir, &fresh) {
        // Cache write failure isn't fatal — we still have the key. Log
        // + carry on; the next call will refetch and try again.
        warn!(error = %e, "control.key.cache.write_failed");
    }
    Ok(fresh)
}

/// Drop the cached `server.pub` files. Call after a Noise handshake
/// fails — covers the rare case where the server key legitimately
/// rotated mid-TTL.
pub fn invalidate_server_key_cache(state_dir: &Path) {
    let key_path = state_dir.join(KEY_CACHE_FILE);
    let meta_path = state_dir.join(KEY_CACHE_META_FILE);
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&meta_path);
    debug!(?key_path, "control.key.cache.invalidated");
}

fn read_cached_key(state_dir: &Path) -> Option<MachinePublic> {
    let key_path = state_dir.join(KEY_CACHE_FILE);
    let meta_path = state_dir.join(KEY_CACHE_META_FILE);
    let key_str = std::fs::read_to_string(&key_path).ok()?;
    let meta_str = std::fs::read_to_string(&meta_path).ok()?;
    let fetched_unix: u64 = meta_str
        .lines()
        .find_map(|line| line.strip_prefix("fetched_at_unix=").map(str::trim))
        .and_then(|s| s.parse().ok())?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    let age = Duration::from_secs(now_unix.saturating_sub(fetched_unix));
    if age >= SERVER_KEY_CACHE_TTL {
        debug!(age_secs = age.as_secs(), "control.key.cache.stale");
        return None;
    }
    MachinePublic::from_mkey_str(key_str.trim()).ok()
}

fn write_cached_key(state_dir: &Path, key: &MachinePublic) -> std::io::Result<()> {
    use std::io::Write as _;
    std::fs::create_dir_all(state_dir)?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Atomic-ish write: write to tmp, rename over. Single-process so
    // we don't worry about cross-process serialization.
    let key_path = state_dir.join(KEY_CACHE_FILE);
    let meta_path = state_dir.join(KEY_CACHE_META_FILE);
    let key_tmp = state_dir.join(format!("{KEY_CACHE_FILE}.tmp"));
    let meta_tmp = state_dir.join(format!("{KEY_CACHE_META_FILE}.tmp"));
    {
        let mut f = std::fs::File::create(&key_tmp)?;
        writeln!(f, "{}", key.to_mkey_string())?;
        f.sync_all()?;
    }
    {
        let mut f = std::fs::File::create(&meta_tmp)?;
        writeln!(f, "fetched_at_unix={now_unix}")?;
        f.sync_all()?;
    }
    std::fs::rename(&key_tmp, &key_path)?;
    std::fs::rename(&meta_tmp, &meta_path)?;
    Ok(())
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    /// Synthesize a temp directory by appending PID + a counter to
    /// `std::env::temp_dir()`. Avoids `tempfile` dep on the Vita
    /// build (newlib doesn't ship `tempfile`-compatible mkstemp).
    fn fresh_state_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("ts-control-cache-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn synthetic_key() -> MachinePublic {
        MachinePublic([0xAB; 32])
    }

    #[test]
    fn write_then_read_roundtrip() {
        let dir = fresh_state_dir();
        let key = synthetic_key();
        write_cached_key(&dir, &key).unwrap();
        let got = read_cached_key(&dir).expect("cached read");
        assert_eq!(got, key);
    }

    #[test]
    fn missing_files_return_none() {
        let dir = fresh_state_dir();
        assert!(read_cached_key(&dir).is_none());
    }

    #[test]
    fn unparseable_meta_returns_none() {
        let dir = fresh_state_dir();
        std::fs::write(dir.join(KEY_CACHE_FILE), "mkey:not-hex").unwrap();
        std::fs::write(dir.join(KEY_CACHE_META_FILE), "garbage").unwrap();
        assert!(read_cached_key(&dir).is_none());
    }

    #[test]
    fn stale_cache_returns_none() {
        let dir = fresh_state_dir();
        let key = synthetic_key();
        std::fs::write(
            dir.join(KEY_CACHE_FILE),
            format!("{}\n", key.to_mkey_string()),
        )
        .unwrap();
        // Timestamp from before the TTL window.
        let old_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(SERVER_KEY_CACHE_TTL.as_secs() + 60);
        std::fs::write(
            dir.join(KEY_CACHE_META_FILE),
            format!("fetched_at_unix={old_unix}\n"),
        )
        .unwrap();
        assert!(read_cached_key(&dir).is_none());
    }

    #[test]
    fn invalidate_removes_files() {
        let dir = fresh_state_dir();
        write_cached_key(&dir, &synthetic_key()).unwrap();
        assert!(dir.join(KEY_CACHE_FILE).exists());
        invalidate_server_key_cache(&dir);
        assert!(!dir.join(KEY_CACHE_FILE).exists());
        assert!(!dir.join(KEY_CACHE_META_FILE).exists());
    }
}
