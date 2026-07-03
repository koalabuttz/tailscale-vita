//! TOML config for the Tailscale-on-Vita Runtime. Reads from
//! `ux0:/data/tailscale-vita/config.toml` (or wherever
//! `Config::load_or_template` is pointed).
//!
//! On first run, if the file doesn't exist, a template is written and
//! `Config::load_or_template` returns `ConfigError::TemplateWritten`
//! with a clear "fill in auth_key and re-run" message — the demo's
//! main.rs can log this as an actionable error.

use std::path::Path;

use serde::Deserialize;

use crate::error::ConfigError;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Headscale URL — e.g. "http://192.168.x.x:8080" for a LAN dev
    /// Headscale, or "https://controlplane.tailscale.com" for prod.
    pub control_url: String,

    /// Auth key. **Empty (the default) = interactive QR login** (M18):
    /// register with the `Auth` struct omitted, show the returned AuthURL
    /// as an on-screen QR, and wait for the user to approve on a phone.
    /// A non-empty value is an automation override for hands-free
    /// registration — bare hex on Headscale 0.26; `tskey-auth-...` on
    /// Tailscale prod. Passed verbatim — don't strip prefixes.
    pub auth_key: String,

    /// Hostname this Vita advertises in `Hostinfo`.
    #[serde(default = "default_hostname")]
    pub hostname: String,

    /// `tracing` filter. Defaults to "info".
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Where KeyStore + auth-key.txt + last_seq + session_handle live.
    #[serde(default = "default_state_dir")]
    pub state_dir: String,

    /// Port for the demo HTTP listener. Default 8080.
    #[serde(default = "default_demo_port")]
    pub demo_port: u16,

    /// DerpTransport conn-pool cap. PLAN-V1 §M8 sets this at 8.
    #[serde(default = "default_max_derp")]
    pub max_derp_conns: usize,

    /// TcpListener pre-allocated socket-pool size. PLAN-V1 §M10 = 4.
    #[serde(default = "default_listener_pool")]
    pub listener_pool_size: usize,

    /// Demo runtime window in seconds. `None` = run forever (until
    /// PS-button or other process-level termination).
    #[serde(default)]
    pub run_window_secs: Option<u64>,

    /// CapabilityVersion to send. Don't change unless you know what
    /// you're doing — Headscale 0.26's floor is 88; we send 90.
    #[serde(default = "default_capver")]
    pub capver: u32,

    /// M11 Phase 2 flag. When true, the demo eboot's main() skips
    /// `Runtime::up` and just sleeps forever — the demo becomes a host
    /// process for the SUPRX (which runs the actual runtime). Set
    /// this in `config.toml` when running with the
    /// `tailscale-vita-plugin.suprx` loaded under `*TVIT00010`.
    /// Default false: demo behaves as in M10 and runs the runtime
    /// itself.
    #[serde(default)]
    pub suprx_host_only: bool,

    /// M14 LocalAPI port (loopback). `Some(41112)` is the default and
    /// matches upstream Go's `tailscale-localapi`. Set to `None` (or
    /// omit and use `localapi_port = 0` in TOML — currently no way to
    /// express None in TOML serde) to disable LocalAPI entirely.
    /// In practice, leave at default unless 41112 conflicts with
    /// another homebrew on the device.
    #[serde(default = "default_localapi_port")]
    pub localapi_port: Option<u16>,

    /// `[ftp]` — optional FTP server on the tailnet IP, so the Vita's
    /// filesystem is reachable from any network. Disabled by default (it
    /// exposes the filesystem; the tailnet ACL is the boundary). See
    /// [`ts_ftp::FtpConfig`].
    #[serde(default)]
    pub ftp: ts_ftp::FtpConfig,

    /// `[egress_probe]` — Fork-B diagnostic: UDP egress-shape probe for
    /// the WG data-plane bug. Off by default. See
    /// [`crate::egress_probe::EgressProbeConfig`] + docs/EGRESS-PROBE.md.
    #[serde(default)]
    pub egress_probe: crate::egress_probe::EgressProbeConfig,
}

impl Config {
    /// Load TOML config from `path`. If the file doesn't exist, write
    /// a template and return `ConfigError::TemplateWritten`. Caller
    /// (demo's main) should log the error and exit cleanly so the
    /// user can edit and re-launch.
    pub fn load_or_template(path: &Path) -> Result<Self, ConfigError> {
        // vita_fs (raw sceIo on Vita) — std::fs would crash on the SUPRX
        // bootstrap thread (no newlib _REENT). See S6 audit.
        match vita_fs::read_to_string(path) {
            Ok(s) => Ok(toml::from_str(&s)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::write_template(path)?;
                Err(ConfigError::TemplateWritten {
                    path: path.display().to_string(),
                })
            }
            Err(e) => Err(ConfigError::Io(e)),
        }
    }

    /// Write the template TOML file at `path`. Creates parent dirs.
    pub fn write_template(path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            vita_fs::create_dir_all(parent)?;
        }
        vita_fs::write(path, TEMPLATE.as_bytes())
    }

    /// `host:port` form of `control_url` — the value used as the HTTP/2
    /// `:authority` pseudo-header on the Noise tunnel. Strips the
    /// scheme prefix (`http://` or `https://`).
    pub fn host_authority(&self) -> String {
        let s = self.control_url.as_str();
        if let Some(rest) = s.strip_prefix("https://") {
            rest.trim_end_matches('/').to_string()
        } else if let Some(rest) = s.strip_prefix("http://") {
            rest.trim_end_matches('/').to_string()
        } else {
            s.trim_end_matches('/').to_string()
        }
    }
}

const TEMPLATE: &str = r#"# tailscale-vita demo config
#
# Edit this file in place after the demo writes the template. Required
# fields: `control_url` and `auth_key`. Everything else has defaults.

control_url = "http://HEADSCALE_HOST_IP:8080"

# Leave empty to log in interactively (M18): on first run the Vita
# shows a QR code + URL on screen — scan it with your phone and approve
# the node on Tailscale/Headscale. The authorized node key is then
# persisted, so later boots go straight to Online with no QR.
#
# Optional automation override: paste a pre-auth key to register
# hands-free. Bare hex on Headscale 0.26 / `tskey-auth-...` on Tailscale.
# Generate via:
#   docker exec tailscale-vita-headscale headscale preauthkeys create \
#     --user 1 -e 720h --reusable
auth_key    = ""

hostname    = "vita"
log_level   = "info"
state_dir   = "ux0:/data/tailscale-vita"

# HTTP "hello from vita" listener.
demo_port           = 8080

# DERP / netstack tuning.
max_derp_conns      = 8
listener_pool_size  = 4

# Uncomment for a finite demo window. Default runs forever; PS button
# exits the eboot.
# run_window_secs   = 120

# Don't change unless you know what you're doing. Must match
# `ts_control::CAPVER` (the noise envelope/prologue version) so the
# server sees a single coherent capability version across `/key?v=`,
# the noise upgrade, and the JSON bodies.
capver              = 138

# M11 Phase 2: set true when the SUPRX (`tailscale-vita-plugin.suprx`)
# is loaded under *TVIT00010 — the demo eboot then skips its own
# Runtime startup and just keeps the process alive so the SUPRX can
# run. Default false (M10 demo behavior).
# suprx_host_only   = false

# FTP server on the tailnet IP — reach the Vita's files from any network
# with a standard FTP client. Off by default: it exposes the filesystem,
# gated only by your tailnet ACL. Plaintext is fine — WireGuard encrypts
# the tunnel. `root` jails the client; `..` cannot escape above it.
[ftp]
enabled         = false
port            = 21
root            = "ux0:"
read_only       = false
passive_port_lo = 30000
passive_port_hi = 30009

# Fork-B diagnostic (docs/EGRESS-PROBE.md): ~15 s after startup, send a
# battery of tagged UDP shapes through the production send path to each
# target, to learn which shapes actually egress. Run
# scripts/egress-probe-listener.py on each target host. Off by default.
[egress_probe]
enabled            = false
targets            = []      # e.g. ["192.168.8.101:9999"]
rounds             = 5
initial_delay_secs = 15
spacing_ms         = 250
"#;

fn default_hostname() -> String {
    "vita".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_state_dir() -> String {
    "ux0:/data/tailscale-vita".to_string()
}
fn default_demo_port() -> u16 {
    8080
}
fn default_max_derp() -> usize {
    8
}
fn default_listener_pool() -> usize {
    4
}
fn default_capver() -> u32 {
    ts_control::CAPVER as u32
}
fn default_localapi_port() -> Option<u16> {
    Some(crate::localapi::DEFAULT_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_round_trip() {
        let cfg: Config = toml::from_str(TEMPLATE).unwrap();
        assert_eq!(cfg.control_url, "http://HEADSCALE_HOST_IP:8080");
        assert_eq!(cfg.auth_key, "");
        assert_eq!(cfg.hostname, "vita");
        assert_eq!(cfg.demo_port, 8080);
        assert_eq!(cfg.max_derp_conns, 8);
        assert_eq!(cfg.listener_pool_size, 4);
        assert_eq!(cfg.capver, 138);
        assert_eq!(cfg.run_window_secs, None);
        assert!(!cfg.suprx_host_only);
    }

    #[test]
    fn host_authority_strips_scheme() {
        let cfg = Config {
            control_url: "http://192.0.2.1:8080/".into(),
            auth_key: String::new(),
            hostname: "v".into(),
            log_level: "info".into(),
            state_dir: ".".into(),
            demo_port: 8080,
            max_derp_conns: 8,
            listener_pool_size: 4,
            run_window_secs: None,
            capver: 138,
            suprx_host_only: false,
            localapi_port: Some(crate::localapi::DEFAULT_PORT),
            ftp: ts_ftp::FtpConfig::default(),
            egress_probe: Default::default(),
        };
        assert_eq!(cfg.host_authority(), "192.0.2.1:8080");
    }

    #[test]
    fn host_authority_handles_https() {
        let cfg = Config {
            control_url: "https://controlplane.tailscale.com".into(),
            auth_key: String::new(),
            hostname: "v".into(),
            log_level: "info".into(),
            state_dir: ".".into(),
            demo_port: 8080,
            max_derp_conns: 8,
            listener_pool_size: 4,
            run_window_secs: None,
            capver: 138,
            suprx_host_only: false,
            localapi_port: Some(crate::localapi::DEFAULT_PORT),
            ftp: ts_ftp::FtpConfig::default(),
            egress_probe: Default::default(),
        };
        assert_eq!(cfg.host_authority(), "controlplane.tailscale.com");
    }

    #[test]
    fn missing_optional_fields_fall_back_to_defaults() {
        let minimal = r#"
            control_url = "http://x:8080"
            auth_key = "abc"
        "#;
        let cfg: Config = toml::from_str(minimal).unwrap();
        assert_eq!(cfg.hostname, "vita");
        assert_eq!(cfg.demo_port, 8080);
        assert_eq!(cfg.max_derp_conns, 8);
        assert_eq!(cfg.capver, ts_control::CAPVER as u32);
    }
}
