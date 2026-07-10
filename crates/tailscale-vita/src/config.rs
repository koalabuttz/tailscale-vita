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
    /// HTTPS control URL, or a deliberately pinned HTTP development server.
    pub control_url: String,

    /// Static Noise machine public key (`mkey:<hex>`) required when
    /// `control_url` uses cleartext HTTP. It prevents the otherwise circular
    /// "fetch the key from the party we are trying to authenticate" bootstrap.
    #[serde(default)]
    pub control_server_key: Option<String>,

    /// Development-only escape hatch for legacy HTTP Headscale setups. Do not
    /// enable on a shared or hostile LAN: an attacker can impersonate control
    /// and capture the registration auth key.
    #[serde(default)]
    pub insecure_allow_http_control: bool,

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

    /// `[taildrop]` — optional Taildrop receiver (peerapi) on the tailnet
    /// IP, so `tailscale file cp <f> vita:` drops files onto the memory
    /// card. Disabled by default (any ACL-permitted peer can write; the
    /// tailnet ACL is the boundary). See [`ts_peerapi::TaildropConfig`].
    #[serde(default)]
    pub taildrop: ts_peerapi::TaildropConfig,

    /// `[egress_probe]` — Fork-B diagnostic: UDP egress-shape probe for
    /// the WG data-plane bug. Off by default. See
    /// [`crate::egress_probe::EgressProbeConfig`] + docs/EGRESS-PROBE.md.
    #[serde(default)]
    pub egress_probe: crate::egress_probe::EgressProbeConfig,

    /// `[tailnet]` — lifecycle state (M19). `want_running = false` boots
    /// the runtime parked in `OnlineState::Stopped` (equivalent to
    /// `tailscale down`); the eboot's Tailnet toggle flips it via LocalAPI
    /// `/up`//`/down` and persists it here for the next boot. Default on.
    #[serde(default)]
    pub tailnet: TailnetConfig,
}

/// `[tailnet]` section — the persisted `WantRunning` bit (M19).
#[derive(Clone, Debug, Deserialize)]
pub struct TailnetConfig {
    /// Whether the tailnet data plane runs. `false` parks the runtime in
    /// `OnlineState::Stopped` at boot. **Default true is load-bearing** —
    /// a bare `#[serde(default)]` on a bool deserializes to `false`, which
    /// would boot every upgrading user (whose config predates `[tailnet]`)
    /// into Stopped. The field- and section-level defaults both resolve to
    /// `true` so a missing key OR a missing `[tailnet]` section ⇒ running.
    #[serde(default = "default_true")]
    pub want_running: bool,
}

impl Default for TailnetConfig {
    fn default() -> Self {
        Self {
            want_running: default_true(),
        }
    }
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

# Production: HTTPS validates the control server certificate and Noise key.
control_url = "https://controlplane.tailscale.com"

# For a development Headscale instance that only serves HTTP, pin its Noise
# server key (the `mkey:...` returned by `/key`) here. HTTP without this pin
# is refused. `insecure_allow_http_control = true` exists only as a temporary
# migration escape hatch and must never be used on an untrusted LAN.
# control_url = "http://HEADSCALE_HOST_IP:8080"
# control_server_key = "mkey:<64 hex chars>"
# insecure_allow_http_control = false

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

# Tailnet lifecycle (M19). want_running = false boots the runtime parked
# (Stopped, like `tailscale down`); the dashboard's Tailnet toggle flips
# this via LocalAPI and persists it here for the next boot. Default true —
# a missing key or missing [tailnet] section is treated as running.
[tailnet]
want_running = true

# FTP server on the tailnet IP — reach the Vita's files from any network
# with a standard FTP client. Off by default. Set a strong local password
# before enabling; the service refuses to start with an empty password.
# `root` is a real jail by default. `allow_device_paths` is an explicit,
# dangerous compatibility escape hatch for VitaShell-style `/ur0:/...` paths.
# NOTE: the tailnet ACL is enforced locally, so your ACL must grant BOTH
# `port` AND the passive data range (`passive_port_lo..passive_port_hi`) to
# the peers you connect from, or transfers hang at `425` even after login.
[ftp]
enabled         = false
port            = 21
root            = "ux0:"
username        = "vita"
password        = ""       # required when enabled; never logged
allow_device_paths = false
read_only       = false
passive_port_lo = 30000
passive_port_hi = 30009
max_transfer_bytes = 33554432 # 32 MiB per STOR/RETR

# Taildrop receiver (peerapi) on the tailnet IP. When enabled, run
# `tailscale file cp <file> vita:` from any device on your tailnet and the
# file lands in `dir`. Off by default: like FTP it accepts writes from any
# ACL-permitted peer (the tailnet ACL is the boundary; WireGuard encrypts
# the transfer). `max_size` (bytes) caps a single file. Tip: point `dir` at
# "ux0:/vpk" to turn the Vita into a VPK sideload inbox — drop a .vpk from
# your PC and install it in VitaShell, no USB/FTP dance.
[taildrop]
enabled  = false
dir      = "ux0:/data/tailscale-vita/taildrop"
port     = 8098
max_size = 268435456   # 256 MB

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
fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_round_trip() {
        let cfg: Config = toml::from_str(TEMPLATE).unwrap();
        assert_eq!(cfg.control_url, "https://controlplane.tailscale.com");
        assert_eq!(cfg.auth_key, "");
        assert_eq!(cfg.hostname, "vita");
        assert_eq!(cfg.demo_port, 8080);
        assert_eq!(cfg.max_derp_conns, 8);
        assert_eq!(cfg.listener_pool_size, 4);
        assert_eq!(cfg.capver, 138);
        assert_eq!(cfg.run_window_secs, None);
        assert!(!cfg.suprx_host_only);
        // [tailnet] want_running = true in the template, and the default
        // resolves to true even if the section were absent.
        assert!(cfg.tailnet.want_running);
        // [taildrop] parses from the template block with the expected
        // defaults (off, conventional peerapi port, 256 MB cap).
        assert!(!cfg.taildrop.enabled);
        assert_eq!(cfg.taildrop.port, 8098);
        assert_eq!(cfg.taildrop.dir, "ux0:/data/tailscale-vita/taildrop");
        assert_eq!(cfg.taildrop.max_size, 268_435_456);
    }

    #[test]
    fn host_authority_strips_scheme() {
        let cfg = Config {
            control_url: "http://192.0.2.1:8080/".into(),
            control_server_key: None,
            insecure_allow_http_control: false,
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
            taildrop: ts_peerapi::TaildropConfig::default(),
            egress_probe: Default::default(),
            tailnet: TailnetConfig::default(),
        };
        assert_eq!(cfg.host_authority(), "192.0.2.1:8080");
    }

    #[test]
    fn host_authority_handles_https() {
        let cfg = Config {
            control_url: "https://controlplane.tailscale.com".into(),
            control_server_key: None,
            insecure_allow_http_control: false,
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
            taildrop: ts_peerapi::TaildropConfig::default(),
            egress_probe: Default::default(),
            tailnet: TailnetConfig::default(),
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
        // Load-bearing: a config predating [tailnet] must default to
        // running, NOT the bool-default `false` (which would boot Stopped).
        assert!(cfg.tailnet.want_running);
        // A config predating [taildrop] gets the section default: off.
        assert!(!cfg.taildrop.enabled);
        assert_eq!(cfg.taildrop.port, 8098);
    }
}
