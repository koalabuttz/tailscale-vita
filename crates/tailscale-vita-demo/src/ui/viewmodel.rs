#![allow(dead_code)] // consumers (dashboard/render) are vita-gated; host sees these as dead

//! M17-A S3 — pure snapshot→display transformation. No FFI, no I/O:
//! everything here is host-tested. The renderer maps `Tone` to actual
//! colors; this module decides only WHAT to show.

use std::net::Ipv4Addr;

use tailscale_vita::{OnlineState, PeerView, RuntimeSnapshot};

use super::timefmt;

/// Semantic color class; render.rs maps to RGBA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Dim,
    Normal,
}

/// Top-level dashboard tab, cycled with L/R.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Peers,
    Settings,
    Debug,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Peers, Tab::Settings, Tab::Debug];
    pub fn label(self) -> &'static str {
        match self {
            Tab::Peers => "Peers",
            Tab::Settings => "Settings",
            Tab::Debug => "Debug",
        }
    }
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|&t| t == self).unwrap_or(0)
    }
    pub fn next(self) -> Tab {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }
    pub fn prev(self) -> Tab {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// A row in the Settings tab. The two ftp rows are config toggles
/// (rewrite config.toml, relaunch to apply). `TailnetToggle` (M19) flips
/// the live `want_running` state (`/up`/`/down`, also persisted); its
/// value cell shows `on`/`off` from the lifecycle. `Reconnect` rebuilds
/// the control session; `Reauthenticate` (M19) starts a fresh interactive
/// login (`/login-interactive`); `Logout` expires the node's key at
/// control (guarded by a confirm overlay).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingRow {
    FtpEnabled,
    FtpReadOnly,
    TailnetToggle,
    Reconnect,
    Reauthenticate,
    Logout,
}

impl SettingRow {
    pub const ALL: [SettingRow; 6] = [
        SettingRow::FtpEnabled,
        SettingRow::FtpReadOnly,
        SettingRow::TailnetToggle,
        SettingRow::Reconnect,
        SettingRow::Reauthenticate,
        SettingRow::Logout,
    ];

    /// Display label + right-hand value string for the current state.
    /// `ftp_enabled`/`ftp_read_only` are the live config.toml values
    /// (`None` = couldn't read the file); `lifecycle` drives the tailnet
    /// on/off value cell (`Stopped` ⇒ off).
    pub fn render(
        self,
        ftp_enabled: Option<bool>,
        ftp_read_only: Option<bool>,
        lifecycle: OnlineState,
    ) -> (String, String, Tone) {
        let on_off = |b: Option<bool>| match b {
            Some(true) => ("ON".to_string(), Tone::Good),
            Some(false) => ("OFF".to_string(), Tone::Dim),
            None => ("?".to_string(), Tone::Warn),
        };
        match self {
            SettingRow::FtpEnabled => {
                let (v, t) = on_off(ftp_enabled);
                ("ts-ftp server".into(), v, t)
            }
            SettingRow::FtpReadOnly => {
                let (v, t) = on_off(ftp_read_only);
                ("ts-ftp read-only".into(), v, t)
            }
            SettingRow::TailnetToggle => {
                if lifecycle == OnlineState::Stopped {
                    ("Tailnet".into(), "off".into(), Tone::Dim)
                } else {
                    ("Tailnet".into(), "on".into(), Tone::Good)
                }
            }
            SettingRow::Reconnect => {
                ("Reconnect to control".into(), "press X".into(), Tone::Normal)
            }
            SettingRow::Reauthenticate => {
                ("Re-authenticate".into(), "press X".into(), Tone::Warn)
            }
            SettingRow::Logout => ("Log out".into(), "press X".into(), Tone::Bad),
        }
    }
}

/// Which of the three NeedsLogin full-screen modes is showing, derived from
/// the snapshot's (`auth_url`, `login_in_progress`). Drives both the render
/// copy and the input handling: the logged-out mode accepts ✕ to start a
/// fresh login; the QR + spinner modes accept ○ to cancel — parking the
/// tailnet so the user isn't trapped in the full-screen login. (M19 finding 1.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginMode {
    /// Post-logout parked screen — ✕ starts a fresh interactive login.
    LoggedOut,
    /// Registration underway, no AuthURL yet — spinner; ○ cancels.
    Starting,
    /// AuthURL published — QR + URL text; ○ cancels.
    Qr,
}

impl LoginMode {
    pub fn classify(auth_url_present: bool, login_in_progress: bool) -> LoginMode {
        if auth_url_present {
            LoginMode::Qr
        } else if login_in_progress {
            LoginMode::Starting
        } else {
            LoginMode::LoggedOut
        }
    }
    /// The QR + spinner modes show an "○: cancel login (stops tailnet)" hint
    /// and accept ○ to park the tailnet; the logged-out mode does not (its ✕
    /// starts a login, and there's nothing in flight to cancel).
    pub fn shows_cancel_hint(self) -> bool {
        matches!(self, LoginMode::Starting | LoginMode::Qr)
    }
}

pub struct HeaderVm {
    /// e.g. "vita  100.127.67.48"
    pub title: String,
    /// e.g. "Online" — colored by `lifecycle_tone`.
    pub lifecycle: String,
    pub lifecycle_tone: Tone,
    /// e.g. "DERP 1 · up 2h14m"
    pub right: String,
    /// e.g. "tags: tag:vita · public 174.x.x.x:41641" or the untagged warning.
    pub sub: String,
    pub sub_tone: Tone,
}

pub struct PeerRow {
    pub online: bool,
    pub name: String,
    pub ip: String,
    pub path: String,
    pub path_tone: Tone,
    /// Ping target — present only when the peer is online with a
    /// tailnet IP.
    pub ping_ip: Option<Ipv4Addr>,
    /// Full node-key hex — exact key for the peer-detail lookup.
    pub node_key: String,
}

pub struct DashVm {
    pub header: HeaderVm,
    pub rows: Vec<PeerRow>,
    /// e.g. "updated 2 s ago" — amber when stale.
    pub staleness: String,
    pub staleness_tone: Tone,
}

pub fn build(snap: &RuntimeSnapshot, now_unix: u64) -> DashVm {
    let ip = snap
        .our_addrs
        .first()
        .map(|a| a.addr.to_string())
        .unwrap_or_else(|| "—".into());
    let (lifecycle, lifecycle_tone) = lifecycle_display(snap.lifecycle);

    // M19 identity card: prefer "login · domain" in the header's right
    // slot once the netmap resolves our login name; otherwise fall back to
    // the DERP/uptime status string (still visible verbatim in Debug).
    let right = identity_line(snap).unwrap_or_else(|| {
        let mut r = String::new();
        if snap.derp_home_region != 0 {
            r.push_str(&format!("DERP {}", snap.derp_home_region));
        }
        if !r.is_empty() {
            r.push_str(" · ");
        }
        r.push_str(&format!(
            "up {}",
            fmt_duration_secs(now_unix.saturating_sub(snap.started_at_unix))
        ));
        r
    });

    let (sub, sub_tone) = if snap.acl.has_tags {
        let mut s = format!("tags: {}", snap.acl.tags.join(" "));
        if let Some(pe) = snap.public_endpoint {
            s.push_str(&format!(" · public {pe}"));
        }
        (s, Tone::Dim)
    } else {
        (
            "UNTAGGED auth-key — this device has full untagged-node ACL reach".into(),
            Tone::Warn,
        )
    };

    let mut rows: Vec<PeerRow> = snap.peers.values().map(peer_row).collect();
    rows.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.ip.cmp(&b.ip))
    });

    let age = now_unix.saturating_sub(snap.updated_at_unix);
    let (staleness, staleness_tone) = if age > 10 {
        (format!("updated {age} s ago — STALE"), Tone::Warn)
    } else {
        (format!("updated {age} s ago"), Tone::Dim)
    };

    DashVm {
        header: HeaderVm {
            title: format!("{}  {}", snap.hostname, ip),
            lifecycle,
            lifecycle_tone,
            right,
            sub,
            sub_tone,
        },
        rows,
        staleness,
        staleness_tone,
    }
}

fn peer_row(p: &tailscale_vita::PeerView) -> PeerRow {
    let (path, path_tone) = if !p.online {
        ("—".into(), Tone::Dim)
    } else if p.direct_path_alive {
        match p.direct_path_rtt_ms {
            Some(ms) => (format!("direct {ms} ms"), Tone::Good),
            None => ("direct".into(), Tone::Good),
        }
    } else if p.home_derp != 0 {
        (format!("relay (derp {})", p.home_derp), Tone::Warn)
    } else {
        ("relay".into(), Tone::Warn)
    };
    PeerRow {
        online: p.online,
        name: first_label(&p.name),
        ip: p
            .tailscale_ip
            .map(|i| i.to_string())
            .unwrap_or_else(|| "—".into()),
        path,
        path_tone,
        ping_ip: if p.online { p.tailscale_ip } else { None },
        node_key: p.node_key_hex.clone(),
    }
}

/// ACL posture line for the Settings/header panel — the threat-model
/// priority. Green when tagged, red when the auth-key was untagged
/// (full untagged-node ACL reach).
pub fn acl_line(snap: &RuntimeSnapshot) -> (String, Tone) {
    if snap.acl.has_tags {
        (format!("ACL tags: {}", snap.acl.tags.join(" ")), Tone::Good)
    } else {
        (
            "ACL: UNTAGGED auth-key — full untagged-node reach".into(),
            Tone::Bad,
        )
    }
}

/// Self key-expiry line + tone for the header/settings warning.
pub fn key_expiry_line(snap: &RuntimeSnapshot, now_unix: u64) -> (String, Tone) {
    let line = timefmt::fmt_key_expiry(&snap.our_key_expiry, now_unix);
    let tone = if timefmt::key_expiry_is_warning(&snap.our_key_expiry, now_unix) {
        Tone::Bad
    } else {
        Tone::Dim
    };
    (line, tone)
}

/// Debug-tab rows: runtime internals the main card omits. `(label,
/// value, tone)`. Pure — reads only the snapshot + build string.
pub fn build_debug_rows(
    snap: &RuntimeSnapshot,
    now_unix: u64,
    build: &str,
) -> Vec<(String, String, Tone)> {
    let mut rows = Vec::new();
    rows.push(("lifecycle".into(), format!("{:?}", snap.lifecycle), Tone::Normal));
    if let Some(reason) = &snap.fatal_reason {
        rows.push(("fatal".into(), reason.clone(), Tone::Bad));
    }
    rows.push((
        "updated".into(),
        format!("{} s ago", now_unix.saturating_sub(snap.updated_at_unix)),
        Tone::Dim,
    ));
    rows.push((
        "uptime".into(),
        fmt_duration_secs(now_unix.saturating_sub(snap.started_at_unix)),
        Tone::Dim,
    ));
    rows.push(("peers".into(), snap.peer_count.to_string(), Tone::Normal));
    rows.push((
        "DERP home".into(),
        if snap.derp_home_region == 0 {
            "none".into()
        } else {
            snap.derp_home_region.to_string()
        },
        Tone::Normal,
    ));
    rows.push((
        "DERP alive".into(),
        if snap.alive_derp_regions.is_empty() {
            "none".into()
        } else {
            snap.alive_derp_regions
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(",")
        },
        Tone::Normal,
    ));
    rows.push(("magic UDP".into(), snap.magic_local.to_string(), Tone::Dim));
    rows.push((
        "public".into(),
        snap.public_endpoint
            .map(|e| e.to_string())
            .unwrap_or_else(|| "none (no STUN)".into()),
        Tone::Dim,
    ));
    let (kx, kt) = key_expiry_line(snap, now_unix);
    rows.push(("self key".into(), kx.trim_start_matches("key: ").into(), kt));
    rows.push(("build".into(), build.into(), Tone::Dim));
    rows
}

/// Peer-detail overlay lines for the peer whose node-key hex is `key`.
/// `None` if that peer vanished from the snapshot. `(label, value)`.
pub fn peer_detail_lines(
    snap: &RuntimeSnapshot,
    key: &str,
    now_unix: u64,
) -> Option<Vec<(String, String)>> {
    let p: &PeerView = snap.peers.get(key)?;
    let mut rows = vec![
        ("name".into(), first_label(&p.name)),
        (
            "tailnet IP".into(),
            p.tailscale_ip.map(|i| i.to_string()).unwrap_or_else(|| "—".into()),
        ),
        ("online".into(), if p.online { "yes".into() } else { "no".into() }),
        ("node id".into(), p.node_id.to_string()),
        (
            "DERP home".into(),
            if p.home_derp == 0 { "none".into() } else { p.home_derp.to_string() },
        ),
        (
            "direct path".into(),
            match (p.direct_path_alive, p.direct_path_rtt_ms) {
                (true, Some(ms)) => format!("yes, {ms} ms"),
                (true, None) => "yes".into(),
                (false, _) => "no (relay)".into(),
            },
        ),
    ];
    if let Some(ep) = &p.direct_path_endpoint {
        rows.push(("via".into(), ep.to_string()));
    }
    rows.push((
        "allowed IPs".into(),
        if p.allowed_ips.is_empty() {
            "—".into()
        } else {
            p.allowed_ips.join(" ")
        },
    ));
    rows.push((
        "endpoints".into(),
        if p.endpoints.is_empty() {
            "—".into()
        } else {
            p.endpoints.join(" ")
        },
    ));
    // last_seen is only meaningful for offline peers (Tailscale omits it
    // for online ones; a stale value can linger after reconnect).
    if !p.online {
        let ls = timefmt::fmt_last_seen(&p.last_seen, now_unix);
        if !ls.is_empty() {
            rows.push(("last seen".into(), ls.trim_start_matches("last seen ").into()));
        }
    }
    rows.push((
        "key".into(),
        timefmt::fmt_key_expiry(&p.key_expiry, now_unix)
            .trim_start_matches("key: ")
            .into(),
    ));
    rows.push(("node key".into(), format!("{}…", &p.node_key_hex[..16.min(p.node_key_hex.len())])));
    Some(rows)
}

/// Peer names arrive as FQDNs ("lewis.tail1234.ts.net."); display the
/// first label only.
pub fn first_label(name: &str) -> String {
    name.split('.').next().unwrap_or(name).to_string()
}

/// "37m", "2h14m", "3d1h".
pub fn fmt_duration_secs(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3_600, (secs % 3_600) / 60);
    if d > 0 {
        format!("{d}d{h}h")
    } else if h > 0 {
        format!("{h}h{m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{secs}s")
    }
}

/// M19 identity string for the header's right slot: `login · domain`, or
/// just `login` when the tailnet domain hasn't landed yet or adds nothing.
/// `None` when we have no login name (tagged node, or before the profile
/// arrives) — the caller falls back to the DERP/uptime status string.
///
/// A personal Tailscale account reports the tailnet domain equal to the
/// login (both are the account email), which rendered as the same address
/// twice — and the second copy got truncated by the header width guard, so
/// it read like something was cut off (hardware 2026-07-03). Show the domain
/// only when it's distinct from the login; a real tailnet name
/// (`corp.com`, `tailXXXX.ts.net`) is still surfaced.
fn identity_line(snap: &RuntimeSnapshot) -> Option<String> {
    let login = snap.user_login.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
    match snap.tailnet_domain.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
        Some(domain) if !domain.eq_ignore_ascii_case(login) => Some(format!("{login} · {domain}")),
        _ => Some(login.to_string()),
    }
}

fn lifecycle_display(l: OnlineState) -> (String, Tone) {
    let tone = match l {
        OnlineState::Online => Tone::Good,
        // M18: NeedsLogin is an actionable wait-state (scan the QR), not
        // an error — surface it as a warning tone. The full-screen Login
        // view is rendered separately (S5).
        OnlineState::Connecting | OnlineState::Degraded | OnlineState::NeedsLogin => Tone::Warn,
        OnlineState::Offline | OnlineState::AuthFailed | OnlineState::SecurityFailed => Tone::Bad,
        // M19: the parked `Stopped` state is a deliberate, healthy
        // disconnect — dim, not an error tone.
        OnlineState::Stopped => Tone::Dim,
    };
    (format!("{l:?}"), tone)
}

/// Minimum pixel gap kept between the left-aligned sub/warning line and the
/// right-aligned identity string that share the header baseline.
pub const HEADER_SIDE_GAP: i32 = 16;

/// Header layout guard (M19 finding 2): the identity string is right-aligned
/// on the same baseline as the (possibly 62-char UNTAGGED) sub warning.
/// Returns the pixel budget left for the identity after the sub line + a gap,
/// clamped to 0. The renderer draws the identity only if it fits this budget
/// — eliding or dropping it otherwise — so the security-relevant warning is
/// never overdrawn. `inner_w` is the drawable width between the side margins.
pub fn header_identity_budget(inner_w: i32, sub_w: i32) -> i32 {
    (inner_w - sub_w - HEADER_SIDE_GAP).max(0)
}

/// Whether a confirm-modal press should dismiss the modal (M19 finding 3).
/// The destructive action is only enqueued when no other action is in flight
/// (`action_idle`); if it wasn't enqueued the modal must stay open so the
/// confirm isn't silently consumed while the logout is dropped.
pub fn confirm_dismisses(action_idle: bool) -> bool {
    action_idle
}

/// Clamp the peer-list scroll window so `selected` stays visible.
/// Returns the half-open row range to draw.
pub fn scroll_window(len: usize, selected: usize, viewport: usize) -> (usize, usize) {
    if len <= viewport {
        return (0, len);
    }
    let selected = selected.min(len - 1);
    let mut start = selected.saturating_sub(viewport / 2);
    if start + viewport > len {
        start = len - viewport;
    }
    (start, start + viewport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tailscale_vita::{PeerView, RuntimeSnapshot};

    fn peer(name: &str, online: bool, direct: Option<u64>, derp: u16) -> PeerView {
        PeerView {
            node_key_hex: "ab".repeat(32),
            node_id: 1,
            name: name.into(),
            online,
            tailscale_ip: Some("100.64.0.9".parse().unwrap()),
            allowed_ips: vec!["100.64.0.9/32".into()],
            home_derp: derp,
            endpoints: vec![],
            direct_path_alive: direct.is_some(),
            direct_path_endpoint: None,
            direct_path_rtt_ms: direct,
            last_seen: None,
            key_expiry: None,
        }
    }

    fn snap_with(peers: Vec<PeerView>) -> RuntimeSnapshot {
        let mut s = RuntimeSnapshot::empty("vita".into(), "0.0.0.0:41641".parse().unwrap());
        s.updated_at_unix = 1_000_000;
        s.started_at_unix = 1_000_000 - 8_040; // 2h14m
        s.peers = peers
            .into_iter()
            .enumerate()
            .map(|(i, p)| (format!("{i:064}"), p))
            .collect::<HashMap<_, _>>();
        s
    }

    #[test]
    fn rows_sort_online_first_then_name() {
        let vm = build(
            &snap_with(vec![
                peer("zeta.ts.net.", true, Some(5), 1),
                peer("offline-a.ts.net.", false, None, 1),
                peer("alpha.ts.net.", true, None, 2),
            ]),
            1_000_002,
        );
        let names: Vec<&str> = vm.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "zeta", "offline-a"]);
    }

    #[test]
    fn path_cell_covers_direct_relay_offline() {
        let vm = build(
            &snap_with(vec![
                peer("d.x.", true, Some(12), 1),
                peer("r.x.", true, None, 9),
                peer("o.x.", false, None, 9),
            ]),
            1_000_000,
        );
        let by_name = |n: &str| vm.rows.iter().find(|r| r.name == n).unwrap();
        assert_eq!(by_name("d").path, "direct 12 ms");
        assert_eq!(by_name("d").path_tone, Tone::Good);
        assert!(by_name("d").ping_ip.is_some());
        assert_eq!(by_name("r").path, "relay (derp 9)");
        assert_eq!(by_name("r").path_tone, Tone::Warn);
        assert_eq!(by_name("o").path, "—");
        assert_eq!(by_name("o").path_tone, Tone::Dim);
        assert!(by_name("o").ping_ip.is_none());
    }

    #[test]
    fn header_formats_uptime_and_staleness() {
        let vm = build(&snap_with(vec![]), 1_000_002);
        assert_eq!(vm.header.title, "vita  —");
        assert!(vm.header.right.ends_with("up 2h14m"), "{}", vm.header.right);
        assert_eq!(vm.staleness, "updated 2 s ago");
        assert_eq!(vm.staleness_tone, Tone::Dim);

        let stale = build(&snap_with(vec![]), 1_000_030);
        assert!(stale.staleness.contains("STALE"));
        assert_eq!(stale.staleness_tone, Tone::Warn);
    }

    #[test]
    fn untagged_acl_gets_a_warning_subline() {
        let vm = build(&snap_with(vec![]), 1_000_000);
        assert!(vm.header.sub.contains("UNTAGGED"));
        assert_eq!(vm.header.sub_tone, Tone::Warn);

        let mut s = snap_with(vec![]);
        s.acl.tags = vec!["tag:vita".into()];
        s.acl.has_tags = true;
        let vm = build(&s, 1_000_000);
        assert!(vm.header.sub.contains("tag:vita"));
    }

    #[test]
    fn scroll_window_clamps() {
        assert_eq!(scroll_window(5, 0, 9), (0, 5)); // fits entirely
        assert_eq!(scroll_window(30, 0, 9), (0, 9)); // top
        assert_eq!(scroll_window(30, 29, 9), (21, 30)); // bottom
        let (s, e) = scroll_window(30, 15, 9); // middle: selected visible
        assert!(s <= 15 && 15 < e);
        assert_eq!(e - s, 9);
    }

    #[test]
    fn fmt_duration_buckets() {
        assert_eq!(fmt_duration_secs(42), "42s");
        assert_eq!(fmt_duration_secs(37 * 60), "37m");
        assert_eq!(fmt_duration_secs(2 * 3600 + 14 * 60), "2h14m");
        assert_eq!(fmt_duration_secs(3 * 86400 + 3600), "3d1h");
    }

    #[test]
    fn tab_cycles_both_ways() {
        assert_eq!(Tab::Peers.next(), Tab::Settings);
        assert_eq!(Tab::Debug.next(), Tab::Peers);
        assert_eq!(Tab::Peers.prev(), Tab::Debug);
        assert_eq!(Tab::Settings.index(), 1);
    }

    #[test]
    fn setting_row_renders_states() {
        let ol = OnlineState::Online;
        let (l, v, t) = SettingRow::FtpEnabled.render(Some(true), Some(false), ol);
        assert_eq!(l, "ts-ftp server");
        assert_eq!(v, "ON");
        assert_eq!(t, Tone::Good);
        let (_, v, t) = SettingRow::FtpReadOnly.render(Some(true), Some(false), ol);
        assert_eq!(v, "OFF");
        assert_eq!(t, Tone::Dim);
        let (_, v, t) = SettingRow::FtpEnabled.render(None, None, ol);
        assert_eq!(v, "?");
        assert_eq!(t, Tone::Warn);
        let (l, _, _) = SettingRow::Reconnect.render(None, None, ol);
        assert_eq!(l, "Reconnect to control");
        let (l, v, t) = SettingRow::Reauthenticate.render(None, None, ol);
        assert_eq!(l, "Re-authenticate");
        assert_eq!(v, "press X");
        assert_eq!(t, Tone::Warn);
        let (l, _, t) = SettingRow::Logout.render(None, None, ol);
        assert_eq!(l, "Log out");
        assert_eq!(t, Tone::Bad);
    }

    #[test]
    fn tailnet_toggle_reflects_lifecycle() {
        // ALL is exactly the six M19 rows, in order.
        assert_eq!(SettingRow::ALL.len(), 6);
        assert_eq!(SettingRow::ALL[2], SettingRow::TailnetToggle);
        let (l, v, t) = SettingRow::TailnetToggle.render(None, None, OnlineState::Online);
        assert_eq!(l, "Tailnet");
        assert_eq!(v, "on");
        assert_eq!(t, Tone::Good);
        let (_, v, t) = SettingRow::TailnetToggle.render(None, None, OnlineState::Stopped);
        assert_eq!(v, "off");
        assert_eq!(t, Tone::Dim);
    }

    #[test]
    fn lifecycle_display_stopped_is_dim() {
        let (label, tone) = lifecycle_display(OnlineState::Stopped);
        assert_eq!(label, "Stopped");
        assert_eq!(tone, Tone::Dim);
        assert_eq!(lifecycle_display(OnlineState::Online).1, Tone::Good);
    }

    #[test]
    fn header_right_shows_identity_or_falls_back() {
        // No identity yet → DERP/uptime fallback (unchanged behavior).
        let vm = build(&snap_with(vec![]), 1_000_002);
        assert!(vm.header.right.ends_with("up 2h14m"), "{}", vm.header.right);
        // login + distinct domain → "login · domain".
        let mut s = snap_with(vec![]);
        s.user_login = Some("dave@example.com".into());
        s.tailnet_domain = Some("example.com".into());
        assert_eq!(build(&s, 1_000_002).header.right, "dave@example.com · example.com");
        // login without a domain → just the login name.
        let mut s = snap_with(vec![]);
        s.user_login = Some("dave@example.com".into());
        assert_eq!(build(&s, 1_000_002).header.right, "dave@example.com");
        // Personal account: domain == login (both the email) → collapse to
        // just the login, no redundant/truncated second copy.
        let mut s = snap_with(vec![]);
        s.user_login = Some("dgodlewski9@gmail.com".into());
        s.tailnet_domain = Some("dgodlewski9@gmail.com".into());
        assert_eq!(build(&s, 1_000_002).header.right, "dgodlewski9@gmail.com");
    }

    #[test]
    fn acl_line_flags_untagged() {
        let mut s = snap_with(vec![]);
        let (line, tone) = acl_line(&s);
        assert!(line.contains("UNTAGGED"));
        assert_eq!(tone, Tone::Bad);
        s.acl.tags = vec!["tag:vita".into()];
        s.acl.has_tags = true;
        let (line, tone) = acl_line(&s);
        assert!(line.contains("tag:vita"));
        assert_eq!(tone, Tone::Good);
    }

    #[test]
    fn key_expiry_line_warns() {
        let now = 1_782_950_400; // 2026-07-02
        let mut s = snap_with(vec![]);
        s.our_key_expiry = Some("2026-07-09T00:00:00Z".into()); // 7 days
        let (line, tone) = key_expiry_line(&s, now);
        assert!(line.contains("expires in 7 days"));
        assert_eq!(tone, Tone::Bad);
        s.our_key_expiry = None;
        let (line, tone) = key_expiry_line(&s, now);
        assert!(line.contains("never"));
        assert_eq!(tone, Tone::Dim);
    }

    #[test]
    fn debug_rows_include_internals() {
        let mut s = snap_with(vec![peer("a.x.", true, Some(3), 1)]);
        s.public_endpoint = Some("1.2.3.4:41641".parse().unwrap());
        s.alive_derp_regions = vec![1, 2];
        let rows = build_debug_rows(&s, 1_000_010, "build-xyz");
        let labels: Vec<&str> = rows.iter().map(|(l, _, _)| l.as_str()).collect();
        assert!(labels.contains(&"lifecycle"));
        assert!(labels.contains(&"public"));
        assert!(labels.contains(&"DERP alive"));
        assert!(labels.contains(&"build"));
        let pub_row = rows.iter().find(|(l, _, _)| l == "public").unwrap();
        assert_eq!(pub_row.1, "1.2.3.4:41641");
    }

    #[test]
    fn login_mode_selects_cancel_hint() {
        // auth_url present → QR mode, cancellable.
        let qr = LoginMode::classify(true, false);
        assert_eq!(qr, LoginMode::Qr);
        assert!(qr.shows_cancel_hint());
        // in-progress, no URL yet → spinner, cancellable.
        let starting = LoginMode::classify(false, true);
        assert_eq!(starting, LoginMode::Starting);
        assert!(starting.shows_cancel_hint());
        // auth_url wins even if the in-progress flag lingers.
        assert_eq!(LoginMode::classify(true, true), LoginMode::Qr);
        // parked (logged out) → ✕ starts a login, no cancel affordance.
        let out = LoginMode::classify(false, false);
        assert_eq!(out, LoginMode::LoggedOut);
        assert!(!out.shows_cancel_hint());
    }

    #[test]
    fn header_identity_budget_guards_overlap() {
        let inner = 896; // SCREEN_W 960 - 2*MARGIN(32)
        // Short sub → plenty of room for the identity.
        assert_eq!(header_identity_budget(inner, 200), 896 - 200 - HEADER_SIDE_GAP);
        // A wide (untagged-warning) sub leaves a shrunken budget…
        assert_eq!(header_identity_budget(inner, 820), 60);
        // …and once it fills the row the identity is dropped (budget 0).
        assert_eq!(header_identity_budget(inner, 890), 0);
        assert_eq!(header_identity_budget(inner, 1200), 0);
    }

    #[test]
    fn confirm_dismisses_only_when_idle() {
        // Idle → the logout is enqueued, so the modal closes.
        assert!(confirm_dismisses(true));
        // Busy (e.g. a 7 s reconnect in flight) → send() drops the logout;
        // the modal must stay open so the confirm isn't silently consumed.
        assert!(!confirm_dismisses(false));
    }

    #[test]
    fn peer_detail_lines_for_known_key() {
        let mut s = snap_with(vec![]);
        let mut pv = peer("lewis.ts.net.", true, Some(4), 1);
        pv.node_key_hex = "cd".repeat(32);
        pv.endpoints = vec!["192.168.8.211:54415".into()];
        s.peers.insert("mapkey-1".into(), pv);
        let lines = peer_detail_lines(&s, "mapkey-1", 1_000_000).unwrap();
        let get = |k: &str| lines.iter().find(|(l, _)| l == k).map(|(_, v)| v.clone());
        assert_eq!(get("name").as_deref(), Some("lewis"));
        assert_eq!(get("direct path").as_deref(), Some("yes, 4 ms"));
        assert_eq!(get("endpoints").as_deref(), Some("192.168.8.211:54415"));
        assert!(peer_detail_lines(&s, "no-such-key", 1_000_000).is_none());
    }
}
