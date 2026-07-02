#![allow(dead_code)] // consumers (dashboard/render) are vita-gated; host sees these as dead

//! M17-A S3 — pure snapshot→display transformation. No FFI, no I/O:
//! everything here is host-tested. The renderer maps `Tone` to actual
//! colors; this module decides only WHAT to show.

use std::net::Ipv4Addr;

use tailscale_vita::{OnlineState, RuntimeSnapshot};

/// Semantic color class; render.rs maps to RGBA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Dim,
    Normal,
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

    let mut right = String::new();
    if snap.derp_home_region != 0 {
        right.push_str(&format!("DERP {}", snap.derp_home_region));
    }
    if !right.is_empty() {
        right.push_str(" · ");
    }
    right.push_str(&format!(
        "up {}",
        fmt_duration_secs(now_unix.saturating_sub(snap.started_at_unix))
    ));

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
    }
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

fn lifecycle_display(l: OnlineState) -> (String, Tone) {
    let tone = match l {
        OnlineState::Online => Tone::Good,
        OnlineState::Connecting | OnlineState::Degraded => Tone::Warn,
        OnlineState::Offline | OnlineState::AuthFailed | OnlineState::SecurityFailed => Tone::Bad,
    };
    (format!("{l:?}"), tone)
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
}
