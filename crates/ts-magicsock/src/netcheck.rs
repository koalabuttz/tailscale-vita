//! Probe Tailscale DERP regions' STUN ports (UDP/3478) to discover
//! our public-mapped UDP endpoint and per-region UDP RTT.
//!
//! Used to populate `MapRequest.NetInfo.DerpLatency` and
//! `MapRequest.Endpoints` with real values instead of stubs. Without
//! this, NAT'd peers can't direct-connect to us — they'd only know
//! our LAN endpoints (which are unreachable from outside the LAN).
//!
//! Runs all region probes in parallel via `MagicSocketCtl::stun_probe`,
//! collects results with a per-probe timeout, and aggregates.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use vita_chan::Receiver;
use tracing::{debug, info, warn};

use crate::{MagicSocketCtl, StunResult};

/// Default timeout per probe. Long enough for a slow round-trip,
/// short enough to fail fast.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Standard STUN UDP port. All Tailscale DERP servers run STUN here
/// (the value can be overridden per-node via `DerpNode.STUNPort`, but
/// in practice every region uses 3478).
pub const STUN_PORT: u16 = 3478;

/// Public STUN servers to use as a fallback when Tailscale's DERPs
/// don't respond (some networks / Tailscale-side IP-history ACLs
/// block fresh sources). Resolved at runtime since these hostnames
/// have multiple A records. We only need ONE successful probe to
/// learn our public-mapped endpoint.
pub const PUBLIC_STUN_FALLBACKS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "global.stun.twilio.com:3478",
];

/// Per-region probe result.
#[derive(Debug, Clone)]
pub struct RegionProbe {
    pub region_id: u16,
    pub target: SocketAddr,
    pub rtt: Duration,
    pub reflected: SocketAddr,
}

/// Output of a netcheck round.
#[derive(Debug, Clone, Default)]
pub struct NetcheckReport {
    /// region_id → RTT in seconds. Suitable for direct insertion into
    /// `MapRequest.NetInfo.DerpLatency` (Tailscale uses
    /// `<region>-v4` keys; the caller formats them).
    pub derp_latency: HashMap<u16, f64>,
    /// Region with the lowest measured RTT, or 0 if none responded.
    pub preferred_derp: u16,
    /// Our public-mapped IPv4 endpoint as seen by the v4 STUN servers.
    /// `None` if no v4 probe responded.
    pub public_endpoint: Option<SocketAddr>,
    /// Our public-mapped IPv6 endpoint as seen by the v6 STUN servers
    /// (Tailscale DERPs run STUN on both families). `None` on Vita
    /// (no v6 socket) or when no v6 probe responded.
    pub public_endpoint_v6: Option<SocketAddr>,
    /// All raw per-region results, in the order responses arrived.
    pub probes: Vec<RegionProbe>,
}

/// Identifying info for one DERP region's STUN probe target. Caller
/// supplies these (typically derived from the netmap's DERPMap).
/// At least one of `ipv4_addr` / `ipv6_addr` must be Some.
#[derive(Debug, Clone)]
pub struct StunTarget {
    pub region_id: u16,
    pub ipv4_addr: Option<SocketAddr>,
    pub ipv6_addr: Option<SocketAddr>,
}

/// Issue STUN probes to all `targets` in parallel via `magic`, then
/// gather the results with per-probe `timeout`.
///
/// Each probe is independent; one slow region doesn't block others.
/// Total wall-clock time ~= `timeout`. Failed probes (timeout, parse
/// error, send error) are silently dropped from the report.
pub fn probe_targets(
    magic: &MagicSocketCtl,
    targets: &[StunTarget],
    timeout: Duration,
) -> NetcheckReport {
    info!(
        target_count = targets.len(),
        timeout_ms = timeout.as_millis() as u64,
        "magicsock.netcheck.start"
    );

    // Launch parallel v4 + v6 probes per region. Order doesn't matter;
    // the aggregator below dedups by region_id when computing
    // preferred_derp (first responder wins) and tracks per-family
    // reflections separately for endpoint advertisement.
    let mut inflight: Vec<(u16, SocketAddr, Receiver<StunResult>)> = Vec::new();
    for t in targets {
        if let Some(v4) = t.ipv4_addr {
            match magic.stun_probe(v4) {
                Ok(rx) => inflight.push((t.region_id, v4, rx)),
                Err(e) => warn!(
                    region = t.region_id, target = %v4, error = %e,
                    "magicsock.netcheck.probe.send_failed"
                ),
            }
        }
        if let Some(v6) = t.ipv6_addr {
            match magic.stun_probe(v6) {
                Ok(rx) => inflight.push((t.region_id, v6, rx)),
                Err(e) => debug!(
                    // v6 send failure is expected on Vita (no v6 socket).
                    // debug! instead of warn! to avoid log noise.
                    region = t.region_id, target = %v6, error = %e,
                    "magicsock.netcheck.probe.v6.send_failed"
                ),
            }
        }
    }

    // Collect responses with a SHARED deadline so the total wait is
    // `timeout`, not `timeout * targets.len()`.
    let deadline = std::time::Instant::now() + timeout;
    let mut probes: Vec<RegionProbe> = Vec::new();
    for (region_id, target, rx) in inflight {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(Ok((reflected, rtt))) => {
                debug!(
                    region = region_id,
                    %target,
                    %reflected,
                    rtt_ms = rtt.as_millis() as u64,
                    "magicsock.netcheck.probe.ok"
                );
                probes.push(RegionProbe {
                    region_id,
                    target,
                    rtt,
                    reflected,
                });
            }
            Ok(Err(e)) => warn!(
                region = region_id,
                error = %e,
                "magicsock.netcheck.probe.parse_failed"
            ),
            Err(_elapsed) => debug!(
                region = region_id,
                %target,
                "magicsock.netcheck.probe.timeout"
            ),
        }
    }

    // Aggregate.
    let derp_latency: HashMap<u16, f64> = probes
        .iter()
        .map(|p| (p.region_id, p.rtt.as_secs_f64()))
        .collect();
    let best = probes
        .iter()
        .min_by_key(|p| p.rtt)
        .cloned();
    let preferred_derp = best.as_ref().map(|p| p.region_id).unwrap_or(0);
    // Separate v4 / v6 reflections: each family has its own NAT mapping
    // (or none for v6, which is end-to-end). Pick the lowest-RTT
    // reflection per family for endpoint advertisement.
    let public_endpoint = probes
        .iter()
        .filter(|p| p.reflected.is_ipv4())
        .min_by_key(|p| p.rtt)
        .map(|p| p.reflected);
    let public_endpoint_v6 = probes
        .iter()
        .filter(|p| p.reflected.is_ipv6())
        .min_by_key(|p| p.rtt)
        .map(|p| p.reflected);

    info!(
        responded = probes.len(),
        attempted = targets.len(),
        preferred_derp,
        public_endpoint = ?public_endpoint,
        public_endpoint_v6 = ?public_endpoint_v6,
        "magicsock.netcheck.done"
    );

    NetcheckReport {
        derp_latency,
        preferred_derp,
        public_endpoint,
        public_endpoint_v6,
        probes,
    }
}

/// Best-effort public-endpoint discovery via well-known third-party
/// STUN servers. Used when `probe_targets` against Tailscale DERPs
/// produces no responses (e.g., Tailscale's IP-history ACL blocks us,
/// or the ISP filters outbound UDP/3478 to DERP IPs).
///
/// Returns the first v4 reflection found. v4-only — for v6 use
/// `discover_public_endpoints_dual`.
pub fn discover_public_endpoint(
    magic: &MagicSocketCtl,
    timeout: Duration,
) -> Option<SocketAddr> {
    discover_one_family(magic, timeout, /* want_v6 = */ false)
}

/// Both-families variant. Returns `(v4, v6)`; either may be `None`.
/// On Vita (no v6 socket) v6 is always None. Use this from the
/// runtime to advertise both reflected endpoints in MapRequest.
pub fn discover_public_endpoints_dual(
    magic: &MagicSocketCtl,
    timeout: Duration,
) -> (Option<SocketAddr>, Option<SocketAddr>) {
    let v4 = discover_one_family(magic, timeout, false);
    let v6 = discover_one_family(magic, timeout, true);
    (v4, v6)
}

fn discover_one_family(
    magic: &MagicSocketCtl,
    timeout: Duration,
    want_v6: bool,
) -> Option<SocketAddr> {
    let family_label = if want_v6 { "v6" } else { "v4" };
    for target_str in PUBLIC_STUN_FALLBACKS {
        // Resolve hostname → SocketAddr for the requested family.
        // Google/Cloudflare/Twilio publish both A and AAAA records.
        let resolved: Option<SocketAddr> = match target_str.to_socket_addrs() {
            Ok(it) => it
                .filter(|a| if want_v6 { a.is_ipv6() } else { a.is_ipv4() })
                .next(),
            Err(e) => {
                debug!(
                    target = *target_str,
                    family = family_label,
                    error = %e,
                    "magicsock.netcheck.fallback.dns_failed"
                );
                None
            }
        };
        let Some(target) = resolved else {
            continue;
        };
        let rx = match magic.stun_probe(target) {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    %target,
                    family = family_label,
                    error = %e,
                    "magicsock.netcheck.fallback.send_failed"
                );
                continue;
            }
        };
        match rx.recv_timeout(timeout) {
            Ok(Ok((reflected, rtt))) => {
                info!(
                    target = *target_str,
                    family = family_label,
                    %target,
                    %reflected,
                    rtt_ms = rtt.as_millis() as u64,
                    "magicsock.netcheck.fallback.ok"
                );
                return Some(reflected);
            }
            Ok(Err(e)) => debug!(
                target = *target_str,
                family = family_label,
                error = %e,
                "magicsock.netcheck.fallback.parse_failed"
            ),
            Err(_elapsed) => debug!(
                target = *target_str,
                family = family_label,
                "magicsock.netcheck.fallback.timeout"
            ),
        }
    }
    // v6 exhaustion is benign on Vita (expected outcome); only warn
    // when v4 is exhausted (real network problem).
    if want_v6 {
        debug!(family = family_label, "magicsock.netcheck.fallback.exhausted");
    } else {
        warn!(family = family_label, "magicsock.netcheck.fallback.exhausted");
    }
    None
}
