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
use std::net::SocketAddr;
use std::time::Duration;

use crossbeam_channel::Receiver;
use tracing::{debug, info, warn};

use crate::{MagicSocketCtl, StunResult};

/// Default timeout per probe. Long enough for a slow round-trip,
/// short enough to fail fast.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Standard STUN UDP port. All Tailscale DERP servers run STUN here.
pub const STUN_PORT: u16 = 3478;

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
    /// Our public-mapped UDP endpoint as seen by the STUN servers.
    /// `None` if no probe responded. If multiple probes returned
    /// different reflected addresses (= cone NAT vs symmetric NAT),
    /// we pick the lowest-RTT region's reflection — best chance of
    /// being the path peers will actually direct-connect to.
    pub public_endpoint: Option<SocketAddr>,
    /// All raw per-region results, in the order responses arrived.
    pub probes: Vec<RegionProbe>,
}

/// Identifying info for one DERP region's STUN probe target. Caller
/// supplies these (typically derived from the netmap's DERPMap).
#[derive(Debug, Clone)]
pub struct StunTarget {
    pub region_id: u16,
    pub ipv4_addr: SocketAddr,
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

    // Launch all probes; collect (region_id, target, receiver) tuples.
    let mut inflight: Vec<(u16, SocketAddr, Receiver<StunResult>)> = Vec::new();
    for t in targets {
        match magic.stun_probe(t.ipv4_addr) {
            Ok(rx) => inflight.push((t.region_id, t.ipv4_addr, rx)),
            Err(e) => warn!(
                region = t.region_id,
                target = %t.ipv4_addr,
                error = %e,
                "magicsock.netcheck.probe.send_failed"
            ),
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
    let public_endpoint = best.as_ref().map(|p| p.reflected);

    info!(
        responded = probes.len(),
        attempted = targets.len(),
        preferred_derp,
        public_endpoint = ?public_endpoint,
        "magicsock.netcheck.done"
    );

    NetcheckReport {
        derp_latency,
        preferred_derp,
        public_endpoint,
        probes,
    }
}
