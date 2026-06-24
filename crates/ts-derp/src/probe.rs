//! Home-region selection by parallel TCP-RTT probe.
//!
//! Per PLAN-V1 §"DERP relay protocol" home-region algorithm:
//!
//! 1. TCP-connect-RTT probe each region's first node (host:443 or
//!    `derp_port`) with `DIAL_TIMEOUT` per probe.
//! 2. Pick the lowest RTT.
//! 3. Apply hysteresis: only switch from the cached winner if the new
//!    winner is at least `HOME_SWITCH_FRACTION` (25%) faster.
//! 4. Cache for `HOME_PROBE_CACHE` (5 min) to avoid probe storms.
//!
//! Probes run on short-lived OS threads (one per region). Each thread
//! has a 64 KiB stack since `connect_timeout` doesn't need much.

use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use vita_thread as thread;
use std::time::{Duration, Instant};

use vita_sync::Mutex;
use tracing::{debug, info, warn};

use crate::magic::{DIAL_TIMEOUT, HOME_PROBE_CACHE, HOME_SWITCH_FRACTION};
use crate::{DerpError, DerpMap};

#[derive(Clone, Debug)]
pub struct HomeProbeCache {
    pub region: u16,
    pub rtt: Duration,
    pub measured_at: Instant,
}

#[derive(Default)]
pub struct HomeProbe {
    cache: Arc<Mutex<Option<HomeProbeCache>>>,
}

impl HomeProbe {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pick the home region from `derp_map`. Returns the cached value
    /// if it's still fresh; otherwise probes all regions in parallel.
    pub fn pick_home(&self, derp_map: &DerpMap) -> Result<u16, DerpError> {
        // Cache check (cheap, no probes).
        if let Some(c) = self.cache.lock().clone() {
            if c.measured_at.elapsed() < HOME_PROBE_CACHE
                && derp_map.regions.contains_key(&c.region)
            {
                debug!(region = c.region, age_secs = c.measured_at.elapsed().as_secs(), "derp.probe.cache_hit");
                return Ok(c.region);
            }
        }

        let total = derp_map.regions.len();
        if total == 0 {
            return Err(DerpError::NoReachableRegion {
                probed: 0,
                total: 0,
            });
        }

        info!(total, "derp.probe.start");
        let (tx, rx) = vita_chan::bounded::<(u16, Duration)>(total);
        let mut handles = Vec::with_capacity(total);

        for (region_id, nodes) in &derp_map.regions {
            let Some(node) = nodes.first() else {
                continue;
            };
            let region = *region_id;
            let dial_addr = node.dial_addr();
            let tx = tx.clone();
            let h = thread::Builder::new()
                .name(format!("derp-probe-{region}"))
                .stack_size(64 * 1024)
                .spawn(move || probe_one(region, &dial_addr, &tx))
                .ok();
            if let Some(h) = h {
                handles.push(h);
            } else {
                warn!(region, "derp.probe.thread.spawn_failed");
            }
        }
        drop(tx); // close so rx sees Disconnected once last thread exits

        // Collect with overall budget. DIAL_TIMEOUT + 500 ms slack lets
        // every thread finish.
        let deadline = Instant::now() + DIAL_TIMEOUT + Duration::from_millis(500);
        let mut results: Vec<(u16, Duration)> = Vec::with_capacity(total);
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(r) => results.push(r),
                Err(vita_chan::RecvTimeoutError::Timeout) => {}
                Err(vita_chan::RecvTimeoutError::Disconnected) => break,
            }
        }
        // Best-effort join; threads are short-lived so this rarely blocks.
        for h in handles {
            let _ = h.join();
        }

        if results.is_empty() {
            return Err(DerpError::NoReachableRegion {
                probed: total,
                total,
            });
        }

        results.sort_by_key(|(_, rtt)| *rtt);
        let (winner, rtt) = results[0];

        // Hysteresis.
        let mut cache = self.cache.lock();
        if let Some(prev) = cache.clone() {
            if prev.region != winner {
                let threshold = mul_duration(prev.rtt, HOME_SWITCH_FRACTION);
                if rtt > threshold {
                    debug!(
                        prev_region = prev.region,
                        prev_rtt_ms = prev.rtt.as_millis() as u64,
                        winner,
                        winner_rtt_ms = rtt.as_millis() as u64,
                        "derp.probe.hysteresis.kept_prev"
                    );
                    return Ok(prev.region);
                }
            }
        }
        info!(
            region = winner,
            rtt_ms = rtt.as_millis() as u64,
            probed = results.len(),
            total,
            "derp.probe.winner"
        );
        *cache = Some(HomeProbeCache {
            region: winner,
            rtt,
            measured_at: Instant::now(),
        });
        Ok(winner)
    }

    /// Force-clear the cache (test or operator action).
    pub fn invalidate(&self) {
        *self.cache.lock() = None;
    }

    pub fn cached(&self) -> Option<HomeProbeCache> {
        self.cache.lock().clone()
    }
}

fn probe_one(region: u16, dial_addr: &str, tx: &vita_chan::Sender<(u16, Duration)>) {
    let start = Instant::now();
    let addr = match dial_addr.to_socket_addrs() {
        Ok(mut iter) => match iter.next() {
            Some(a) => a,
            None => {
                debug!(region, dial_addr, "derp.probe.no_socket_addr");
                return;
            }
        },
        Err(e) => {
            debug!(region, dial_addr, error = %e, "derp.probe.resolve_failed");
            return;
        }
    };
    match TcpStream::connect_timeout(&addr, DIAL_TIMEOUT) {
        Ok(_) => {
            let elapsed = start.elapsed();
            let _ = tx.send((region, elapsed));
        }
        Err(e) => {
            debug!(region, dial_addr, error = %e, "derp.probe.tcp_failed");
        }
    }
}

fn mul_duration(d: Duration, factor: f32) -> Duration {
    let nanos = d.as_nanos() as f64 * factor as f64;
    Duration::from_nanos(nanos.round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_starts_empty() {
        let probe = HomeProbe::new();
        assert!(probe.cached().is_none());
    }

    #[test]
    fn empty_map_returns_error() {
        let probe = HomeProbe::new();
        let map = DerpMap::default();
        let r = probe.pick_home(&map);
        assert!(matches!(
            r,
            Err(DerpError::NoReachableRegion { probed: 0, total: 0 })
        ));
    }

    #[test]
    fn mul_duration_quarter() {
        let d = Duration::from_millis(100);
        let q = mul_duration(d, 0.75);
        assert_eq!(q.as_millis(), 75);
    }
}
