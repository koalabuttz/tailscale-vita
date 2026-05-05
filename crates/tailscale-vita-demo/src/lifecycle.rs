//! Per PLAN-V1 §M9: track Vita's connection-to-tailnet state and log
//! transitions. State machine:
//!
//! ```text
//!                        first map_event && first derp_rx
//!         ┌────────────┐ ─────────────────────────────► ┌─────────┐
//!         │ Connecting │                                │ Online  │
//!         └────────────┘                                └─────────┘
//!               ▲                                          │  ▲
//!               │                                          │  │ event
//!               │ event                                    │  │
//!               │                                          ▼  │
//!         ┌────────────┐  5+ control or DERP reconnects ┌──────────┐
//!         │  Offline   │ ◄───────────────────────────── │ Degraded │
//!         └────────────┘                                └──────────┘
//!               │                                          ▲
//!               └──────────────────────────────────────────┘
//!                       no signal in 60 s
//! ```
//!
//! Transitions are emitted at INFO level once per change. A heartbeat
//! line goes out every 60 s while running. After 10 minutes Offline,
//! a WARN-level diagnostic dump fires once.

use std::time::{Duration, Instant};

use tracing::{info, warn};

const DEGRADED_AFTER: Duration = Duration::from_secs(60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const OFFLINE_RECONNECT_THRESHOLD: u32 = 5;
const OFFLINE_DIAG_AFTER: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnlineState {
    /// Initial state — no map event and no DERP rx seen yet.
    Connecting,
    /// First map event AND first DERP rx have both fired. Live.
    Online,
    /// 60+ s without a fresh map event or DERP rx. Conn is suspect
    /// but not yet abandoned.
    Degraded,
    /// 5+ consecutive control or DERP reconnects. We've lost the
    /// path repeatedly.
    Offline,
}

pub struct LifecycleTracker {
    state: OnlineState,
    /// First time we saw a MapEvent of any kind (Snapshot or KeepAlive).
    first_map_event: Option<Instant>,
    /// First time we saw a DERP rx (proxy in v1: alive_regions().len() > 0).
    first_derp_rx: Option<Instant>,
    /// Most recent MapEvent.
    last_map_event: Option<Instant>,
    /// Most recent DERP rx (proxy).
    last_derp_rx: Option<Instant>,
    /// Consecutive control reconnects (cleared on success).
    consecutive_control_reconnects: u32,
    /// Consecutive DERP reconnects (cleared on success).
    consecutive_derp_reconnects: u32,
    /// Last heartbeat-log timestamp.
    last_heartbeat: Option<Instant>,
    /// When we transitioned into Offline. None if never offline.
    offline_since: Option<Instant>,
    /// Whether the 10-min Offline diagnostic has fired (one-shot).
    offline_diag_fired: bool,
}

impl LifecycleTracker {
    pub fn new() -> Self {
        Self {
            state: OnlineState::Connecting,
            first_map_event: None,
            first_derp_rx: None,
            last_map_event: None,
            last_derp_rx: None,
            consecutive_control_reconnects: 0,
            consecutive_derp_reconnects: 0,
            last_heartbeat: None,
            offline_since: None,
            offline_diag_fired: false,
        }
    }

    pub fn state(&self) -> OnlineState {
        self.state
    }

    /// Record a control-plane event (any MapResponse, including KeepAlive).
    pub fn record_map_event(&mut self, now: Instant) {
        if self.first_map_event.is_none() {
            self.first_map_event = Some(now);
        }
        self.last_map_event = Some(now);
        self.consecutive_control_reconnects = 0;
    }

    /// Record DERP-side activity. v1 demo uses
    /// `derp_alive_regions().len() > 0` as a proxy until M10 plumbs a
    /// real per-rx signal.
    pub fn record_derp_rx(&mut self, now: Instant) {
        if self.first_derp_rx.is_none() {
            self.first_derp_rx = Some(now);
        }
        self.last_derp_rx = Some(now);
        self.consecutive_derp_reconnects = 0;
    }

    /// Public API for v1 lifecycle. The M9 demo doesn't drive these
    /// directly (next_event errors propagate via `?` rather than
    /// retrying), but they're used by unit tests to validate the
    /// Offline transition; M10 will wire them at the runtime boundary
    /// when a real reconnect manager is added.
    #[allow(dead_code)]
    pub fn record_control_reconnect(&mut self) {
        self.consecutive_control_reconnects += 1;
    }

    #[allow(dead_code)]
    pub fn record_derp_reconnect(&mut self) {
        self.consecutive_derp_reconnects += 1;
    }

    /// Recompute current state. Logs transitions and emits a heartbeat
    /// every `HEARTBEAT_INTERVAL`. Should be called once per outer-loop
    /// iteration in the demo (~2 s cadence is fine).
    pub fn tick(&mut self, now: Instant, peer_count: usize, alive_regions: usize) {
        let prev = self.state;
        let new = self.compute_next_state(now);
        if new != prev {
            info!(
                ?prev,
                new = ?new,
                first_map_seen = self.first_map_event.is_some(),
                first_derp_seen = self.first_derp_rx.is_some(),
                control_reconnects = self.consecutive_control_reconnects,
                derp_reconnects = self.consecutive_derp_reconnects,
                "lifecycle.transition"
            );
            self.state = new;
            if matches!(new, OnlineState::Offline) {
                self.offline_since = Some(now);
                self.offline_diag_fired = false;
            } else {
                self.offline_since = None;
            }
        }

        // Heartbeat.
        let due = match self.last_heartbeat {
            Some(t) => now.saturating_duration_since(t) >= HEARTBEAT_INTERVAL,
            None => true,
        };
        if due {
            info!(
                state = ?self.state,
                peer_count,
                alive_regions,
                control_reconnects = self.consecutive_control_reconnects,
                derp_reconnects = self.consecutive_derp_reconnects,
                "lifecycle.heartbeat"
            );
            self.last_heartbeat = Some(now);
        }

        // Diag dump after 10 min Offline.
        if let Some(off_since) = self.offline_since {
            if !self.offline_diag_fired
                && now.saturating_duration_since(off_since) >= OFFLINE_DIAG_AFTER
            {
                warn!(
                    offline_secs = now.saturating_duration_since(off_since).as_secs(),
                    control_reconnects = self.consecutive_control_reconnects,
                    derp_reconnects = self.consecutive_derp_reconnects,
                    last_map_seen_secs_ago = self
                        .last_map_event
                        .map(|t| now.saturating_duration_since(t).as_secs())
                        .unwrap_or(0),
                    last_derp_seen_secs_ago = self
                        .last_derp_rx
                        .map(|t| now.saturating_duration_since(t).as_secs())
                        .unwrap_or(0),
                    "lifecycle.offline.diagnostic_dump"
                );
                self.offline_diag_fired = true;
            }
        }
    }

    fn compute_next_state(&self, now: Instant) -> OnlineState {
        // Offline trumps everything.
        if self.consecutive_control_reconnects >= OFFLINE_RECONNECT_THRESHOLD
            || self.consecutive_derp_reconnects >= OFFLINE_RECONNECT_THRESHOLD
        {
            return OnlineState::Offline;
        }

        // Need both signals to leave Connecting.
        let have_map = self.first_map_event.is_some();
        let have_derp = self.first_derp_rx.is_some();
        if !have_map || !have_derp {
            return OnlineState::Connecting;
        }

        // Online vs Degraded based on most recent signal.
        let most_recent = match (self.last_map_event, self.last_derp_rx) {
            (Some(m), Some(d)) => m.max(d),
            (Some(m), None) => m,
            (None, Some(d)) => d,
            (None, None) => return OnlineState::Connecting, // shouldn't happen
        };
        if now.saturating_duration_since(most_recent) > DEGRADED_AFTER {
            OnlineState::Degraded
        } else {
            OnlineState::Online
        }
    }
}

impl Default for LifecycleTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: u64) -> Instant {
        // Tests can't construct an Instant from raw seconds, but they can
        // start from `Instant::now()` and add durations relative to a base.
        // We capture a base once and offset from it.
        static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let base = BASE.get_or_init(Instant::now);
        *base + Duration::from_secs(secs)
    }

    #[test]
    fn starts_connecting() {
        let lt = LifecycleTracker::new();
        assert_eq!(lt.state(), OnlineState::Connecting);
    }

    #[test]
    fn connecting_to_online_on_both_signals() {
        let mut lt = LifecycleTracker::new();
        lt.record_map_event(t(0));
        lt.tick(t(0), 0, 0);
        assert_eq!(lt.state(), OnlineState::Connecting);

        lt.record_derp_rx(t(1));
        lt.tick(t(1), 0, 1);
        assert_eq!(lt.state(), OnlineState::Online);
    }

    #[test]
    fn online_to_degraded_after_60s_no_signal() {
        let mut lt = LifecycleTracker::new();
        lt.record_map_event(t(0));
        lt.record_derp_rx(t(0));
        lt.tick(t(0), 0, 1);
        assert_eq!(lt.state(), OnlineState::Online);

        lt.tick(t(61), 0, 1);
        assert_eq!(lt.state(), OnlineState::Degraded);
    }

    #[test]
    fn degraded_back_to_online_on_event() {
        let mut lt = LifecycleTracker::new();
        lt.record_map_event(t(0));
        lt.record_derp_rx(t(0));
        lt.tick(t(0), 0, 1);
        lt.tick(t(61), 0, 1);
        assert_eq!(lt.state(), OnlineState::Degraded);

        lt.record_map_event(t(62));
        lt.tick(t(62), 0, 1);
        assert_eq!(lt.state(), OnlineState::Online);
    }

    #[test]
    fn offline_after_5_control_reconnects() {
        let mut lt = LifecycleTracker::new();
        lt.record_map_event(t(0));
        lt.record_derp_rx(t(0));
        lt.tick(t(0), 0, 1);
        for _ in 0..5 {
            lt.record_control_reconnect();
        }
        lt.tick(t(1), 0, 1);
        assert_eq!(lt.state(), OnlineState::Offline);
    }

    #[test]
    fn offline_after_5_derp_reconnects() {
        let mut lt = LifecycleTracker::new();
        lt.record_map_event(t(0));
        lt.record_derp_rx(t(0));
        lt.tick(t(0), 0, 1);
        for _ in 0..5 {
            lt.record_derp_reconnect();
        }
        lt.tick(t(1), 0, 1);
        assert_eq!(lt.state(), OnlineState::Offline);
    }

    #[test]
    fn successful_event_clears_reconnect_counter() {
        let mut lt = LifecycleTracker::new();
        for _ in 0..4 {
            lt.record_control_reconnect();
        }
        lt.record_map_event(t(0));
        // Counter cleared by record_map_event.
        for _ in 0..4 {
            lt.record_control_reconnect();
        }
        lt.tick(t(1), 0, 1);
        assert_ne!(lt.state(), OnlineState::Offline);
    }

    #[test]
    fn offline_diag_dump_fires_at_10min() {
        let mut lt = LifecycleTracker::new();
        for _ in 0..5 {
            lt.record_control_reconnect();
        }
        lt.tick(t(0), 0, 0);
        assert_eq!(lt.state(), OnlineState::Offline);
        assert!(!lt.offline_diag_fired);

        lt.tick(t(599), 0, 0);
        assert!(!lt.offline_diag_fired);

        lt.tick(t(600), 0, 0);
        assert!(lt.offline_diag_fired);
    }
}
