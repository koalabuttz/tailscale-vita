//! Tailnet connection-state machine. M9 introduced this in the demo;
//! M10 moves it here so the public `Runtime` API can drive it on
//! behalf of any embedding application.
//!
//! State machine:
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
//! Transitions emit one INFO log per change; a heartbeat fires every
//! 60 s. After 10 minutes Offline, a one-shot WARN diagnostic dump
//! captures last-error context.

use std::time::{Duration, Instant};

use serde::Serialize;
use vita_log::{info, warn};

const DEGRADED_AFTER: Duration = Duration::from_secs(60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const OFFLINE_RECONNECT_THRESHOLD: u32 = 5;
const OFFLINE_DIAG_AFTER: Duration = Duration::from_secs(600);

/// Distinguishes the two terminal failure kinds. Maps onto the
/// corresponding `OnlineState` variant via `mark_fatal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatalKind {
    Auth,
    Security,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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
    /// Auth-fatal terminal state (M13.5): the control plane rejected
    /// our identity (bad / expired / revoked auth-key) and there's no
    /// point retrying. UI should prompt the user to fix `auth_key` in
    /// `config.toml`. Sticky — once entered, no event clears it.
    AuthFailed,
    /// Security-fatal terminal state (M13.5): the server's Noise pub
    /// key changed unexpectedly, or `/key` returned malformed data.
    /// UI should prompt the user to investigate (could be a MITM, or
    /// could be a legitimate rotation requiring `server.pub` reset).
    SecurityFailed,
}

pub struct LifecycleTracker {
    state: OnlineState,
    first_map_event: Option<Instant>,
    first_derp_rx: Option<Instant>,
    last_map_event: Option<Instant>,
    last_derp_rx: Option<Instant>,
    consecutive_control_reconnects: u32,
    consecutive_derp_reconnects: u32,
    last_heartbeat: Option<Instant>,
    offline_since: Option<Instant>,
    offline_diag_fired: bool,
    /// Human-readable explanation for a terminal `AuthFailed` /
    /// `SecurityFailed` state. Empty when state is non-fatal.
    /// Surfaced via `fatal_reason()` so UI / logs / `tailscale status`
    /// can show what happened.
    fatal_reason: Option<String>,
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
            fatal_reason: None,
        }
    }

    pub fn state(&self) -> OnlineState {
        self.state
    }

    /// Reason for a terminal `AuthFailed` / `SecurityFailed` state.
    /// Returns `None` if the current state isn't fatal.
    pub fn fatal_reason(&self) -> Option<&str> {
        self.fatal_reason.as_deref()
    }

    /// Transition to a sticky terminal state (`AuthFailed` or
    /// `SecurityFailed`). After this, `compute_next_state` short-
    /// circuits and returns the same state regardless of events; only
    /// `LifecycleTracker::new()` (i.e., a process restart) clears it.
    pub fn mark_fatal(&mut self, kind: FatalKind, reason: impl Into<String>) {
        let new = match kind {
            FatalKind::Auth => OnlineState::AuthFailed,
            FatalKind::Security => OnlineState::SecurityFailed,
        };
        let reason = reason.into();
        info!(?new, %reason, "lifecycle.fatal");
        self.state = new;
        self.fatal_reason = Some(reason);
    }

    /// Record a control-plane event (any MapResponse, including KeepAlive).
    pub fn record_map_event(&mut self, now: Instant) {
        if self.first_map_event.is_none() {
            self.first_map_event = Some(now);
        }
        self.last_map_event = Some(now);
        self.consecutive_control_reconnects = 0;
    }

    /// Record DERP-side activity. v1 proxy: any region in
    /// `derp_alive_regions().is_empty() == false` counts.
    pub fn record_derp_rx(&mut self, now: Instant) {
        if self.first_derp_rx.is_none() {
            self.first_derp_rx = Some(now);
        }
        self.last_derp_rx = Some(now);
        self.consecutive_derp_reconnects = 0;
    }

    /// Increment the control-plane reconnect counter. M10 Runtime calls
    /// this when MapClient errors out and we re-establish.
    pub fn record_control_reconnect(&mut self) {
        self.consecutive_control_reconnects += 1;
    }

    /// Increment the DERP reconnect counter. M10 Runtime calls this
    /// when a DERP region's I/O thread dies and we re-dial.
    pub fn record_derp_reconnect(&mut self) {
        self.consecutive_derp_reconnects += 1;
    }

    /// Recompute current state. Logs transitions and heartbeats every
    /// `HEARTBEAT_INTERVAL`. Should be called once per outer-loop tick
    /// in the runtime (~2 s cadence is fine).
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
        // Sticky fatal states bypass all other computation. Once we've
        // marked AuthFailed / SecurityFailed, no map event or DERP rx
        // can recover us — only a process restart with corrected
        // config/state can.
        if matches!(
            self.state,
            OnlineState::AuthFailed | OnlineState::SecurityFailed
        ) {
            return self.state;
        }
        if self.consecutive_control_reconnects >= OFFLINE_RECONNECT_THRESHOLD
            || self.consecutive_derp_reconnects >= OFFLINE_RECONNECT_THRESHOLD
        {
            return OnlineState::Offline;
        }
        let have_map = self.first_map_event.is_some();
        let have_derp = self.first_derp_rx.is_some();
        if !have_map || !have_derp {
            return OnlineState::Connecting;
        }
        let most_recent = match (self.last_map_event, self.last_derp_rx) {
            (Some(m), Some(d)) => m.max(d),
            (Some(m), None) => m,
            (None, Some(d)) => d,
            (None, None) => return OnlineState::Connecting,
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

    #[test]
    fn auth_failed_is_sticky_across_recovery_events() {
        let mut lt = LifecycleTracker::new();
        lt.mark_fatal(FatalKind::Auth, "register: MachineAuthorized=false");
        assert_eq!(lt.state(), OnlineState::AuthFailed);
        assert_eq!(
            lt.fatal_reason(),
            Some("register: MachineAuthorized=false")
        );
        // Even a recovery-shaped event sequence shouldn't unstick.
        lt.record_map_event(t(0));
        lt.record_derp_rx(t(0));
        lt.tick(t(0), 0, 1);
        assert_eq!(lt.state(), OnlineState::AuthFailed);
    }

    #[test]
    fn security_failed_is_sticky() {
        let mut lt = LifecycleTracker::new();
        lt.mark_fatal(FatalKind::Security, "server Noise key changed");
        assert_eq!(lt.state(), OnlineState::SecurityFailed);
        lt.record_map_event(t(0));
        lt.tick(t(0), 0, 0);
        assert_eq!(lt.state(), OnlineState::SecurityFailed);
    }
}
