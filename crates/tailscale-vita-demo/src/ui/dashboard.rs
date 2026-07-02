//! M17-A S3/S4 — the dashboard event loop (vita-only). Main-thread
//! render at vblank; input with edge-detection + D-pad key-repeat;
//! viewmodel rebuilt only when the poller's generation moves.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vita_chan::bounded;
use vita_log::info;

use super::client::{self, PingRequest, PingState, Shared};
use super::render::{Renderer, VIEWPORT_ROWS};
use super::viewmodel::{self, DashVm, Tone};
use super::{buttons, ffi};

const REPEAT_FIRST: Duration = Duration::from_millis(250);
const REPEAT_NEXT: Duration = Duration::from_millis(120);
/// How long a finished ping result stays in the footer.
const PING_LINE_TTL: Duration = Duration::from_secs(12);
/// After this long with zero successful polls, hint at the SUPRX.
const RUNTIME_HINT_AFTER: Duration = Duration::from_secs(30);

/// D-pad auto-repeat state for one direction.
struct Repeat {
    held_since: Option<Instant>,
    last_fire: Instant,
}

impl Repeat {
    fn new() -> Self {
        Self {
            held_since: None,
            last_fire: Instant::now(),
        }
    }

    /// Returns true when the action should fire this frame.
    fn tick(&mut self, held: bool, now: Instant) -> bool {
        if !held {
            self.held_since = None;
            return false;
        }
        match self.held_since {
            None => {
                self.held_since = Some(now);
                self.last_fire = now;
                true // fire immediately on press
            }
            Some(since) => {
                let due = if now.duration_since(since) < REPEAT_FIRST {
                    return false;
                } else {
                    REPEAT_NEXT
                };
                if now.duration_since(self.last_fire) >= due {
                    self.last_fire = now;
                    true
                } else {
                    false
                }
            }
        }
    }
}

pub fn run(exit: &AtomicBool) {
    let renderer = Renderer::init();

    let shared: Arc<Mutex<Shared>> = Shared::new();
    // bounded(1): at most one queued ping; the UI refuses to queue more
    // while one is in flight anyway.
    let (ping_tx, ping_rx) = bounded::<PingRequest>(1);
    client::spawn_poller(Arc::clone(&shared), ping_rx);

    let started = Instant::now();
    let mut vm: Option<DashVm> = None;
    let mut seen_generation: u64 = 0;
    let mut selected: usize = 0;
    // Selection identity: rows re-sort on every snapshot (a peer coming
    // online shifts positions), so a bare index would silently retarget
    // — and X would ping the wrong peer. Track (name, ip) and re-locate
    // after each viewmodel rebuild.
    let mut selected_key: Option<(String, String)> = None;
    let mut prev_buttons: u32 = 0;
    let mut rep_up = Repeat::new();
    let mut rep_down = Repeat::new();
    let mut first_frame_logged = false;

    loop {
        if exit.load(Ordering::Relaxed) {
            info!("ui.exit");
            return;
        }
        let now = Instant::now();

        // ── Input ──
        let pad = unsafe {
            let mut pad = std::mem::zeroed::<ffi::SceCtrlData>();
            let _ = ffi::sceCtrlPeekBufferPositive(0, &mut pad, 1);
            pad
        };
        let pressed = pad.buttons & !prev_buttons;
        prev_buttons = pad.buttons;

        // ── Poll shared state; rebuild the viewmodel on change ──
        let (generation, snapshot, ping, last_error, failures, last_ok) = {
            let s = shared.lock().unwrap_or_else(|p| p.into_inner());
            (
                s.generation,
                if s.generation != seen_generation {
                    s.snapshot.clone()
                } else {
                    None
                },
                s.ping.clone(),
                s.last_error.clone(),
                s.consecutive_failures,
                s.last_ok_at,
            )
        };
        if generation != seen_generation {
            seen_generation = generation;
            if let Some(snap) = snapshot {
                vm = Some(viewmodel::build(&snap, now_unix()));
                // Re-locate the selected peer in the re-sorted rows.
                if let (Some(vm), Some((name, ip))) = (&vm, &selected_key) {
                    if let Some(i) = vm
                        .rows
                        .iter()
                        .position(|r| &r.name == name && &r.ip == ip)
                    {
                        selected = i;
                    }
                }
            }
        }

        // ── Navigation + ping action ──
        if let Some(vm) = &vm {
            let len = vm.rows.len();
            if len > 0 {
                selected = selected.min(len - 1);
                if rep_up.tick(pad.buttons & buttons::UP != 0, now) && selected > 0 {
                    selected -= 1;
                }
                if rep_down.tick(pad.buttons & buttons::DOWN != 0, now) && selected + 1 < len {
                    selected += 1;
                }
                let row = &vm.rows[selected];
                selected_key = Some((row.name.clone(), row.ip.clone()));
                if pressed & buttons::CROSS != 0 {
                    let idle = !matches!(ping, PingState::InFlight { .. });
                    if idle {
                        let row = &vm.rows[selected];
                        if let Some(ip) = row.ping_ip {
                            let _ = ping_tx.try_send(PingRequest {
                                ip,
                                peer_name: row.name.clone(),
                            });
                        }
                    }
                }
            }
        }

        // ── Draw ──
        match &vm {
            Some(vm) => {
                let window = viewmodel::scroll_window(vm.rows.len(), selected, VIEWPORT_ROWS);
                let ping_line = match &ping {
                    PingState::Idle => None,
                    PingState::InFlight { peer_name } => {
                        Some((format!("pinging {peer_name}..."), Tone::Warn))
                    }
                    PingState::Done { line, ok, at } if at.elapsed() < PING_LINE_TTL => {
                        Some((line.clone(), if *ok { Tone::Good } else { Tone::Bad }))
                    }
                    PingState::Done { .. } => None,
                };
                // Poll failures after we HAVE a snapshot → show stale data
                // plus a warning banner rather than blanking the screen.
                let banner = (failures >= 3).then(|| "runtime not responding - data is stale");
                renderer.frame(
                    vm,
                    selected,
                    window,
                    ping_line.as_ref().map(|(l, t)| (l.as_str(), *t)),
                    banner,
                );
            }
            None => {
                // No snapshot yet: cold start, runtime still booting, or
                // the SUPRX never loaded.
                let (headline, tone) = if last_ok.is_some() {
                    ("connecting to tailnet...", Tone::Warn)
                } else if started.elapsed() > RUNTIME_HINT_AFTER {
                    (
                        "runtime not detected - is the SUPRX in ur0:tai/config.txt?",
                        Tone::Bad,
                    )
                } else {
                    ("waiting for runtime (SUPRX)...", Tone::Warn)
                };
                let detail = last_error.unwrap_or_else(|| "starting".into());
                renderer.banner_frame(headline, &detail, tone);
            }
        }

        if !first_frame_logged {
            info!("ui.frame.first");
            first_frame_logged = true;
        }
    }
}

/// Wall-clock unix seconds (device RTC).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
