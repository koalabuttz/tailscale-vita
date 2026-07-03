//! M17-A/B/C — dashboard event loop (vita-only). Main-thread render at
//! vblank; tabbed UI (Peers / Settings / Debug) with a peer-detail
//! overlay; input via buttons (edge + D-pad repeat), left stick, and the
//! front touchscreen; UI actions (ping / reconnect / config toggle) run
//! on the worker thread. See docs/PLAN-M17BC.md.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vita_chan::bounded;
use vita_log::info;

use super::client::{self, ActionState, Shared, UiAction};
use super::render::{self, Renderer, VIEWPORT_ROWS};
use super::viewmodel::{self, DashVm, SettingRow, Tab, Tone};
use super::{buttons, ffi};

const REPEAT_FIRST: Duration = Duration::from_millis(250);
const REPEAT_NEXT: Duration = Duration::from_millis(120);
const ACTION_LINE_TTL: Duration = Duration::from_secs(12);
const RUNTIME_HINT_AFTER: Duration = Duration::from_secs(30);
/// Left-stick deflection thresholds (0..255, center 128).
const STICK_UP: u8 = 96;
const STICK_DOWN: u8 = 160;

struct Repeat {
    held_since: Option<Instant>,
    last_fire: Instant,
}
impl Repeat {
    fn new() -> Self {
        Self { held_since: None, last_fire: Instant::now() }
    }
    fn tick(&mut self, held: bool, now: Instant) -> bool {
        if !held {
            self.held_since = None;
            return false;
        }
        match self.held_since {
            None => {
                self.held_since = Some(now);
                self.last_fire = now;
                true
            }
            Some(since) => {
                if now.duration_since(since) < REPEAT_FIRST {
                    return false;
                }
                if now.duration_since(self.last_fire) >= REPEAT_NEXT {
                    self.last_fire = now;
                    true
                } else {
                    false
                }
            }
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn run(exit: &AtomicBool) {
    let renderer = Renderer::init();
    let shared: Arc<Mutex<Shared>> = Shared::new();
    let (action_tx, action_rx) = bounded::<UiAction>(1);
    client::spawn_worker(Arc::clone(&shared), action_rx);

    let started = Instant::now();
    let mut tab = Tab::Peers;
    let mut snapshot: Option<tailscale_vita::RuntimeSnapshot> = None;
    let mut vm: Option<DashVm> = None;
    let mut seen_generation: u64 = 0;

    let mut peers_selected: usize = 0;
    let mut selected_key: Option<(String, String)> = None;
    let mut settings_selected: usize = 0;
    let mut debug_scroll: usize = 0;
    let mut detail_key: Option<String> = None;

    let mut prev_buttons: u32 = 0;
    let mut prev_touch = false;
    let mut rep_up = Repeat::new();
    let mut rep_down = Repeat::new();
    let mut first_frame_logged = false;

    loop {
        if exit.load(Ordering::Relaxed) {
            info!("ui.exit");
            return;
        }
        let now = Instant::now();

        // ── Input: buttons, stick, touch ──
        let pad = unsafe {
            let mut p = std::mem::zeroed::<ffi::SceCtrlData>();
            let _ = ffi::sceCtrlPeekBufferPositive(0, &mut p, 1);
            p
        };
        let pressed = pad.buttons & !prev_buttons;
        prev_buttons = pad.buttons;
        let held_up = pad.buttons & buttons::UP != 0 || pad.ly < STICK_UP;
        let held_down = pad.buttons & buttons::DOWN != 0 || pad.ly > STICK_DOWN;
        let fire_up = rep_up.tick(held_up, now);
        let fire_down = rep_down.tick(held_down, now);

        let touch = read_touch();
        let tap = touch.filter(|_| !prev_touch); // rising edge = a tap
        prev_touch = touch.is_some();

        // ── Pull worker state; rebuild viewmodel on generation change ──
        let (generation, snap_opt, action, last_error, failures, last_ok, ftp_en, ftp_ro) = {
            let s = shared.lock().unwrap_or_else(|p| p.into_inner());
            (
                s.generation,
                if s.generation != seen_generation { s.snapshot.clone() } else { None },
                s.action.clone(),
                s.last_error.clone(),
                s.consecutive_failures,
                s.last_ok_at,
                s.ftp_enabled,
                s.ftp_read_only,
            )
        };
        if generation != seen_generation {
            seen_generation = generation;
            if let Some(snap) = snap_opt {
                vm = Some(viewmodel::build(&snap, now_unix()));
                if let (Some(vm), Some((name, ip))) = (&vm, &selected_key) {
                    if let Some(i) = vm.rows.iter().position(|r| &r.name == name && &r.ip == ip) {
                        peers_selected = i;
                    }
                }
                snapshot = Some(snap);
            }
        }

        let action_idle = !matches!(action, ActionState::InFlight { .. });
        let send = |a: UiAction| {
            if action_idle {
                let _ = action_tx.try_send(a);
            }
        };

        // ── Navigation / actions (overlay captures input when open) ──
        if detail_key.is_some() {
            if pressed & (buttons::CIRCLE | buttons::TRIANGLE | buttons::CROSS) != 0 {
                detail_key = None;
            }
        } else {
            // Tab switch: L/R shoulders (LTRIGGER or L1 — varies by unit),
            // D-pad Left/Right, or a tap on the tab bar.
            if pressed & buttons::TAB_PREV != 0 {
                tab = tab.prev();
            }
            if pressed & buttons::TAB_NEXT != 0 {
                tab = tab.next();
            }
            if let Some((tx, ty)) = tap {
                if let Some(t) = render::tab_at(tx, ty) {
                    tab = t;
                }
            }

            match tab {
                Tab::Peers => {
                    if let Some(vm) = &vm {
                        let len = vm.rows.len();
                        if len > 0 {
                            peers_selected = peers_selected.min(len - 1);
                            if fire_up && peers_selected > 0 {
                                peers_selected -= 1;
                            }
                            if fire_down && peers_selected + 1 < len {
                                peers_selected += 1;
                            }
                            // Touch: tap a peer row to select it.
                            if let Some((_, ty)) = tap {
                                if let Some(slot) = render::peer_slot_at(ty) {
                                    let (start, _) =
                                        viewmodel::scroll_window(len, peers_selected, VIEWPORT_ROWS);
                                    let idx = start + slot;
                                    if idx < len {
                                        peers_selected = idx;
                                    }
                                }
                            }
                            let row = &vm.rows[peers_selected];
                            selected_key = Some((row.name.clone(), row.ip.clone()));
                            if pressed & buttons::CROSS != 0 {
                                if let Some(ip) = row.ping_ip {
                                    send(UiAction::Ping { ip, peer_name: row.name.clone() });
                                }
                            }
                            if pressed & buttons::CIRCLE != 0 {
                                detail_key = Some(row.node_key.clone());
                            }
                        }
                    }
                }
                Tab::Settings => {
                    let n = SettingRow::ALL.len();
                    if fire_up && settings_selected > 0 {
                        settings_selected -= 1;
                    }
                    if fire_down && settings_selected + 1 < n {
                        settings_selected += 1;
                    }
                    if pressed & buttons::CROSS != 0 {
                        match SettingRow::ALL[settings_selected] {
                            SettingRow::FtpEnabled => send(UiAction::ToggleFtp { key: "enabled" }),
                            SettingRow::FtpReadOnly => {
                                send(UiAction::ToggleFtp { key: "read_only" })
                            }
                            SettingRow::Reconnect => send(UiAction::Reconnect),
                        }
                    }
                }
                Tab::Debug => {
                    if fire_down {
                        debug_scroll += 1;
                    }
                    if fire_up {
                        debug_scroll = debug_scroll.saturating_sub(1);
                    }
                }
            }
        }

        // ── Draw ──
        let now_u = now_unix();
        match (&vm, &snapshot) {
            (Some(vm), Some(snap)) => {
                renderer.begin();
                renderer.header(vm, tab);
                let action_line = action_footer(&action);
                match tab {
                    Tab::Peers => {
                        let window =
                            viewmodel::scroll_window(vm.rows.len(), peers_selected, VIEWPORT_ROWS);
                        let banner = (failures >= 3)
                            .then_some("runtime not responding - data is stale");
                        renderer.peers_body(vm, peers_selected, window, banner);
                    }
                    Tab::Settings => {
                        let acl = viewmodel::acl_line(snap);
                        let kx = viewmodel::key_expiry_line(snap, now_u);
                        let rows: Vec<(String, String, Tone)> = SettingRow::ALL
                            .iter()
                            .map(|r| r.render(ftp_en, ftp_ro))
                            .collect();
                        renderer.settings_body(
                            (&acl.0, acl.1),
                            (&kx.0, kx.1),
                            &rows,
                            settings_selected,
                        );
                    }
                    Tab::Debug => {
                        let rows = viewmodel::build_debug_rows(snap, now_u, env!("BUILD_TIMESTAMP"));
                        let max = rows.len().saturating_sub(1);
                        debug_scroll = debug_scroll.min(max);
                        renderer.debug_body(&rows, debug_scroll);
                    }
                }
                let legend = match tab {
                    Tab::Peers => "L/R tab  UP/DN select  X ping  O detail",
                    Tab::Settings => "L/R tab  UP/DN select  X activate",
                    Tab::Debug => "L/R tab  UP/DN scroll",
                };
                renderer.footer(
                    action_line.as_ref().map(|(l, t)| (l.as_str(), *t)),
                    (&vm.staleness, vm.staleness_tone),
                    legend,
                );
                // Peer-detail overlay (any tab).
                if let Some(key) = &detail_key {
                    match viewmodel::peer_detail_lines(snap, key, now_u) {
                        Some(lines) => {
                            let title = lines
                                .iter()
                                .find(|(l, _)| l == "name")
                                .map(|(_, v)| v.clone())
                                .unwrap_or_else(|| "peer".into());
                            renderer.detail_overlay(&title, &lines);
                        }
                        None => detail_key = None, // peer vanished
                    }
                }
                renderer.end();
            }
            _ => {
                let (headline, tone) = if last_ok.is_some() {
                    ("connecting to tailnet...", Tone::Warn)
                } else if started.elapsed() > RUNTIME_HINT_AFTER {
                    ("runtime not detected - is the SUPRX in ur0:tai/config.txt?", Tone::Bad)
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

/// Footer line for the current action state (drops after TTL).
fn action_footer(action: &ActionState) -> Option<(String, Tone)> {
    match action {
        ActionState::Idle => None,
        ActionState::InFlight { label } => Some((label.clone(), Tone::Warn)),
        ActionState::Done { line, ok, at } if at.elapsed() < ACTION_LINE_TTL => {
            Some((line.clone(), if *ok { Tone::Good } else { Tone::Bad }))
        }
        ActionState::Done { .. } => None,
    }
}

/// Poll the front touchscreen; return the first touch mapped to screen
/// pixels (front panel is 2× the screen), or None if nothing is down.
fn read_touch() -> Option<(f32, f32)> {
    let data = unsafe {
        let mut d = std::mem::zeroed::<ffi::SceTouchData>();
        let n = ffi::sceTouchPeek(ffi::SCE_TOUCH_PORT_FRONT, &mut d, 1);
        if n < 1 {
            return None;
        }
        d
    };
    if data.report_num == 0 {
        return None;
    }
    let r = data.report[0];
    Some((r.x as f32 / ffi::TOUCH_SCALE, r.y as f32 / ffi::TOUCH_SCALE))
}
