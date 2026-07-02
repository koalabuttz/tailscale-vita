//! M17-A/B/C — vita2d renderer (vita-only). Maps the pure viewmodel to
//! pixels; owns vita2d init + the PGF font. Layout constants are `pub`
//! so `dashboard` can hit-test touches against the same rects. 960×544.

use std::ffi::CString;

use vita_log::{info, warn};

use super::ffi;
use super::viewmodel::{DashVm, Tab, Tone};

const fn rgba(r: u8, g: u8, b: u8, a: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16) | ((a as u32) << 24)
}

const BG: u32 = rgba(14, 16, 22, 255);
const CARD: u32 = rgba(24, 27, 36, 255);
const ROW_SEL: u32 = rgba(38, 44, 60, 255);
const TAB_ON: u32 = rgba(48, 96, 200, 255);
const RULE: u32 = rgba(52, 58, 76, 255);
const OVERLAY: u32 = rgba(8, 9, 13, 235);
const TEXT: u32 = rgba(228, 230, 236, 255);
const TITLE: u32 = rgba(255, 255, 255, 255);
const GOOD: u32 = rgba(96, 220, 130, 255);
const WARN: u32 = rgba(240, 200, 90, 255);
const BAD: u32 = rgba(238, 100, 100, 255);
const DIM: u32 = rgba(120, 126, 140, 255);

pub const SCREEN_W: f32 = 960.0;
pub const SCREEN_H: f32 = 544.0;
const MARGIN: i32 = 32;
const HEADER_H: f32 = 128.0;
const ROW_H: i32 = 34;
const LIST_TOP: i32 = 168;
const FOOTER_TOP: f32 = 484.0;
pub const VIEWPORT_ROWS: usize = ((FOOTER_TOP as i32 - LIST_TOP - 8) / ROW_H) as usize;

// Tab bar geometry (inside the header card). Three equal cells.
pub const TAB_Y: f32 = 92.0;
pub const TAB_H: f32 = 30.0;
pub const TAB_COUNT: usize = 3;
pub fn tab_cell_w() -> f32 {
    (SCREEN_W - 2.0 * MARGIN as f32) / TAB_COUNT as f32
}

// Settings rows.
const SET_TOP: i32 = 232;
const SET_ROW_H: i32 = 44;

fn tone_color(t: Tone) -> u32 {
    match t {
        Tone::Good => GOOD,
        Tone::Warn => WARN,
        Tone::Bad => BAD,
        Tone::Dim => DIM,
        Tone::Normal => TEXT,
    }
}

/// Which tab label (if any) a screen-space touch at (x,y) lands on.
pub fn tab_at(x: f32, y: f32) -> Option<Tab> {
    if y < TAB_Y || y > TAB_Y + TAB_H {
        return None;
    }
    let rel = x - MARGIN as f32;
    if rel < 0.0 {
        return None;
    }
    let idx = (rel / tab_cell_w()) as usize;
    Tab::ALL.get(idx).copied()
}

/// Which peer-list slot (0-based, within the current viewport) a touch
/// at (x,y) lands on. `None` if outside the list area.
pub fn peer_slot_at(y: f32) -> Option<usize> {
    let yi = y as i32;
    if yi < LIST_TOP || yi >= LIST_TOP + (VIEWPORT_ROWS as i32) * ROW_H {
        return None;
    }
    Some(((yi - LIST_TOP) / ROW_H) as usize)
}

pub struct Renderer {
    font: *mut ffi::Vita2dPgf,
}

impl Renderer {
    pub fn init() -> Self {
        let (rc, font) = unsafe {
            let rc = ffi::vita2d_init();
            let _ = ffi::sceCtrlSetSamplingMode(ffi::SCE_CTRL_MODE_ANALOG);
            let _ = ffi::sceTouchSetSamplingState(
                ffi::SCE_TOUCH_PORT_FRONT,
                ffi::SCE_TOUCH_SAMPLING_STATE_START,
            );
            ffi::vita2d_set_clear_color(BG);
            (rc, ffi::vita2d_load_default_pgf())
        };
        info!(vita2d_rc = rc, font_loaded = !font.is_null(), "ui.init");
        if font.is_null() {
            warn!("ui.init: default PGF font failed to load — text disabled");
        }
        Self { font }
    }

    pub fn begin(&self) {
        unsafe {
            ffi::vita2d_start_drawing();
            ffi::vita2d_clear_screen();
        }
    }
    pub fn end(&self) {
        unsafe {
            ffi::vita2d_end_drawing();
            ffi::vita2d_swap_buffers(); // vblank wait — yields to runtime threads
        }
    }
    fn rect(&self, x: f32, y: f32, w: f32, h: f32, c: u32) {
        unsafe { ffi::vita2d_draw_rectangle(x, y, w, h, c) };
    }
    pub fn text(&self, x: i32, y: i32, color: u32, scale: f32, s: &str) {
        if self.font.is_null() {
            return;
        }
        let Ok(c) = CString::new(s) else { return };
        unsafe { ffi::vita2d_pgf_draw_text(self.font, x, y, color, scale, c.as_ptr()) };
    }
    fn text_w(&self, scale: f32, s: &str) -> i32 {
        if self.font.is_null() {
            return 0;
        }
        let Ok(c) = CString::new(s) else { return 0 };
        unsafe { ffi::vita2d_pgf_text_width(self.font, scale, c.as_ptr()) }
    }
    fn text_right(&self, right_x: i32, y: i32, color: u32, scale: f32, s: &str) {
        let w = self.text_w(scale, s);
        self.text(right_x - w, y, color, scale, s);
    }

    /// Header card: node line + lifecycle + a sub line + tab bar.
    pub fn header(&self, vm: &DashVm, active: Tab) {
        self.rect(0.0, 0.0, SCREEN_W, HEADER_H, CARD);
        self.rect(0.0, HEADER_H, SCREEN_W, 2.0, RULE);
        self.text(MARGIN, 40, TITLE, 1.15, &vm.header.title);
        self.text_right(
            (SCREEN_W as i32) - MARGIN,
            40,
            tone_color(vm.header.lifecycle_tone),
            1.15,
            &vm.header.lifecycle,
        );
        self.text(MARGIN, 74, tone_color(vm.header.sub_tone), 0.85, &vm.header.sub);

        // Tab bar.
        let cw = tab_cell_w();
        for (i, tab) in Tab::ALL.iter().enumerate() {
            let x = MARGIN as f32 + i as f32 * cw;
            if *tab == active {
                self.rect(x, TAB_Y, cw - 6.0, TAB_H, TAB_ON);
            } else {
                self.rect(x, TAB_Y, cw - 6.0, TAB_H, ROW_SEL);
            }
            let label = tab.label();
            let lw = self.text_w(0.9, label);
            let color = if *tab == active { TITLE } else { DIM };
            self.text(
                (x + (cw - 6.0 - lw as f32) / 2.0) as i32,
                (TAB_Y + 21.0) as i32,
                color,
                0.9,
                label,
            );
        }
    }

    /// Peers tab body. `banner` (Some) draws a stale-data strip above
    /// the list; the last-known list stays visible.
    pub fn peers_body(
        &self,
        vm: &DashVm,
        selected: usize,
        window: (usize, usize),
        banner: Option<&str>,
    ) {
        if let Some(msg) = banner {
            self.rect(0.0, HEADER_H + 2.0, SCREEN_W, 24.0, ROW_SEL);
            self.text(MARGIN, (HEADER_H as i32) + 19, WARN, 0.75, msg);
        }
        if vm.rows.is_empty() {
            self.text(MARGIN, LIST_TOP + 40, DIM, 1.0, "no peers in netmap yet");
            return;
        }
        let (start, end) = window;
        for (slot, idx) in (start..end).enumerate() {
            let row = &vm.rows[idx];
            let y_top = LIST_TOP + (slot as i32) * ROW_H;
            let baseline = y_top + 24;
            if idx == selected {
                self.rect(
                    (MARGIN - 12) as f32,
                    y_top as f32,
                    SCREEN_W - 2.0 * (MARGIN - 12) as f32,
                    ROW_H as f32,
                    ROW_SEL,
                );
            }
            unsafe {
                ffi::vita2d_draw_fill_circle(
                    (MARGIN + 6) as f32,
                    (y_top + ROW_H / 2) as f32,
                    5.0,
                    if row.online { GOOD } else { DIM },
                );
            }
            let nc = if row.online { TEXT } else { DIM };
            self.text(MARGIN + 26, baseline, nc, 0.95, &row.name);
            self.text(MARGIN + 320, baseline, nc, 0.95, &row.ip);
            self.text(MARGIN + 560, baseline, tone_color(row.path_tone), 0.95, &row.path);
        }
        if end < vm.rows.len() {
            self.text(
                MARGIN + 26,
                LIST_TOP + (VIEWPORT_ROWS as i32) * ROW_H + 18,
                DIM,
                0.8,
                &format!("... {} more", vm.rows.len() - end),
            );
        }
    }

    /// Settings tab body: ACL + key-expiry panel, then the toggle rows.
    pub fn settings_body(
        &self,
        acl: (&str, Tone),
        key_expiry: (&str, Tone),
        rows: &[(String, String, Tone)],
        selected: usize,
    ) {
        self.text(MARGIN, 168, tone_color(acl.1), 0.9, acl.0);
        self.text(MARGIN, 198, tone_color(key_expiry.1), 0.9, key_expiry.0);
        for (i, (label, value, tone)) in rows.iter().enumerate() {
            let y_top = SET_TOP + (i as i32) * SET_ROW_H;
            if i == selected {
                self.rect(
                    (MARGIN - 12) as f32,
                    y_top as f32,
                    SCREEN_W - 2.0 * (MARGIN - 12) as f32,
                    SET_ROW_H as f32,
                    ROW_SEL,
                );
            }
            self.text(MARGIN + 8, y_top + 30, TEXT, 1.0, label);
            self.text_right((SCREEN_W as i32) - MARGIN, y_top + 30, tone_color(*tone), 1.0, value);
        }
    }

    /// Debug tab body: label/value rows with a scroll offset.
    pub fn debug_body(&self, rows: &[(String, String, Tone)], scroll: usize) {
        let top = 158;
        let row_h = 30;
        let max_rows = ((FOOTER_TOP as i32 - top) / row_h) as usize;
        for (slot, row) in rows.iter().skip(scroll).take(max_rows).enumerate() {
            let y = top + (slot as i32) * row_h + 22;
            self.text(MARGIN, y, DIM, 0.85, &row.0);
            self.text(MARGIN + 220, y, tone_color(row.2), 0.85, &row.1);
        }
        if scroll + max_rows < rows.len() {
            self.text(MARGIN, (FOOTER_TOP as i32) - 6, DIM, 0.7, "v more");
        }
    }

    /// Modal peer-detail overlay over the current tab.
    pub fn detail_overlay(&self, title: &str, lines: &[(String, String)]) {
        self.rect(60.0, 70.0, SCREEN_W - 120.0, SCREEN_H - 140.0, OVERLAY);
        self.rect(60.0, 70.0, SCREEN_W - 120.0, 3.0, TAB_ON);
        self.text(88, 118, TITLE, 1.2, title);
        for (i, (label, value)) in lines.iter().enumerate() {
            let y = 158 + (i as i32) * 30;
            self.text(88, y, DIM, 0.85, label);
            self.text(300, y, TEXT, 0.85, value);
        }
        self.text(88, (SCREEN_H as i32) - 84, DIM, 0.8, "O / triangle: close");
    }

    /// Footer: action-result line + staleness + legend.
    pub fn footer(&self, action: Option<(&str, Tone)>, staleness: (&str, Tone), legend: &str) {
        self.rect(0.0, FOOTER_TOP, SCREEN_W, 2.0, RULE);
        if let Some((line, tone)) = action {
            self.text(MARGIN, (FOOTER_TOP as i32) + 26, tone_color(tone), 0.9, line);
        }
        self.text(MARGIN, (FOOTER_TOP as i32) + 52, tone_color(staleness.1), 0.8, staleness.0);
        self.text_right((SCREEN_W as i32) - MARGIN, (FOOTER_TOP as i32) + 52, DIM, 0.8, legend);
    }

    /// Full-screen banner for pre-snapshot states.
    pub fn banner_frame(&self, headline: &str, detail: &str, tone: Tone) {
        self.begin();
        self.text(MARGIN, 220, tone_color(tone), 1.2, headline);
        self.text(MARGIN, 270, DIM, 0.9, detail);
        self.end();
    }
}
