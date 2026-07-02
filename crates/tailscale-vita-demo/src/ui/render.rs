//! M17-A S3 — vita2d renderer (vita-only). Maps the pure viewmodel to
//! pixels; owns vita2d init + the PGF font. All layout constants live
//! here. 960×544 screen.

use std::ffi::CString;

use vita_log::{info, warn};

use super::ffi;
use super::viewmodel::{DashVm, Tone};

const fn rgba(r: u8, g: u8, b: u8, a: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16) | ((a as u32) << 24)
}

const BG: u32 = rgba(14, 16, 22, 255);
const CARD: u32 = rgba(24, 27, 36, 255);
const ROW_SEL: u32 = rgba(38, 44, 60, 255);
const RULE: u32 = rgba(52, 58, 76, 255);
const TEXT: u32 = rgba(228, 230, 236, 255);
const TITLE: u32 = rgba(255, 255, 255, 255);
const GOOD: u32 = rgba(96, 220, 130, 255);
const WARN: u32 = rgba(240, 200, 90, 255);
const BAD: u32 = rgba(238, 100, 100, 255);
const DIM: u32 = rgba(120, 126, 140, 255);

const SCREEN_W: f32 = 960.0;
const MARGIN: i32 = 32;
const HEADER_H: f32 = 118.0;
const ROW_H: i32 = 34;
const LIST_TOP: i32 = 156;
const FOOTER_TOP: f32 = 484.0;
/// Peer rows that fit between header and footer.
pub const VIEWPORT_ROWS: usize = ((FOOTER_TOP as i32 - LIST_TOP - 8) / ROW_H) as usize;

fn tone_color(t: Tone) -> u32 {
    match t {
        Tone::Good => GOOD,
        Tone::Warn => WARN,
        Tone::Bad => BAD,
        Tone::Dim => DIM,
        Tone::Normal => TEXT,
    }
}

pub struct Renderer {
    font: *mut ffi::Vita2dPgf,
}

impl Renderer {
    /// vita2d + input init. Must run on the main thread before any
    /// frame; logs `ui.init` with what it got.
    pub fn init() -> Self {
        let (rc, font) = unsafe {
            let rc = ffi::vita2d_init();
            let _ = ffi::sceCtrlSetSamplingMode(ffi::SCE_CTRL_MODE_ANALOG);
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

    pub fn text(&self, x: i32, y: i32, color: u32, scale: f32, s: &str) {
        if self.font.is_null() {
            return;
        }
        let Ok(c) = CString::new(s) else { return };
        unsafe {
            ffi::vita2d_pgf_draw_text(self.font, x, y, color, scale, c.as_ptr());
        }
    }

    fn text_width(&self, scale: f32, s: &str) -> i32 {
        if self.font.is_null() {
            return 0;
        }
        let Ok(c) = CString::new(s) else { return 0 };
        unsafe { ffi::vita2d_pgf_text_width(self.font, scale, c.as_ptr()) }
    }

    fn text_right(&self, right_x: i32, y: i32, color: u32, scale: f32, s: &str) {
        let w = self.text_width(scale, s);
        self.text(right_x - w, y, color, scale, s);
    }

    /// One full dashboard frame.
    pub fn frame(
        &self,
        vm: &DashVm,
        selected: usize,
        window: (usize, usize),
        ping_line: Option<(&str, Tone)>,
        banner: Option<&str>,
    ) {
        self.begin();

        // ── Header card ──
        unsafe {
            ffi::vita2d_draw_rectangle(0.0, 0.0, SCREEN_W, HEADER_H, CARD);
            ffi::vita2d_draw_rectangle(0.0, HEADER_H, SCREEN_W, 2.0, RULE);
        }
        self.text(MARGIN, 44, TITLE, 1.15, &vm.header.title);
        self.text_right(
            (SCREEN_W as i32) - MARGIN,
            44,
            tone_color(vm.header.lifecycle_tone),
            1.15,
            &vm.header.lifecycle,
        );
        self.text(MARGIN, 82, DIM, 0.9, &vm.header.right);
        self.text(MARGIN, 108, tone_color(vm.header.sub_tone), 0.85, &vm.header.sub);

        // ── Stale-data warning strip (last-known peer list stays visible) ──
        if let Some(msg) = banner {
            unsafe {
                ffi::vita2d_draw_rectangle(0.0, HEADER_H + 2.0, SCREEN_W, 26.0, ROW_SEL);
            }
            self.text(MARGIN, (HEADER_H as i32) + 21, WARN, 0.8, msg);
        }

        // ── Peer list ──
        if vm.rows.is_empty() {
            self.text(MARGIN, 260, DIM, 1.0, "no peers in netmap yet");
        } else {
            let (start, end) = window;
            for (slot, idx) in (start..end).enumerate() {
                let row = &vm.rows[idx];
                let y_top = LIST_TOP + (slot as i32) * ROW_H;
                let baseline = y_top + 24;
                if idx == selected {
                    unsafe {
                        ffi::vita2d_draw_rectangle(
                            (MARGIN - 12) as f32,
                            y_top as f32,
                            SCREEN_W - 2.0 * (MARGIN - 12) as f32,
                            ROW_H as f32,
                            ROW_SEL,
                        );
                    }
                }
                let dot = if row.online { GOOD } else { DIM };
                unsafe {
                    ffi::vita2d_draw_fill_circle(
                        (MARGIN + 6) as f32,
                        (y_top + ROW_H / 2) as f32,
                        5.0,
                        dot,
                    );
                }
                let name_color = if row.online { TEXT } else { DIM };
                self.text(MARGIN + 26, baseline, name_color, 0.95, &row.name);
                self.text(MARGIN + 320, baseline, name_color, 0.95, &row.ip);
                self.text(
                    MARGIN + 560,
                    baseline,
                    tone_color(row.path_tone),
                    0.95,
                    &row.path,
                );
            }
            if end < vm.rows.len() {
                self.text(
                    MARGIN + 26,
                    LIST_TOP + (VIEWPORT_ROWS as i32) * ROW_H + 20,
                    DIM,
                    0.8,
                    &format!("... {} more", vm.rows.len() - end),
                );
            }
        }

        // ── Footer ──
        unsafe {
            ffi::vita2d_draw_rectangle(0.0, FOOTER_TOP, SCREEN_W, 2.0, RULE);
        }
        if let Some((line, tone)) = ping_line {
            self.text(MARGIN, (FOOTER_TOP as i32) + 26, tone_color(tone), 0.9, line);
        }
        self.text(
            MARGIN,
            (FOOTER_TOP as i32) + 52,
            tone_color(vm.staleness_tone),
            0.8,
            &vm.staleness,
        );
        self.text_right(
            (SCREEN_W as i32) - MARGIN,
            (FOOTER_TOP as i32) + 52,
            DIM,
            0.8,
            "UP/DOWN select   X ping",
        );

        self.end();
    }

    /// Full-screen banner frames for pre-snapshot states.
    pub fn banner_frame(&self, headline: &str, detail: &str, tone: Tone) {
        self.begin();
        self.text(MARGIN, 220, tone_color(tone), 1.2, headline);
        self.text(MARGIN, 270, DIM, 0.9, detail);
        self.end();
    }
}
