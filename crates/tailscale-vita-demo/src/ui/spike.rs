//! S1 spike render loop (vita-only). Draws build info + frame counter
//! and echoes held buttons — nothing else. Its whole job is to prove
//! on hardware that (a) the build.rs link plumbing produced a working
//! vita2d, (b) GXM init coexists with the live SUPRX in this process,
//! (c) sceCtrl input reads. See docs/PLAN-M17A.md §S1.

use std::ffi::CString;

use vita_log::{info, warn};

use super::buttons;
use super::ffi;

/// vita2d colors are RGBA8 packed little-endian: R | G<<8 | B<<16 | A<<24.
const fn rgba(r: u8, g: u8, b: u8, a: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16) | ((a as u32) << 24)
}

const BG: u32 = rgba(14, 16, 22, 255);
const TITLE: u32 = rgba(96, 220, 130, 255);
const TEXT: u32 = rgba(228, 230, 236, 255);
const ACCENT: u32 = rgba(240, 200, 90, 255);
const DIM: u32 = rgba(120, 126, 140, 255);

pub fn run() -> ! {
    let (init_rc, font) = unsafe {
        let rc = ffi::vita2d_init();
        let _ = ffi::sceCtrlSetSamplingMode(ffi::SCE_CTRL_MODE_ANALOG);
        ffi::vita2d_set_clear_color(BG);
        let font = ffi::vita2d_load_default_pgf();
        (rc, font)
    };
    info!(
        vita2d_rc = init_rc,
        font_loaded = !font.is_null(),
        "ui.init"
    );
    if font.is_null() {
        // Screen would be text-less; keep running so the colored clear
        // still proves GXM works, and the log carries the failure.
        warn!("ui.init: default PGF font failed to load — text disabled");
    }

    let mut frame: u64 = 0;
    loop {
        let pad = unsafe {
            let mut pad = std::mem::zeroed::<ffi::SceCtrlData>();
            let _ = ffi::sceCtrlPeekBufferPositive(0, &mut pad, 1);
            pad
        };

        unsafe {
            ffi::vita2d_start_drawing();
            ffi::vita2d_clear_screen();
        }
        draw(font, 40, 60, TITLE, 1.1, "tailscale-vita — M17-A S1 render spike");
        draw(
            font,
            40,
            110,
            TEXT,
            1.0,
            &format!("build  {}", env!("BUILD_TIMESTAMP")),
        );
        draw(font, 40, 150, TEXT, 1.0, &format!("frame  {frame}"));
        let held = buttons::names(pad.buttons);
        draw(font, 40, 190, ACCENT, 1.0, &format!("held   [{held}]"));
        draw(
            font,
            40,
            500,
            DIM,
            0.85,
            "eboot render loop only — the SUPRX runtime is untouched",
        );
        unsafe {
            ffi::vita2d_end_drawing();
            ffi::vita2d_swap_buffers(); // blocks on vblank → yields to runtime threads
        }

        if frame == 0 {
            info!("ui.frame.first");
        }
        frame = frame.wrapping_add(1);
    }
}

fn draw(font: *mut ffi::Vita2dPgf, x: i32, y: i32, color: u32, scale: f32, text: &str) {
    if font.is_null() {
        return;
    }
    // PGF wants NUL-terminated text; our strings never contain NUL.
    let Ok(c) = CString::new(text) else { return };
    unsafe {
        ffi::vita2d_pgf_draw_text(font, x, y, color, scale, c.as_ptr());
    }
}
