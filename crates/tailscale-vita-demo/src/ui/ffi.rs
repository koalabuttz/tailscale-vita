//! Hand-rolled `extern "C"` bindings for the S1 spike — vita2d (2D GPU
//! renderer, prebuilt in VitaSDK) + sceCtrl input. House FFI pattern
//! per crates/vita-fs/src/vita.rs: no `#[link]` attrs; symbols resolve
//! from the link line emitted by this crate's build.rs.
//!
//! Signatures verified against $VITASDK/arm-vita-eabi/include/vita2d.h
//! and psp2/ctrl.h + psp2common/ctrl.h at authoring time.

#![allow(dead_code)]

use std::ffi::{c_char, c_float, c_int, c_uint};

/// Opaque `vita2d_pgf` font handle.
#[repr(C)]
pub struct Vita2dPgf {
    _private: [u8; 0],
}

extern "C" {
    pub fn vita2d_init() -> c_int;
    pub fn vita2d_fini() -> c_int;
    pub fn vita2d_wait_rendering_done();
    pub fn vita2d_clear_screen();
    pub fn vita2d_swap_buffers();
    pub fn vita2d_start_drawing();
    pub fn vita2d_end_drawing();
    pub fn vita2d_set_clear_color(color: c_uint);
    pub fn vita2d_draw_rectangle(x: c_float, y: c_float, w: c_float, h: c_float, color: c_uint);
    pub fn vita2d_draw_fill_circle(x: c_float, y: c_float, radius: c_float, color: c_uint);

    /// Loads the Vita system font (ScePgf). NULL on failure.
    pub fn vita2d_load_default_pgf() -> *mut Vita2dPgf;
    pub fn vita2d_free_pgf(font: *mut Vita2dPgf);
    pub fn vita2d_pgf_draw_text(
        font: *mut Vita2dPgf,
        x: c_int,
        y: c_int,
        color: c_uint,
        scale: c_float,
        text: *const c_char,
    ) -> c_int;
    pub fn vita2d_pgf_text_width(font: *mut Vita2dPgf, scale: c_float, text: *const c_char)
        -> c_int;
}

/// psp2common/ctrl.h `SceCtrlData` — exactly 0x20 bytes (the header
/// carries a `VITASDK_BUILD_ASSERT_EQ(0x20, SceCtrlData)`; the mirror
/// assert below keeps our layout honest).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SceCtrlData {
    pub time_stamp: u64,
    /// Bit mask of `SceCtrlButtons` (see `super::buttons`).
    pub buttons: u32,
    pub lx: u8,
    pub ly: u8,
    pub rx: u8,
    pub ry: u8,
    /// Header calls these reserved (per-button fields exist only on
    /// the Ext variants); unused by the dashboard — layout padding.
    pub reserved_buttons: [u8; 12],
    pub reserved: [u8; 4],
}

const _: () = assert!(std::mem::size_of::<SceCtrlData>() == 0x20);

pub const SCE_CTRL_MODE_ANALOG: c_int = 1;

extern "C" {
    pub fn sceCtrlSetSamplingMode(mode: c_int) -> c_int;
    pub fn sceCtrlPeekBufferPositive(port: c_int, pad_data: *mut SceCtrlData, count: c_int)
        -> c_int;
}

// ── Front touchscreen (psp2/touch.h) ──
// Front-panel logical resolution is 1920×1088 = exactly 2× the 960×544
// screen, so touch→screen is a flat divide-by-2 (see `TOUCH_SCALE`).

pub const SCE_TOUCH_PORT_FRONT: u32 = 0;
pub const SCE_TOUCH_SAMPLING_STATE_START: c_int = 1;
pub const SCE_TOUCH_MAX_REPORT: usize = 8;
/// Front-panel coord → screen pixel divisor.
pub const TOUCH_SCALE: f32 = 2.0;

/// psp2/touch.h `SceTouchReport` — 0x10 bytes (header asserts it).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SceTouchReport {
    pub id: u8,
    pub force: u8,
    pub x: i16,
    pub y: i16,
    pub reserved: [u8; 8],
    pub info: u16,
}

/// psp2/touch.h `SceTouchData` — 0x90 bytes (header asserts it).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SceTouchData {
    pub time_stamp: u64,
    pub status: u32,
    pub report_num: u32,
    pub report: [SceTouchReport; SCE_TOUCH_MAX_REPORT],
}

const _: () = assert!(std::mem::size_of::<SceTouchReport>() == 0x10);
const _: () = assert!(std::mem::size_of::<SceTouchData>() == 0x90);

extern "C" {
    /// `port` is SceUInt32; `state` is a C enum (int width).
    pub fn sceTouchSetSamplingState(port: c_uint, state: c_int) -> c_int;
    pub fn sceTouchPeek(port: c_uint, data: *mut SceTouchData, n_bufs: c_uint) -> c_int;
}
