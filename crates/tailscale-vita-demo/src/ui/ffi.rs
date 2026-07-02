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
