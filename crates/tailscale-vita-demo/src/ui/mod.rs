//! M17-A dashboard UI (docs/PLAN-M17A.md).
//!
//! Structure (S2/S3/S4):
//! - `client`    — loopback LocalAPI poller + ping executor (host-buildable)
//! - `viewmodel` — pure snapshot→display transform (host-tested)
//! - `render`    — vita2d drawing (vita-only)
//! - `dashboard` — main-thread event loop: input, selection, frames (vita-only)
//! - `buttons`   — SceCtrl mask helpers (pure)
//! - `ffi`       — vita2d + sceCtrl extern "C" (vita-only)
//!
//! The dashboard is a pure LocalAPI HTTP client over loopback
//! (127.0.0.1:41112) — it never touches the Runtime directly, so it
//! works identically whether the runtime lives in the SUPRX
//! (suprx_host_only) or in this eboot (normal mode).

mod buttons;
mod client;
mod config_edit;
mod qr;
mod timefmt;
mod viewmodel;

#[cfg(target_os = "vita")]
mod dashboard;
#[cfg(target_os = "vita")]
mod ffi;
#[cfg(target_os = "vita")]
mod render;

use std::sync::atomic::AtomicBool;

/// Run the dashboard until `exit` is set (never, in suprx_host_only
/// mode). Must be called on the main thread (vita2d owns the display).
#[cfg(target_os = "vita")]
pub fn run_dashboard(exit: &AtomicBool) {
    dashboard::run(exit);
}

/// Host stub: no screen — just park until `exit`, preserving the old
/// keep-the-process-alive behavior so `cargo test/build` on the host
/// stays green. The demo binary is never actually run on the host.
#[cfg(not(target_os = "vita"))]
pub fn run_dashboard(exit: &AtomicBool) {
    while !exit.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
