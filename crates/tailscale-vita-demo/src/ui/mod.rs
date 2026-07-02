//! M17-A dashboard UI (docs/PLAN-M17A.md).
//!
//! S1 — render+input spike: prove that vita2d + sceCtrl link into the
//! eboot and run alongside the live SUPRX (which owns the runtime in
//! this same process) before any real UI exists. The spike replaces
//! the `suprx_host_only` sleep-forever loop with: clear screen, draw
//! build info + frame counter, echo held buttons, swap at vblank.
//!
//! The render loop lives on the eboot's main thread; `vita2d_swap_buffers`
//! blocks on vblank, which yields the CPU to the SUPRX's runtime
//! threads — the S1 success criterion includes the tailnet staying
//! reachable while this loop runs.

mod buttons;

#[cfg(target_os = "vita")]
mod ffi;
#[cfg(target_os = "vita")]
mod spike;

/// Host builds keep the old host-the-SUPRX behavior (sleep forever) so
/// `cargo test --workspace` stays green — the demo binary is never run
/// on the host, but it must always compile there.
#[cfg(not(target_os = "vita"))]
mod spike {
    pub fn run() -> ! {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}

/// Run the S1 spike loop. Never returns.
pub fn run_spike() -> ! {
    spike::run()
}
