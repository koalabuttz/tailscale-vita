//! Thread-spawn shim that works in both eboot (std::thread backend)
//! and SUPRX (SCE primitives backend) contexts on the Vita.
//!
//! Why this exists: the SUPRX has a statically-linked copy of
//! libpthread that conflicts with the eboot's copy when both try to
//! initialize (separate `pte_processInitialized` flags + reent_list
//! arrays, shared TLS slot 0x89). pthread_init() called from the
//! SUPRX crashes silently. See `docs/SUPRX-PTHREAD-INVESTIGATION.md`
//! for the full root-cause analysis.
//!
//! The fix is to never call into libc-pthread from the SUPRX. This
//! crate provides a `Builder` API that mirrors `std::thread::Builder`
//! but is `cfg`-gated:
//!
//! - `cfg(target_os = "vita")` → SCE backend. Uses
//!   `sceKernelCreateThread` + `sceKernelStartThread` directly, no
//!   pthread involvement.
//! - `cfg(not(target_os = "vita"))` → std::thread wrapper. Same
//!   behavior as before — tests + host_diagnostic stay working.
//!
//! Spawn-site migration is mechanical: replace
//! `std::thread::Builder::new()` with `vita_thread::Builder::new()`.

use std::io;

#[cfg(target_os = "vita")]
mod vita;
#[cfg(target_os = "vita")]
use vita as imp;

#[cfg(not(target_os = "vita"))]
mod host;
#[cfg(not(target_os = "vita"))]
use host as imp;

/// Builder for a thread, mirroring `std::thread::Builder`'s API for the
/// subset of features used in this workspace.
#[derive(Default, Debug)]
pub struct Builder {
    name: Option<String>,
    stack_size: Option<usize>,
}

impl Builder {
    /// New unset Builder. Defaults: no name, backend's default stack
    /// (typically 256 KiB on Vita, ~2 MiB on host).
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn stack_size(mut self, size: usize) -> Self {
        self.stack_size = Some(size);
        self
    }

    /// Spawn the closure on a fresh thread. Returns a `JoinHandle`
    /// that the caller can `.join()` to block until completion.
    ///
    /// The closure is wrapped so it never propagates a panic out
    /// to the SCE thread entry — on panic the thread simply exits
    /// (matches std::thread's "unwind to the entry" behavior).
    pub fn spawn<F>(self, f: F) -> io::Result<JoinHandle>
    where
        F: FnOnce() + Send + 'static,
    {
        imp::spawn(self.name, self.stack_size, f).map(JoinHandle)
    }
}

/// Joinable handle for a spawned thread. Dropping it without joining
/// detaches the thread (matches `std::thread::JoinHandle::drop`).
///
/// On the Vita backend, detached threads continue running until they
/// exit naturally; the SCE thread handle leaks until the surrounding
/// process exits (SUPRX unload). In practice every spawn site in
/// this workspace stores the handle and joins in Drop, so leaks
/// don't accumulate.
pub struct JoinHandle(imp::Handle);

impl JoinHandle {
    /// Block until the spawned thread finishes. Returns an error if
    /// the underlying join primitive fails (SCE error code or
    /// panicked-thread on host).
    pub fn join(self) -> io::Result<()> {
        imp::join(self.0)
    }

    /// True if the thread has finished executing. Non-blocking check.
    /// Matches `std::thread::JoinHandle::is_finished`.
    pub fn is_finished(&self) -> bool {
        imp::is_finished(&self.0)
    }
}

/// Sleep the current thread for `dur`. Wraps the backend's sleep
/// primitive (`sceKernelDelayThread` on Vita, `nanosleep` on host).
/// Neither path involves pthread, so this is SUPRX-safe.
pub fn sleep(dur: std::time::Duration) {
    imp::sleep(dur);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn spawn_and_join_returns_ok() {
        let handle = Builder::new()
            .name("test-roundtrip")
            .stack_size(64 * 1024)
            .spawn(|| {})
            .unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn closure_captures_arc() {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_cloned = Arc::clone(&flag);
        let handle = Builder::new()
            .name("test-arc")
            .spawn(move || {
                flag_cloned.store(true, Ordering::Release);
            })
            .unwrap();
        handle.join().unwrap();
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn dropped_handle_thread_still_runs() {
        // Detach semantics: dropping the JoinHandle without join
        // doesn't kill the thread.
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cloned = Arc::clone(&counter);
        let handle = Builder::new()
            .name("test-detach")
            .spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                counter_cloned.fetch_add(1, Ordering::Release);
            })
            .unwrap();
        drop(handle);
        // Give the thread time to run.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(counter.load(Ordering::Acquire), 1);
    }

    #[test]
    fn nested_spawn() {
        // Spawning from inside another spawn — verifies the closure
        // marshalling doesn't have a "first spawn only" assumption.
        let depth = Arc::new(AtomicUsize::new(0));
        let outer_depth = Arc::clone(&depth);
        let outer = Builder::new()
            .name("outer")
            .spawn(move || {
                outer_depth.fetch_add(1, Ordering::Release);
                let inner_depth = Arc::clone(&outer_depth);
                let inner = Builder::new()
                    .name("inner")
                    .spawn(move || {
                        inner_depth.fetch_add(1, Ordering::Release);
                    })
                    .unwrap();
                inner.join().unwrap();
            })
            .unwrap();
        outer.join().unwrap();
        assert_eq!(depth.load(Ordering::Acquire), 2);
    }

    #[test]
    fn stack_size_respected() {
        // 1 MiB stack — would overflow a tiny default stack but
        // succeeds with our request. Doesn't *verify* the SCE backend
        // honors stack_size (impossible from host) but confirms the
        // Builder API path doesn't drop the argument.
        let handle = Builder::new()
            .name("test-stack")
            .stack_size(1024 * 1024)
            .spawn(|| {
                let big: [u8; 256 * 1024] = [0u8; 256 * 1024];
                std::hint::black_box(big);
            })
            .unwrap();
        handle.join().unwrap();
    }
}
