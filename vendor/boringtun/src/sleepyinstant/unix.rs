// vita-patch: replaced the `nix` dependency with raw libc::clock_gettime.
// `nix-0.31` does not recognize Vita's target_os and fails to compile;
// boringtun only needed nix here, for its TimeSpec wrapper. Going via
// libc directly works on every Unix-like target including Vita.

use std::time::Duration;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd"
))]
const CLOCK_ID: libc::clockid_t = libc::CLOCK_MONOTONIC;
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd"
)))]
const CLOCK_ID: libc::clockid_t = libc::CLOCK_MONOTONIC;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Instant {
    t: libc::timespec,
}

impl Instant {
    pub(crate) fn now() -> Self {
        let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // std::time::Instant unwraps as well, so feel safe doing so here.
        let rc = unsafe { libc::clock_gettime(CLOCK_ID, &mut t) };
        if rc != 0 {
            panic!("clock_gettime failed");
        }
        Self { t }
    }

    fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        const NANOSECOND: libc::c_long = 1_000_000_000;
        let (tv_sec, tv_nsec) = if self.t.tv_nsec < earlier.t.tv_nsec {
            (
                self.t.tv_sec - earlier.t.tv_sec - 1,
                self.t.tv_nsec - earlier.t.tv_nsec + NANOSECOND,
            )
        } else {
            (
                self.t.tv_sec - earlier.t.tv_sec,
                self.t.tv_nsec - earlier.t.tv_nsec,
            )
        };

        if tv_sec < 0 {
            None
        } else {
            Some(Duration::new(tv_sec as _, tv_nsec as _))
        }
    }

    pub(crate) fn duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(Duration::ZERO)
    }
}
