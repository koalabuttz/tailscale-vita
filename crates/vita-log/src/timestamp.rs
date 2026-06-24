//! Backend-gated timestamp formatter.
//!
//! On Vita: `sceKernelGetProcessTimeWide` returns microseconds since
//! process start. We format as `[s.usec]` — monotonic, allocation-
//! free aside from the result String. No `_REENT` touch.
//!
//! On host: `OffsetDateTime::now_utc()` formatted as ISO 8601 — the
//! original behavior, preserved so unit tests + host_diagnostic logs
//! remain human-readable wall-clock timestamps.

#[cfg(target_os = "vita")]
pub(crate) fn format() -> String {
    extern "C" {
        fn sceKernelGetProcessTimeWide() -> u64;
    }
    // SAFETY: no preconditions.
    let usecs = unsafe { sceKernelGetProcessTimeWide() };
    let secs = usecs / 1_000_000;
    let frac = usecs % 1_000_000;
    format!("[{secs:>5}.{frac:06}]")
}

#[cfg(not(target_os = "vita"))]
pub(crate) fn format() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "?".into())
}
