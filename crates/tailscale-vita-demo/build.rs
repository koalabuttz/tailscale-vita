use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Format as ISO-ish without pulling chrono. Day-resolution is fine; we
    // include the unix timestamp for sub-second uniqueness across rebuilds
    // in the same minute.
    let secs_per_day = 86400u64;
    let days = now / secs_per_day;
    let secs_today = now % secs_per_day;
    let h = secs_today / 3600;
    let m = (secs_today % 3600) / 60;
    let s = secs_today % 60;
    // Days since 1970-01-01. Skip a real Gregorian conversion; we just want a
    // monotonic string. Output looks like: "20180.18:48:32" — readable enough.
    println!("cargo::rustc-env=BUILD_TIMESTAMP={}.{:02}:{:02}:{:02}", days, h, m, s);
    println!("cargo::rustc-env=BUILD_UNIX={}", now);
    println!("cargo::rerun-if-changed=src");
}
