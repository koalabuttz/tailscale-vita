use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Build timestamp baked into the ALIVE log line — same scheme as the
    // demo's build.rs (day-count.ISO-ish; monotonic, chrono-free).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs_per_day = 86400u64;
    let days = now / secs_per_day;
    let secs_today = now % secs_per_day;
    let h = secs_today / 3600;
    let m = (secs_today % 3600) / 60;
    let s = secs_today % 60;
    println!("cargo::rustc-env=BUILD_TIMESTAMP={}.{:02}:{:02}:{:02}", days, h, m, s);
    println!("cargo::rustc-env=BUILD_UNIX={}", now);
    // Nonexistent path ⇒ cargo reruns this script every build, so dep-crate
    // edits can't produce a stale BUILD_UNIX (lesson from the demo, M14C).
    println!("cargo::rerun-if-changed=NONEXISTENT_FORCE_RERUN");

    // gdd FFI: sceKernelPowerTick (SceProcessmgr) + sceKernelGetFreeMemorySize
    // (SceSysmem). arm-vita-eabi-gcc's default specs only auto-link base
    // stubs; list these explicitly like the demo does for its UI stubs.
    println!("cargo::rerun-if-env-changed=VITASDK");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("vita") {
        let vitasdk =
            std::env::var("VITASDK").unwrap_or_else(|_| "/home/david/vitasdk".into());
        println!("cargo::rustc-link-search=native={vitasdk}/arm-vita-eabi/lib");
        println!("cargo::rustc-link-arg=-lSceProcessmgr_stub");
        println!("cargo::rustc-link-arg=-lSceSysmem_stub");
    }
}
