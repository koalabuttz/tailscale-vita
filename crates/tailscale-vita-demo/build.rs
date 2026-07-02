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
    // Force build.rs to run every invocation regardless of source-file
    // changes — Cargo treats nonexistent rerun-if-changed paths as
    // "always rerun" (per cargo docs). The previous claim in this
    // file ("no directive ⇒ runs every build") was wrong: with no
    // directives, Cargo only reruns the script when files inside the
    // demo crate change, so edits in dep crates (ts-control, etc.)
    // produced binaries with a stale BUILD_UNIX. The diagnostic was
    // useless precisely when we needed it (M14C bringup).
    println!("cargo::rerun-if-changed=NONEXISTENT_FORCE_RERUN");

    // M17-A S1 (docs/PLAN-M17A.md): the dashboard UI links vita2d plus
    // the Sce stubs that arm-vita-eabi-gcc's default specs do NOT
    // auto-link (only base stubs like SceNet/SceIofilemgr come free).
    // Everything sits in one --start-group..--end-group span so
    // static-archive ordering can't break the link. Gated on the vita
    // target: host builds/tests never see these flags.
    println!("cargo::rerun-if-env-changed=VITASDK");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("vita") {
        let vitasdk =
            std::env::var("VITASDK").unwrap_or_else(|_| "/home/david/vitasdk".into());
        println!("cargo::rustc-link-search=native={vitasdk}/arm-vita-eabi/lib");
        println!("cargo::rustc-link-arg=-Wl,--start-group");
        for lib in [
            "vita2d",
            // Referenced by libvita2d.a (per nm): GXM render, display
            // swap, common-dialog update, app budget query, PGF font.
            "SceGxm_stub",
            "SceDisplay_stub",
            "SceCommonDialog_stub",
            "SceAppMgr_stub",
            "ScePgf_stub",
            "SceSysmodule_stub",
            // Input for the dashboard.
            "SceCtrl_stub",
            // vita2d's texture/TTF loader objects reference these; the
            // linker only pulls archive members we actually use, and
            // unused ones cost zero bytes — listed so a future
            // vita2d_load_PNG_file call doesn't break the link.
            "freetype",
            "png16",
            "jpeg",
            "z",
            "m",
        ] {
            println!("cargo::rustc-link-arg=-l{lib}");
        }
        println!("cargo::rustc-link-arg=-Wl,--end-group");
    }
}
