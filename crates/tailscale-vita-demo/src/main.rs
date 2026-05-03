use std::thread;
use std::time::Duration;

use tracing::{info, info_span, warn};

fn main() {
    if let Err(e) = vita_log::init() {
        eprintln!("vita-log init failed: {e}");
        return;
    }

    let _span = info_span!("startup").entered();
    info!(milestone = "M1", "tailscale-vita-demo starting");

    for tick in 0..3 {
        info!(tick, "heartbeat");
        thread::sleep(Duration::from_secs(1));
    }

    if std::env::var("M1_DEMO_PANIC").as_deref() == Ok("1") {
        warn!("M1_DEMO_PANIC=1 set; spawning a thread that will panic");
        let h = thread::Builder::new()
            .name("panic-test".into())
            .spawn(|| {
                panic!("intentional M1 demo panic");
            })
            .expect("spawn panic-test thread");
        let _ = h.join();
        info!("panic-test thread joined; main continues");
    }

    info!("tailscale-vita-demo exiting cleanly");
    vita_log::flush();
}
