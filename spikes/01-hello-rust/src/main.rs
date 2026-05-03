use std::thread;
use std::time::Duration;

mod logger;

macro_rules! log {
    ($($arg:tt)*) => { logger::log_line(&format!($($arg)*)) };
}

fn main() {
    logger::init("ux0:/data/spike-1.log");
    log!("hello from tailscale-vita spike 1");
    for i in 0..3 {
        log!("tick {i}");
        thread::sleep(Duration::from_secs(1));
    }
    log!("goodbye");
}
