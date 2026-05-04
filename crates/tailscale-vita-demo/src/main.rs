use std::path::Path;
use std::thread;
use std::time::Duration;

use tracing::{error, info, info_span};

const STATE_DIR: &str = "ux0:/data/tailscale-vita";
const HEADSCALE_URL: &str = "http://192.168.8.147:8080";
const CAPVER: u32 = 90;

fn main() {
    if let Err(e) = vita_log::init() {
        eprintln!("vita-log init failed: {e}");
        return;
    }
    let _span = info_span!("startup", milestone = "M4").entered();

    if let Err(e) = run() {
        error!(error = %e, "M4 demo failed");
    }
    vita_log::flush();
    thread::sleep(Duration::from_secs(1));
}

fn run() -> Result<(), ts_control::ControlError> {
    info!(headscale = HEADSCALE_URL, capver = CAPVER, "fetching Noise pubkey");

    let seen = ts_control::fetch_server_key(HEADSCALE_URL, CAPVER)?;
    info!(seen = %seen, "control.key.received");

    let dir = Path::new(STATE_DIR);
    let pinned = ts_control::pin_or_load_server_key(dir, &seen)?;
    info!(pinned = %pinned, "control.key.pinned");

    info!("M4 demo done");
    Ok(())
}
