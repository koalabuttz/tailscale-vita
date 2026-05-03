use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

mod logger;

macro_rules! log {
    ($($arg:tt)*) => { logger::log_line(&format!($($arg)*)) };
}

const SERVER: &str = env!("ECHO_SERVER", "set ECHO_SERVER=ip:port at build time");

fn main() {
    logger::init("ux0:/data/spike-2.log");
    log!("udp-echo spike starting; target = {SERVER}");

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            log!("bind failed: {e}");
            return;
        }
    };
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();

    for i in 0..5 {
        let payload = format!("ping {i} from vita");
        match sock.send_to(payload.as_bytes(), SERVER) {
            Ok(n) => log!("sent {n} bytes: {payload:?}"),
            Err(e) => {
                log!("send_to failed: {e}");
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        }

        let mut buf = [0u8; 1500];
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let s = String::from_utf8_lossy(&buf[..n]);
                log!("recv {n} bytes from {peer}: {s:?}");
            }
            Err(e) => log!("recv_from failed: {e}"),
        }
        thread::sleep(Duration::from_millis(500));
    }

    log!("udp-echo spike done; sleeping 5s before exit");
    thread::sleep(Duration::from_secs(5));
}
