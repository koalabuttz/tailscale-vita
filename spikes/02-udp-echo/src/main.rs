use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

// Set this to the host running `host/echo.py` and reachable from the Vita.
// On Vita3K's default network adapter, the host is typically reachable on
// the LAN IP of the dev workstation.
const SERVER: &str = env!("ECHO_SERVER", "set ECHO_SERVER=ip:port at build time");

fn main() {
    println!("udp-echo spike starting; target = {SERVER}");

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            println!("bind failed: {e}");
            return;
        }
    };
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();

    for i in 0..5 {
        let payload = format!("ping {i} from vita");
        match sock.send_to(payload.as_bytes(), SERVER) {
            Ok(n) => println!("sent {n} bytes: {payload:?}"),
            Err(e) => {
                println!("send_to failed: {e}");
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        }

        let mut buf = [0u8; 1500];
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let s = String::from_utf8_lossy(&buf[..n]);
                println!("recv {n} bytes from {peer}: {s:?}");
            }
            Err(e) => println!("recv_from failed: {e}"),
        }
        thread::sleep(Duration::from_millis(500));
    }

    println!("udp-echo spike done; sleeping 5s before exit");
    thread::sleep(Duration::from_secs(5));
}
