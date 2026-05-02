use std::thread;
use std::time::Duration;

fn main() {
    println!("hello from tailscale-vita spike 1");
    for i in 0..3 {
        println!("tick {i}");
        thread::sleep(Duration::from_secs(1));
    }
    println!("goodbye");
}
