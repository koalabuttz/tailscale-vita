//! Spike: confirm `boringtun` (the WireGuard data plane we plan to use)
//! cross-compiles for `armv7-sony-vita-newlibeabihf`.
//!
//! This intentionally does *not* speak to the network or do a real
//! handshake. We only need to know that:
//!   - All transitive deps (ring, parking_lot, chacha20poly1305, ...)
//!     compile and link for the Vita target.
//!   - boringtun's public types (`x25519::StaticSecret`, `noise::Tunn`)
//!     are constructible.
//!
//! If this VPK boots and prints "boringtun init OK", the architectural
//! assumption that `boringtun` is usable on Vita holds.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use rand_core::OsRng;

mod logger;

macro_rules! log {
    ($($arg:tt)*) => { logger::log_line(&format!($($arg)*)) };
}

fn main() {
    logger::init("ux0:/data/spike-3.log");
    log!("boringtun-compile spike: starting");

    let server_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let server_public = x25519::PublicKey::from(&server_secret);
    let client_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let client_public = x25519::PublicKey::from(&client_secret);

    log!("server pub: {:02x?}", server_public.as_bytes());
    log!("client pub: {:02x?}", client_public.as_bytes());

    let mut tun = Tunn::new(
        client_secret,
        server_public,
        None,    // preshared key
        Some(25), // persistent keepalive
        1,        // index
        None,     // rate limiter
    );

    let mut dst = [0u8; 2048];
    let result = tun.encapsulate(&[], &mut dst);
    match result {
        TunnResult::WriteToNetwork(handshake) => {
            log!(
                "boringtun init OK: produced handshake init of {} bytes",
                handshake.len()
            );
        }
        other => {
            log!("unexpected encapsulate result: {other:?}");
        }
    }

    // Touch Arc + thread sanity to confirm parking_lot / std::sync work too.
    let counter = Arc::new(parking_lot::Mutex::new(0u32));
    let c2 = counter.clone();
    let h = thread::spawn(move || {
        for _ in 0..100 {
            *c2.lock() += 1;
        }
    });
    h.join().unwrap();
    log!("parking_lot Mutex roundtrip: {}", *counter.lock());

    log!("boringtun-compile spike: done; sleeping 5s");
    thread::sleep(Duration::from_secs(5));
}
