//! M21 Phase B — Tailscale daemon skeleton for the gdd (background
//! application) process. See docs/PLAN-M21.md.
//!
//! Not the real daemon yet: this binary proves the Rust substrate inside
//! a Vita bgapp before the runtime moves in (Phase C):
//!
//!   - crt0 heap grant: 32 MB `_newlib_heap_size_user` under the SELF's
//!     48 MB budget (`MEMSIZE 49152`, via `[package.metadata.vita]`).
//!     A grant the partition can't satisfy dies silently BEFORE main —
//!     the ALIVE log line is itself the probe.
//!   - std::thread + std::net: UDP echo on :31338 (LAN-visible, same
//!     port as the C spike) and a TCP listener on 127.0.0.1:41112 — the
//!     exact socket shape LocalAPI binds, so the C launcher's Phase A
//!     cross-process probe re-verifies against std::net.
//!   - vita-log's writer thread (daemon.log).
//!
//! Builds and runs on the host too (localhost servers, log in cwd):
//! `cargo run -p tailscale-vita-daemon`.

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use vita_log::{error, info, LogConfig};

/// 32 MB newlib heap. Must stay comfortably under the gdd SELF's
/// MEMSIZE 49152 KB budget — crt0 grants this before main() runs.
#[cfg(target_os = "vita")]
#[no_mangle]
#[used]
pub static _newlib_heap_size_user: u32 = 32 * 1024 * 1024;

const ECHO_PORT: u16 = 31338;
const XPROC_PORT: u16 = 41112;

/// Dedicated file for the Phase B/C bring-up; the split from vita.log is
/// deliberate — two processes must not append the same log, and the demo
/// eboot still owns vita.log.
#[cfg(target_os = "vita")]
const LOG_PATH: &str = "ux0:data/tailscale-vita/daemon.log";
#[cfg(not(target_os = "vita"))]
const LOG_PATH: &str = "daemon.log";

static ECHOES: AtomicU32 = AtomicU32::new(0);
static XHITS: AtomicU32 = AtomicU32::new(0);

#[cfg(target_os = "vita")]
mod ffi {
    #[repr(C)]
    pub struct SceKernelFreeMemorySizeInfo {
        pub size: i32,
        pub size_user: i32,
        pub size_cdram: i32,
        pub size_phycont: i32,
    }
    extern "C" {
        pub fn sceKernelPowerTick(tick_type: i32) -> i32;
        pub fn sceKernelGetFreeMemorySize(
            info: *mut SceKernelFreeMemorySizeInfo,
        ) -> i32;
    }
    pub const SCE_KERNEL_POWER_TICK_DISABLE_AUTO_SUSPEND: i32 = 1;
}

fn main() {
    if let Err(e) = vita_log::init_with_config(LogConfig {
        path: LOG_PATH.into(),
        ..LogConfig::default()
    }) {
        eprintln!("vita-log init failed: {e}");
        return;
    }
    info!(
        build = env!("BUILD_TIMESTAMP"),
        heap_mb = 32,
        "daemon skeleton ALIVE (gdd process, Rust std up)"
    );

    mem_probe();

    thread::spawn(echo_server);
    thread::spawn(xproc_server);

    // Main thread: BGFTP-style stay-awake tick + a 30 s heartbeat. The
    // console will not auto-sleep while the daemon runs; making this
    // configurable is Phase C ([power] keep_awake).
    let start = Instant::now();
    let mut last_beat = 0u64;
    loop {
        #[cfg(target_os = "vita")]
        unsafe {
            ffi::sceKernelPowerTick(ffi::SCE_KERNEL_POWER_TICK_DISABLE_AUTO_SUSPEND);
        }
        thread::sleep(Duration::from_secs(5));
        let up = start.elapsed().as_secs();
        if up - last_beat >= 30 {
            last_beat = up;
            info!(
                up_s = up,
                echoes = ECHOES.load(Ordering::Relaxed),
                xhits = XHITS.load(Ordering::Relaxed),
                "heartbeat"
            );
            vita_log::flush();
        }
    }
}

/// Rust twin of the C spike's probe_memory: what's free in the partition
/// beyond the heap, and is the heap actually usable at size?
fn mem_probe() {
    #[cfg(target_os = "vita")]
    {
        let mut mi = ffi::SceKernelFreeMemorySizeInfo {
            size: std::mem::size_of::<ffi::SceKernelFreeMemorySizeInfo>() as i32,
            size_user: 0,
            size_cdram: 0,
            size_phycont: 0,
        };
        let rc = unsafe { ffi::sceKernelGetFreeMemorySize(&mut mi) };
        if rc >= 0 {
            info!(
                free_user_kb = mi.size_user / 1024,
                free_cdram_kb = mi.size_cdram / 1024,
                free_phycont_kb = mi.size_phycont / 1024,
                "partition free beyond heap"
            );
        } else {
            error!(rc = format!("{rc:#010x}"), "free-memory probe failed");
        }
    }

    // Touch 20 of the 32 MB through the normal allocator (page stride).
    let mut big = vec![0u8; 20 * 1024 * 1024];
    for i in (0..big.len()).step_by(4096) {
        big[i] = 0xA5;
    }
    drop(big);
    info!(touched_mb = 20, "malloc+touch OK on 32 MB heap");
    vita_log::flush();
}

fn echo_server() {
    let sock = match UdpSocket::bind(("0.0.0.0", ECHO_PORT)) {
        Ok(s) => s,
        Err(e) => {
            // EADDRINUSE here = the old C spike bgapp is still running;
            // peel its LiveArea card and relaunch.
            error!(error = %e, port = ECHO_PORT, "UDP echo bind failed");
            return;
        }
    };
    info!(port = ECHO_PORT, "UDP echo up");
    let start = Instant::now();
    let mut buf = [0u8; 512];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let count = ECHOES.fetch_add(1, Ordering::Relaxed) + 1;
                let reply = format!(
                    "daemon up={}s echoes={count}\n",
                    start.elapsed().as_secs()
                );
                let _ = sock.send_to(reply.as_bytes(), from);
                info!(n, %from, count, "echo");
            }
            Err(e) => {
                error!(error = %e, "UDP recv failed");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// The LocalAPI socket shape: TCP on 127.0.0.1:41112, one canned HTTP
/// response per connection. The C launcher (gdc) probes this from its
/// own process + sceNet context — Phase A's verdict, re-run over std::net.
fn xproc_server() {
    let listener = match TcpListener::bind(("127.0.0.1", XPROC_PORT)) {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, port = XPROC_PORT, "xproc TCP bind failed");
            return;
        }
    };
    info!(port = XPROC_PORT, "xproc TCP listener up (127.0.0.1)");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "xproc accept failed");
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut req = [0u8; 256];
        let n = stream.read(&mut req).unwrap_or(0);
        const BODY: &str = "tailscale-vita-daemon skeleton\n";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{BODY}",
            BODY.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let hits = XHITS.fetch_add(1, Ordering::Relaxed) + 1;
        info!(hits, req_bytes = n, "xproc served");
    }
}
