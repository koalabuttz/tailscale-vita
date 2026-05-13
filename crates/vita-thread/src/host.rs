//! Host backend: thin wrapper around `std::thread::Builder`. Used on
//! x86_64 Linux (workspace tests + host_diagnostic) where std::thread
//! works normally. On the eboot path (cargo-vita builds), this is also
//! the backend if/when std::thread is usable — but the eboot uses
//! `tailscale-vita-demo` which already calls `Runtime::up` directly
//! via std::thread before vita-thread existed, so this backend is
//! effectively host-only in practice.

use std::io;
use std::thread::{self, JoinHandle as StdJoinHandle};

pub struct Handle(StdJoinHandle<()>);

pub fn spawn<F>(
    name: Option<String>,
    stack_size: Option<usize>,
    f: F,
) -> io::Result<Handle>
where
    F: FnOnce() + Send + 'static,
{
    let mut b = thread::Builder::new();
    if let Some(n) = name {
        b = b.name(n);
    }
    if let Some(s) = stack_size {
        b = b.stack_size(s);
    }
    b.spawn(f).map(Handle)
}

pub fn join(h: Handle) -> io::Result<()> {
    h.0.join()
        .map_err(|_| io::Error::other("thread panicked"))
}

pub fn is_finished(h: &Handle) -> bool {
    h.0.is_finished()
}

pub fn sleep(dur: std::time::Duration) {
    std::thread::sleep(dur);
}
