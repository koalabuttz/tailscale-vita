use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

static LOG_PATH: OnceLock<&'static str> = OnceLock::new();
static LOCK: Mutex<()> = Mutex::new(());

pub fn init(path: &'static str) {
    let _ = LOG_PATH.set(path);
    let _ = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path);
    std::panic::set_hook(Box::new(|info| {
        log_line(&format!("PANIC: {info}"));
    }));
}

pub fn log_line(s: &str) {
    println!("{s}");
    let Some(path) = LOG_PATH.get() else { return };
    let _g = LOCK.lock();
    if let Ok(mut f) = OpenOptions::new().append(true).create(true).open(path) {
        let _ = writeln!(f, "{s}");
        let _ = f.flush();
    }
}
