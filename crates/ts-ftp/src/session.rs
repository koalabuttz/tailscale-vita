//! Per-control-connection FTP session: greet, then read CRLF command lines
//! and dispatch until QUIT or disconnect. Each session runs on its own thread
//! (spawned by the accept loop, bounded by `MAX_SESSIONS`), so one slow or
//! stalled client can't block others. PASV-only. Permissive auth — the tailnet
//! ACL is the boundary.

use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use netstack::tcp::TcpStream;
use netstack::TcpListener;
use vita_log::{debug, info, warn};

use crate::command::{self, Command};
use crate::reply::{dir_reply, reply, reply_multiline};
use crate::vfs::{self, Vfs};
use crate::{data, listing, Ctx, CTRL_IDLE_TIMEOUT, CTRL_POLL, DATA_ACCEPT_TIMEOUT, DATA_RW_TIMEOUT};

/// Control reader: a `BufReader` over the control stream. `get_mut()` yields
/// the underlying stream for writing replies (writes bypass the read buffer).
type Ctrl = BufReader<TcpStream>;

enum Flow {
    Continue,
    Quit,
}

/// Handle one control connection start-to-finish. Runs on its own session
/// thread; `shutdown` lets an idle/blocked read bail promptly when the server
/// is stopping instead of lingering the full `CTRL_IDLE_TIMEOUT`.
pub(crate) fn handle(ctrl: TcpStream, peer: SocketAddr, ctx: &Ctx, shutdown: &AtomicBool) {
    let mut ctrl = ctrl;
    // Short poll timeout (not the full idle budget) so `read_line` can re-check
    // `shutdown` and the idle deadline between reads. Partial reads accumulate
    // across polls, so a command split over the wire still assembles.
    let _ = ctrl.set_read_timeout(Some(CTRL_POLL));
    let _ = ctrl.set_write_timeout(Some(DATA_RW_TIMEOUT));
    let mut reader = BufReader::new(ctrl);

    if reply(reader.get_mut(), 220, "ts-ftp ready").is_err() {
        return;
    }

    let mut session = Session::new(ctx);
    while !shutdown.load(Ordering::Acquire) {
        let line = match read_line(&mut reader, shutdown) {
            Some(l) => l,
            None => break, // EOF, idle timeout, shutdown, or read error
        };
        if line.is_empty() {
            continue;
        }
        let cmd = command::parse(&line);
        debug!(%peer, ?cmd, "ts-ftp.cmd");
        match session.dispatch(&cmd, &mut reader, ctx) {
            Ok(Flow::Continue) => {}
            Ok(Flow::Quit) => break,
            Err(_) => break, // a control write failed; client is gone
        }
    }
}

/// Read one CRLF-terminated command line, stripping the line ending. The
/// control stream carries a short (`CTRL_POLL`) read timeout, so this polls in
/// a loop: a timeout re-checks `shutdown` and the `CTRL_IDLE_TIMEOUT` budget
/// rather than ending the session, while partial reads accumulate in `buf`.
/// Returns `None` on EOF, idle-timeout, shutdown, or a real read error (a
/// closed stream reports `BrokenPipe`, ending the session promptly).
fn read_line(reader: &mut Ctrl, shutdown: &AtomicBool) -> Option<String> {
    let mut buf = Vec::new();
    let deadline = Instant::now() + CTRL_IDLE_TIMEOUT;
    loop {
        match reader.read_until(b'\n', &mut buf) {
            // EOF. A trailing fragment without a newline is a broken client; drop it.
            Ok(0) => return None,
            Ok(_) if matches!(buf.last(), Some(b'\n')) => {
                while matches!(buf.last(), Some(b'\n' | b'\r')) {
                    buf.pop();
                }
                return Some(String::from_utf8_lossy(&buf).into_owned());
            }
            // Read returned bytes but no line end yet — keep reading.
            Ok(_) => {}
            // Poll timeout: bail on shutdown or idle-budget exhaustion, else retry.
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if shutdown.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

struct Session {
    vfs: Vfs,
    /// Current virtual directory, always absolute (`"/"`, `"/data"`, …).
    cwd: String,
    authed: bool,
    /// Pending PASV data listener + its advertised port.
    pasv: Option<(TcpListener, u16)>,
    /// `RNFR` target, awaiting `RNTO`.
    rename_from: Option<String>,
    read_only: bool,
}

impl Session {
    fn new(ctx: &Ctx) -> Self {
        Self {
            vfs: Vfs::new(&ctx.cfg.root),
            cwd: "/".to_string(),
            authed: false,
            pasv: None,
            rename_from: None,
            read_only: ctx.cfg.read_only,
        }
    }

    fn dispatch(&mut self, cmd: &Command, r: &mut Ctrl, ctx: &Ctx) -> io::Result<Flow> {
        use Command::*;

        // Commands answerable before login.
        match cmd {
            User(_) => {
                reply(r.get_mut(), 331, "user ok, send PASS")?;
                return Ok(Flow::Continue);
            }
            Pass(_) => {
                self.authed = true;
                reply(r.get_mut(), 230, "logged in")?;
                return Ok(Flow::Continue);
            }
            Quit => {
                reply(r.get_mut(), 221, "goodbye")?;
                return Ok(Flow::Quit);
            }
            Syst => {
                reply(r.get_mut(), 215, "UNIX Type: L8")?;
                return Ok(Flow::Continue);
            }
            Feat => {
                reply_multiline(
                    r.get_mut(),
                    211,
                    "Features",
                    &["EPSV", "PASV", "SIZE", "UTF8"],
                    "End",
                )?;
                return Ok(Flow::Continue);
            }
            Noop => {
                reply(r.get_mut(), 200, "noop ok")?;
                return Ok(Flow::Continue);
            }
            _ => {}
        }

        if !self.authed {
            reply(r.get_mut(), 530, "please login with USER and PASS")?;
            return Ok(Flow::Continue);
        }

        match cmd {
            Type(_) => reply(r.get_mut(), 200, "type set to I")?, // always binary
            Pwd => {
                let m = format!("{} is current directory", dir_reply(&self.cwd));
                reply(r.get_mut(), 257, &m)?;
            }
            Cwd(arg) => self.do_cwd(arg, r)?,
            Cdup => self.do_cwd("..", r)?,
            Pasv => self.do_pasv(r, ctx)?,
            Epsv(arg) => self.do_epsv(arg.as_deref(), r, ctx)?,
            List(arg) => self.do_list(arg.as_deref(), false, r)?,
            Nlst(arg) => self.do_list(arg.as_deref(), true, r)?,
            Retr(arg) => self.do_retr(arg, r)?,
            Stor(arg) => self.do_stor(arg, r)?,
            Size(arg) => self.do_size(arg, r)?,
            Dele(arg) => self.do_dele(arg, r)?,
            Mkd(arg) => self.do_mkd(arg, r)?,
            Rnfr(arg) => self.do_rnfr(arg, r)?,
            Rnto(arg) => self.do_rnto(arg, r)?,
            Rmd(_) => reply(r.get_mut(), 550, "RMD not supported")?,
            _ => reply(r.get_mut(), 502, "command not implemented")?,
        }
        Ok(Flow::Continue)
    }

    fn do_cwd(&mut self, arg: &str, r: &mut Ctrl) -> io::Result<()> {
        let vpath = match self.vfs.resolve(&self.cwd, arg) {
            Some(v) => v,
            None => return reply(r.get_mut(), 550, "invalid path"),
        };
        let real = self.vfs.to_real(&vpath);
        // Confirm it's a directory by listing it.
        match vita_fs::read_dir(Path::new(&real)) {
            Ok(_) => {
                self.cwd = vpath;
                reply(r.get_mut(), 250, "directory changed")
            }
            Err(_) => reply(r.get_mut(), 550, "no such directory"),
        }
    }

    fn do_pasv(&mut self, r: &mut Ctrl, ctx: &Ctx) -> io::Result<()> {
        let ip = match *ctx.tailnet_ip.lock() {
            Some(ip) => ip,
            None => return reply(r.get_mut(), 425, "tailnet address not ready"),
        };
        // Drop any previous pending listener before binding a new one.
        self.pasv = None;
        match data::bind_passive(
            &ctx.stack,
            &ctx.next_pasv_port,
            ctx.cfg.passive_port_lo,
            ctx.cfg.passive_port_hi,
        ) {
            Ok((listener, port)) => {
                let text = data::format_227(ip, port);
                self.pasv = Some((listener, port));
                reply(r.get_mut(), 227, &text)
            }
            Err(e) => {
                warn!(error = %e, "ts-ftp.pasv.bind_failed");
                reply(r.get_mut(), 425, "can't open data port")
            }
        }
    }

    fn do_epsv(&mut self, arg: Option<&str>, r: &mut Ctrl, ctx: &Ctx) -> io::Result<()> {
        // `EPSV ALL` only locks the client into extended passive mode; there
        // is no data connection to open, so just acknowledge it. We don't
        // enforce the lock (all our data commands work in either mode).
        if arg.is_some_and(|a| a.eq_ignore_ascii_case("ALL")) {
            return reply(r.get_mut(), 200, "EPSV ALL ok");
        }
        // Unlike PASV, the `229` reply carries no host — only the port — so
        // EPSV needs no tailnet IP and works regardless of the address the
        // client reached us on. Drop any previous pending listener first.
        self.pasv = None;
        match data::bind_passive(
            &ctx.stack,
            &ctx.next_pasv_port,
            ctx.cfg.passive_port_lo,
            ctx.cfg.passive_port_hi,
        ) {
            Ok((listener, port)) => {
                let text = data::format_229(port);
                self.pasv = Some((listener, port));
                reply(r.get_mut(), 229, &text)
            }
            Err(e) => {
                warn!(error = %e, "ts-ftp.epsv.bind_failed");
                reply(r.get_mut(), 425, "can't open data port")
            }
        }
    }

    fn do_list(&mut self, arg: Option<&str>, names_only: bool, r: &mut Ctrl) -> io::Result<()> {
        // Resolve the target dir: ignore `ls`-style flag args (e.g. "-la").
        let vpath = match arg {
            Some(a) if !a.is_empty() && !a.starts_with('-') => match self.vfs.resolve(&self.cwd, a) {
                Some(v) => v,
                None => return reply(r.get_mut(), 550, "invalid path"),
            },
            _ => self.cwd.clone(),
        };
        // The virtual root `/` is the device-list level: list the known mount
        // points (VitaShell convention) rather than the jail root's contents.
        let entries = if vfs::is_root(&vpath) {
            vfs::device_entries()
        } else {
            let real = self.vfs.to_real(&vpath);
            match vita_fs::read_dir(Path::new(&real)) {
                Ok(e) => e,
                Err(_) => return reply(r.get_mut(), 550, "no such directory"),
            }
        };
        let body = if names_only {
            listing::format_nlst(&entries)
        } else {
            listing::format_list(&entries)
        };
        self.send_data(body.as_bytes(), r)
    }

    fn do_retr(&mut self, arg: &str, r: &mut Ctrl) -> io::Result<()> {
        let vpath = match self.vfs.resolve(&self.cwd, arg) {
            Some(v) => v,
            None => return reply(r.get_mut(), 550, "invalid path"),
        };
        let real = self.vfs.to_real(&vpath);
        let bytes = match vita_fs::read(Path::new(&real)) {
            Ok(b) => b,
            Err(e) => {
                warn!(real = %real, error = %e, "ts-ftp.retr.read_err");
                return reply(r.get_mut(), 550, "no such file");
            }
        };
        // BUG-A probe (2026-07-03): if this logs len=0 while SIZE reports
        // non-zero, the fault is vita_fs::read/path (fs layer); if len>0 yet
        // curl gets nothing, it's the data-socket transport (see pump_data).
        info!(real = %real, len = bytes.len(), "ts-ftp.retr.read");
        self.send_data(&bytes, r)
    }

    fn do_stor(&mut self, arg: &str, r: &mut Ctrl) -> io::Result<()> {
        if self.read_only {
            return reply(r.get_mut(), 550, "server is read-only");
        }
        let vpath = match self.vfs.resolve(&self.cwd, arg) {
            Some(v) => v,
            None => return reply(r.get_mut(), 550, "invalid path"),
        };
        let real = self.vfs.to_real(&vpath);
        let (listener, _) = match self.pasv.take() {
            Some(x) => x,
            None => return reply(r.get_mut(), 425, "use PASV first"),
        };
        reply(r.get_mut(), 150, "ready to receive")?;
        match listener.accept_timeout(DATA_ACCEPT_TIMEOUT) {
            Ok((mut data, _)) => {
                let _ = data.set_read_timeout(Some(DATA_RW_TIMEOUT));
                let mut buf = Vec::new();
                let recv = read_to_end(&mut data, &mut buf);
                drop(data);
                match recv {
                    Ok(()) => match vita_fs::write(Path::new(&real), &buf) {
                        Ok(()) => reply(r.get_mut(), 226, "stored"),
                        Err(e) => {
                            warn!(error = %e, "ts-ftp.stor.write");
                            reply(r.get_mut(), 550, "write failed")
                        }
                    },
                    Err(e) => {
                        warn!(error = %e, "ts-ftp.stor.recv");
                        reply(r.get_mut(), 426, "receive failed")
                    }
                }
            }
            Err(_) => reply(r.get_mut(), 425, "data connection failed"),
        }
    }

    fn do_size(&mut self, arg: &str, r: &mut Ctrl) -> io::Result<()> {
        let vpath = match self.vfs.resolve(&self.cwd, arg) {
            Some(v) => v,
            None => return reply(r.get_mut(), 550, "invalid path"),
        };
        let (parent, name) = vfs::split_parent(&vpath);
        let real_parent = self.vfs.to_real(&parent);
        match vita_fs::read_dir(Path::new(&real_parent)) {
            Ok(entries) => match entries.iter().find(|e| e.name == name && !e.is_dir) {
                Some(e) => reply(r.get_mut(), 213, &e.size.to_string()),
                None => reply(r.get_mut(), 550, "no such file"),
            },
            Err(_) => reply(r.get_mut(), 550, "no such file"),
        }
    }

    fn do_dele(&mut self, arg: &str, r: &mut Ctrl) -> io::Result<()> {
        if self.read_only {
            return reply(r.get_mut(), 550, "server is read-only");
        }
        let vpath = match self.vfs.resolve(&self.cwd, arg) {
            Some(v) => v,
            None => return reply(r.get_mut(), 550, "invalid path"),
        };
        let real = self.vfs.to_real(&vpath);
        match vita_fs::remove_file(Path::new(&real)) {
            Ok(()) => reply(r.get_mut(), 250, "deleted"),
            Err(e) => {
                warn!(error = %e, "ts-ftp.dele");
                reply(r.get_mut(), 550, "delete failed")
            }
        }
    }

    fn do_mkd(&mut self, arg: &str, r: &mut Ctrl) -> io::Result<()> {
        if self.read_only {
            return reply(r.get_mut(), 550, "server is read-only");
        }
        let vpath = match self.vfs.resolve(&self.cwd, arg) {
            Some(v) => v,
            None => return reply(r.get_mut(), 550, "invalid path"),
        };
        let real = self.vfs.to_real(&vpath);
        match vita_fs::create_dir_all(Path::new(&real)) {
            Ok(()) => reply(r.get_mut(), 257, &format!("{} created", dir_reply(&vpath))),
            Err(e) => {
                warn!(error = %e, "ts-ftp.mkd");
                reply(r.get_mut(), 550, "mkdir failed")
            }
        }
    }

    fn do_rnfr(&mut self, arg: &str, r: &mut Ctrl) -> io::Result<()> {
        if self.read_only {
            return reply(r.get_mut(), 550, "server is read-only");
        }
        match self.vfs.resolve(&self.cwd, arg) {
            Some(v) => {
                self.rename_from = Some(v);
                reply(r.get_mut(), 350, "ready for RNTO")
            }
            None => reply(r.get_mut(), 550, "invalid path"),
        }
    }

    fn do_rnto(&mut self, arg: &str, r: &mut Ctrl) -> io::Result<()> {
        let from = match self.rename_from.take() {
            Some(f) => f,
            None => return reply(r.get_mut(), 503, "RNFR first"),
        };
        let to = match self.vfs.resolve(&self.cwd, arg) {
            Some(v) => v,
            None => return reply(r.get_mut(), 550, "invalid path"),
        };
        let real_from = self.vfs.to_real(&from);
        let real_to = self.vfs.to_real(&to);
        match vita_fs::rename(Path::new(&real_from), Path::new(&real_to)) {
            Ok(()) => reply(r.get_mut(), 250, "renamed"),
            Err(e) => {
                warn!(error = %e, "ts-ftp.rnto");
                reply(r.get_mut(), 550, "rename failed")
            }
        }
    }

    /// Open the pending PASV/EPSV data connection and hand it to
    /// [`pump_data`], which writes `bytes`, closes the socket, then reports
    /// `226`/`426`. `425` if no PASV/EPSV preceded this. Shared verbatim by
    /// LIST/NLST (listing bytes) and RETR (file bytes) — the file pump and
    /// the listing pump are the *same* code path.
    fn send_data(&mut self, bytes: &[u8], r: &mut Ctrl) -> io::Result<()> {
        let (listener, _) = match self.pasv.take() {
            Some(x) => x,
            None => return reply(r.get_mut(), 425, "use PASV first"),
        };
        reply(r.get_mut(), 150, "opening data connection")?;
        match listener.accept_timeout(DATA_ACCEPT_TIMEOUT) {
            Ok((mut data, peer)) => {
                info!(%peer, want = bytes.len(), "ts-ftp.data.accepted");
                let _ = data.set_write_timeout(Some(DATA_RW_TIMEOUT));
                pump_data(data, r.get_mut(), bytes)
            }
            Err(_) => {
                warn!("ts-ftp.data.accept_failed");
                reply(r.get_mut(), 425, "data connection failed")
            }
        }
    }
}

/// The data connection the transfer pump drives. It only needs to write the
/// payload and then an explicit `close` that flushes/drains before the
/// control `226`. For the real netstack stream `close` drops the socket —
/// its `Drop` sends the FIN and waits (bounded) for the TX buffer to drain.
/// The trait exists so the write-then-close-then-`226` *ordering* is
/// host-testable with a mock (no live netstack required).
trait DataStream: Write {
    fn close(self) -> io::Result<()>
    where
        Self: Sized;

    /// Bytes still queued (unsent or unacked) on the connection right now.
    /// `0` means the peer has acknowledged everything written. Logged before
    /// close to diagnose a transfer that writes OK yet delivers nothing.
    fn pending(&self) -> usize;
}

impl DataStream for TcpStream {
    fn close(self) -> io::Result<()> {
        drop(self); // FIN + bounded TX-drain, see netstack TcpStream::drop
        Ok(())
    }

    fn pending(&self) -> usize {
        self.send_queue()
    }
}

/// Write `bytes` to the data connection, close it (drain), then report the
/// outcome on the control stream. The close happens **before** the `226`, so
/// the client never sees a `226` with the data socket still open. On a write
/// failure the socket is still closed and `426` is sent.
fn pump_data<D: DataStream, C: Write>(mut data: D, ctrl: &mut C, bytes: &[u8]) -> io::Result<()> {
    let sent = data.write_all(bytes);
    // BUG-A probe: `wrote_ok=false` => write_all stalled in the netstack;
    // `pending>0` => bytes are queued but the peer hasn't ACK'd them, i.e.
    // the data socket isn't transmitting (window/WgDevice-drop), which the
    // netstack Drop now turns into a RST instead of a silent hang.
    info!(
        len = bytes.len(),
        wrote_ok = sent.is_ok(),
        pending = data.pending(),
        "ts-ftp.pump.wrote"
    );
    let _ = data.close(); // close/drain the data socket first
    info!("ts-ftp.pump.closed");
    match sent {
        Ok(()) => reply(ctrl, 226, "transfer complete"),
        Err(e) => {
            warn!(error = %e, "ts-ftp.data.write");
            reply(ctrl, 426, "transfer failed")
        }
    }
}

/// Read a data stream to EOF. A read timeout is treated as end-of-data
/// (best-effort for v1; the client normally signals EOF by closing → `Ok(0)`).
fn read_to_end(s: &mut TcpStream, out: &mut Vec<u8>) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                return Ok(())
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    type Log = Rc<RefCell<Vec<String>>>;

    /// Mock data connection: records `write`/`close` into a shared log so the
    /// pump's ordering (bytes → close → reply) is observable.
    struct MockData {
        log: Log,
        fail: bool,
    }
    impl Write for MockData {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "boom"));
            }
            self.log.borrow_mut().push(format!("write {}", buf.len()));
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl DataStream for MockData {
        fn close(self) -> io::Result<()> {
            self.log.borrow_mut().push("close".into());
            Ok(())
        }
        fn pending(&self) -> usize {
            0
        }
    }

    /// Mock control stream: records each fully-formed reply into the same log
    /// (`reply` flushes exactly once per line, so we snapshot on flush).
    struct MockCtrl {
        log: Log,
        buf: Vec<u8>,
    }
    impl Write for MockCtrl {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            let s = String::from_utf8_lossy(&self.buf).trim_end().to_string();
            self.log.borrow_mut().push(format!("reply {s}"));
            self.buf.clear();
            Ok(())
        }
    }

    // Issue #1: RETR (and LIST/NLST — same pump) must write the payload,
    // close the data socket, and only THEN send 226. Never a bare 226 with
    // the socket still open, never zero bytes.
    #[test]
    fn pump_writes_bytes_then_closes_then_226() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let data = MockData { log: log.clone(), fail: false };
        let mut ctrl = MockCtrl { log: log.clone(), buf: Vec::new() };
        let payload = vec![0u8; 286]; // the field-report SIZE
        pump_data(data, &mut ctrl, &payload).unwrap();
        assert_eq!(
            *log.borrow(),
            vec![
                "write 286".to_string(),
                "close".to_string(),
                "reply 226 transfer complete".to_string(),
            ]
        );
    }

    // On a write failure the socket is still closed before the 426.
    #[test]
    fn pump_closes_socket_and_reports_426_on_write_error() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let data = MockData { log: log.clone(), fail: true };
        let mut ctrl = MockCtrl { log: log.clone(), buf: Vec::new() };
        pump_data(data, &mut ctrl, b"whatever").unwrap();
        assert_eq!(
            *log.borrow(),
            vec!["close".to_string(), "reply 426 transfer failed".to_string()]
        );
    }
}
