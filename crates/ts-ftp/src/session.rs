//! Per-control-connection FTP session: greet, then read CRLF command lines
//! and dispatch until QUIT or disconnect. Each session runs on its own thread
//! (spawned by the accept loop, bounded by `MAX_SESSIONS`), so one slow or
//! stalled client can't block others. PASV-only. Permissive auth — the tailnet
//! ACLs are enforced by the runtime before this service sees a packet; this
//! module additionally authenticates FTP clients and enforces service limits.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use netstack::tcp::TcpStream;
use netstack::TcpListener;
use vita_log::{debug, info, warn};

use crate::command::{self, Command};
use crate::reply::{dir_reply, reply, reply_multiline};
use crate::vfs::{self, Vfs};
use crate::{
    data, listing, Ctx, CTRL_IDLE_TIMEOUT, CTRL_POLL, DATA_ACCEPT_TIMEOUT, DATA_RW_TIMEOUT,
    MAX_COMMAND_BYTES,
};

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

    let mut session = Session::new(ctx, peer);
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
fn read_line<R: BufRead>(reader: &mut R, shutdown: &AtomicBool) -> Option<String> {
    let mut buf = Vec::new();
    let deadline = Instant::now() + CTRL_IDLE_TIMEOUT;
    loop {
        // Bound each read to the remaining command-line budget. `read_until`
        // does not return while bytes keep arriving without a newline, so an
        // unbounded check *between* calls can't stop a fast no-newline stream
        // from growing `buf` without limit (pre-auth memory exhaustion). The
        // `Take` cap makes a single call read at most one byte past the limit,
        // so the over-cap guard below reliably fires. `buf.len()` never exceeds
        // `MAX_COMMAND_BYTES + 1` because the budget shrinks as `buf` grows.
        let budget = (MAX_COMMAND_BYTES + 1).saturating_sub(buf.len()) as u64;
        match (&mut *reader).take(budget).read_until(b'\n', &mut buf) {
            Ok(_) if buf.len() > MAX_COMMAND_BYTES => return None,
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
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
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
    pending_user: Option<String>,
    control_peer_ip: IpAddr,
    /// Pending PASV data listener + its advertised port.
    pasv: Option<(TcpListener, u16)>,
    /// `RNFR` target, awaiting `RNTO`.
    rename_from: Option<String>,
    read_only: bool,
    max_transfer_bytes: u64,
    /// Shared STOR temp-file counter (see [`crate::Ctx::partial_seq`]).
    partial_seq: Arc<AtomicU64>,
}

impl Session {
    fn new(ctx: &Ctx, control_peer: SocketAddr) -> Self {
        Self {
            vfs: Vfs::new(&ctx.cfg.root, ctx.cfg.allow_device_paths),
            cwd: "/".to_string(),
            authed: false,
            pending_user: None,
            control_peer_ip: control_peer.ip(),
            pasv: None,
            rename_from: None,
            read_only: ctx.cfg.read_only,
            max_transfer_bytes: ctx.cfg.max_transfer_bytes,
            partial_seq: Arc::clone(&ctx.partial_seq),
        }
    }

    fn dispatch(&mut self, cmd: &Command, r: &mut Ctrl, ctx: &Ctx) -> io::Result<Flow> {
        use Command::*;

        // Commands answerable before login.
        match cmd {
            User(user) => {
                self.pending_user = Some(user.clone());
                reply(r.get_mut(), 331, "user ok, send PASS")?;
                return Ok(Flow::Continue);
            }
            Pass(password) => {
                let user = self.pending_user.take().unwrap_or_default();
                if credentials_match(&ctx.cfg.username, &ctx.cfg.password, &user, password) {
                    self.authed = true;
                    reply(r.get_mut(), 230, "logged in")?;
                } else {
                    reply(r.get_mut(), 530, "login incorrect")?;
                }
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
            Some(a) if !a.is_empty() && !a.starts_with('-') => match self.vfs.resolve(&self.cwd, a)
            {
                Some(v) => v,
                None => return reply(r.get_mut(), 550, "invalid path"),
            },
            _ => self.cwd.clone(),
        };
        // The virtual root `/` is the device-list level: list the known mount
        // points (VitaShell convention) rather than the jail root's contents.
        let real = self.vfs.to_real(&vpath);
        let entries = match vita_fs::read_dir(Path::new(&real)) {
            Ok(e) => e,
            Err(_) => return reply(r.get_mut(), 550, "no such directory"),
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
        // `vita_fs::read` slurps the whole file into RAM, so the size cap must
        // be enforced BEFORE the read — and it must fail closed. If the size
        // can't be determined (parent dir unreadable / no matching entry), a
        // real readable file would have listed via the same `read_dir` LIST
        // uses, so an unknown size means not-found; reading it anyway risks an
        // unbounded allocation that OOMs the whole runtime.
        match file_size(&self.vfs, &vpath) {
            Some(size) if size > self.max_transfer_bytes => {
                return reply(r.get_mut(), 552, "file exceeds transfer limit");
            }
            Some(_) => {}
            None => return reply(r.get_mut(), 550, "cannot stat file"),
        }
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
            Ok((mut data, data_peer)) if data_peer.ip() == self.control_peer_ip => {
                let _ = data.set_read_timeout(Some(DATA_RW_TIMEOUT));
                // Per-upload unique temp name (adjacent to `real`, so the rename
                // stays intra-device) so two concurrent STORs of the same target
                // never share a `.partial`. Mirrors ts-peerapi's `partial_seq`.
                let id = self.partial_seq.fetch_add(1, Ordering::Relaxed);
                let partial = format!("{real}.{id:016x}.upload.partial");
                let recv = stream_to_file(&mut data, Path::new(&partial), self.max_transfer_bytes);
                drop(data);
                match recv {
                    Ok(_) => match vita_fs::rename(Path::new(&partial), Path::new(&real)) {
                        Ok(()) => reply(r.get_mut(), 226, "stored"),
                        Err(e) => {
                            let _ = vita_fs::remove_file(Path::new(&partial));
                            warn!(error = %e, "ts-ftp.stor.rename");
                            reply(r.get_mut(), 550, "write failed")
                        }
                    },
                    Err(e) => {
                        let _ = vita_fs::remove_file(Path::new(&partial));
                        warn!(error = %e, "ts-ftp.stor.recv");
                        let code = if e.kind() == io::ErrorKind::FileTooLarge {
                            552
                        } else {
                            426
                        };
                        reply(r.get_mut(), code, "receive failed")
                    }
                }
            }
            Ok((_data, data_peer)) => {
                warn!(control = %self.control_peer_ip, %data_peer, "ts-ftp.data.peer_mismatch");
                reply(r.get_mut(), 425, "data peer mismatch")
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
            Ok((mut data, peer)) if peer.ip() == self.control_peer_ip => {
                info!(%peer, want = bytes.len(), "ts-ftp.data.accepted");
                let _ = data.set_write_timeout(Some(DATA_RW_TIMEOUT));
                pump_data(data, r.get_mut(), bytes)
            }
            Ok((_data, peer)) => {
                warn!(control = %self.control_peer_ip, %peer, "ts-ftp.data.peer_mismatch");
                reply(r.get_mut(), 425, "data peer mismatch")
            }
            Err(_) => {
                warn!("ts-ftp.data.accept_failed");
                reply(r.get_mut(), 425, "data connection failed")
            }
        }
    }
}

fn credentials_match(
    expected_user: &str,
    expected_password: &str,
    user: &str,
    password: &str,
) -> bool {
    use subtle::ConstantTimeEq;
    (expected_user.as_bytes().ct_eq(user.as_bytes())
        & expected_password.as_bytes().ct_eq(password.as_bytes()))
    .unwrap_u8()
        == 1
}

fn file_size(vfs: &Vfs, vpath: &str) -> Option<u64> {
    let (parent, name) = vfs::split_parent(vpath);
    let real_parent = vfs.to_real(&parent);
    vita_fs::read_dir(Path::new(&real_parent))
        .ok()?
        .into_iter()
        .find(|entry| entry.name == name && !entry.is_dir)
        .map(|entry| entry.size)
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

/// Receive a STOR body straight into a temporary file. This keeps the FTP
/// data path bounded even when a peer sends a file far larger than RAM.
fn stream_to_file(s: &mut TcpStream, path: &Path, max_bytes: u64) -> io::Result<u64> {
    vita_fs::write(path, b"")?;
    let mut buf = [0u8; 8192];
    let mut total = 0u64;
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                total = total.saturating_add(n as u64);
                if total > max_bytes {
                    return Err(io::Error::from(io::ErrorKind::FileTooLarge));
                }
                vita_fs::append(path, &buf[..n])?;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(e)
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;

    type Log = Rc<RefCell<Vec<String>>>;

    #[test]
    fn read_line_rejects_a_line_without_newline_over_the_cap() {
        // A newline-less stream longer than the cap must be rejected without
        // buffering all of it (the pre-auth memory-exhaustion guard). `Cursor`
        // never returns WouldBlock, so this exercises the `Take` bound rather
        // than the idle-timeout path.
        let payload = vec![b'A'; MAX_COMMAND_BYTES + 50];
        let mut reader = BufReader::new(Cursor::new(payload));
        let never = AtomicBool::new(false);
        assert_eq!(read_line(&mut reader, &never), None);
    }

    #[test]
    fn read_line_returns_a_normal_command() {
        let mut reader = BufReader::new(Cursor::new(b"USER vita\r\nPASS x\r\n".to_vec()));
        let never = AtomicBool::new(false);
        assert_eq!(read_line(&mut reader, &never).as_deref(), Some("USER vita"));
        assert_eq!(read_line(&mut reader, &never).as_deref(), Some("PASS x"));
    }

    #[test]
    fn credentials_require_exact_user_and_password() {
        assert!(credentials_match(
            "vita",
            "correct horse",
            "vita",
            "correct horse"
        ));
        assert!(!credentials_match(
            "vita",
            "correct horse",
            "other",
            "correct horse"
        ));
        assert!(!credentials_match("vita", "correct horse", "vita", "wrong"));
        assert!(!credentials_match("vita", "correct horse", "vita", ""));
    }

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
        let data = MockData {
            log: log.clone(),
            fail: false,
        };
        let mut ctrl = MockCtrl {
            log: log.clone(),
            buf: Vec::new(),
        };
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
        let data = MockData {
            log: log.clone(),
            fail: true,
        };
        let mut ctrl = MockCtrl {
            log: log.clone(),
            buf: Vec::new(),
        };
        pump_data(data, &mut ctrl, b"whatever").unwrap();
        assert_eq!(
            *log.borrow(),
            vec!["close".to_string(), "reply 426 transfer failed".to_string()]
        );
    }
}
