//! Per-control-connection FTP session: greet, then read CRLF command lines
//! and dispatch until QUIT or disconnect. Serial (one session at a time) and
//! PASV-only. Permissive auth — the tailnet ACL is the boundary.

use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::Path;

use netstack::tcp::TcpStream;
use netstack::TcpListener;
use vita_log::{debug, warn};

use crate::command::{self, Command};
use crate::reply::{reply, reply_multiline};
use crate::vfs::{self, Vfs};
use crate::{data, listing, Ctx, CTRL_IDLE_TIMEOUT, DATA_ACCEPT_TIMEOUT, DATA_RW_TIMEOUT};

/// Control reader: a `BufReader` over the control stream. `get_mut()` yields
/// the underlying stream for writing replies (writes bypass the read buffer).
type Ctrl = BufReader<TcpStream>;

enum Flow {
    Continue,
    Quit,
}

/// Handle one control connection start-to-finish.
pub(crate) fn handle(ctrl: TcpStream, peer: SocketAddr, ctx: &Ctx) {
    let mut ctrl = ctrl;
    let _ = ctrl.set_read_timeout(Some(CTRL_IDLE_TIMEOUT));
    let _ = ctrl.set_write_timeout(Some(DATA_RW_TIMEOUT));
    let mut reader = BufReader::new(ctrl);

    if reply(reader.get_mut(), 220, "ts-ftp ready").is_err() {
        return;
    }

    let mut session = Session::new(ctx);
    loop {
        let line = match read_line(&mut reader) {
            Some(l) => l,
            None => break, // EOF, idle timeout, or read error
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

/// Read one CRLF-terminated command line, stripping the line ending. Returns
/// `None` on EOF / idle-timeout / error (all end the session).
fn read_line(reader: &mut Ctrl) -> Option<String> {
    let mut buf = Vec::new();
    match reader.read_until(b'\n', &mut buf) {
        Ok(0) => None,
        Ok(_) => {
            while matches!(buf.last(), Some(b'\n' | b'\r')) {
                buf.pop();
            }
            Some(String::from_utf8_lossy(&buf).into_owned())
        }
        Err(_) => None,
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
    /// Next PASV port to try (rotates through the configured range).
    next_port: u16,
    pasv_lo: u16,
    pasv_hi: u16,
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
            next_port: ctx.cfg.passive_port_lo,
            pasv_lo: ctx.cfg.passive_port_lo,
            pasv_hi: ctx.cfg.passive_port_hi,
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
                reply_multiline(r.get_mut(), 211, "Features", &["PASV", "SIZE", "UTF8"], "End")?;
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
                let m = format!("\"{}\" is current directory", self.cwd);
                reply(r.get_mut(), 257, &m)?;
            }
            Cwd(arg) => self.do_cwd(arg, r)?,
            Cdup => self.do_cwd("..", r)?,
            Pasv => self.do_pasv(r, ctx)?,
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
        match data::bind_passive(&ctx.stack, &mut self.next_port, self.pasv_lo, self.pasv_hi) {
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

    fn do_list(&mut self, arg: Option<&str>, names_only: bool, r: &mut Ctrl) -> io::Result<()> {
        // Resolve the target dir: ignore `ls`-style flag args (e.g. "-la").
        let vpath = match arg {
            Some(a) if !a.is_empty() && !a.starts_with('-') => match self.vfs.resolve(&self.cwd, a) {
                Some(v) => v,
                None => return reply(r.get_mut(), 550, "invalid path"),
            },
            _ => self.cwd.clone(),
        };
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
        let bytes = match vita_fs::read(Path::new(&real)) {
            Ok(b) => b,
            Err(_) => return reply(r.get_mut(), 550, "no such file"),
        };
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
            Ok(()) => reply(r.get_mut(), 257, &format!("\"{vpath}\" created")),
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

    /// Open the pending PASV data connection, write `bytes`, close it (the
    /// close drains/flushes), and report `226`/`426`. `425` if no PASV.
    fn send_data(&mut self, bytes: &[u8], r: &mut Ctrl) -> io::Result<()> {
        let (listener, _) = match self.pasv.take() {
            Some(x) => x,
            None => return reply(r.get_mut(), 425, "use PASV first"),
        };
        reply(r.get_mut(), 150, "opening data connection")?;
        match listener.accept_timeout(DATA_ACCEPT_TIMEOUT) {
            Ok((mut data, _)) => {
                let _ = data.set_write_timeout(Some(DATA_RW_TIMEOUT));
                let sent = data.write_all(bytes);
                drop(data); // FIN + 2s TX-drain flushes the bytes
                match sent {
                    Ok(()) => reply(r.get_mut(), 226, "transfer complete"),
                    Err(e) => {
                        warn!(error = %e, "ts-ftp.data.write");
                        reply(r.get_mut(), 426, "transfer failed")
                    }
                }
            }
            Err(_) => reply(r.get_mut(), 425, "data connection failed"),
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
