//! `ControlStream` — the TCP-or-TLS-wrapped socket the control client
//! uses for the post-upgrade Noise+HTTP/2 tunnel.
//!
//! Headscale dev runs cleartext HTTP (port 8080), so we used a bare
//! `TcpStream` end-to-end through M5–M12. M14 adds HTTPS for
//! `controlplane.tailscale.com:443`, which forces every layer above
//! the upgrade dance to be agnostic between plain and TLS-wrapped
//! TCP. Rather than pushing a generic parameter through every site,
//! we wrap the two cases in this enum and forward `Read` / `Write`
//! plus the `set_*_timeout` knobs the async-IO pump needs.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;

use crate::ControlError;

pub type Tls = StreamOwned<ClientConnection, TcpStream>;

pub enum ControlStream {
    Plain(TcpStream),
    Tls(Box<Tls>),
}

impl ControlStream {
    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        match self {
            ControlStream::Plain(s) => s.set_read_timeout(t),
            ControlStream::Tls(s) => s.get_ref().set_read_timeout(t),
        }
    }

    pub fn set_write_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        match self {
            ControlStream::Plain(s) => s.set_write_timeout(t),
            ControlStream::Tls(s) => s.get_ref().set_write_timeout(t),
        }
    }

    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        match self {
            ControlStream::Plain(s) => s.set_nodelay(on),
            ControlStream::Tls(s) => s.get_ref().set_nodelay(on),
        }
    }
}

impl Read for ControlStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ControlStream::Plain(s) => s.read(buf),
            ControlStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for ControlStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ControlStream::Plain(s) => s.write(buf),
            ControlStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ControlStream::Plain(s) => s.flush(),
            ControlStream::Tls(s) => s.flush(),
        }
    }
}

/// Wrap a `TcpStream` in rustls + webpki-roots, validating against
/// the given `server_name` (SNI / cert hostname). Builds the same
/// rustls `ClientConfig` shape as `ts-derp::handshake::wrap_tls` but
/// kept local to avoid an awkward cross-crate dep on ts-derp from
/// ts-control.
pub fn wrap_tls(tcp: TcpStream, server_name: &str) -> Result<ControlStream, ControlError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // builder_with_provider(ring) bypasses rustls' process-default
    // CryptoProvider, which is a std::sync::OnceLock — forbidden on the
    // SUPRX bootstrap thread (no pthread/_REENT init). See S6 audit.
    let mut config = rustls::ClientConfig::builder_with_provider(
        std::sync::Arc::new(rustls::crypto::ring::default_provider()),
    )
    .with_safe_default_protocol_versions()
    .expect("ring provider supports the safe default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    // ALPN `http/1.1` matches what Cloudflare's edge expects from
    // clients dialing `controlplane.tailscale.com` over HTTPS for the
    // 101 Upgrade flow. Go's `crypto/tls` always advertises ALPN
    // matching the next protocol.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // Honor `SSLKEYLOGFILE` for debugging — emits TLS session secrets
    // in NSS keylog format so Wireshark can decrypt captured traffic.
    // Equivalent to Go's `tls.Config.KeyLogWriter`. No-op when the
    // env var is unset.
    config.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());
    let server_name: ServerName<'static> = ServerName::try_from(server_name.to_owned())
        .map_err(|e| ControlError::Tls(format!("bad ServerName '{server_name}': {e}")))?;
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| ControlError::Tls(format!("rustls ClientConnection::new: {e}")))?;
    Ok(ControlStream::Tls(Box::new(StreamOwned::new(conn, tcp))))
}
