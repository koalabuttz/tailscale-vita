//! Match incoming `(method, path)` to an endpoint handler. Trivial
//! routing — LocalAPI's surface is small enough that a match block
//! is cleaner than a pattern-trie crate.

use std::sync::Arc;

use parking_lot::RwLock;
use ts_magicsock::MagicSocketCtl;

use crate::localapi::handlers;
use crate::localapi::http::{Request, write_error, write_json_response};
use crate::runtime::ControlHandle;
use crate::snapshot::RuntimeSnapshot;

use std::net::TcpStream;

/// Bundled state every handler needs. Cheap to clone (Arc-only +
/// MagicSocketCtl is already a thin Arc-wrapper).
#[derive(Clone)]
pub struct HandlerCtx {
    pub snapshot: Arc<RwLock<RuntimeSnapshot>>,
    pub controller: ControlHandle,
    pub magic: MagicSocketCtl,
}

/// Dispatch one request to the right handler. Writes the response
/// directly to the stream so individual handlers don't have to
/// allocate twice.
pub fn dispatch(
    stream: &mut TcpStream,
    req: &Request,
    ctx: &HandlerCtx,
) -> std::io::Result<()> {
    let result = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/localapi/v0/status") => {
            let (status, body) = handlers::status(ctx);
            write_json_response(stream, status, &body)
        }
        ("GET", "/localapi/v0/whois") => {
            let (status, body) = handlers::whois(ctx, &req.query);
            write_json_response(stream, status, &body)
        }
        ("GET", "/localapi/v0/health") => {
            let (status, body) = handlers::health(ctx);
            write_json_response(stream, status, &body)
        }
        ("GET", "/localapi/v0/netmap") => {
            let (status, body) = handlers::netmap(ctx);
            write_json_response(stream, status, &body)
        }
        ("GET", "/localapi/v0/ping") => {
            let (status, body) = handlers::ping(ctx, &req.query);
            write_json_response(stream, status, &body)
        }
        ("POST", "/localapi/v0/reconnect") => {
            let (status, body) = handlers::reconnect(ctx);
            write_json_response(stream, status, &body)
        }
        ("GET", _) | ("POST", _) => write_error(stream, 404, "no such endpoint"),
        _ => write_error(stream, 405, "method not allowed"),
    };
    result
}
