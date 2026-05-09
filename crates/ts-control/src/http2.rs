//! Plan A: HTTP/2 client driven by `h2` over our `AsyncNoiseStream`.
//! See `M5a-DECISION.md`.
//!
//! Architecture:
//! - We own a tokio current-thread runtime (no `enable_io`, no `mio` —
//!   works on Vita's Tier-3 target where `vita-rust/mio` is archived).
//! - On `Http2Conn::open`, we run `h2::client::handshake` to negotiate
//!   SETTINGS, then spawn a tokio task that drives the `Connection`
//!   future. The `SendRequest` half is kept on the foreground.
//! - `request()` uses `block_on` to send a request and read the full
//!   response. v1 doesn't yet need streaming bodies that outlive a
//!   single request — M7's MapResponse long-poll uses a different path.
//! - On Drop, the runtime is shut down → tasks aborted → AsyncNoiseStream
//!   drops → noise-pump thread joined.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Method, Request};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::{Builder, Runtime};
use tracing::{debug, info};

use crate::async_io::AsyncNoiseStream;
use crate::ControlError;

/// User-Agent stamped on every `/machine/*` HTTP/2 request over the
/// Noise tunnel (M14F). Kept identical to the value we send on the
/// HTTP/1.1 `/ts2021` upgrade — a single string lets server-side log
/// joiners correlate the upgrade and the post-upgrade requests.
const USER_AGENT: &str = "tailscale-vita/0.1";

/// One opened HTTP/2 connection over a Noise tunnel.
pub struct Http2Conn {
    rt: Runtime,
    send: h2::client::SendRequest<Bytes>,
    _conn_task: tokio::task::JoinHandle<()>,
    /// M7: streaming body from the most recent `request_stream`. `None`
    /// when no stream is in flight; `Some(...)` after a successful
    /// `request_stream` until the body is fully drained or the conn drops.
    body: Option<h2::RecvStream>,
}

/// Response head returned by `request_stream` — body chunks come later
/// via `Http2Conn::next_chunk`.
pub struct Http2ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

/// Outcome of `next_chunk_timeout`: a chunk, clean EOF, or the timeout
/// elapsed without either.
pub enum ChunkOutcome {
    Chunk(Bytes),
    Eof,
    Timeout,
}

/// Newtype so we can implement `AsyncRead + AsyncWrite` for the move into
/// h2 without the orphan-rules problems of impl'ing on a foreign type.
struct AsyncNoiseStreamPin(AsyncNoiseStream);

impl AsyncRead for AsyncNoiseStreamPin {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for AsyncNoiseStreamPin {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub struct Http2Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Http2Conn {
    pub fn open(stream: AsyncNoiseStream) -> Result<Self, ControlError> {
        let rt = Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|e| ControlError::Transport(format!("tokio Builder: {e}")))?;

        let stream = AsyncNoiseStreamPin(stream);

        let (send, conn_fut) = rt
            .block_on(async move { h2::client::handshake(stream).await })
            .map_err(|e| ControlError::Transport(format!("h2 handshake: {e}")))?;
        info!("control.http2.handshake.complete");

        let conn_task = rt.spawn(async move {
            if let Err(e) = conn_fut.await {
                debug!(error = %e, "h2 Connection future ended");
            }
        });

        Ok(Self {
            rt,
            send,
            _conn_task: conn_task,
            body: None,
        })
    }

    /// Variant of `request` for streaming response bodies (M7's
    /// `/machine/map` long-poll).
    ///
    /// Sends the request, awaits the response head, then stashes the
    /// `RecvStream` on `self`. Caller drains chunks via `next_chunk()`
    /// in a loop. Calling `request_stream` again drops any pending body.
    pub fn request_stream(
        &mut self,
        method: Method,
        path: &str,
        body: &[u8],
        extra_headers: &[(&str, &str)],
        authority: &str,
    ) -> Result<Http2ResponseHead, ControlError> {
        // Drop any pending body before starting a new stream.
        self.body = None;

        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", authority)
            // M14F: Cloudflare/Tailscale-edge appears to soft-degrade
            // HTTP/2 requests with no User-Agent (treats as bot-like).
            // Go's stdlib `http.Client` always sets one (defaults to
            // `Go-http-client/1.1`); we match the *intent* by sending
            // an explicit Vita-flavored UA so we look like a real
            // client at the WAF layer.
            .header("user-agent", USER_AGENT);
        for (k, v) in extra_headers {
            builder = builder.header(*k, *v);
        }
        let req = builder
            .body(())
            .map_err(|e| ControlError::Transport(format!("build request: {e}")))?;

        let body_bytes = Bytes::copy_from_slice(body);
        let send_handle = self.send.clone();
        let path_owned = path.to_string();

        let (status, headers, recv_stream) = self.rt.block_on(async move {
            let send = send_handle;
            let mut send = send
                .ready()
                .await
                .map_err(|e| ControlError::Transport(format!("h2 ready: {e}")))?;
            let (resp_fut, mut send_stream) = send
                .send_request(req, body_bytes.is_empty())
                .map_err(|e| ControlError::Transport(format!("h2 send_request: {e}")))?;
            if !body_bytes.is_empty() {
                send_stream
                    .send_data(body_bytes, true)
                    .map_err(|e| ControlError::Transport(format!("h2 send_data: {e}")))?;
            }
            let resp = resp_fut
                .await
                .map_err(|e| ControlError::Transport(format!("h2 resp: {e}")))?;
            let status = resp.status().as_u16();
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_owned(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect();
            let recv_stream = resp.into_body();
            Ok::<_, ControlError>((status, headers, recv_stream))
        })?;

        info!(
            status,
            headers_count = headers.len(),
            path = %path_owned,
            "control.http2.response_head"
        );
        self.body = Some(recv_stream);
        Ok(Http2ResponseHead { status, headers })
    }

    /// Block on the next chunk of the streaming body stored on `self`.
    /// Returns `Ok(None)` at clean EOF. Auto-releases flow-control credit
    /// per chunk so the h2 window doesn't stall.
    pub fn next_chunk(&mut self) -> Result<Option<Bytes>, ControlError> {
        let Self { rt, body, .. } = self;
        let body_ref = body
            .as_mut()
            .ok_or_else(|| ControlError::Transport("no streaming body active".into()))?;
        rt.block_on(async {
            match body_ref.data().await {
                Some(Ok(c)) => {
                    let _ = body_ref.flow_control().release_capacity(c.len());
                    Ok(Some(c))
                }
                Some(Err(e)) => Err(ControlError::Transport(format!("h2 body chunk: {e}"))),
                None => Ok(None),
            }
        })
    }

    /// Variant of `next_chunk` with a deadline. Returns
    /// `ChunkOutcome::Timeout` if no chunk arrived within `timeout`,
    /// allowing the caller to re-check upper-level deadlines (e.g.
    /// the M7 framer's 2-min watchdog) without blocking forever.
    pub fn next_chunk_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<ChunkOutcome, ControlError> {
        let Self { rt, body, .. } = self;
        let body_ref = body
            .as_mut()
            .ok_or_else(|| ControlError::Transport("no streaming body active".into()))?;
        rt.block_on(async {
            match tokio::time::timeout(timeout, body_ref.data()).await {
                Ok(Some(Ok(c))) => {
                    let _ = body_ref.flow_control().release_capacity(c.len());
                    Ok(ChunkOutcome::Chunk(c))
                }
                Ok(Some(Err(e))) => {
                    Err(ControlError::Transport(format!("h2 body chunk: {e}")))
                }
                Ok(None) => Ok(ChunkOutcome::Eof),
                Err(_elapsed) => Ok(ChunkOutcome::Timeout),
            }
        })
    }

    /// True if a streaming body is currently attached.
    pub fn streaming(&self) -> bool {
        self.body.is_some()
    }

    /// Drop any attached streaming body (e.g., before a soft reconnect
    /// re-issues the request).
    pub fn drop_stream(&mut self) {
        self.body = None;
    }

    /// Issue an HTTP/2 request. Reads the full response body before
    /// returning.
    pub fn request(
        &mut self,
        method: Method,
        path: &str,
        body: &[u8],
        extra_headers: &[(&str, &str)],
        authority: &str,
    ) -> Result<Http2Response, ControlError> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", authority)
            // M14F: see request_stream() for User-Agent rationale.
            .header("user-agent", USER_AGENT);
        for (k, v) in extra_headers {
            builder = builder.header(*k, *v);
        }
        let req = builder
            .body(())
            .map_err(|e| ControlError::Transport(format!("build request: {e}")))?;

        let body_bytes = Bytes::copy_from_slice(body);
        let send_handle = self.send.clone();
        let path_owned = path.to_string();

        self.rt.block_on(async move {
            let mut send = send_handle;
            let mut send = send
                .ready()
                .await
                .map_err(|e| ControlError::Transport(format!("h2 ready: {e}")))?;
            let (resp_fut, mut send_stream) = send
                .send_request(req, body_bytes.is_empty())
                .map_err(|e| ControlError::Transport(format!("h2 send_request: {e}")))?;
            if !body_bytes.is_empty() {
                send_stream
                    .send_data(body_bytes, true)
                    .map_err(|e| ControlError::Transport(format!("h2 send_data: {e}")))?;
            }
            let resp = resp_fut
                .await
                .map_err(|e| ControlError::Transport(format!("h2 resp: {e}")))?;
            let status = resp.status().as_u16();
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                .collect();
            let mut body_stream = resp.into_body();
            let mut body = Vec::new();
            while let Some(chunk) = body_stream
                .data()
                .await
                .transpose()
                .map_err(|e| ControlError::Transport(format!("h2 body chunk: {e}")))?
            {
                body.extend_from_slice(&chunk);
                let _ = body_stream.flow_control().release_capacity(chunk.len());
            }
            info!(status, body_len = body.len(), path = %path_owned, "control.http2.response");
            Ok(Http2Response { status, headers, body })
        })
    }
}
