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

/// One opened HTTP/2 connection over a Noise tunnel.
pub struct Http2Conn {
    rt: Runtime,
    send: h2::client::SendRequest<Bytes>,
    _conn_task: tokio::task::JoinHandle<()>,
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
        })
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
            .header("host", authority);
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
