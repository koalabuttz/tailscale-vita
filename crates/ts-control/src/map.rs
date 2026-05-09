//! `/machine/map` long-poll driver.
//!
//! Runs on the foreground (caller's) thread. Owns the `Http2Conn` and
//! keeps a `NetMap` of the tailnet. Returns `MapEvent`s the demo can
//! act on — push to wg-engine, log the snapshot, etc.
//!
//! Wire pipeline:
//!
//! ```text
//! Http2Conn::next_chunk_timeout (Bytes, raw gzip-compressed)
//!         → flate2::Decompress (streaming)
//!         → length-prefix accumulator (4 B LE len + body)
//!         → serde_json -> MapResponseWire
//!         → NetMap::apply -> NetMapDelta
//! ```
//!
//! Persistence:
//! - `<state_dir>/last_seq`        — 8 B LE i64
//! - `<state_dir>/session_handle`  — utf-8 base64 (≤ 64 B)

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use http::Method;
use rand_core::{OsRng, RngCore};
use tracing::{debug, info, warn};

use crate::http2::{ChunkOutcome, Http2Conn};
use crate::netmap::{NetMap, NetMapDelta};
use crate::persist::atomic_write;
use crate::types::{
    DiscoPublic, MapHostinfoWire, MapRequestWire, MapResponseWire, NetInfoWire, NodePublic,
};
use crate::ControlError;

// Upstream's `tailcfg.CurrentCapabilityVersion` was 138 as of
// 2026-03-31. We started at 90 (Headscale 0.26 compat band), but
// real Tailscale at capver 138 may treat capver-90 clients as
// degraded — the open DiscoKey-zero issue is the prime suspect for
// that. Bumping to 138 to test. Headscale 0.26 may push back on
// this; if so, reintroduce a per-control_url override.
const MAP_VERSION: u32 = 138;
const IPN_VERSION: &str = "tailscale-vita/0.1.0";
const HOSTINFO_OS: &str = "linux";
const HOSTINFO_OS_VERSION: &str = "vita-3.74";
const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;
const WATCHDOG: Duration = Duration::from_secs(120);
const SESSION_HANDLE_BYTES: usize = 16;
const LAST_SEQ_FILE: &str = "last_seq";
const SESSION_HANDLE_FILE: &str = "session_handle";

pub struct MapClient {
    conn: Http2Conn,
    node_pub: NodePublic,
    disco_pub: DiscoPublic,
    hostname: String,
    /// Per-process logtail-style ID echoed in every MapRequest's
    /// Hostinfo for parity with upstream.
    backend_log_id: String,
    authority: String,
    state_dir: PathBuf,
    netmap: NetMap,
    framer: Framer,
    last_frame_at: Instant,
    /// Local endpoint candidates this node thinks peers can reach it on,
    /// formatted as `ip:port` (IPv4 or `[ipv6]:port`). Populated by the
    /// runtime once the Disco UDP socket is bound and the LAN IP is
    /// known. Sent in `MapRequest.Endpoints` on the next dial /
    /// reissue. Empty until M12F wires the runtime hook.
    local_endpoints: Vec<String>,
}

#[derive(Debug)]
pub enum MapEvent {
    /// A non-keepalive frame was applied. Carries the delta the caller
    /// should push into wg-engine.
    Snapshot(NetMapSnapshot),
    /// Server keepalive ping. Refreshes the watchdog; no NetMap change.
    KeepAlive { seq: i64 },
    /// `next_event` returned without a frame (caller's poll cadence
    /// elapsed). The connection is still healthy.
    Idle,
}

/// Public NetMap summary for the demo. The actual `NetMap` lives inside
/// `MapClient`; this is a read-only snapshot of what just changed.
#[derive(Debug)]
pub struct NetMapSnapshot {
    pub seq: i64,
    pub our_addrs: Vec<crate::netmap::AllowedIp>,
    pub peer_count: usize,
    pub derp_region_count: usize,
    pub delta: NetMapDelta,
}

impl MapClient {
    /// Open a streaming `/machine/map` request through `conn`. Loads
    /// (or generates) the persistent `last_seq` and `session_handle`.
    ///
    /// `local_endpoints` is the M12 direct-paths candidate list — pass
    /// `Vec::new()` to omit (Headscale tolerates empty Endpoints).
    pub fn start(
        mut conn: Http2Conn,
        node_pub: NodePublic,
        disco_pub: DiscoPublic,
        hostname: String,
        backend_log_id: String,
        authority: String,
        state_dir: PathBuf,
        local_endpoints: Vec<String>,
    ) -> Result<Self, ControlError> {
        let (last_seq, session_handle) = load_session_state(&state_dir)?;
        info!(
            last_seq,
            handle_short = %short_handle(&session_handle),
            endpoint_count = local_endpoints.len(),
            "control.map.session.resume"
        );

        let request = build_map_request(
            &node_pub,
            &disco_pub,
            &hostname,
            &backend_log_id,
            last_seq,
            &session_handle,
            &local_endpoints,
        );
        let body = serde_json::to_vec(&request)?;
        info!(
            body_len = body.len(),
            seq = last_seq,
            body = %String::from_utf8_lossy(&body),
            "control.map.request.send"
        );

        let head = conn.request_stream(
            Method::POST,
            "/machine/map",
            &body,
            &[
                ("content-type", "application/json"),
                ("accept-encoding", "gzip"),
            ],
            &authority,
        )?;

        if head.status != 200 {
            return Err(ControlError::Http {
                status: head.status,
                body: format!("/machine/map non-200 head"),
            });
        }

        let gzipped = head
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-encoding") && v.contains("gzip"));
        info!(gzipped, "control.map.stream.opened");

        let mut netmap = NetMap::default();
        netmap.last_seq = last_seq;
        netmap.session_handle = session_handle;

        Ok(Self {
            conn,
            node_pub,
            disco_pub,
            hostname,
            backend_log_id,
            authority,
            state_dir,
            netmap,
            framer: Framer::new(gzipped),
            last_frame_at: Instant::now(),
            local_endpoints,
        })
    }

    /// Replace the local-endpoint candidate list. Takes effect on the
    /// next `reissue()` (the open long-poll continues to advertise the
    /// previous set until it cycles).
    pub fn set_local_endpoints(&mut self, endpoints: Vec<String>) {
        info!(
            count = endpoints.len(),
            "control.map.local_endpoints.set"
        );
        self.local_endpoints = endpoints;
    }

    /// Drive the long-poll for one event with a per-call deadline. The
    /// 2-minute watchdog fires across calls (`last_frame_at` tracks
    /// when we last saw any frame, including KeepAlives).
    pub fn next_event(&mut self, timeout: Duration) -> Result<MapEvent, ControlError> {
        let watchdog_deadline = self.last_frame_at + WATCHDOG;
        let now = Instant::now();
        if now >= watchdog_deadline {
            return Err(ControlError::MapWatchdog {
                idle_secs: WATCHDOG.as_secs(),
            });
        }
        let effective = std::cmp::min(timeout, watchdog_deadline - now);

        match self.framer.next_frame(&mut self.conn, effective)? {
            FrameOutcome::Frame(resp) => {
                self.last_frame_at = Instant::now();
                self.handle_frame(resp)
            }
            FrameOutcome::Timeout => Ok(MapEvent::Idle),
            FrameOutcome::Eof => Err(ControlError::MapConnectionLost(
                "server closed map stream".into(),
            )),
        }
    }

    fn handle_frame(&mut self, resp: MapResponseWire) -> Result<MapEvent, ControlError> {
        if resp.keep_alive {
            debug!(seq = resp.seq, "control.map.keepalive");
            return Ok(MapEvent::KeepAlive { seq: resp.seq });
        }

        let prev_handle = self.netmap.session_handle.clone();
        let delta = self.netmap.apply(&resp);

        // Persist last_seq after every applied frame.
        if delta.seq > 0 {
            persist_last_seq(&self.state_dir, delta.seq)?;
        }
        // Persist session_handle if the server assigned/changed one.
        if !self.netmap.session_handle.is_empty()
            && self.netmap.session_handle != prev_handle
        {
            persist_session_handle(&self.state_dir, &self.netmap.session_handle)?;
        }

        info!(
            seq = delta.seq,
            peer_count = self.netmap.peers.len(),
            upserted = delta.upserted.len(),
            removed = delta.removed.len(),
            rekeyed = delta.rekeyed.len(),
            patches = delta.patches_applied,
            our_addrs = ?self.netmap.our_addrs,
            "control.map.netmap"
        );

        Ok(MapEvent::Snapshot(NetMapSnapshot {
            seq: delta.seq,
            our_addrs: self.netmap.our_addrs.clone(),
            peer_count: self.netmap.peers.len(),
            derp_region_count: self.netmap.derp_regions.len(),
            delta,
        }))
    }

    /// Soft reconnect: re-issue `POST /machine/map` over the same
    /// `Http2Conn`. Used after a clean EOF (server closed the map
    /// stream — typically a no-op idle terminator) without rebuilding
    /// the Noise tunnel.
    pub fn reissue(&mut self) -> Result<(), ControlError> {
        warn!(
            seq = self.netmap.last_seq,
            handle_short = %short_handle(&self.netmap.session_handle),
            "control.map.reissue"
        );
        self.conn.drop_stream();
        self.framer = Framer::new(true); // assume gzip; will re-detect from head

        let request = build_map_request(
            &self.node_pub,
            &self.disco_pub,
            &self.hostname,
            &self.backend_log_id,
            self.netmap.last_seq,
            &self.netmap.session_handle,
            &self.local_endpoints,
        );
        let body = serde_json::to_vec(&request)?;
        let head = self.conn.request_stream(
            Method::POST,
            "/machine/map",
            &body,
            &[
                ("content-type", "application/json"),
                ("accept-encoding", "gzip"),
            ],
            &self.authority,
        )?;
        if head.status != 200 {
            return Err(ControlError::Http {
                status: head.status,
                body: "reissue /machine/map non-200".into(),
            });
        }
        let gzipped = head
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-encoding") && v.contains("gzip"));
        self.framer = Framer::new(gzipped);
        self.last_frame_at = Instant::now();
        Ok(())
    }

    /// Surrender the inner `Http2Conn` so the caller can drop it (or
    /// build a new MapClient on top of it).
    pub fn into_conn(self) -> Http2Conn {
        self.conn
    }

    /// Read-only access to the current NetMap.
    pub fn netmap(&self) -> &NetMap {
        &self.netmap
    }
}

fn build_map_request(
    node_pub: &NodePublic,
    disco_pub: &DiscoPublic,
    hostname: &str,
    backend_log_id: &str,
    last_seq: i64,
    session_handle: &str,
    endpoints: &[String],
) -> MapRequestWire {
    MapRequestWire {
        version: MAP_VERSION,
        compress: String::new(),
        keep_alive: true,
        node_key: node_pub.to_nodekey_string(),
        disco_key: disco_pub.to_discokey_string(),
        hostinfo: MapHostinfoWire {
            ipn_version: IPN_VERSION.into(),
            backend_log_id: backend_log_id.into(),
            hostname: hostname.into(),
            os: HOSTINFO_OS.into(),
            os_version: HOSTINFO_OS_VERSION.into(),
            net_info: NetInfoWire {
                // PreferredDERP=0 means "haven't picked a home region
                // yet" — valid for the first MapRequest. The runtime
                // can call `set_preferred_derp` after derp probing
                // settles to refresh this on the next reissue. Not
                // currently wired (no observable difference vs 0
                // tested against real Tailscale; see M14B notes).
                preferred_derp: 0,
                link_type: String::new(),
                working_udp: Some(true),
                working_ipv6: Some(false),
                have_port_map: false,
            },
        },
        stream: true,
        omit_peers: false,
        read_only: false,
        endpoints: endpoints.to_vec(),
        map_session_handle: session_handle.to_string(),
        map_session_seq: last_seq,
    }
}

// ---------- Framer: gzip + length-prefix accumulator ----------------------

enum FrameOutcome {
    Frame(MapResponseWire),
    Eof,
    Timeout,
}

/// Streams gzip-compressed or identity bytes from `Http2Conn` into a
/// running buffer, then peels off `[u32_le len][body]` frames as they
/// become available.
///
/// **Why threaded gzip**: flate2's `write::GzDecoder<Vec<u8>>` and
/// `write::DeflateDecoder<Vec<u8>>` both buffer their output internally
/// — bytes don't appear in the inner sink until `finish()` is called.
/// That defeats streaming. The `read::GzDecoder<R>` family streams
/// correctly, but needs a `R: Read` source that blocks rather than
/// returning Ok(0) (which signals EOF and ends the decompressor).
///
/// Solution: a dedicated worker thread runs `read::GzDecoder<ChannelReader>`
/// where `ChannelReader::read` blocks on a `mpsc::Receiver<Vec<u8>>`. The
/// framer pushes compressed bytes into the channel; the worker emits
/// decompressed bytes onto a second channel. Same pattern as M5's
/// `noise_pump` thread.
struct Framer {
    decoder: Option<GzipWorker>,
    plain_buf: Vec<u8>, // accumulator for identity-encoded streams
    gzip_buf: Vec<u8>,  // accumulator for gzip-decompressed bytes from worker
}

impl Framer {
    fn new(gzipped: bool) -> Self {
        Self {
            decoder: if gzipped {
                Some(GzipWorker::spawn())
            } else {
                None
            },
            plain_buf: Vec::with_capacity(64 * 1024),
            gzip_buf: Vec::with_capacity(64 * 1024),
        }
    }

    fn next_frame(
        &mut self,
        conn: &mut Http2Conn,
        timeout: Duration,
    ) -> Result<FrameOutcome, ControlError> {
        let deadline = Instant::now() + timeout;
        loop {
            self.drain_decompressor()?;
            if let Some(frame) = self.try_extract()? {
                return Ok(FrameOutcome::Frame(frame));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(FrameOutcome::Timeout);
            }
            let remaining = deadline - now;
            match conn.next_chunk_timeout(remaining)? {
                ChunkOutcome::Chunk(c) => self.feed(c)?,
                ChunkOutcome::Eof => {
                    // Flush any remaining decompressed bytes before signaling EOF.
                    if let Some(w) = self.decoder.as_mut() {
                        w.close_input();
                    }
                    self.drain_decompressor()?;
                    if let Some(frame) = self.try_extract()? {
                        return Ok(FrameOutcome::Frame(frame));
                    }
                    return Ok(FrameOutcome::Eof);
                }
                ChunkOutcome::Timeout => return Ok(FrameOutcome::Timeout),
            }
        }
    }

    fn feed(&mut self, chunk: Bytes) -> Result<(), ControlError> {
        if let Some(w) = self.decoder.as_mut() {
            w.feed(chunk.to_vec())?;
        } else {
            self.plain_buf.extend_from_slice(chunk.as_ref());
        }
        Ok(())
    }

    /// Pull whatever decompressed bytes the worker has produced since
    /// last poll. Non-blocking.
    fn drain_decompressor(&mut self) -> Result<(), ControlError> {
        if let Some(w) = self.decoder.as_mut() {
            w.drain_into(&mut self.gzip_buf)?;
        }
        Ok(())
    }

    fn buffer_mut(&mut self) -> &mut Vec<u8> {
        if self.decoder.is_some() {
            &mut self.gzip_buf
        } else {
            &mut self.plain_buf
        }
    }

    fn try_extract(&mut self) -> Result<Option<MapResponseWire>, ControlError> {
        let buf = self.buffer_mut();
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(ControlError::MapFrameTooLarge {
                len,
                cap: MAX_FRAME_SIZE,
            });
        }
        if buf.len() < 4 + len {
            return Ok(None);
        }
        let body_slice = &buf[4..4 + len];
        let resp: MapResponseWire = serde_json::from_slice(body_slice)
            .map_err(|e| ControlError::MapDecode(format!("json: {e}")))?;
        buf.drain(..4 + len);
        Ok(Some(resp))
    }
}

// ---------- Threaded gzip decompressor ------------------------------------

struct GzipWorker {
    compressed_tx: Option<Sender<Vec<u8>>>,
    decompressed_rx: Receiver<Result<Vec<u8>, String>>,
    join: Option<JoinHandle<()>>,
}

impl GzipWorker {
    fn spawn() -> Self {
        let (compressed_tx, compressed_rx) = mpsc::channel::<Vec<u8>>();
        let (decompressed_tx, decompressed_rx) = mpsc::channel::<Result<Vec<u8>, String>>();
        let join = thread::Builder::new()
            .name("ts-gz".into())
            .stack_size(256 * 1024)
            .spawn(move || run_gzip_worker(compressed_rx, decompressed_tx))
            .expect("spawn ts-gz worker");
        Self {
            compressed_tx: Some(compressed_tx),
            decompressed_rx,
            join: Some(join),
        }
    }

    fn feed(&mut self, bytes: Vec<u8>) -> Result<(), ControlError> {
        let tx = self
            .compressed_tx
            .as_ref()
            .ok_or_else(|| ControlError::MapDecode("gzip worker closed".into()))?;
        tx.send(bytes)
            .map_err(|_| ControlError::MapDecode("gzip worker recv side closed".into()))
    }

    fn drain_into(&mut self, out: &mut Vec<u8>) -> Result<(), ControlError> {
        loop {
            match self.decompressed_rx.try_recv() {
                Ok(Ok(chunk)) => out.extend_from_slice(&chunk),
                Ok(Err(e)) => return Err(ControlError::MapDecode(e)),
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }

    fn close_input(&mut self) {
        // Dropping the sender signals EOF to the worker.
        self.compressed_tx = None;
    }
}

impl Drop for GzipWorker {
    fn drop(&mut self) {
        // Ensure compressed_tx is dropped first so the worker exits.
        self.compressed_tx = None;
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn run_gzip_worker(
    rx: Receiver<Vec<u8>>,
    tx: Sender<Result<Vec<u8>, String>>,
) {
    let reader = ChannelReader {
        rx,
        leftover: Vec::new(),
        leftover_pos: 0,
    };
    let mut decoder = flate2::read::GzDecoder::new(reader);
    let mut buf = [0u8; 8192];
    loop {
        match decoder.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                if tx.send(Ok(buf[..n].to_vec())).is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(format!("gzip: {e}")));
                break;
            }
        }
    }
}

struct ChannelReader {
    rx: Receiver<Vec<u8>>,
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl std::io::Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        // Refill leftover if exhausted.
        while self.leftover_pos >= self.leftover.len() {
            match self.rx.recv() {
                Ok(c) => {
                    self.leftover = c;
                    self.leftover_pos = 0;
                }
                Err(_) => return Ok(0), // sender dropped == EOF
            }
        }
        let avail = self.leftover.len() - self.leftover_pos;
        let n = out.len().min(avail);
        out[..n].copy_from_slice(&self.leftover[self.leftover_pos..self.leftover_pos + n]);
        self.leftover_pos += n;
        Ok(n)
    }
}

// ---------- Persistence ---------------------------------------------------

fn load_session_state(dir: &Path) -> Result<(i64, String), ControlError> {
    let last_seq = match std::fs::read(dir.join(LAST_SEQ_FILE)) {
        Ok(b) if b.len() == 8 => i64::from_le_bytes(b.try_into().unwrap()),
        _ => 0,
    };
    let session_handle = match std::fs::read(dir.join(SESSION_HANDLE_FILE)) {
        Ok(b) => String::from_utf8(b)
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => generate_session_handle(dir)?,
        Err(e) => return Err(ControlError::Io(e)),
    };
    Ok((last_seq, session_handle))
}

fn generate_session_handle(dir: &Path) -> Result<String, ControlError> {
    let mut bytes = [0u8; SESSION_HANDLE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let handle = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    persist_session_handle(dir, &handle)?;
    Ok(handle)
}

fn persist_last_seq(dir: &Path, seq: i64) -> Result<(), ControlError> {
    atomic_write(&dir.join(LAST_SEQ_FILE), &seq.to_le_bytes())
}

fn persist_session_handle(dir: &Path, handle: &str) -> Result<(), ControlError> {
    atomic_write(&dir.join(SESSION_HANDLE_FILE), handle.as_bytes())
}

fn short_handle(s: &str) -> String {
    if s.len() <= 8 {
        s.to_string()
    } else {
        format!("{}…", &s[..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// Drive the framer's gzip worker until either a frame is ready,
    /// the buffer reaches the expected size, or `deadline` elapses.
    fn drain_until(framer: &mut Framer, deadline: Instant) {
        while Instant::now() < deadline {
            framer.drain_decompressor().unwrap();
            if framer.buffer_mut().len() >= 4 {
                let len = u32::from_le_bytes([
                    framer.buffer_mut()[0],
                    framer.buffer_mut()[1],
                    framer.buffer_mut()[2],
                    framer.buffer_mut()[3],
                ]) as usize;
                if framer.buffer_mut().len() >= 4 + len {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Build a synthetic gzip stream of `[u32_le len][JSON]` frames and
    /// verify the framer extracts them in order. The framer's gzip
    /// worker runs in a background thread, so we poll-with-deadline.
    #[test]
    fn frame_decoder_roundtrip() {
        let frames = vec![
            br#"{"KeepAlive":true}"#.to_vec(),
            br#"{"Seq":1,"Domain":"example.com"}"#.to_vec(),
            br#"{"Seq":2,"KeepAlive":true}"#.to_vec(),
        ];
        let mut wire = Vec::new();
        for f in &frames {
            wire.extend_from_slice(&(f.len() as u32).to_le_bytes());
            wire.extend_from_slice(f);
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&wire).unwrap();
        let compressed = gz.finish().unwrap();

        let mut framer = Framer::new(true);
        framer.feed(Bytes::from(compressed)).unwrap();

        let extract_deadline = || Instant::now() + Duration::from_secs(2);

        drain_until(&mut framer, extract_deadline());
        let f1 = framer.try_extract().unwrap().unwrap();
        assert!(f1.keep_alive);

        drain_until(&mut framer, extract_deadline());
        let f2 = framer.try_extract().unwrap().unwrap();
        assert_eq!(f2.seq, 1);
        assert_eq!(f2.domain, "example.com");

        drain_until(&mut framer, extract_deadline());
        let f3 = framer.try_extract().unwrap().unwrap();
        assert_eq!(f3.seq, 2);
        assert!(f3.keep_alive);
    }

    #[test]
    fn frame_decoder_handles_split_chunks() {
        let frame = br#"{"Seq":7}"#.to_vec();
        let mut wire = Vec::new();
        wire.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        wire.extend_from_slice(&frame);
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&wire).unwrap();
        let compressed = gz.finish().unwrap();

        let mut framer = Framer::new(true);
        // Feed in small slices to exercise streaming decompression.
        for slice in compressed.chunks(3) {
            framer.feed(Bytes::copy_from_slice(slice)).unwrap();
        }
        drain_until(&mut framer, Instant::now() + Duration::from_secs(2));
        let f = framer.try_extract().unwrap().unwrap();
        assert_eq!(f.seq, 7);
    }

    #[test]
    fn frame_decoder_rejects_huge_frame() {
        // Hand-craft a 4-byte LE length of 16 MiB (> MAX_FRAME_SIZE) on
        // an identity-encoded stream.
        let mut wire = Vec::new();
        wire.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes());
        // No body bytes are needed; the cap check fires before we read body.
        let mut framer = Framer::new(false);
        framer.feed(Bytes::from(wire)).unwrap();
        assert!(matches!(
            framer.try_extract(),
            Err(ControlError::MapFrameTooLarge { len: _, cap: _ })
        ));
    }

    #[test]
    fn short_handle_truncates() {
        assert_eq!(short_handle("abc"), "abc");
        assert_eq!(short_handle("abcdefghij"), "abcdefgh…");
    }
}
