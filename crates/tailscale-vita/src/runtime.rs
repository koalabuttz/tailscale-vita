//! `Runtime` — the long-running tailnet client. Owns the Noise tunnel,
//! HTTP/2 conn, WG engine, DERP transport, netstack, and `MapClient`,
//! and exposes a small public API for embedding apps:
//!
//! - `Runtime::up(config)` — blocks: KeyStore → magicsock bind →
//!   snapshot + LocalAPI (spawned early so the dashboard can render the
//!   M18 interactive-login QR) → Noise+h2 → interactive register/login
//!   loop → engine + DerpTransport + Stack + MapClient. Returns once the
//!   node is authorized; the first MapResponse arrives inside
//!   `run_event_loop`.
//! - `runtime.netstack()` — for binding TcpListeners.
//! - `runtime.lifecycle()` — read current `OnlineState`.
//! - `runtime.run_event_loop(should_stop)` — drives MapClient + DERP
//!   plumbing + lifecycle. Returns when `should_stop` returns true OR
//!   the tunnel dies.
//! - `runtime.shutdown()` — drops in the right order.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vita_chan::{unbounded, Receiver, Sender, TryRecvError};
use vita_sync::{Mutex, RwLock};
use smoltcp::wire::Ipv4Cidr as SmolIpv4Cidr;
use vita_log::{debug, info, warn};

use netstack::{Stack, StackConfig};
use ts_control::async_io::AsyncNoiseStream;
use ts_control::http2::Http2Conn;
use ts_control::record::NoiseStream;
use ts_control::{KeyStore, MapClient, MapEvent, NetMap};
use ts_derp::{DerpMap, DerpNodeAddr, DerpTransport, DerpTransportCtl};
use ts_disco::keys::{DiscoPrivateKey, DiscoPublicKey, NodePublicKey};
use ts_magicsock::{MagicSocket, MagicSocketCtl, DEFAULT_PORT as MAGICSOCK_PORT};
use wg_engine::{Engine, EngineConfig, Ipv4Cidr, PeerConfig, TransportAddr};

use crate::config::Config;
use crate::dual_transport::DualTransport;
use crate::error::RuntimeError;
use crate::lifecycle::{FatalKind, LifecycleTracker, OnlineState};
use crate::snapshot::{
    node_key_hex, now_unix, AclSummary, AllowedIpView, PeerView, RuntimeSnapshot,
};
use crate::proto::{consume_early_payload, hex_short, read_server_response};

pub struct Runtime {
    config: Config,
    state_dir: PathBuf,
    /// Cached `host:port` form of `config.control_url`. Used for HTTP/2
    /// `:authority` headers. Reused across reconnects (control-plane
    /// hostname doesn't drift mid-session).
    host_authority: String,
    /// Persistent keypairs (machine/node/disco/nl). M13 needs these on
    /// reconnect: every fresh Noise+H2 tunnel re-keys with
    /// `ks.machine_priv` against the same server pub. Disk is the
    /// source of truth; we cache a clone here to avoid re-reading the
    /// four files on every reconnect.
    ks: KeyStore,
    derp_ctl: DerpTransportCtl,
    engine: Arc<Engine>,
    magic_ctl: MagicSocketCtl,
    /// Held to keep the magic-socket worker alive; dropped on shutdown.
    _magic_socket: Option<MagicSocket>,
    /// `None` after `shutdown()` has consumed it. Held in `Option` so
    /// `shutdown` can take it; runtime field access through
    /// `self.stack` panics if shutdown has already been called.
    stack: Option<Stack>,
    map: Option<MapClient>,
    /// M19: mirrors `config.tailnet.want_running`, seeded at `up()`. A
    /// parked boot (`false`) skips interactive login + MapClient::start
    /// and publishes `Stopped`; the event loop flips it on `/up`//`/down`
    /// signals to park/resume without a process restart.
    want_running: bool,
    lifecycle: Mutex<LifecycleTracker>,
    /// Sender side of the M13.5 Stage 4 control-signal channel.
    /// Cloned out via `controller()` for management UIs.
    signal_tx: Sender<ControlSignal>,
    /// Receiver side, drained at the top of every event-loop iteration.
    /// Wrapped in `Option` so `run_event_loop` can `take()` it (mirrors
    /// the `map` / `stack` pattern).
    signal_rx: Option<Receiver<ControlSignal>>,
    /// M14 published runtime state. Event loop writes on every
    /// `MapEvent::Snapshot` + lifecycle transition; LocalAPI handlers
    /// (and any future cross-thread readers) clone the Arc and take a
    /// read lock. Initial value is the `RuntimeSnapshot::empty(...)`
    /// placeholder until the first event-loop publish replaces it.
    snapshot: Arc<RwLock<RuntimeSnapshot>>,
    /// M14 LocalAPI server handle. `None` if bind failed at startup
    /// or LocalAPI was disabled in config. Dropped on shutdown.
    _localapi: Option<crate::localapi::LocalApiServer>,
    /// Optional FTP-on-the-tailnet service. `None` if `config.ftp.enabled`
    /// is false or the bind failed. Dropped (stop + join) on shutdown.
    _ts_ftp: Option<ts_ftp::TsFtpServer>,
    /// Node's tailnet IPv4, published on the first MapResponse (in
    /// `run_event_loop`, alongside `stack.set_local_addrs`). Shared with
    /// the ts-ftp service for PASV `227` replies. `None` until registered.
    tailnet_ip: ts_ftp::TailnetIp,
}

/// Out-of-band signals the management UI can send to the running
/// event loop. M13.5 Stage 4. Future LiveArea bubble app uses these
/// to drive control-plane state changes without restarting the daemon.
///
/// Important: signals do NOT bypass fatal states. If we're in
/// `OnlineState::AuthFailed`, `ForceReconnect` is ignored; the user
/// must fix `config.toml` and restart. The UI's job is to surface
/// fatal states, not paper over them.
#[derive(Debug, Clone)]
pub enum ControlSignal {
    /// Re-establish the control-plane session immediately, skipping
    /// any pending backoff. Used after a config tweak the user just
    /// made, or as a manual "kick the daemon" gesture.
    ForceReconnect,
    /// M19: flip `want_running`. `true` = `/up` (resume from Stopped),
    /// `false` = `/down` (park: close the control session + drop WG
    /// peers, hold `OnlineState::Stopped`). Live state only — the eboot
    /// persists the bit in config.toml.
    SetWantRunning(bool),
    /// M19: `/logout` — expire the node key at control (a RegisterRequest
    /// with `Expiry = now`), drop the session + WG peers, delete the
    /// persisted map-session state, and park logged-out (`NeedsLogin`,
    /// no auto re-login). The node key is regenerated at the next login.
    Logout,
    /// M19: `/login-interactive` — start an interactive (QR) login now.
    /// Used post-logout (the "press ✕ to log in" screen) and as a manual
    /// re-authenticate. Drives the stop-aware `interactive_login`.
    LoginInteractive,
}

/// Sender-side handle for `ControlSignal`. Returned from
/// `Runtime::controller()`; cloneable and `Send`/`Sync` so the UI
/// thread can hold it independently of the event-loop thread.
///
/// The `tx` field is `pub(crate)` so the M14 LocalAPI module (a
/// sibling under `tailscale-vita/src/`) can construct one for its
/// HandlerCtx in tests. External callers should obtain a handle via
/// `Runtime::controller()` only.
#[derive(Clone)]
pub struct ControlHandle {
    pub(crate) tx: Sender<ControlSignal>,
}

impl ControlHandle {
    /// Request an immediate reconnect. Returns `Ok(())` if the signal
    /// was queued, `Err(...)` if the event loop has shut down (the
    /// receiver was dropped).
    pub fn force_reconnect(&self) -> Result<(), vita_chan::SendError<ControlSignal>> {
        self.tx.send(ControlSignal::ForceReconnect)
    }

    /// Low-level send for future signal variants.
    pub fn send(
        &self,
        sig: ControlSignal,
    ) -> Result<(), vita_chan::SendError<ControlSignal>> {
        self.tx.send(sig)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RunStats {
    pub snapshots: u32,
    pub keepalives: u32,
    pub control_errors: u32,
    pub final_lifecycle: OnlineState,
    pub final_peer_count: usize,
    pub final_alive_regions: usize,
}

impl Default for OnlineState {
    fn default() -> Self {
        OnlineState::Connecting
    }
}

/// S7 raw-sceIo trace into the SUPRX phase2-trace file, to localize a
/// hard data-abort inside Runtime::up (which crosses crate boundaries
/// away from tailscale-vita-rt's `trace`). No newlib/alloc dependency.
#[cfg(target_os = "vita")]
fn suprx_trace(msg: &str) {
    use std::ffi::{c_char, c_int, c_void};
    extern "C" {
        fn sceIoOpen(path: *const c_char, flag: c_int, mode: c_int) -> c_int;
        fn sceIoWrite(fd: c_int, buf: *const c_void, len: u32) -> c_int;
        fn sceIoClose(fd: c_int) -> c_int;
    }
    let path = c"ux0:data/tailscale-vita/phase2-trace.txt".as_ptr();
    unsafe {
        let fd = sceIoOpen(path, 0x0002 | 0x0200 | 0x0100, 0o666);
        if fd >= 0 {
            let _ = sceIoWrite(fd, msg.as_ptr() as *const c_void, msg.len() as u32);
            let _ = sceIoWrite(fd, b"\n".as_ptr() as *const c_void, 1);
            let _ = sceIoClose(fd);
        }
    }
}
#[cfg(not(target_os = "vita"))]
fn suprx_trace(_msg: &str) {}

/// One-shot WG data-plane crypto self-test. Runs the in-process
/// encapsulate/decapsulate round-trip in [`wg_engine::data_plane_selftest`]
/// and returns its one-line trace summary + fork verdict. Called once at SUPRX
/// startup to localize the data-plane bug to crypto vs network without touching
/// the wire. The `SelfTestReport` type stays inside wg-engine — we return a
/// formatted `String` so callers (tailscale-vita-rt) need no extra dependency.
pub fn wg_selftest_line() -> String {
    wg_engine::data_plane_selftest().summary()
}

impl Runtime {
    /// Block until the v1 control plane is up: fetch server key, load
    /// keystore, complete Noise+HTTP/2 handshake, register, spin up
    /// engine + DerpTransport + Stack + MapClient.
    pub fn up(config: Config) -> Result<Self, RuntimeError> {
        suprx_trace("up1: Runtime::up entry");
        let state_dir = PathBuf::from(&config.state_dir);
        let host_authority = config.host_authority();

        info!(
            control_url = %config.control_url,
            hostname = %config.hostname,
            "runtime.up.start"
        );

        // KeyStore first — persistent machine/node/disco keys. Both the
        // initial login below and any M13 reconnect reuse this. `mut`
        // because the M18 interactive-login loop regenerates the node
        // key if the control plane reports NodeKeyExpired.
        let mut ks = KeyStore::load_or_generate(&state_dir)?;
        suprx_trace("up2: keystore loaded");

        // Bind the Disco / direct-path UDP socket early (M18). Try the
        // canonical 41641 first; if it's taken (or sceNet rejects), fall
        // back to an ephemeral port. magicsock must be live BEFORE the
        // control session because both LocalAPI (active Disco pings) and
        // the interactive-login snapshot are spun up ahead of login. The
        // bound port goes into our MapRequest.Endpoints advertisement.
        let (non_disco_tx, non_disco_rx) = unbounded();
        let disco_priv = DiscoPrivateKey::from_bytes(ks.disco_priv.0);
        let our_node_pub_disco = NodePublicKey::from(ks.node_pub.0);
        let (magic_socket, magic_ctl) = bind_magicsock(
            disco_priv,
            our_node_pub_disco,
            non_disco_tx,
        )?;
        let magic_local = magic_ctl.local_addr();
        suprx_trace("up3: magicsock bound");
        info!(%magic_local, "magicsock.bound");

        // Local endpoint candidates for MapRequest.Endpoints. Discover
        // our LAN IP via the connect-trick (kernel routing decision —
        // no packet actually sent).
        suprx_trace("up4: pre build_local_endpoints (connect-trick)");
        let local_endpoints = build_local_endpoints(&config.control_url, magic_local);
        suprx_trace("up4b: local endpoints built");
        // M14E: parallel `tailcfg.EndpointType` codes. Every endpoint
        // we build via the connect-trick is a LAN IP (Vita's WiFi
        // address), so type 1 = `EndpointLocal`. Real Tailscale
        // requires this paired array to non-Unknown-classify our
        // advertised endpoints.
        let local_endpoint_types: Vec<u8> = vec![1u8; local_endpoints.len()];
        info!(
            ?local_endpoints,
            ?local_endpoint_types,
            "magicsock.endpoints.advertise"
        );

        // M18: control-signal channel + published snapshot + LocalAPI
        // server, all created BEFORE the control session. An empty
        // auth_key means we log in interactively (scan a QR), which can
        // block for minutes; LocalAPI + the snapshot must already be
        // serving so the dashboard can render the NeedsLogin screen with
        // the AuthURL. The lifecycle tracker is likewise created early so
        // the login loop can drive it into NeedsLogin.
        let (signal_tx, signal_rx) = unbounded();
        let snapshot = Arc::new(RwLock::new(RuntimeSnapshot::empty(
            config.hostname.clone(),
            magic_local,
        )));
        let lifecycle = Mutex::new(LifecycleTracker::new());

        // M14: spawn LocalAPI server if configured. Bind failure is
        // non-fatal — the daemon keeps running without LocalAPI.
        let localapi = match config.localapi_port {
            Some(port) => crate::localapi::LocalApiServer::spawn(
                port,
                Arc::clone(&snapshot),
                ControlHandle {
                    tx: signal_tx.clone(),
                },
                magic_ctl.clone(),
            ),
            None => {
                info!("localapi.disabled (config.localapi_port = None)");
                None
            }
        };

        // M18: interactive control-plane login. Establish the Noise+H2
        // tunnel, then register — looping with Followup=<AuthURL> until
        // the node is authorized. An empty auth_key triggers the QR path
        // (NeedsLogin + auth_url published into the snapshot); a
        // non-empty key takes the one-shot path (a returned AuthURL is a
        // hard AuthRejected inside register()). NodeKeyExpired
        // regenerates the node key and restarts the loop. This blocks
        // until the node is authorized (or a fatal control error).
        // Interactive login owns conn creation now: the control plane
        // closes the Noise/h2 conn after each register response, so the
        // followup re-poll cannot reuse it — a fresh conn is established
        // per attempt inside the loop (which also survives transient
        // control errors instead of aborting the whole runtime).
        // M19: generate the BackendLogID unconditionally (a parked boot
        // needs one too — it is reused when the first `/up` bootstraps).
        let backend_log_id = generate_backend_log_id();
        info!(backend_log_id = %backend_log_id, "control.backend_log_id.generated");

        // M19: `want_running = false` boots parked — skip interactive
        // login (and MapClient::start below) and publish Stopped, but
        // still build the full data plane so a later `/up` resumes via
        // the normal reconnect bootstrap.
        let want_running = config.tailnet.want_running;
        let conn = if want_running {
            suprx_trace("up5: pre interactive_login (fresh conn per attempt)");
            let mut no_abort = || None::<LoginAbort>;
            match interactive_login(
                &config,
                &mut ks,
                &host_authority,
                &state_dir,
                &snapshot,
                &lifecycle,
                &backend_log_id,
                &mut no_abort,
            )? {
                LoginOutcome::Authorized(conn) => {
                    suprx_trace("up7: REGISTERED + authorized");
                    info!("control.login.authorized");
                    Some(conn)
                }
                // Unreachable: `up()` passes a no-op abort that never
                // fires. Defensive rather than `unwrap`.
                LoginOutcome::Aborted(_) => {
                    return Err(RuntimeError::Internal(
                        "interactive login aborted during boot".into(),
                    ));
                }
            }
        } else {
            suprx_trace("park1: boot parked (want_running=false)");
            info!("runtime.up.parked (config.tailnet.want_running=false)");
            lifecycle.lock().set_stopped();
            publish_login_state(&snapshot, &lifecycle, None, false);
            None
        };

        // Node identity is now authorized. Build the WG data plane with
        // the (possibly regenerated) node key. Order preserved from
        // pre-M18: DerpTransport → Engine → DualTransport → Stack →
        // MapClient. Same 32 priv bytes serve WG identity AND DERP
        // NaCl-box ECDH (verified in spike-05); the disco priv is
        // separate.
        let our_secret = x25519_dalek::StaticSecret::from(ks.node_priv.0);
        let (derp_transport, derp_ctl) =
            DerpTransport::new(ks.node_priv.0, ks.node_pub.0, config.max_derp_conns);

        let engine = Arc::new(Engine::new(EngineConfig {
            our_static_secret: our_secret,
            mtu: 1280,
            peers: vec![],
        })?);
        let dual = DualTransport::new(magic_ctl.clone(), non_disco_rx, derp_transport);
        let hint: Arc<dyn wg_engine::DirectPathHint> = Arc::new(magic_ctl.clone());
        let engine_running = engine.start_with_hint(dual, Some(hint))?;
        suprx_trace("up8: wg engine pump started");
        info!("wg-engine: pump running with DualTransport(Magic+Derp)");

        let stack = Stack::start(StackConfig::new(), engine_running)?;
        suprx_trace("up9: netstack poll started");
        info!("netstack: poll thread running (no local IP yet)");

        // MapClient on the authorized conn (skipped for a parked boot,
        // where `conn` is None). Resumes `last_seq` from state_dir so a
        // warm start doesn't redownload the world.
        let map = match conn {
            Some(conn) => {
                let m = finish_session(
                    conn,
                    &ks,
                    &config,
                    &host_authority,
                    &state_dir,
                    local_endpoints,
                    local_endpoint_types,
                    backend_log_id,
                )?;
                suprx_trace("up10: control session up (map started)");
                info!("control.map.started");
                Some(m)
            }
            None => {
                suprx_trace("park2: parked boot; MapClient not started");
                None
            }
        };

        // M16: tailnet-IP holder, published on the first MapResponse (see
        // run_event_loop). Shared with the optional ts-ftp service so its
        // PASV `227` replies advertise the right address.
        let tailnet_ip: ts_ftp::TailnetIp = Arc::new(Mutex::new(None));

        // M16: spawn the FTP service if enabled. Bind failure is non-fatal —
        // the daemon keeps running without FTP. `stack.handle()` is a Send
        // handle so the FTP thread can bind PASV listeners on its own.
        let ts_ftp = if config.ftp.enabled {
            ts_ftp::TsFtpServer::spawn(
                stack.handle(),
                config.ftp.clone(),
                Arc::clone(&tailnet_ip),
            )
        } else {
            info!("ts-ftp.disabled (config.ftp.enabled = false)");
            None
        };

        // Fork-B diagnostic: UDP egress-shape probe (E2/E3). Config-gated,
        // off by default. ~15 s after startup it sends a tagged shape
        // battery through the production tx_queue path (plus a direct-send
        // control) to the configured listener targets; results land in
        // phase2-trace.txt as `wgpr:` lines and at the listener
        // (scripts/egress-probe-listener.py). See docs/EGRESS-PROBE.md.
        if config.egress_probe.enabled {
            let trace_fn: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|s: &str| {
                suprx_trace(s);
                info!("{}", s);
            });
            crate::egress_probe::spawn(
                magic_ctl.clone(),
                config.egress_probe.clone(),
                trace_fn,
            );
        }

        Ok(Self {
            config,
            state_dir,
            host_authority,
            ks,
            derp_ctl,
            engine,
            magic_ctl,
            _magic_socket: Some(magic_socket),
            stack: Some(stack),
            map,
            want_running,
            lifecycle,
            signal_tx,
            signal_rx: Some(signal_rx),
            snapshot,
            _localapi: localapi,
            _ts_ftp: ts_ftp,
            tailnet_ip,
        })
    }

    /// Clone the published runtime snapshot handle. Readers should
    /// `lock.read()` for short windows; the event loop writes to it
    /// on each `MapEvent::Snapshot` (~once per 2-30 s in steady state).
    pub fn snapshot(&self) -> Arc<RwLock<RuntimeSnapshot>> {
        Arc::clone(&self.snapshot)
    }

    /// Cloneable handle for sending `ControlSignal` to this runtime.
    /// Use it from management UIs (LiveArea bubble app, future SOCKS
    /// proxy admin endpoint, etc.) to trigger control-plane state
    /// changes. Signals are processed at the top of each event-loop
    /// iteration; expect ~2 s of latency.
    pub fn controller(&self) -> ControlHandle {
        ControlHandle {
            tx: self.signal_tx.clone(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Borrowed access to the netstack so the demo can bind a
    /// TcpListener on the tailnet IP:port.
    pub fn netstack(&self) -> &Stack {
        self.stack
            .as_ref()
            .expect("runtime: netstack accessed after shutdown")
    }

    pub fn lifecycle(&self) -> OnlineState {
        self.lifecycle.lock().state()
    }

    pub fn engine_peer_count(&self) -> usize {
        self.engine.peer_count()
    }

    pub fn alive_derp_regions(&self) -> Vec<u16> {
        self.derp_ctl.alive_regions()
    }

    /// Drive the MapClient + DERP plumbing + lifecycle until
    /// `should_stop` returns true. Each iteration polls one `MapEvent`
    /// with a 2 s timeout.
    pub fn run_event_loop<F>(&mut self, mut should_stop: F) -> Result<RunStats, RuntimeError>
    where
        F: FnMut() -> bool,
    {
        let stack = self
            .stack
            .as_ref()
            .ok_or_else(|| RuntimeError::Internal("runtime stack already shut down".into()))?;
        // M19: may legitimately be `None` on a parked boot
        // (`want_running = false` skipped MapClient::start in `up()`).
        // The event loop holds `Stopped` until the first `/up`.
        let mut map_opt: Option<MapClient> = self.map.take();
        let signal_rx = self.signal_rx.take().ok_or_else(|| {
            RuntimeError::Internal("runtime signal_rx already taken".into())
        })?;
        // Capture the start-time once so /health uptime is stable
        // across reconnect-induced republishes.
        let started_at_unix = now_unix();
        // Latest STUN-discovered public endpoint. Set by `run_netcheck`
        // before the first MapResponse advertises it. Republished into
        // the snapshot on every `publish_snapshot` call so consumers
        // see the same value the server sees.
        let mut public_endpoint: Option<SocketAddr> = None;
        // M14: timestamp of the most recent snapshot publish. Drives
        // the 3-second-cadence refresh loop below so /status doesn't
        // serve frozen direct-path state between netmap deltas.
        let mut last_snapshot_publish_at = Instant::now();
        // M15-B: one-shot ACL-posture warning. Fires once on the
        // first MapResponse if `netmap.our_tags` is empty (auth-key
        // wasn't tagged → device has full tailnet access). Reset on
        // reconnect so a fresh session re-evaluates (tag changes
        // server-side are unlikely but possible).
        let mut acl_warned = false;

        let mut snapshots = 0u32;
        let mut keepalives = 0u32;
        let mut control_errors = 0u32;
        let mut derp_map_set = false;
        let mut local_addrs_set = false;
        // Track each peer's DERP region. Used to dispatch CallMeMaybe
        // sends queued by magicsock — magicsock owns the encryption
        // half; the runtime owns DERP transport, so we need to know
        // which region to relay through.
        let mut peer_regions: HashMap<[u8; 32], u16> = HashMap::new();
        // Fire the NetInfo "lite" MapRequest exactly once after the
        // first snapshot establishes the DERP map. Without this call,
        // real Tailscale's coord server never commits our DiscoKey /
        // HomeDERP / Endpoints to its persistent state — peers see us
        // with `disco_key=discokey:0...` no matter how long the
        // streaming long-poll runs. Mirrors upstream Go's
        // `controlclient.Direct.SetDerpHomeRegion` which sends a
        // `stream=false` MapRequest with NetInfo + OmitPeers=true.
        //
        // Reset to false on reconnect so a fresh control-plane session
        // re-arms the NetInfo write path (the server treats each
        // session independently).
        let mut sent_netinfo_once = false;
        // M13 reconnect bookkeeping. attempt counts contiguous failures;
        // resets to 0 on a successful event. Backoff is 2^attempt
        // seconds capped at RECONNECT_BACKOFF_CAP.
        let mut reconnect_attempt: u32 = 0;
        // M19 lifecycle spine: live copy of `want_running` (a `/down`
        // parks it false, an `/up` resumes it true). Deferred-action
        // flags for the two blocking mid-loop operations, set in the
        // signal-drain loop and handled just after it.
        let mut want_running = self.want_running;
        let mut logout_requested = false;
        let mut login_interactive_requested = false;

        while !should_stop() {
            // M13.5 Stage 4: drain any pending control signals. Fatal
            // states block signals — UI must surface the failure to
            // the user, not paper over it.
            let lifecycle_state = self.lifecycle.lock().state();
            let is_fatal = matches!(
                lifecycle_state,
                OnlineState::AuthFailed | OnlineState::SecurityFailed
            );
            loop {
                match signal_rx.try_recv() {
                    Ok(ControlSignal::ForceReconnect) => {
                        if is_fatal {
                            warn!(
                                state = ?lifecycle_state,
                                "control.signal.force_reconnect.ignored.fatal"
                            );
                            continue;
                        }
                        info!("control.signal.force_reconnect");
                        // Tear down current session; the reconnect
                        // block below will rebuild with attempt=0
                        // (immediate, no backoff sleep).
                        map_opt = None;
                        reconnect_attempt = 0;
                    }
                    Ok(ControlSignal::SetWantRunning(desired)) => {
                        if is_fatal {
                            warn!(
                                state = ?lifecycle_state,
                                "control.signal.want_running.ignored.fatal"
                            );
                            continue;
                        }
                        if desired && !want_running {
                            // `/up` — resume from Stopped. Clear the park,
                            // drop any dead session, bootstrap immediately.
                            info!("control.signal.want_running.up");
                            suprx_trace("resume: want_running -> up");
                            want_running = true;
                            self.want_running = true;
                            self.lifecycle.lock().clear_stopped();
                            map_opt = None;
                            reconnect_attempt = 0;
                        } else if !desired && want_running {
                            // `/down` — park. Close the control session and
                            // quiet the data plane; dropping `map_opt`
                            // alone would leave WG peers live (recon risk).
                            info!("control.signal.want_running.down");
                            suprx_trace("park: want_running -> down");
                            want_running = false;
                            self.want_running = false;
                            map_opt = None;
                            clear_engine_peers(&self.engine, &mut peer_regions);
                            self.lifecycle.lock().set_stopped();
                            publish_login_state(&self.snapshot, &self.lifecycle, None, false);
                        }
                    }
                    Ok(ControlSignal::Logout) => {
                        if is_fatal {
                            warn!(
                                state = ?lifecycle_state,
                                "control.signal.logout.ignored.fatal"
                            );
                            continue;
                        }
                        info!("control.signal.logout");
                        logout_requested = true;
                    }
                    Ok(ControlSignal::LoginInteractive) => {
                        if is_fatal {
                            warn!(
                                state = ?lifecycle_state,
                                "control.signal.login_interactive.ignored.fatal"
                            );
                            continue;
                        }
                        info!("control.signal.login_interactive");
                        login_interactive_requested = true;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        // All ControlHandle clones dropped. Not an
                        // error — just no more signals will arrive.
                        debug!("control.signal.channel.disconnected");
                        break;
                    }
                }
            }

            // M19 parked (`want_running = false`). Hold Stopped and don't
            // touch the control/data plane; only signal draining (above)
            // keeps `/up` responsive. A short cooperative sleep paces the
            // loop (no `next_event` to block on while parked).
            if !want_running {
                logout_requested = false;
                login_interactive_requested = false;
                self.lifecycle.lock().set_stopped();
                if cooperative_sleep(Duration::from_secs(2), &mut should_stop) {
                    break;
                }
                continue;
            }

            // M19 `/logout` — expire the node key at control on a fresh
            // conn, then park logged-out (NeedsLogin, no auto re-login).
            if logout_requested {
                logout_requested = false;
                perform_logout(
                    &self.config,
                    &self.ks,
                    &self.host_authority,
                    &self.state_dir,
                    &self.snapshot,
                    &self.lifecycle,
                    &self.engine,
                    &mut peer_regions,
                    &mut map_opt,
                );
                // Whether logout succeeded (→ NeedsLogin, map_opt None) or
                // failed (→ prior state kept), re-enter the loop rather
                // than fall through to next_event on a maybe-None map.
                continue;
            }

            // M13 reconnect: sessionless + running + not logged-out + not
            // already escalating → sleep with backoff + attempt bootstrap.
            if map_opt.is_none()
                && !login_interactive_requested
                && self.lifecycle.lock().state() != OnlineState::NeedsLogin
            {
                let delay = reconnect_backoff(reconnect_attempt);
                info!(
                    delay_secs = delay.as_secs(),
                    attempt = reconnect_attempt,
                    "control.reconnect.backoff"
                );
                if cooperative_sleep(delay, &mut should_stop) {
                    break;
                }
                // Re-derive local endpoints — LAN IP could have changed
                // during the outage (Vita roamed WiFi).
                let magic_local = self.magic_ctl.local_addr();
                let local_eps = build_local_endpoints(&self.config.control_url, magic_local);
                let local_ep_types: Vec<u8> = vec![1u8; local_eps.len()];
                match bootstrap_control_session(
                    &self.config,
                    &self.ks,
                    &self.host_authority,
                    local_eps,
                    local_ep_types,
                    &self.state_dir,
                    BootstrapPhase::Reconnect(reconnect_attempt + 1),
                ) {
                    Ok(BootstrapOutcome::Session(m)) => {
                        info!(attempt = reconnect_attempt + 1, "control.reconnect.ok");
                        map_opt = Some(m);
                        // reconnect_attempt is reset below in either
                        // the next_event Ok arm (line ~325) or the
                        // transient-error arm — either way, no need
                        // to clear it here.
                        // Fresh session needs a fresh NetInfo write so
                        // the server re-commits DiscoKey state.
                        sent_netinfo_once = false;
                        // M15-B: re-evaluate ACL posture on fresh
                        // session — tags can change server-side
                        // between sessions if the user re-issued the
                        // auth-key while we were disconnected.
                        acl_warned = false;
                    }
                    Ok(BootstrapOutcome::NeedsInteractiveLogin) => {
                        // M19: the persisted node key lost authorization
                        // while we were disconnected (expired/deauthed).
                        // Escalate to interactive login (closes the M18
                        // reconnect deferral). Handled just below so the
                        // signal-driven and reconnect-driven paths share
                        // one implementation.
                        info!("control.reconnect.escalate_interactive_login");
                        login_interactive_requested = true;
                    }
                    Err(e) => {
                        // Same fatal-vs-transient triage as the
                        // in-session error arm. A bad auth_key
                        // discovered during reconnect should fail
                        // fast, not spin forever.
                        let class = classify_control_error(&e);
                        match class {
                            ErrorClass::AuthFatal => {
                                warn!(error = %e, "control.reconnect.auth_fatal");
                                self.lifecycle
                                    .lock()
                                    .mark_fatal(FatalKind::Auth, e.to_string());
                                publish_fatal_state(
                                    &self.snapshot,
                                    &self.lifecycle,
                                );
                                return Err(RuntimeError::Control(e));
                            }
                            ErrorClass::SecurityFatal => {
                                warn!(error = %e, "control.reconnect.security_fatal");
                                self.lifecycle
                                    .lock()
                                    .mark_fatal(FatalKind::Security, e.to_string());
                                publish_fatal_state(
                                    &self.snapshot,
                                    &self.lifecycle,
                                );
                                return Err(RuntimeError::Control(e));
                            }
                            ErrorClass::Transient => {
                                reconnect_attempt = reconnect_attempt.saturating_add(1);
                                warn!(
                                    error = %e,
                                    attempt = reconnect_attempt,
                                    "control.reconnect.failed"
                                );
                                continue; // backoff harder next iter
                            }
                        }
                    }
                }
            }

            // M19 mid-life interactive login — the `/login-interactive`
            // signal, the post-logout ✕ screen, or a reconnect escalation
            // above. Runs the stop-aware login loop, then opens the
            // session via `finish_session` (same tail as first boot).
            if login_interactive_requested {
                login_interactive_requested = false;
                let session_blid = generate_backend_log_id();
                info!(backend_log_id = %session_blid, "control.backend_log_id.generated");
                let magic_local = self.magic_ctl.local_addr();
                let local_eps = build_local_endpoints(&self.config.control_url, magic_local);
                let local_ep_types: Vec<u8> = vec![1u8; local_eps.len()];
                let mut abort = || peek_login_abort(&signal_rx, &mut should_stop);
                match interactive_login(
                    &self.config,
                    &mut self.ks,
                    &self.host_authority,
                    &self.state_dir,
                    &self.snapshot,
                    &self.lifecycle,
                    &session_blid,
                    &mut abort,
                ) {
                    Ok(LoginOutcome::Authorized(conn)) => {
                        match finish_session(
                            conn,
                            &self.ks,
                            &self.config,
                            &self.host_authority,
                            &self.state_dir,
                            local_eps,
                            local_ep_types,
                            session_blid,
                        ) {
                            Ok(m) => {
                                info!("control.login_interactive.session_up");
                                map_opt = Some(m);
                                reconnect_attempt = 0;
                                sent_netinfo_once = false;
                                acl_warned = false;
                            }
                            Err(e) => {
                                warn!(error = %e, "control.login_interactive.finish_session.failed");
                            }
                        }
                    }
                    Ok(LoginOutcome::Aborted(LoginAbort::Parked)) => {
                        // A `/down` arrived mid-login — park (mirror the
                        // SetWantRunning(false) transition).
                        info!("control.login_interactive.aborted.parked");
                        want_running = false;
                        self.want_running = false;
                        map_opt = None;
                        clear_engine_peers(&self.engine, &mut peer_regions);
                        self.lifecycle.lock().set_stopped();
                        publish_login_state(&self.snapshot, &self.lifecycle, None, false);
                    }
                    Ok(LoginOutcome::Aborted(LoginAbort::Shutdown)) => {
                        // should_stop fired; the while guard exits next check.
                        info!("control.login_interactive.aborted.shutdown");
                    }
                    Err(e) => {
                        let class = classify_control_error(&e);
                        match class {
                            ErrorClass::AuthFatal => {
                                warn!(error = %e, "control.login_interactive.auth_fatal");
                                self.lifecycle
                                    .lock()
                                    .mark_fatal(FatalKind::Auth, e.to_string());
                                publish_fatal_state(&self.snapshot, &self.lifecycle);
                                return Err(RuntimeError::Control(e));
                            }
                            ErrorClass::SecurityFatal => {
                                warn!(error = %e, "control.login_interactive.security_fatal");
                                self.lifecycle
                                    .lock()
                                    .mark_fatal(FatalKind::Security, e.to_string());
                                publish_fatal_state(&self.snapshot, &self.lifecycle);
                                return Err(RuntimeError::Control(e));
                            }
                            ErrorClass::Transient => {
                                warn!(error = %e, "control.login_interactive.failed");
                            }
                        }
                    }
                }
                continue;
            }

            // M19 sessionless but not parked (e.g. logged out awaiting
            // `/login-interactive`). Idle without spinning — and crucially
            // WITHOUT ticking: a tick would recompute the stale tracker
            // out of NeedsLogin.
            if map_opt.is_none() {
                if cooperative_sleep(Duration::from_secs(2), &mut should_stop) {
                    break;
                }
                continue;
            }

            let map = map_opt.as_mut().expect("map_opt populated above");
            let event = match map.next_event(Duration::from_secs(2)) {
                Ok(e) => e,
                Err(e) => {
                    control_errors += 1;
                    let class = classify_control_error(&e);
                    match class {
                        ErrorClass::AuthFatal => {
                            warn!(error = %e, "control.map.error.auth_fatal");
                            self.lifecycle
                                .lock()
                                .mark_fatal(FatalKind::Auth, e.to_string());
                            publish_fatal_state(
                                &self.snapshot,
                                &self.lifecycle,
                            );
                            return Err(RuntimeError::Control(e));
                        }
                        ErrorClass::SecurityFatal => {
                            warn!(error = %e, "control.map.error.security_fatal");
                            self.lifecycle
                                .lock()
                                .mark_fatal(FatalKind::Security, e.to_string());
                            publish_fatal_state(
                                &self.snapshot,
                                &self.lifecycle,
                            );
                            return Err(RuntimeError::Control(e));
                        }
                        ErrorClass::Transient => {
                            warn!(error = %e, "control.map.error");
                            self.lifecycle.lock().record_control_reconnect();
                            // Drop the dead session; next loop iter
                            // handles backoff + bootstrap. attempt=0
                            // so the first reconnect is immediate.
                            map_opt = None;
                            reconnect_attempt = 0;
                            continue;
                        }
                    }
                }
            };
            let now = Instant::now();
            // Any successful event clears the reconnect-attempt counter.
            reconnect_attempt = 0;

            match event {
                MapEvent::Snapshot(snap) => {
                    snapshots += 1;
                    self.lifecycle.lock().record_map_event(now);

                    if !derp_map_set && snap.derp_region_count > 0 {
                        let derp_map = build_derp_map(map.netmap());
                        self.derp_ctl.set_derp_map(derp_map.clone());
                        match self.derp_ctl.pick_and_set_home(&derp_map) {
                            Ok(home) => info!(
                                home,
                                regions = derp_map.regions.len(),
                                "derp.home.selected"
                            ),
                            Err(e) => warn!(error = %e, "derp.home.selection.failed"),
                        }
                        derp_map_set = true;
                    }

                    // Fire the NetInfo lite MapRequest once, after the
                    // DERP map is loaded. M14M-Phase11 found that the
                    // server's persistent-state write path (DiscoKey,
                    // home region, endpoints) only triggers on a
                    // non-streaming MapRequest carrying NetInfo with
                    // real DerpLatency.
                    //
                    // Stage 3 (M12 prereq): probe each DERP region's
                    // STUN port (UDP/3478) via our magicsock to
                    // discover (a) our public-mapped endpoint for
                    // peers behind different NATs and (b) real
                    // round-trip times to populate DerpLatency. Falls
                    // back to stub 50 ms latencies if every probe
                    // fails (e.g. UDP egress blocked).
                    if derp_map_set && !sent_netinfo_once {
                        sent_netinfo_once = true;
                        let report = run_netcheck(&self.magic_ctl, map.netmap());
                        let preferred_derp = if report.preferred_derp != 0 {
                            report.preferred_derp
                        } else {
                            self.derp_ctl.home_region()
                        };
                        let latencies: Vec<(String, f64)> = if !report.derp_latency.is_empty() {
                            report
                                .derp_latency
                                .iter()
                                .map(|(rid, secs)| (format!("{}-v4", rid), *secs))
                                .collect()
                        } else {
                            // Fallback: stub 50 ms for every known region.
                            map.netmap()
                                .derp_regions
                                .keys()
                                .flat_map(|rid| {
                                    vec![
                                        (format!("{}-v4", rid), 0.050),
                                        (format!("{}-v6", rid), 0.050),
                                    ]
                                })
                                .collect()
                        };
                        // Public-endpoint discovery: prefer the DERP-
                        // probe's reflection if any DERP responded;
                        // else fall back to public STUN (Google /
                        // Cloudflare / Twilio). Tailscale's own DERPs
                        // sometimes refuse STUN from clients without
                        // recent activity history.
                        // Update the outer-scope `public_endpoint` so
                        // every snapshot republish carries the latest
                        // STUN-discovered address. Now dual-family
                        // (M15-C): if any v6 reflection came back from
                        // the DERP probes, advertise it alongside v4;
                        // fall back to public-STUN for both families.
                        public_endpoint = report.public_endpoint;
                        let mut public_endpoint_v6 = report.public_endpoint_v6;
                        if public_endpoint.is_none() || public_endpoint_v6.is_none() {
                            let (v4, v6) = ts_magicsock::netcheck::discover_public_endpoints_dual(
                                &self.magic_ctl,
                                ts_magicsock::netcheck::DEFAULT_PROBE_TIMEOUT,
                            );
                            if public_endpoint.is_none() {
                                public_endpoint = v4;
                            }
                            if public_endpoint_v6.is_none() {
                                public_endpoint_v6 = v6;
                            }
                        }
                        let mut extra: Vec<String> = Vec::new();
                        if let Some(sa) = public_endpoint {
                            extra.push(sa.to_string());
                        }
                        if let Some(sa) = public_endpoint_v6 {
                            extra.push(sa.to_string());
                        }
                        // Tell magicsock which endpoints to advertise
                        // in any CallMeMaybe we send: our LAN binding
                        // plus the STUN-reflected public address(es).
                        // These are what peers will dial back to.
                        let mut local_eps: Vec<SocketAddr> =
                            vec![self.magic_ctl.local_addr()];
                        if let Some(v6_local) = self.magic_ctl.local_addr_v6() {
                            local_eps.push(v6_local);
                        }
                        if let Some(pe) = public_endpoint {
                            if !local_eps.contains(&pe) {
                                local_eps.push(pe);
                            }
                        }
                        if let Some(pe) = public_endpoint_v6 {
                            if !local_eps.contains(&pe) {
                                local_eps.push(pe);
                            }
                        }
                        self.magic_ctl.set_local_endpoints(local_eps);
                        match map.send_netinfo_update(preferred_derp, latencies, extra) {
                            Ok(()) => info!(
                                preferred_derp,
                                "control.map.netinfo_update.sent"
                            ),
                            Err(e) => warn!(error = %e, "control.map.netinfo_update.failed"),
                        }
                    }

                    if !local_addrs_set && !snap.our_addrs.is_empty() {
                        let local_cidrs: Vec<SmolIpv4Cidr> = snap
                            .our_addrs
                            .iter()
                            .map(|a| SmolIpv4Cidr::new(a.addr, a.prefix))
                            .collect();
                        info!(
                            addrs = ?local_cidrs,
                            "netstack.local_addrs.from_mapresponse"
                        );
                        stack.set_local_addrs(local_cidrs);
                        // M16: publish the tailnet IP for the ts-ftp service's
                        // PASV replies (first IPv4 addr; same one smoltcp uses).
                        *self.tailnet_ip.lock() = snap.our_addrs.first().map(|a| a.addr);
                        local_addrs_set = true;
                    }

                    push_delta_to_engine(&self.engine, &snap, self.derp_ctl.home_region());
                    push_delta_to_magicsock(&self.magic_ctl, &snap);
                    update_peer_regions(
                        &mut peer_regions,
                        &snap,
                        self.derp_ctl.home_region(),
                    );
                    // M14: republish the LocalAPI-readable snapshot.
                    // `map` is still in scope as `&mut MapClient` from
                    // the next_event() result; netmap() is &self.
                    let (lifecycle, fatal_reason) = {
                        let lt = self.lifecycle.lock();
                        (lt.state(), lt.fatal_reason().map(str::to_owned))
                    };
                    publish_snapshot(
                        &self.snapshot,
                        started_at_unix,
                        &self.config.hostname,
                        map.netmap(),
                        &self.magic_ctl,
                        self.derp_ctl.home_region(),
                        self.derp_ctl.alive_regions(),
                        public_endpoint,
                        lifecycle,
                        fatal_reason,
                    );
                    last_snapshot_publish_at = Instant::now();

                    // M15-B: one-shot ACL-posture warning on the
                    // first MapResponse. If the server returned no
                    // tags for our node, the auth-key was untagged
                    // and the device has full tailnet access. Loud
                    // INFO/WARN so the user actually notices.
                    if !acl_warned {
                        acl_warned = true;
                        let tags = &map.netmap().our_tags;
                        if tags.is_empty() {
                            warn!(
                                "control.acl.untagged: this Vita has FULL tailnet access. \
                                 Re-issue the auth-key with --tags=tag:vita and write an ACL \
                                 in the Tailscale admin panel to restrict reach."
                            );
                        } else {
                            info!(
                                tags = ?tags,
                                "control.acl.tagged"
                            );
                        }
                    }
                }
                MapEvent::KeepAlive { seq } => {
                    keepalives += 1;
                    self.lifecycle.lock().record_map_event(now);
                    info!(seq, count = keepalives, "control.map.keepalive");
                }
                MapEvent::Idle => {}
            }

            // M14: republish the snapshot periodically so direct-path
            // state (alive/RTT, which changes when magicsock's pump
            // gets a Pong) freshens between MapEvent::Snapshot frames.
            // Pure netmap snapshots only fire when peers add/leave;
            // in steady state we'd otherwise serve a frozen snapshot.
            // 3 s cadence: cheap (~1 ms snapshot build for ~30 peers)
            // and matches the expected human-cadence of /status polls.
            if last_snapshot_publish_at.elapsed() >= Duration::from_secs(3) {
                let (lifecycle, fatal_reason) = {
                    let lt = self.lifecycle.lock();
                    (lt.state(), lt.fatal_reason().map(str::to_owned))
                };
                publish_snapshot(
                    &self.snapshot,
                    started_at_unix,
                    &self.config.hostname,
                    map.netmap(),
                    &self.magic_ctl,
                    self.derp_ctl.home_region(),
                    self.derp_ctl.alive_regions(),
                    public_endpoint,
                    lifecycle,
                    fatal_reason,
                );
                last_snapshot_publish_at = Instant::now();
            }

            // Drain CallMeMaybe send queue (Stage 4). For each
            // (peer_node, encrypted_bytes), look up the peer's home
            // region and relay via DERP. The peer's magicsock receives
            // the frame (via its own DualTransport disco peek), decodes
            // the CMM, and pings each advertised endpoint to open NAT.
            for (peer_node, bytes) in self.magic_ctl.take_pending_cmm() {
                let region = match peer_regions.get(&peer_node).copied() {
                    Some(r) if r != 0 => r,
                    _ => {
                        // No region known yet (peer not in netmap, or
                        // HomeDERP=0). Skip; will retry next pump
                        // after MapResponse populates the region.
                        continue;
                    }
                };
                match self.derp_ctl.send(region, peer_node, &bytes) {
                    Ok(()) => info!(
                        peer = ?&peer_node[..4],
                        region,
                        n = bytes.len(),
                        "magicsock.callme.send"
                    ),
                    Err(e) => warn!(
                        peer = ?&peer_node[..4],
                        region,
                        error = %e,
                        "magicsock.callme.send.failed"
                    ),
                }
            }

            // Proxy DERP rx signal until a real per-rx hook lands.
            if !self.derp_ctl.alive_regions().is_empty() {
                self.lifecycle.lock().record_derp_rx(now);
            }
            self.lifecycle.lock().tick(
                now,
                self.engine.peer_count(),
                self.derp_ctl.alive_regions().len(),
            );
        }

        // Map drops here — terminating the long-poll cleanly.
        drop(map_opt);

        Ok(RunStats {
            snapshots,
            keepalives,
            control_errors,
            final_lifecycle: self.lifecycle.lock().state(),
            final_peer_count: self.engine.peer_count(),
            final_alive_regions: self.derp_ctl.alive_regions().len(),
        })
    }

    /// Graceful teardown. Closes DERP conns, drops the netstack
    /// (which joins poll thread + wg-engine pump). Idempotent — safe
    /// to call from `Drop`.
    pub fn shutdown(mut self) {
        info!("runtime.shutdown.requested");
        // DERP first so conns close cleanly.
        self.derp_ctl.shutdown();
        // Drop map (if we never ran the event loop).
        self.map = None;
        // Stack drop joins netstack poll + engine pump.
        let _ = self.stack.take();
        info!("runtime.shutdown.complete");
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // If the demo neglected to call shutdown(), do it now (in field
        // drop order, this is implicit, but we want the explicit order:
        // derp first, then map, then stack).
        self.derp_ctl.shutdown();
        self.map = None;
        let _ = self.stack.take();
    }
}

/// Run STUN-based netcheck against every region in the netmap's
/// DERPMap. Returns aggregated reflected endpoint + per-region RTT.
///
/// Each region's first node is probed at `<ipv4>:3478` (the standard
/// STUN port that all Tailscale DERP servers run). Probes go in
/// parallel via `MagicSocketCtl::stun_probe`; aggregation waits up to
/// `DEFAULT_PROBE_TIMEOUT` for responses.
///
/// Skipping a region is benign — its absence from the report just
/// means that region won't appear in `DerpLatency` (and the server
/// won't consider it for our home selection).
fn run_netcheck(magic_ctl: &MagicSocketCtl, nm: &NetMap) -> ts_magicsock::netcheck::NetcheckReport {
    let mut targets: Vec<ts_magicsock::netcheck::StunTarget> = Vec::new();
    for (region_id, region) in &nm.derp_regions {
        let Some(node) = region.nodes.first() else {
            continue;
        };
        // Each DERP node carries both `ipv4` and `ipv6` fields; the
        // server populates them. STUN runs on UDP/3478 for both
        // families. Skip empty / unparseable values rather than
        // synthesizing a "0.0.0.0" target.
        let stun_port = ts_magicsock::netcheck::STUN_PORT;
        let ipv4_addr = if node.ipv4.is_empty() {
            None
        } else {
            format!("{}:{}", node.ipv4, stun_port)
                .parse::<std::net::SocketAddr>()
                .map_err(|_| {
                    warn!(region_id, ipv4 = %node.ipv4, "netcheck.target.v4.parse_failed");
                })
                .ok()
        };
        let ipv6_addr = if node.ipv6.is_empty() {
            None
        } else {
            // IPv6 addresses need brackets in `[v6]:port` form.
            format!("[{}]:{}", node.ipv6, stun_port)
                .parse::<std::net::SocketAddr>()
                .map_err(|_| {
                    debug!(region_id, ipv6 = %node.ipv6, "netcheck.target.v6.parse_failed");
                })
                .ok()
        };
        if ipv4_addr.is_none() && ipv6_addr.is_none() {
            continue;
        }
        targets.push(ts_magicsock::netcheck::StunTarget {
            region_id: *region_id,
            ipv4_addr,
            ipv6_addr,
        });
    }
    ts_magicsock::netcheck::probe_targets(
        magic_ctl,
        &targets,
        ts_magicsock::netcheck::DEFAULT_PROBE_TIMEOUT,
    )
}

/// Translate ts-control's `NetMap.derp_regions` into ts-derp's
/// `DerpMap` shape. Both HashMap<u16, region-info> but with different
/// node types — copy field-by-field. Lifted verbatim from M9 demo.
fn build_derp_map(nm: &NetMap) -> DerpMap {
    let mut regions = std::collections::HashMap::with_capacity(nm.derp_regions.len());
    for (region_id, region) in &nm.derp_regions {
        let nodes: Vec<DerpNodeAddr> = region
            .nodes
            .iter()
            .map(|n| DerpNodeAddr {
                region_id: n.region_id,
                name: n.name.clone(),
                hostname: n.hostname.clone(),
                ipv4: n.ipv4.clone(),
                ipv6: n.ipv6.clone(),
                derp_port: n.derp_port,
            })
            .collect();
        regions.insert(*region_id, nodes);
    }
    DerpMap { regions }
}

fn push_delta_to_engine(
    engine: &Engine,
    snap: &ts_control::NetMapSnapshot,
    our_home: u16,
) {
    let delta = &snap.delta;
    info!(
        seq = snap.seq,
        peer_count = snap.peer_count,
        derp_regions = snap.derp_region_count,
        upserted = delta.upserted.len(),
        removed = delta.removed.len(),
        rekeyed = delta.rekeyed.len(),
        patches = delta.patches_applied,
        "control.map.netmap"
    );

    for p in &delta.upserted {
        let allowed_ips = engine_allowed_ips(&p.allowed_ips);
        let pubkey = x25519_dalek::PublicKey::from(p.node_key);
        let region = if p.home_derp != 0 {
            p.home_derp
        } else {
            our_home
        };
        let initial_endpoint = if region != 0 {
            Some(TransportAddr::Derp {
                region,
                peer_pubkey: p.node_key,
            })
        } else {
            None
        };
        if let Err(e) = engine.upsert_peer(PeerConfig {
            pubkey,
            preshared_key: None,
            persistent_keepalive_secs: Some(25),
            allowed_ips,
            initial_endpoint,
        }) {
            warn!(error = %e, node_id = p.node_id, "control.map.peer.upsert.failed");
        } else {
            info!(
                node_id = p.node_id,
                allowed_ips = ?p.allowed_ips,
                home_derp = p.home_derp,
                routed_via_region = region,
                "control.map.peer.upsert"
            );
        }
    }

    for k in &delta.removed {
        let pubkey = x25519_dalek::PublicKey::from(*k);
        engine.remove_peer(&pubkey);
        info!(?k, "control.map.peer.remove");
    }

    for r in &delta.rekeyed {
        let old = x25519_dalek::PublicKey::from(r.old_key);
        engine.remove_peer(&old);
        let allowed_ips = engine_allowed_ips(&r.snapshot.allowed_ips);
        let new_pubkey = x25519_dalek::PublicKey::from(r.snapshot.node_key);
        let region = if r.snapshot.home_derp != 0 {
            r.snapshot.home_derp
        } else {
            our_home
        };
        let initial_endpoint = if region != 0 {
            Some(TransportAddr::Derp {
                region,
                peer_pubkey: r.snapshot.node_key,
            })
        } else {
            None
        };
        let _ = engine.upsert_peer(PeerConfig {
            pubkey: new_pubkey,
            preshared_key: None,
            persistent_keepalive_secs: Some(25),
            allowed_ips,
            initial_endpoint,
        });
        info!(node_id = r.snapshot.node_id, "control.map.peer.rekeyed");
    }
}

/// Convert a peer's netmap AllowedIPs into the engine's route set.
/// Default routes (prefix 0 — an exit node's 0.0.0.0/0 offer) are
/// dropped: the Vita never routes through exit nodes, and installing
/// one into the engine's longest-prefix index makes it swallow every
/// destination whose /32 is missing (2026-07-02 data-plane bug —
/// every echo reply was sent to the exit node). Subnet routes with
/// prefix >= 1 are kept; the /32 tailnet addrs always win LPM.
fn engine_allowed_ips(list: &[ts_control::AllowedIp]) -> Vec<Ipv4Cidr> {
    list.iter()
        .filter(|a| a.prefix > 0)
        .map(|a| Ipv4Cidr {
            addr: a.addr,
            prefix: a.prefix,
        })
        .collect()
}

/// Cap on the reconnect backoff. Linux/macOS tailscaled uses ~1 min;
/// matches our cadence (a stuck control plane recovers within this
/// window in practice, and we'd rather waste a minute than hammer).
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(60);

/// Bucketing for `ControlError` triage. Drives whether the event loop
/// retries (with backoff), or short-circuits to a terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorClass {
    /// Network blip, server hiccup, idle long-poll cutover — retry
    /// after backoff. The vast majority of errors fall here.
    Transient,
    /// Server rejected our identity. No retry will help; user must
    /// fix `auth_key` and restart.
    AuthFatal,
    /// Server's Noise key changed or `/key` returned malformed data.
    /// Could be MITM or legitimate rotation; either way the user must
    /// investigate.
    SecurityFatal,
}

/// Decide whether a `ControlError` is worth retrying. Conservatively
/// bias toward `Transient` for ambiguous errors — false-positive
/// transient retries cost a backoff cycle, but false-positive fatal
/// classification strands the user.
fn classify_control_error(err: &ts_control::ControlError) -> ErrorClass {
    use ts_control::ControlError;
    match err {
        // Explicit auth failure from /machine/register.
        ControlError::AuthRejected { .. } => ErrorClass::AuthFatal,
        // HTTP 401/403 = unauthorized; 410 Gone = identity revoked.
        // 4xx other than these is usually a wire-protocol mismatch
        // (5xx is the server's problem and we retry).
        ControlError::Http { status, .. } if matches!(*status, 401 | 403 | 410) => {
            ErrorClass::AuthFatal
        }
        // The register-path also emits a plain `Transport(_)` when the
        // server returns `MachineAuthorized=false` without an AuthURL.
        // Sniff for the marker so we don't infinite-loop on a revoked
        // node — see register.rs:108-112.
        ControlError::Transport(s) if s.contains("MachineAuthorized=false") => {
            ErrorClass::AuthFatal
        }
        // Noise-side trust failures — refuse to retry.
        ControlError::BadServerKey { .. } | ControlError::ServerKeyChanged => {
            ErrorClass::SecurityFatal
        }
        // Everything else: network, idle long-poll, frame decode hiccup,
        // 5xx server errors, etc. Retry.
        _ => ErrorClass::Transient,
    }
}

/// ±jitter on the exponential backoff, expressed as a fraction of the
/// base delay. 0.25 = the actual delay is in `[base*0.75, base*1.25]`.
/// Decorrelates retries from multiple tailnet devices recovering
/// together (avoids the synchronized-retry "thundering herd" pattern).
const BACKOFF_JITTER_FRAC: f64 = 0.25;

/// Compute the sleep delay before reconnect attempt `attempt` (0-indexed).
///
/// Returns `Duration::ZERO` when `attempt == 0` so the first reconnect
/// after a healthy session is immediate — most control-plane errors
/// are transient h2 frames that re-handshake successfully on the very
/// next dial. Subsequent attempts double: ~1 s, ~2 s, ~4 s, ~8 s, ~16 s,
/// ~32 s, then ~60 s (clamped). Each non-zero delay is jittered by
/// ±25% to avoid the thundering-herd effect when multiple tailnet
/// devices recover from a network outage simultaneously.
fn reconnect_backoff(attempt: u32) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }
    // 2^(attempt-1) seconds. Saturate `1 << shift` against overflow at
    // attempt ≥ 64; capped to RECONNECT_BACKOFF_CAP either way.
    let secs = 1u64.checked_shl(attempt - 1).unwrap_or(u64::MAX);
    let base = Duration::from_secs(secs).min(RECONNECT_BACKOFF_CAP);
    apply_jitter(base, BACKOFF_JITTER_FRAC)
}

/// Multiplicative jitter: returns a Duration in `[d*(1-frac), d*(1+frac)]`.
/// Uses `OsRng` from `rand_core` (already in the workspace via
/// `crypto_box`/`x25519_dalek` — no new dep). Resolution is
/// milliseconds, which is fine for reconnect-cadence purposes.
fn apply_jitter(d: Duration, frac: f64) -> Duration {
    use rand_core::RngCore;
    let mut rng = rand_core::OsRng;
    // Sample u32 → fold into [-1, 1].
    let raw = rng.next_u32() as f64 / u32::MAX as f64; // [0, 1]
    let signed = (raw * 2.0) - 1.0; // [-1, 1]
    let multiplier = 1.0 + signed * frac;
    let base_ms = d.as_millis() as f64;
    let jittered_ms = (base_ms * multiplier).max(0.0) as u64;
    Duration::from_millis(jittered_ms)
}

/// Sleep `delay`, polling `should_stop` every 250 ms so the demo can
/// exit promptly during a long backoff. Returns `true` if we got
/// stopped (caller should break out of the event loop).
fn cooperative_sleep<F: FnMut() -> bool>(delay: Duration, should_stop: &mut F) -> bool {
    let wake = Instant::now() + delay;
    while Instant::now() < wake {
        if should_stop() {
            return true;
        }
        let remaining = wake.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(Duration::from_millis(250)));
    }
    false
}

/// Which reconnect attempt is invoking `bootstrap_control_session`.
/// Used only for log distinctness — the work performed is identical.
/// (The first-time bootstrap from `Runtime::up` no longer goes through
/// this helper; M18 split its Noise/H2 setup into `establish_control_conn`
/// so the interactive-login loop can drive register directly.)
#[derive(Clone, Copy, Debug)]
enum BootstrapPhase {
    /// Reconnect attempt N after a control-plane error. The number is
    /// surfaced only through Debug logging (M18 removed the `Initial`
    /// variant — interactive login owns first-boot now), so allow the
    /// field to read as "unused" to dead-code analysis.
    Reconnect(#[allow(dead_code)] u32),
}

/// Fetch server key → Noise IK → HTTP/2 → register → open MapClient.
///
/// Idempotent w.r.t. our persistent state: KeyStore is reloaded from
/// disk by the caller, register is re-sent (Tailscale's register is
/// idempotent — same node_pub + auth_key reaches the same node row,
/// and Ephemeral=true means re-registering a stale identity creates
/// a new one without us caring). `last_seq` for delta-resume lives in
/// `state_dir` and `MapClient::start` picks it up via the same path.
///
/// On reconnect, the magicsock + DERP + engine + netstack are all
/// untouched — only the long-poll tunnel is rebuilt.
fn bootstrap_control_session(
    config: &Config,
    ks: &KeyStore,
    host_authority: &str,
    local_endpoints: Vec<String>,
    local_endpoint_types: Vec<u8>,
    state_dir: &Path,
    phase: BootstrapPhase,
) -> Result<BootstrapOutcome, ts_control::ControlError> {
    info!(?phase, "control.bootstrap.start");

    let mut conn = establish_control_conn(config, ks, state_dir)?;

    // Register. Reconnect uses the persisted (already-authorized) node
    // key, so this is one-shot: Followup=None. Ephemeral=true is baked
    // into ts_control::register so repeating is safe — the server either
    // confirms the existing ephemeral node or attaches us to a fresh row.
    let auth_key = config.auth_key.trim();
    let backend_log_id = generate_backend_log_id();
    info!(backend_log_id = %backend_log_id, "control.backend_log_id.generated");
    let outcome = ts_control::register(
        &mut conn,
        auth_key,
        &ks.node_pub,
        &ks.nl_pub,
        &backend_log_id,
        &config.hostname,
        host_authority,
        None,
    )?;
    suprx_trace("cs7: REGISTERED with control plane!");
    // M19: a reconnect can't itself run the interactive (QR) login loop
    // (no screen ownership here), but if the node lost authorization
    // while we were disconnected (expired or deauthorized) we no longer
    // strand the user — we signal `NeedsInteractiveLogin` so the event
    // loop escalates to the stop-aware `interactive_login` in place
    // (closes the M18 reconnect deferral).
    if outcome.node_key_expired {
        warn!("control.reconnect.node_key_expired; escalating to interactive login");
        return Ok(BootstrapOutcome::NeedsInteractiveLogin);
    }
    if let Some(url) = outcome.pending_auth_url {
        warn!(auth_url = %url, "control.reconnect.needs_login; escalating to interactive login");
        return Ok(BootstrapOutcome::NeedsInteractiveLogin);
    }
    info!(
        machine_authorized = outcome.machine_authorized,
        "control.register.ok"
    );

    // MapClient. Picks up `last_seq` from state_dir so a reconnect
    // resumes the netmap delta instead of redownloading the world.
    let map = finish_session(
        conn,
        ks,
        config,
        host_authority,
        state_dir,
        local_endpoints,
        local_endpoint_types,
        backend_log_id,
    )?;
    info!(?phase, "control.bootstrap.done");
    Ok(BootstrapOutcome::Session(map))
}

/// Result of a reconnect-time [`bootstrap_control_session`]. A normal
/// reconnect yields `Session`; if the persisted node key lost
/// authorization while we were disconnected (expired or deauthorized) it
/// yields `NeedsInteractiveLogin` so the event loop can escalate to the
/// stop-aware [`interactive_login`] in place (closing the M18 reconnect
/// deferral) rather than looping forever on a dead key.
enum BootstrapOutcome {
    Session(MapClient),
    NeedsInteractiveLogin,
}

/// Open the `MapClient` on an authorized `conn`. Factored from the
/// identical `MapClient::start` tails in `Runtime::up`,
/// `bootstrap_control_session`, and the mid-life interactive-login path
/// so first boot, reconnect, and re-login all produce `map_opt` the same
/// way. Resumes `last_seq` from `state_dir`.
#[allow(clippy::too_many_arguments)]
fn finish_session(
    conn: Http2Conn,
    ks: &KeyStore,
    config: &Config,
    host_authority: &str,
    state_dir: &Path,
    local_endpoints: Vec<String>,
    local_endpoint_types: Vec<u8>,
    backend_log_id: String,
) -> Result<MapClient, ts_control::ControlError> {
    MapClient::start(
        conn,
        ks.node_pub,
        ks.disco_pub,
        config.hostname.clone(),
        backend_log_id,
        host_authority.to_string(),
        state_dir.to_path_buf(),
        local_endpoints,
        local_endpoint_types,
    )
}

/// M19 park/logout: drop every WG peer from the engine so the data plane
/// goes quiet immediately — dropping the `MapClient` alone leaves the
/// engine's peers live (recon risk). `peer_regions` holds the current
/// peer set (its keys are the WG public-key bytes); clear it alongside.
fn clear_engine_peers(engine: &Engine, peer_regions: &mut HashMap<[u8; 32], u16>) {
    for node_key in peer_regions.keys() {
        engine.remove_peer(&x25519_dalek::PublicKey::from(*node_key));
    }
    let n = peer_regions.len();
    peer_regions.clear();
    info!(peers = n, "control.engine.peers.cleared");
}

/// M19 logout: delete the persisted map-session state so the next login
/// (a fresh identity) doesn't resume the previous node's netmap delta.
/// Filenames mirror `ts_control::map` (`last_seq` / `session_handle`); a
/// missing file is fine (nothing to clear).
fn delete_session_state(state_dir: &Path) {
    for name in ["last_seq", "session_handle"] {
        let path = state_dir.join(name);
        match vita_fs::remove_file(&path) {
            Ok(()) => info!(file = name, "control.logout.session_state.deleted"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(file = name, error = %e, "control.logout.session_state.delete_failed"),
        }
    }
}

/// M19 `/logout`: expire the node key at control (a RegisterRequest with
/// `Expiry = now`) on a FRESH conn, then, on success, park logged-out:
/// drop the session + WG peers, delete the persisted map-session state,
/// and publish `NeedsLogin` (no auto re-login — the user explicitly
/// left). The node key is deliberately left in place; the next login
/// sends it, control answers expired/AuthURL, and the M18 regenerate
/// branch runs. On any failure we log and keep the prior state (no local
/// wipe unless control confirmed the expiry).
#[allow(clippy::too_many_arguments)]
fn perform_logout(
    config: &Config,
    ks: &KeyStore,
    host_authority: &str,
    state_dir: &Path,
    snapshot: &Arc<RwLock<RuntimeSnapshot>>,
    lifecycle: &Mutex<LifecycleTracker>,
    engine: &Engine,
    peer_regions: &mut HashMap<[u8; 32], u16>,
    map_opt: &mut Option<MapClient>,
) {
    suprx_trace("logout1: establishing fresh conn for logout");
    let mut conn = match establish_control_conn(config, ks, state_dir) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "control.logout.conn_failed; staying in prior state");
            suprx_trace("logout: conn failed; staying");
            return;
        }
    };
    let backend_log_id = generate_backend_log_id();
    match ts_control::logout(
        &mut conn,
        &ks.node_pub,
        &ks.nl_pub,
        &backend_log_id,
        &config.hostname,
        host_authority,
    ) {
        Ok(()) => {
            info!("control.logout.ok");
            suprx_trace("logout2: logout OK; entering logged-out state");
            *map_opt = None;
            clear_engine_peers(engine, peer_regions);
            delete_session_state(state_dir);
            lifecycle.lock().set_needs_login();
            // NeedsLogin + auth_url None + login_in_progress false =
            // the "logged out — press ✕ to log in" screen.
            publish_login_state(snapshot, lifecycle, None, false);
        }
        Err(e) => {
            warn!(error = %e, "control.logout.failed; staying in prior state");
            suprx_trace("logout2: logout FAILED; staying");
        }
    }
}

/// M19: peek pending control signals during a blocking interactive
/// login. A `/down` (`SetWantRunning(false)`) or a shutdown
/// (`should_stop`) aborts the login; other signals are consumed and
/// ignored (we're already logging in). Returns the abort reason, or
/// `None` to keep waiting. Used as the `interactive_login` `abort`
/// closure from the event loop (recon risk: pre-M19 only process death
/// interrupted an unapproved login).
fn peek_login_abort<F: FnMut() -> bool>(
    signal_rx: &Receiver<ControlSignal>,
    should_stop: &mut F,
) -> Option<LoginAbort> {
    if should_stop() {
        return Some(LoginAbort::Shutdown);
    }
    loop {
        match signal_rx.try_recv() {
            Ok(ControlSignal::SetWantRunning(false)) => return Some(LoginAbort::Parked),
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
}

/// Establish the control-plane transport: fetch server key → Noise IK →
/// HTTP/2 over the Noise tunnel. Returns the open `Http2Conn`; the
/// caller drives register + MapClient. Split out of
/// `bootstrap_control_session` (M18) so the interactive-login loop can
/// re-POST `/machine/register` on the *same* conn while waiting for the
/// user to approve.
fn establish_control_conn(
    config: &Config,
    ks: &KeyStore,
    state_dir: &Path,
) -> Result<Http2Conn, ts_control::ControlError> {
    suprx_trace("cs1: pre fetch_server_key (first HTTPS/TLS)");

    // 1. Fetch server's Noise pubkey via cache (M13.5 Stage 2). Cache
    // TTL is 1 h; on a Noise failure below we invalidate + retry to
    // cover the legitimate-rotation case.
    let server_pub = ts_control::fetch_server_key_cached(
        &config.control_url,
        config.capver,
        state_dir,
    )?;
    suprx_trace("cs2: server key received");
    info!(server_pub = %server_pub, "control.key.received");

    // 2. Noise IK handshake.
    info!("starting Noise IK handshake");
    let mut hs = match ts_control::NoiseHandshaker::new(&ks.machine_priv, &server_pub) {
        Ok(h) => h,
        Err(e) => {
            // Handshake construction failure could mean the cached
            // server pub is stale. Drop the cache so the next
            // bootstrap attempt refetches.
            warn!(error = %e, "control.noise.handshaker.failed; invalidating server-key cache");
            ts_control::invalidate_server_key_cache(state_dir);
            return Err(e);
        }
    };
    let header_b64 = hs.build_init_header()?;
    info!(b64_len = header_b64.len(), "control.noise.init.built");

    suprx_trace("cs3: pre dial_and_upgrade (TCP connect + 101)");
    let mut upgraded = ts_control::upgrade::dial_and_upgrade(&config.control_url, &header_b64)?;
    suprx_trace("cs4: upgraded (101); noise handshake next");
    info!(leftover = upgraded.leftover.len(), "control.upgrade.101");

    let server_response = read_server_response(&mut upgraded)?;
    let nt = match hs.finalize(&server_response) {
        Ok(nt) => nt,
        Err(e) => {
            // Most likely a server-key rotation we didn't notice
            // (cached key doesn't match what the server is actually
            // signing with anymore). Invalidate so the next attempt
            // refetches.
            warn!(error = %e, "control.noise.finalize.failed; invalidating server-key cache");
            ts_control::invalidate_server_key_cache(state_dir);
            return Err(e);
        }
    };
    info!(
        handshake_hash = %hex_short(&nt.handshake_hash),
        "control.noise.handshake.complete"
    );

    let leftover = upgraded.leftover;
    let mut noise_stream = NoiseStream::new(upgraded.tcp, nt, leftover);
    consume_early_payload(&mut noise_stream)?;

    suprx_trace("cs5: noise handshake complete; opening h2");
    // 3. HTTP/2 over the Noise tunnel.
    let async_stream = AsyncNoiseStream::spawn(noise_stream);
    info!("opening HTTP/2 over Noise");
    let conn = Http2Conn::open(async_stream)?;
    suprx_trace("cs6: h2 handshake complete (tokio block_on worked!)");
    info!("control.http2.handshake.complete");
    Ok(conn)
}

/// Safety re-poll cadence for the M18 interactive-login loop. The server
/// long-polls on `Followup` (blocking until the user approves), so this
/// short sleep is only a backstop against an early return — it stops a
/// busy-spin without slowing real approval.
const LOGIN_REPOLL_INTERVAL: Duration = Duration::from_secs(2);

/// M19: result of [`interactive_login`]. `Authorized` carries the open,
/// authorized conn (the caller opens `MapClient` on it via
/// `finish_session`); `Aborted` means the `abort` closure fired before
/// the node authorized, so no session was established.
enum LoginOutcome {
    Authorized(Http2Conn),
    Aborted(LoginAbort),
}

/// M19: why the stop-aware [`interactive_login`] abandoned a wait.
/// Returned by the `abort` closure and surfaced on
/// `LoginOutcome::Aborted` so the event loop can react (park vs. exit).
#[derive(Debug, Clone, Copy)]
enum LoginAbort {
    /// A `/down` (`SetWantRunning(false)`) arrived — park instead.
    Parked,
    /// The runtime is shutting down (`should_stop` fired).
    Shutdown,
}

/// M18/M19 interactive control-plane login. Registers on a fresh
/// Noise+H2 `conn` per attempt, looping with `Followup=<AuthURL>` until
/// the node is authorized. On the empty-`auth_key` path it publishes
/// `OnlineState::NeedsLogin` + the AuthURL into the snapshot so the
/// dashboard can render a QR; the user scans + approves on a phone and
/// the server's long-poll then returns `MachineAuthorized=true`.
/// `NodeKeyExpired` regenerates the node key and restarts the loop.
///
/// The `backend_log_id` is generated by the caller (M19: unconditionally
/// in `up()`, freshly per session in the event loop) and passed in so a
/// parked boot has one too; on success the caller starts `MapClient` on
/// the returned conn/session via `finish_session`.
///
/// With a non-empty `auth_key` this is effectively one-shot: register()
/// never yields a pending AuthURL for a supplied key (it returns
/// `AuthRejected` instead), so no NeedsLogin is ever published and the
/// loop returns on the first authorized response.
///
/// M19: stop-aware. `abort` is checked once per loop pass (2 s cadence);
/// when it returns `Some`, the login is abandoned and `LoginOutcome::
/// Aborted` is returned so a `/down` or shutdown can break an otherwise-
/// blocking QR wait (recon risk: pre-M19 only process death interrupted
/// it). `Runtime::up` passes a no-op abort — boot behavior unchanged.
#[allow(clippy::too_many_arguments)]
fn interactive_login(
    config: &Config,
    ks: &mut KeyStore,
    host_authority: &str,
    state_dir: &Path,
    snapshot: &Arc<RwLock<RuntimeSnapshot>>,
    lifecycle: &Mutex<LifecycleTracker>,
    backend_log_id: &str,
    abort: &mut dyn FnMut() -> Option<LoginAbort>,
) -> Result<LoginOutcome, ts_control::ControlError> {
    let auth_key = config.auth_key.trim();
    // A supplied key is an automation override: a real auth/config problem
    // must SURFACE (return Err), not silently retry forever. The empty-key
    // interactive path instead RETRIES transient control errors — the user
    // may still be walking to their phone, and the wait-loop must not tear
    // the whole runtime down (which strands their approval; the original
    // bug shipped: `register(...)?` on a dead reused conn killed Runtime::up).
    let key_supplied = !auth_key.is_empty();

    // M19: signal "login in progress" so the dashboard can show a spinner
    // before the AuthURL (and its QR) arrives. Cleared on authorize /
    // abort below.
    publish_login_state(snapshot, lifecycle, None, true);

    let mut followup: Option<String> = None;
    let mut published_needs_login = false;
    let mut attempt: u32 = 0;

    loop {
        // M19: stop-aware — a `/down` or shutdown breaks an unapproved
        // login. Checked each loop pass (the 2 s repoll sleep below paces
        // it) so the abort lands within one cycle.
        if let Some(reason) = abort() {
            info!(?reason, "control.login.aborted");
            suprx_trace("login: aborted (down/shutdown)");
            publish_login_state(snapshot, lifecycle, None, false);
            return Ok(LoginOutcome::Aborted(reason));
        }
        attempt += 1;
        // Fresh conn per attempt. The control plane closes the Noise/h2
        // conn after each register response, so the followup re-POST
        // cannot reuse the previous one (the reference Rust port likewise
        // reconnects per poll). server-key is cached, so this is cheap
        // after the first handshake.
        let mut conn = match establish_control_conn(config, ks, state_dir) {
            Ok(c) => c,
            Err(e) => {
                if key_supplied {
                    return Err(e);
                }
                suprx_trace(&format!("login: conn attempt {attempt} failed; retry"));
                warn!(error = %e, attempt, "control.login.conn_failed; retrying");
                std::thread::sleep(LOGIN_REPOLL_INTERVAL);
                continue;
            }
        };

        let outcome = match ts_control::register(
            &mut conn,
            auth_key,
            &ks.node_pub,
            &ks.nl_pub,
            backend_log_id,
            &config.hostname,
            host_authority,
            followup.as_deref(),
        ) {
            Ok(o) => o,
            // A supplied key that the server refuses is genuinely fatal.
            Err(e @ ts_control::ControlError::AuthRejected { .. }) => return Err(e),
            Err(e) => {
                if key_supplied {
                    return Err(e);
                }
                suprx_trace(&format!("login: register attempt {attempt} err; retry"));
                warn!(error = %e, attempt, "control.login.register_err; retrying");
                std::thread::sleep(LOGIN_REPOLL_INTERVAL);
                continue;
            }
        };

        // NodeKeyExpired: the persisted node identity is dead
        // server-side. Mint a fresh key and restart the login from
        // scratch (drop any Followup — it referenced the old key's URL).
        // Guard on !machine_authorized so a response that somehow carries
        // both flags still accepts the just-granted authorization.
        if outcome.node_key_expired && !outcome.machine_authorized {
            warn!("control.login.node_key_expired; regenerating node key + restarting login");
            suprx_trace("login: node_key_expired; regenerating node key");
            ks.regenerate_node_key(state_dir)?;
            followup = None;
            continue;
        }

        if outcome.machine_authorized {
            // Leave the NeedsLogin wait-state so the dashboard flips off
            // the QR screen immediately, before the event loop's first
            // snapshot publish. Always clear the in-progress marker set at
            // loop start (M19), whether or not we ever went pending.
            if published_needs_login {
                lifecycle.lock().clear_needs_login();
            }
            publish_login_state(snapshot, lifecycle, None, false);
            suprx_trace(&format!("login: AUTHORIZED on attempt {attempt}"));
            info!(attempt, "control.login.authorized");
            return Ok(LoginOutcome::Authorized(conn));
        }

        match outcome.pending_auth_url {
            Some(url) => {
                info!(
                    auth_url = %url,
                    attempt,
                    "control.login.pending; publishing NeedsLogin (scan to log in)"
                );
                if !published_needs_login {
                    suprx_trace("login: pending; publishing NeedsLogin (scan QR)");
                }
                lifecycle.lock().set_needs_login();
                publish_login_state(snapshot, lifecycle, Some(url.clone()), true);
                published_needs_login = true;
                followup = Some(url);
                std::thread::sleep(LOGIN_REPOLL_INTERVAL);
            }
            None => {
                // Unauthorized, no AuthURL, not expired. For a supplied key
                // this is a genuine failure; for the interactive path just
                // keep polling (a fresh conn next round).
                if key_supplied {
                    return Err(ts_control::ControlError::Transport(
                        "register: not authorized and no AuthURL".into(),
                    ));
                }
                suprx_trace(&format!("login: unauth+no-url attempt {attempt}; retry"));
                std::thread::sleep(LOGIN_REPOLL_INTERVAL);
            }
        }
    }
}

/// M18/M19: patch the published snapshot's `lifecycle` + `auth_url` +
/// `login_in_progress` without a full netmap rebuild (there's no netmap
/// yet during login). Mirrors [`publish_fatal_state`]; holds the write
/// lock for a few microseconds. Also used by the park/logout transitions
/// to publish `Stopped` / `NeedsLogin` promptly.
fn publish_login_state(
    out: &Arc<RwLock<RuntimeSnapshot>>,
    lifecycle: &Mutex<LifecycleTracker>,
    auth_url: Option<String>,
    login_in_progress: bool,
) {
    let state = lifecycle.lock().state();
    let mut w = out.write();
    w.lifecycle = state;
    w.auth_url = auth_url;
    w.login_in_progress = login_in_progress;
    w.updated_at_unix = now_unix();
}

/// Maintain a `node_pub → DERP region` map from each MapResponse
/// snapshot. Used by the Stage-4 CallMeMaybe dispatcher to know which
/// region to relay through for a given peer. Mirrors the region
/// resolution in `push_delta_to_engine`: peer's HomeDERP if non-zero,
/// else our own home region as a fallback.
fn update_peer_regions(
    regions: &mut HashMap<[u8; 32], u16>,
    snap: &ts_control::NetMapSnapshot,
    our_home: u16,
) {
    let delta = &snap.delta;
    for p in &delta.upserted {
        let region = if p.home_derp != 0 { p.home_derp } else { our_home };
        regions.insert(p.node_key, region);
    }
    for k in &delta.removed {
        regions.remove(k);
    }
    for r in &delta.rekeyed {
        regions.remove(&r.old_key);
        let region = if r.snapshot.home_derp != 0 {
            r.snapshot.home_derp
        } else {
            our_home
        };
        regions.insert(r.snapshot.node_key, region);
    }
}

/// Build a fresh `RuntimeSnapshot` from the live netmap + magicsock
/// + DERP + lifecycle state, and publish it into the shared slot.
///
/// Called from the event loop after each `MapEvent::Snapshot` (when
/// the netmap changes) and at lifecycle transitions. The write is
/// fast — readers (LocalAPI handlers) take a read lock briefly to
/// clone, so contention is negligible.
///
/// Arguments are kept un-bundled rather than passed via `&self` so
/// the helper is callable from within the event loop without
/// borrowing all of `self` at once.
fn publish_snapshot(
    out: &Arc<RwLock<RuntimeSnapshot>>,
    started_at_unix: u64,
    hostname: &str,
    netmap: &ts_control::NetMap,
    magic_ctl: &MagicSocketCtl,
    derp_home_region: u16,
    alive_derp_regions: Vec<u16>,
    public_endpoint: Option<SocketAddr>,
    lifecycle: OnlineState,
    fatal_reason: Option<String>,
) {
    let mut peers = HashMap::with_capacity(netmap.peers.len());
    for (node_key, peer) in netmap.peers.iter() {
        let direct_endpoint = magic_ctl.alive_endpoint(node_key);
        let direct_rtt = magic_ctl
            .peer_rtt(node_key)
            .map(|d| d.as_millis() as u64);
        // Primary tailnet IP: pick the first /32 entry (typical case
        // for a node-IP-only peer). Peers with CIDR routes still get
        // those listed under `allowed_ips`, just no `tailscale_ip`.
        let tailscale_ip = peer
            .allowed_ips
            .iter()
            .find(|a| a.prefix == 32)
            .map(|a| a.addr);
        let allowed_ips: Vec<String> = peer
            .allowed_ips
            .iter()
            .map(|a| format!("{}/{}", a.addr, a.prefix))
            .collect();
        let endpoints: Vec<String> =
            peer.endpoints.iter().map(|sa| sa.to_string()).collect();
        let hex = node_key_hex(node_key);
        peers.insert(
            hex.clone(),
            PeerView {
                node_key_hex: hex,
                node_id: peer.node_id,
                name: peer.name.clone(),
                online: peer.online,
                tailscale_ip,
                allowed_ips,
                home_derp: peer.home_derp,
                endpoints,
                direct_path_alive: direct_endpoint.is_some(),
                direct_path_endpoint: direct_endpoint,
                direct_path_rtt_ms: direct_rtt,
                last_seen: peer.last_seen.clone(),
                key_expiry: peer.key_expiry.clone(),
            },
        );
    }

    let our_addrs: Vec<AllowedIpView> = netmap
        .our_addrs
        .iter()
        .map(|a| AllowedIpView {
            addr: a.addr,
            prefix: a.prefix,
        })
        .collect();

    let acl = AclSummary {
        tags: netmap.our_tags.clone(),
        has_tags: !netmap.our_tags.is_empty(),
    };

    let new_snap = RuntimeSnapshot {
        updated_at_unix: now_unix(),
        started_at_unix,
        hostname: hostname.to_string(),
        our_addrs,
        lifecycle,
        fatal_reason,
        // M18: cleared once we're past interactive login (steady state).
        // The login wait-loop sets it via `publish_login_state`; here
        // the netmap is live so there's nothing to log in for.
        auth_url: None,
        peer_count: netmap.peers.len(),
        derp_home_region,
        alive_derp_regions,
        magic_local: magic_ctl.local_addr(),
        public_endpoint,
        acl,
        our_key_expiry: netmap.our_key_expiry.clone(),
        // M19 identity card — sourced from persistent NetMap state so the
        // 3 s full-replace republish can't blank them (unlike partial
        // publishers). `login_in_progress` is always false in steady
        // state; only `publish_login_state` sets it true mid-login.
        tailnet_domain: (!netmap.domain.is_empty()).then(|| netmap.domain.clone()),
        user_login: netmap.our_login_name().map(str::to_owned),
        login_in_progress: false,
        peers,
    };
    *out.write() = new_snap;
}

/// Patch the published snapshot's lifecycle + fatal_reason without
/// rebuilding peers/netmap. Used when an event-loop error transitions
/// us into a terminal state — UI consumers see the new state on the
/// next read even though we have no fresh netmap to publish.
///
/// Optimized for the path where the snapshot is mostly populated;
/// holds the write lock for a few microseconds.
fn publish_fatal_state(
    out: &Arc<RwLock<RuntimeSnapshot>>,
    lifecycle: &Mutex<LifecycleTracker>,
) {
    let lt = lifecycle.lock();
    let state = lt.state();
    let reason = lt.fatal_reason().map(str::to_owned);
    drop(lt);
    let mut w = out.write();
    w.lifecycle = state;
    w.fatal_reason = reason;
    w.updated_at_unix = now_unix();
}

/// Plumb each peer's Disco identity + endpoint candidates into the
/// magic socket so its ping pump can probe direct paths. Called per
/// MapResponse alongside `push_delta_to_engine`.
fn push_delta_to_magicsock(magic: &MagicSocketCtl, snap: &ts_control::NetMapSnapshot) {
    let delta = &snap.delta;
    for p in &delta.upserted {
        let disco_pub = match p.disco_key {
            Some(b) => DiscoPublicKey::from(b),
            None => continue, // pre-disco peer; can't reach directly
        };
        if p.endpoints.is_empty() {
            continue;
        }
        magic.upsert_peer(p.node_key, disco_pub, p.endpoints.clone());
        info!(
            node_id = p.node_id,
            endpoint_count = p.endpoints.len(),
            "magicsock.peer.upsert"
        );
    }
    for k in &delta.removed {
        magic.remove_peer(k);
    }
    for r in &delta.rekeyed {
        magic.remove_peer(&r.old_key);
        if let Some(b) = r.snapshot.disco_key {
            if !r.snapshot.endpoints.is_empty() {
                magic.upsert_peer(
                    r.snapshot.node_key,
                    DiscoPublicKey::from(b),
                    r.snapshot.endpoints.clone(),
                );
            }
        }
    }
}

/// Bind the Disco/direct-path UDP socket. Tries the canonical 41641
/// first; on failure (port taken, sceNet rejection) falls back to
/// ephemeral (0.0.0.0:0).
fn bind_magicsock(
    disco_priv: DiscoPrivateKey,
    our_node_pub: NodePublicKey,
    non_disco_tx: vita_chan::Sender<ts_magicsock::NonDiscoPacket>,
) -> Result<(MagicSocket, MagicSocketCtl), RuntimeError> {
    let primary: SocketAddr = (IpAddr::from([0, 0, 0, 0]), MAGICSOCK_PORT).into();
    match MagicSocket::bind(primary, disco_priv, our_node_pub, non_disco_tx.clone()) {
        Ok(p) => Ok(p),
        Err(e) => {
            warn!(error = %e, port = MAGICSOCK_PORT, "magicsock.bind.primary_failed; trying ephemeral");
            let fallback: SocketAddr = (IpAddr::from([0, 0, 0, 0]), 0).into();
            // Re-derive disco_priv from a fresh copy of the key bytes
            // (the previous one was moved into the failed bind call).
            // Avoid persisting a separate priv copy by reading it back
            // from the disco-pub-derived secret — but DiscoPrivateKey
            // doesn't support that. Workaround: clone via from_bytes()
            // BEFORE the first bind. See caller.
            //
            // Since bind_magicsock takes `disco_priv` by value and we
            // already consumed it, the caller must have given us a
            // unique copy if they want fallback. Phase 2 keeps it
            // simple and propagates the original error.
            let _ = fallback;
            Err(RuntimeError::Internal(format!(
                "magicsock bind failed on {primary}: {e}"
            )))
        }
    }
}

/// Generate a 32-hex-char `BackendLogID` for the lifetime of this
/// runtime. Upstream uses logtail's session ID; we just need
/// something unique-per-process that *looks* like a real client.
fn generate_backend_log_id() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(32);
    use std::fmt::Write as _;
    for b in &bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Discover our LAN IP via the connect-trick (ask the kernel which
/// local IP would route to a given external address; no packet sent).
/// Returns the formatted endpoint strings to advertise in
/// MapRequest.Endpoints. Empty vec on discovery failure — better to
/// send nothing than wrong addresses.
///
/// **Important**: an empty Endpoints list appears to be the silent
/// gate that causes real Tailscale (capver 138) to refuse to commit
/// our `Node.DiscoKey` to its database. The connect-trick used to
/// silently fail on `https://` control URLs because the URL has no
/// port and `UdpSocket::connect(&str)` requires `host:port` form, so
/// MapRequest went out with `Endpoints: []`. We now parse out
/// host+port (defaulting 443 for https, 80 for http) before probing.
fn build_local_endpoints(control_url: &str, magic_local: SocketAddr) -> Vec<String> {
    let (host, default_port) = if let Some(rest) = control_url.strip_prefix("https://") {
        (rest, 443u16)
    } else if let Some(rest) = control_url.strip_prefix("http://") {
        (rest, 80u16)
    } else {
        (control_url, 443u16)
    };
    let host = host.split('/').next().unwrap_or(host);
    let host_port = if host.contains(':') {
        // Already has explicit port (e.g. Headscale on `<host>:8080`).
        host.to_string()
    } else {
        format!("{host}:{default_port}")
    };
    let probe = match UdpSocket::bind(("0.0.0.0", 0)).and_then(|s| {
        s.connect(host_port.as_str())?;
        s.local_addr()
    }) {
        Ok(addr) => addr,
        Err(e) => {
            warn!(error = %e, %host_port, "lan_ip.probe.failed");
            return vec![];
        }
    };
    let lan_ip = probe.ip();
    if lan_ip.is_unspecified() {
        warn!("lan_ip.probe returned 0.0.0.0; not advertising endpoints");
        return vec![];
    }
    let port = magic_local.port();
    let endpoint = match lan_ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };
    vec![endpoint]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exit-node default routes must never reach the engine's LPM index;
    /// everything else passes through (2026-07-02 data-plane bug).
    #[test]
    fn engine_allowed_ips_drops_default_routes() {
        let list = vec![
            ts_control::AllowedIp {
                addr: "100.64.0.2".parse().unwrap(),
                prefix: 32,
            },
            ts_control::AllowedIp {
                addr: "0.0.0.0".parse().unwrap(),
                prefix: 0,
            },
            ts_control::AllowedIp {
                addr: "192.168.50.0".parse().unwrap(),
                prefix: 24,
            },
        ];
        let out = engine_allowed_ips(&list);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|c| c.prefix > 0));
        assert!(out.iter().any(|c| c.prefix == 32));
        assert!(out.iter().any(|c| c.prefix == 24));
    }

    /// Asserts `actual` lies in `[base * (1-frac), base * (1+frac)]`.
    /// Used to validate jittered backoff without flaking on the RNG.
    fn assert_within_jitter(actual: Duration, base: Duration, frac: f64) {
        let base_ms = base.as_millis() as f64;
        let low = ((base_ms * (1.0 - frac)).floor()) as u128;
        let high = ((base_ms * (1.0 + frac)).ceil()) as u128;
        let actual_ms = actual.as_millis();
        assert!(
            (low..=high).contains(&actual_ms),
            "jittered {actual_ms} ms not in [{low}, {high}] for base {base_ms} ms"
        );
    }

    #[test]
    fn reconnect_backoff_first_attempt_is_immediate() {
        // Attempt 0 = "we just got a fresh error, retry now." Jitter
        // does NOT apply — we want predictable immediacy here.
        assert_eq!(reconnect_backoff(0), Duration::ZERO);
    }

    #[test]
    fn reconnect_backoff_doubles_within_jitter() {
        // Each step's base is 2^(attempt-1) seconds, jittered ±25%.
        for (attempt, base_secs) in [(1u32, 1u64), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32)] {
            let got = reconnect_backoff(attempt);
            assert_within_jitter(got, Duration::from_secs(base_secs), BACKOFF_JITTER_FRAC);
        }
    }

    #[test]
    fn reconnect_backoff_clamps_at_cap_with_jitter() {
        // 2^6 = 64s > 60s cap. The clamp happens before jitter so the
        // jittered value sits in cap-band.
        for attempt in [7u32, 8, 20, u32::MAX] {
            let got = reconnect_backoff(attempt);
            assert_within_jitter(got, RECONNECT_BACKOFF_CAP, BACKOFF_JITTER_FRAC);
        }
    }

    #[test]
    fn jitter_stays_within_bounds_under_many_samples() {
        // Validate the apply_jitter helper directly. Sample 1000 times
        // and assert every sample is in range. Catches RNG misuse.
        let base = Duration::from_secs(10);
        for _ in 0..1000 {
            let got = apply_jitter(base, 0.25);
            assert_within_jitter(got, base, 0.25);
        }
    }

    #[test]
    fn control_handle_force_reconnect_delivers_signal() {
        // Validate the handle wiring without standing up a full
        // Runtime. The event loop's drain logic is exercised by
        // hardware verification (Stage 5).
        let (tx, rx) = unbounded::<ControlSignal>();
        let handle = ControlHandle { tx };
        handle.force_reconnect().expect("send should succeed");
        match rx.try_recv() {
            Ok(ControlSignal::ForceReconnect) => {}
            other => panic!("expected ForceReconnect, got {other:?}"),
        }
    }

    #[test]
    fn control_handle_send_fails_after_receiver_dropped() {
        let (tx, rx) = unbounded::<ControlSignal>();
        let handle = ControlHandle { tx };
        drop(rx);
        assert!(handle.force_reconnect().is_err());
    }

    #[test]
    fn control_handle_sends_m19_signals() {
        // The four M19 endpoints all reach the event loop over the one
        // ControlSignal channel; the handle can carry each variant.
        let (tx, rx) = unbounded::<ControlSignal>();
        let handle = ControlHandle { tx };
        handle.send(ControlSignal::SetWantRunning(false)).unwrap();
        handle.send(ControlSignal::Logout).unwrap();
        handle.send(ControlSignal::LoginInteractive).unwrap();
        assert!(matches!(
            rx.try_recv(),
            Ok(ControlSignal::SetWantRunning(false))
        ));
        assert!(matches!(rx.try_recv(), Ok(ControlSignal::Logout)));
        assert!(matches!(rx.try_recv(), Ok(ControlSignal::LoginInteractive)));
    }

    #[test]
    fn peek_login_abort_shutdown_wins() {
        // should_stop takes priority — a shutdown aborts even with a
        // full signal queue.
        let (tx, rx) = unbounded::<ControlSignal>();
        tx.send(ControlSignal::SetWantRunning(false)).unwrap();
        let mut stop = || true;
        assert!(matches!(
            peek_login_abort(&rx, &mut stop),
            Some(LoginAbort::Shutdown)
        ));
    }

    #[test]
    fn peek_login_abort_down_parks() {
        let (tx, rx) = unbounded::<ControlSignal>();
        tx.send(ControlSignal::SetWantRunning(false)).unwrap();
        let mut stop = || false;
        assert!(matches!(
            peek_login_abort(&rx, &mut stop),
            Some(LoginAbort::Parked)
        ));
    }

    #[test]
    fn peek_login_abort_ignores_other_signals() {
        // A login is already in progress — SetWantRunning(true),
        // LoginInteractive, and ForceReconnect are consumed and ignored,
        // leaving the wait to continue.
        let (tx, rx) = unbounded::<ControlSignal>();
        tx.send(ControlSignal::LoginInteractive).unwrap();
        tx.send(ControlSignal::SetWantRunning(true)).unwrap();
        tx.send(ControlSignal::ForceReconnect).unwrap();
        let mut stop = || false;
        assert!(peek_login_abort(&rx, &mut stop).is_none());
    }

    #[test]
    fn peek_login_abort_empty_queue_keeps_waiting() {
        let (_tx, rx) = unbounded::<ControlSignal>();
        let mut stop = || false;
        assert!(peek_login_abort(&rx, &mut stop).is_none());
    }

    #[test]
    fn classify_auth_rejected_is_fatal() {
        let err = ts_control::ControlError::AuthRejected {
            auth_url: "https://login.tailscale.com/a/abc".into(),
        };
        assert_eq!(classify_control_error(&err), ErrorClass::AuthFatal);
    }

    #[test]
    fn classify_http_401_403_410_are_auth_fatal() {
        for status in [401u16, 403, 410] {
            let err = ts_control::ControlError::Http {
                status,
                body: "".into(),
            };
            assert_eq!(
                classify_control_error(&err),
                ErrorClass::AuthFatal,
                "HTTP {status} should be AuthFatal"
            );
        }
    }

    #[test]
    fn classify_http_5xx_is_transient() {
        for status in [500u16, 502, 503, 504] {
            let err = ts_control::ControlError::Http {
                status,
                body: "".into(),
            };
            assert_eq!(
                classify_control_error(&err),
                ErrorClass::Transient,
                "HTTP {status} should be Transient"
            );
        }
    }

    #[test]
    fn classify_machine_unauthorized_transport_message_is_auth_fatal() {
        // register.rs:108-112 emits this shape when MachineAuthorized
        // is false but no AuthURL is present (e.g., revoked node).
        let err = ts_control::ControlError::Transport(
            "register: MachineAuthorized=false (no AuthURL)".into(),
        );
        assert_eq!(classify_control_error(&err), ErrorClass::AuthFatal);
    }

    #[test]
    fn classify_generic_transport_is_transient() {
        let err = ts_control::ControlError::Transport("ureq: timed out".into());
        assert_eq!(classify_control_error(&err), ErrorClass::Transient);
    }

    #[test]
    fn classify_bad_server_key_is_security_fatal() {
        let err = ts_control::ControlError::BadServerKey {
            reason: "expected 64 hex chars in mkey",
        };
        assert_eq!(classify_control_error(&err), ErrorClass::SecurityFatal);
        assert_eq!(
            classify_control_error(&ts_control::ControlError::ServerKeyChanged),
            ErrorClass::SecurityFatal
        );
    }

    #[test]
    fn classify_watchdog_and_eof_are_transient() {
        let watchdog = ts_control::ControlError::MapWatchdog { idle_secs: 120 };
        assert_eq!(classify_control_error(&watchdog), ErrorClass::Transient);
        let eof =
            ts_control::ControlError::MapConnectionLost("server closed map stream".into());
        assert_eq!(classify_control_error(&eof), ErrorClass::Transient);
    }
}
