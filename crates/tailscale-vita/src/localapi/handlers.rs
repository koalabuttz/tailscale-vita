//! LocalAPI endpoint handlers. Each function takes `&HandlerCtx` (and
//! optionally a parsed query string) and returns `(status_code,
//! body_bytes)`. Body is always JSON; the router writes the
//! Content-Type header.
//!
//! Stage 3 implements the four read-only endpoints (status, whois,
//! health, netmap). Stage 4 fills in the active ones (ping, reconnect).
//! Handlers must not block — they take read-locks on the snapshot
//! briefly and return immediately.

use std::net::Ipv4Addr;

use serde::Serialize;
use vita_log::debug;

use crate::localapi::http::query_get;
use crate::localapi::router::HandlerCtx;
use crate::snapshot::{now_unix, PeerView};

/// `GET /localapi/v0/status` — full runtime snapshot as JSON. Same
/// shape as `RuntimeSnapshot` (Serialize derive).
pub fn status(ctx: &HandlerCtx) -> (u16, Vec<u8>) {
    let snap = ctx.snapshot.read();
    match serde_json::to_vec(&*snap) {
        Ok(bytes) => (200, bytes),
        Err(e) => {
            debug!(error = %e, "localapi.status.serialize");
            (500, json_error("serialize failed"))
        }
    }
}

/// `GET /localapi/v0/whois?addr=100.x.y.z` — identify a peer at a
/// tailnet IP. 404 if no peer matches. 400 if `addr` missing or
/// malformed.
pub fn whois(ctx: &HandlerCtx, query: &str) -> (u16, Vec<u8>) {
    let addr_str = match query_get(query, "addr") {
        Some(v) => v,
        None => return (400, json_error("missing query param: addr")),
    };
    let target: Ipv4Addr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return (400, json_error("addr is not a valid IPv4")),
    };

    let snap = ctx.snapshot.read();
    let found: Option<&PeerView> = snap
        .peers
        .values()
        .find(|p| p.tailscale_ip == Some(target));
    match found {
        Some(peer) => match serde_json::to_vec(peer) {
            Ok(bytes) => (200, bytes),
            Err(_) => (500, json_error("serialize failed")),
        },
        None => (404, json_error("no peer with that tailnet IP")),
    }
}

/// `GET /localapi/v0/health` — small liveness payload that ALSO
/// reflects the lifecycle state so monitoring scripts can tell
/// "running but auth-failed" from "running and online".
pub fn health(ctx: &HandlerCtx) -> (u16, Vec<u8>) {
    #[derive(Serialize)]
    struct Health {
        ok: bool,
        uptime_secs: u64,
        lifecycle: crate::lifecycle::OnlineState,
        fatal_reason: Option<String>,
    }
    let snap = ctx.snapshot.read();
    let now = now_unix();
    let uptime = now.saturating_sub(snap.started_at_unix);
    let lifecycle = snap.lifecycle;
    let fatal_reason = snap.fatal_reason.clone();
    drop(snap);
    let body = Health {
        ok: !matches!(
            lifecycle,
            crate::lifecycle::OnlineState::AuthFailed
                | crate::lifecycle::OnlineState::SecurityFailed
        ),
        uptime_secs: uptime,
        lifecycle,
        fatal_reason,
    };
    (
        200,
        serde_json::to_vec(&body).unwrap_or_else(|_| json_error("serialize failed")),
    )
}

/// `GET /localapi/v0/netmap` — alias for `/status` today. We keep
/// them as separate endpoints so future divergence (e.g., adding a
/// DerpMap field that's noisy and only the netmap variant carries it)
/// doesn't break /status consumers.
pub fn netmap(ctx: &HandlerCtx) -> (u16, Vec<u8>) {
    status(ctx)
}

/// `GET /localapi/v0/ping?ip=100.x.y.z` — active Disco probe.
/// Returns `{rtt_ms, endpoint}` on success, `{error: "..."}` otherwise.
/// 5-second timeout — Disco round-trips on a live tailnet path are
/// typically <100 ms, so 5 s is generous.
pub fn ping(ctx: &HandlerCtx, query: &str) -> (u16, Vec<u8>) {
    use std::time::Duration;
    let ip_str = match query_get(query, "ip") {
        Some(v) => v,
        None => return (400, json_error("missing query param: ip")),
    };
    let target_ip: Ipv4Addr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return (400, json_error("ip is not a valid IPv4")),
    };

    // Resolve tailnet IP → node-key via snapshot.
    let node_pub: [u8; 32] = {
        let snap = ctx.snapshot.read();
        match snap
            .peers
            .values()
            .find(|p| p.tailscale_ip == Some(target_ip))
        {
            Some(peer) => match hex_to_bytes(&peer.node_key_hex) {
                Some(b) => b,
                None => return (500, json_error("snapshot peer has malformed node_key_hex")),
            },
            None => return (404, json_error("no peer with that tailnet IP")),
        }
    };

    match ctx.magic.ping_now(&node_pub, Duration::from_secs(5)) {
        Ok((endpoint, rtt)) => {
            #[derive(Serialize)]
            struct Resp {
                rtt_ms: u64,
                endpoint: String,
            }
            let body = Resp {
                rtt_ms: rtt.as_millis() as u64,
                endpoint: endpoint.to_string(),
            };
            (
                200,
                serde_json::to_vec(&body)
                    .unwrap_or_else(|_| json_error("serialize failed")),
            )
        }
        Err(e) => {
            debug!(error = %e, "localapi.ping.failed");
            // Map domain errors to 200-with-error (so curl scripts can
            // parse the JSON) — these are expected outcomes, not
            // server faults.
            (200, json_error(&e.to_string()))
        }
    }
}

/// `POST /localapi/v0/reconnect` — kick the control-plane reconnect.
/// Refuses in fatal lifecycle states (mirrors the event loop's
/// signal-drop logic).
pub fn reconnect(ctx: &HandlerCtx) -> (u16, Vec<u8>) {
    let snap = ctx.snapshot.read();
    let state = snap.lifecycle;
    let fatal_reason = snap.fatal_reason.clone();
    drop(snap);
    if matches!(
        state,
        crate::lifecycle::OnlineState::AuthFailed
            | crate::lifecycle::OnlineState::SecurityFailed
    ) {
        #[derive(Serialize)]
        struct Resp {
            ok: bool,
            error: String,
        }
        let body = Resp {
            ok: false,
            error: format!(
                "runtime in fatal state ({state:?}); fix config + restart instead{}",
                fatal_reason
                    .as_ref()
                    .map(|r| format!(": {r}"))
                    .unwrap_or_default()
            ),
        };
        return (
            409,
            serde_json::to_vec(&body)
                .unwrap_or_else(|_| json_error("serialize failed")),
        );
    }
    match ctx.controller.force_reconnect() {
        Ok(()) => {
            #[derive(Serialize)]
            struct Resp {
                ok: bool,
            }
            (
                202,
                serde_json::to_vec(&Resp { ok: true })
                    .unwrap_or_else(|_| json_error("serialize failed")),
            )
        }
        Err(_) => (503, json_error("control loop has shut down")),
    }
}

/// `POST /localapi/v0/up` — resume the tailnet (`WantRunning = true`),
/// driving the runtime out of `Stopped`. Zero-parameter; body ignored.
pub fn up(ctx: &HandlerCtx) -> (u16, Vec<u8>) {
    control_action(ctx, crate::runtime::ControlSignal::SetWantRunning(true))
}

/// `POST /localapi/v0/down` — park the tailnet (`WantRunning = false`):
/// close the control session + drop WG peers, hold `Stopped`.
/// Zero-parameter; body ignored.
pub fn down(ctx: &HandlerCtx) -> (u16, Vec<u8>) {
    control_action(ctx, crate::runtime::ControlSignal::SetWantRunning(false))
}

/// `POST /localapi/v0/logout` — expire the node key at control and park
/// logged-out (`NeedsLogin`, no auto re-login). The node key is
/// regenerated at the next login. Zero-parameter; body ignored.
pub fn logout(ctx: &HandlerCtx) -> (u16, Vec<u8>) {
    control_action(ctx, crate::runtime::ControlSignal::Logout)
}

/// `POST /localapi/v0/login-interactive` — start an interactive (QR)
/// login now (post-logout screen or a manual re-authenticate).
/// Zero-parameter; body ignored.
pub fn login_interactive(ctx: &HandlerCtx) -> (u16, Vec<u8>) {
    control_action(ctx, crate::runtime::ControlSignal::LoginInteractive)
}

/// Shared body for the M19 zero-parameter lifecycle POSTs (`/up`,
/// `/down`, `/logout`, `/login-interactive`). Mirrors the `reconnect`
/// template: refuse in fatal lifecycle states with 409, otherwise queue
/// the signal (202 = accepted, watch /status) or report a dead loop
/// (503). Body carries no parameters, so nothing to parse.
fn control_action(
    ctx: &HandlerCtx,
    signal: crate::runtime::ControlSignal,
) -> (u16, Vec<u8>) {
    let snap = ctx.snapshot.read();
    let state = snap.lifecycle;
    let fatal_reason = snap.fatal_reason.clone();
    drop(snap);
    if matches!(
        state,
        crate::lifecycle::OnlineState::AuthFailed
            | crate::lifecycle::OnlineState::SecurityFailed
    ) {
        #[derive(Serialize)]
        struct Resp {
            ok: bool,
            error: String,
        }
        let body = Resp {
            ok: false,
            error: format!(
                "runtime in fatal state ({state:?}); fix config + restart instead{}",
                fatal_reason
                    .as_ref()
                    .map(|r| format!(": {r}"))
                    .unwrap_or_default()
            ),
        };
        return (
            409,
            serde_json::to_vec(&body)
                .unwrap_or_else(|_| json_error("serialize failed")),
        );
    }
    match ctx.controller.send(signal) {
        Ok(()) => {
            #[derive(Serialize)]
            struct Resp {
                ok: bool,
            }
            (
                202,
                serde_json::to_vec(&Resp { ok: true })
                    .unwrap_or_else(|_| json_error("serialize failed")),
            )
        }
        Err(_) => (503, json_error("control loop has shut down")),
    }
}

fn hex_to_bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte_chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(byte_chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

fn json_error(msg: &str) -> Vec<u8> {
    // Hand-rolled to avoid pulling serde_json for a 1-key object.
    // Caller is responsible for not passing a string with embedded
    // `"` — all our error sites use static strings.
    format!("{{\"error\":\"{msg}\"}}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::localapi::router::HandlerCtx;
    use crate::runtime::ControlHandle;
    use crate::snapshot::{AllowedIpView, RuntimeSnapshot};
    use vita_chan::unbounded;
    use vita_sync::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Test context. Returns the rx side too so callers can keep it
    /// alive — `reconnect_returns_202_in_normal_state` needs a live
    /// receiver or `force_reconnect` returns 503.
    fn synthetic_ctx() -> (
        HandlerCtx,
        Arc<RwLock<RuntimeSnapshot>>,
        vita_chan::Receiver<crate::runtime::ControlSignal>,
    ) {
        use ts_disco::keys::{DiscoPrivateKey, NodePublicKey};
        use ts_magicsock::MagicSocket;
        let snap = RuntimeSnapshot {
            updated_at_unix: 1_700_000_100,
            started_at_unix: 1_700_000_000,
            hostname: "vita".into(),
            our_addrs: vec![AllowedIpView {
                addr: Ipv4Addr::new(100, 127, 67, 49),
                prefix: 32,
            }],
            lifecycle: crate::lifecycle::OnlineState::Online,
            fatal_reason: None,
            auth_url: None,
            peer_count: 1,
            derp_home_region: 12,
            alive_derp_regions: vec![12],
            magic_local: "0.0.0.0:41641".parse().unwrap(),
            public_endpoint: Some("66.31.113.175:41641".parse().unwrap()),
            acl: crate::snapshot::AclSummary {
                tags: vec!["tag:vita".into()],
                has_tags: true,
            },
            our_key_expiry: Some("2027-01-15T00:00:00Z".into()),
            tailnet_domain: Some("example.com".into()),
            user_login: Some("dave@example.com".into()),
            login_in_progress: false,
            peers: {
                let mut m = HashMap::new();
                m.insert(
                    "ab".repeat(32),
                    PeerView {
                        node_key_hex: "ab".repeat(32),
                        node_id: 42,
                        name: "phone".into(),
                        online: true,
                        tailscale_ip: Some(Ipv4Addr::new(100, 64, 0, 5)),
                        allowed_ips: vec!["100.64.0.5/32".into()],
                        home_derp: 12,
                        endpoints: vec!["166.198.24.1:29944".into()],
                        direct_path_alive: true,
                        direct_path_endpoint: Some("166.198.24.1:29944".parse().unwrap()),
                        direct_path_rtt_ms: Some(68),
                        last_seen: None,
                        key_expiry: None,
                    },
                );
                m
            },
        };
        let arc = Arc::new(RwLock::new(snap));
        let (tx, rx) = unbounded();
        // Stand up an ephemeral magicsock on loopback. The /status,
        // /whois, /health, /netmap, /reconnect tests don't exercise
        // it; only /ping would. We keep the _sock guard alive via
        // an OnceLock so the socket isn't dropped mid-test.
        let priv_key = DiscoPrivateKey::random();
        let node_pub = NodePublicKey::from([0u8; 32]);
        let (non_disco_tx, _non_disco_rx) = unbounded();
        let (magic_sock, magic_ctl) = MagicSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            priv_key,
            node_pub,
            non_disco_tx,
        )
        .expect("magicsock bind");
        // Leak the magic_sock so the worker thread keeps running for
        // the duration of the test. (Each test gets a fresh
        // synthetic_ctx call → fresh leaked socket.)
        Box::leak(Box::new(magic_sock));
        let ctx = HandlerCtx {
            snapshot: Arc::clone(&arc),
            controller: ControlHandle { tx },
            magic: magic_ctl,
        };
        (ctx, arc, rx)
    }

    #[test]
    fn status_returns_200_and_serializable_json() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, body) = status(&ctx);
        assert_eq!(code, 200);
        // Body should round-trip through serde_json::Value.
        let v: serde_json::Value = serde_json::from_slice(&body).expect("valid json");
        assert_eq!(v["hostname"], "vita");
        assert_eq!(v["lifecycle"], "Online");
        assert_eq!(v["peers"][&"ab".repeat(32)]["name"], "phone");
        assert_eq!(v["peers"][&"ab".repeat(32)]["direct_path_rtt_ms"], 68);
    }

    #[test]
    fn whois_finds_peer_by_tailscale_ip() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, body) = whois(&ctx, "addr=100.64.0.5");
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["name"], "phone");
    }

    #[test]
    fn whois_returns_404_for_unknown_ip() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, _) = whois(&ctx, "addr=100.99.99.99");
        assert_eq!(code, 404);
    }

    #[test]
    fn whois_returns_400_for_missing_param() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, _) = whois(&ctx, "");
        assert_eq!(code, 400);
    }

    #[test]
    fn whois_returns_400_for_malformed_addr() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, _) = whois(&ctx, "addr=not-an-ip");
        assert_eq!(code, 400);
    }

    #[test]
    fn health_reports_ok_and_uptime() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, body) = health(&ctx);
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["lifecycle"], "Online");
        // uptime_secs should be ≥ 0 (uses wall-clock vs started_at).
        assert!(v["uptime_secs"].is_number());
    }

    #[test]
    fn health_reports_not_ok_when_auth_failed() {
        let (ctx, snap, _rx) = synthetic_ctx();
        snap.write().lifecycle = crate::lifecycle::OnlineState::AuthFailed;
        snap.write().fatal_reason = Some("test reason".into());
        let (code, body) = health(&ctx);
        assert_eq!(code, 200); // still 200 — ok=false is in the body
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["lifecycle"], "AuthFailed");
        assert_eq!(v["fatal_reason"], "test reason");
    }

    #[test]
    fn ping_returns_400_for_missing_ip() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, _) = ping(&ctx, "");
        assert_eq!(code, 400);
    }

    #[test]
    fn ping_returns_404_for_unknown_ip() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, _) = ping(&ctx, "ip=100.99.99.99");
        assert_eq!(code, 404);
    }

    #[test]
    fn reconnect_returns_409_in_fatal_state() {
        let (ctx, snap, _rx) = synthetic_ctx();
        snap.write().lifecycle = crate::lifecycle::OnlineState::AuthFailed;
        snap.write().fatal_reason = Some("bad auth key".into());
        let (code, body) = reconnect(&ctx);
        assert_eq!(code, 409);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], false);
        let err = v["error"].as_str().unwrap();
        assert!(err.contains("bad auth key"), "error msg should embed fatal_reason: {err}");
    }

    #[test]
    fn reconnect_returns_202_in_normal_state() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, body) = reconnect(&ctx);
        assert_eq!(code, 202);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn up_returns_202_in_normal_state() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, body) = up(&ctx);
        assert_eq!(code, 202);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn down_returns_202_in_normal_state() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, body) = down(&ctx);
        assert_eq!(code, 202);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn logout_returns_202_in_normal_state() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, body) = logout(&ctx);
        assert_eq!(code, 202);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn login_interactive_returns_202_in_normal_state() {
        let (ctx, _, _rx) = synthetic_ctx();
        let (code, body) = login_interactive(&ctx);
        assert_eq!(code, 202);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn lifecycle_posts_refuse_409_in_fatal_state() {
        let (ctx, snap, _rx) = synthetic_ctx();
        snap.write().lifecycle = crate::lifecycle::OnlineState::AuthFailed;
        snap.write().fatal_reason = Some("bad auth key".into());
        for (code, body) in [up(&ctx), down(&ctx), logout(&ctx), login_interactive(&ctx)] {
            assert_eq!(code, 409);
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["ok"], false);
            assert!(v["error"].as_str().unwrap().contains("bad auth key"));
        }
    }

    #[test]
    fn lifecycle_posts_return_503_when_loop_dead() {
        // Dropping rx severs the signal channel; `send` then errors,
        // proving these handlers use the generic `send` path (503).
        let (ctx, _, rx) = synthetic_ctx();
        drop(rx);
        assert_eq!(up(&ctx).0, 503);
        assert_eq!(down(&ctx).0, 503);
        assert_eq!(logout(&ctx).0, 503);
        assert_eq!(login_interactive(&ctx).0, 503);
    }

    #[test]
    fn hex_to_bytes_round_trips() {
        assert!(hex_to_bytes("ab").is_none()); // too short
        assert!(hex_to_bytes(&"z".repeat(64)).is_none()); // non-hex
        let got = hex_to_bytes(&"ab".repeat(32)).unwrap();
        assert_eq!(got, [0xAB; 32]);
    }
}
