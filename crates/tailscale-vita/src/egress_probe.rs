//! Fork-B E2/E3 — controlled UDP egress-shape probe for the WG
//! data-plane bug (see docs/EGRESS-PROBE.md and the
//! `wg_dataplane_peer_session_bug` investigation).
//!
//! The bug: WG transport-data frames (byte0=0x04, len>32) sent through
//! the production path never reach any peer, while keepalives (0x04/32),
//! handshakes (0x01/148, 0x02/92) and Disco (0x54.../110-124) through
//! the SAME `sendto` do. This probe sends a battery of tagged UDP shapes
//! through that exact production path (`MagicSocketCtl::send_to` →
//! tx_queue → v4 worker drain → sceNetSendto), plus a direct-send
//! control (the STUN context, known-delivering), to listener targets we
//! control. Which shapes ARRIVE — observed with
//! `scripts/egress-probe-listener.py` — collapses the remaining fork:
//!
//! - a shape arrives on a same-LAN listener but not across the carrier
//!   → on-path middlebox (H1); compare shapes to find its classifier.
//! - the wg-data shape drops even on the same LAN → local sceNet/driver
//!   egress fault (H2); the recorded return counts localize it further.
//!
//! Every probe datagram carries a trailer tag in its last 4 bytes:
//! `[0xA5, shape_id | ctx<<4, round, 0x5A]` (ctx 0 = tx_queue drain,
//! ctx 1 = direct send). The tag sits in ciphertext-position bytes —
//! random-looking to any stateless classifier — so it identifies probes
//! at the listener without perturbing DPI classification.
//!
//! Shape battery (why each exists):
//!   1 `wg-data-96`  96 B, exact WG transport-data layout, high entropy.
//!                   The shape that never arrives in production.
//!   2 `flip0-96`    byte-identical to 1 except byte0=0x14.
//!                   Isolates "byte0 == 0x04" as the discriminator.
//!   3 `ka-32`       32 B keepalive layout. Positive control — this
//!                   shape DOES deliver in production.
//!   4 `zero-96`     like 1 but all-zero body. Isolates content entropy.
//!   5 `wg-data-110` 110 B type-4 — a size PROVEN to deliver (as Disco).
//!                   Deconfounds size vs message type.
//!   6 `disco-110`   110 B with the real Disco magic. Positive control
//!                   at the same size as shape 5.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use ts_magicsock::MagicSocketCtl;
use vita_log::{info, warn};

/// `[egress_probe]` TOML section. Off by default — this is a
/// diagnostic, not a service.
#[derive(Clone, Debug, Deserialize)]
pub struct EgressProbeConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Listener endpoints, `"ip:port"`. Typically one on the same LAN
    /// as the Vita (no carrier in path) and optionally one across the
    /// carrier (public VM). Unparseable entries are logged + skipped.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Full battery repetitions. Arrival is reported as a rate, not a
    /// single bit — a lone drop can be transient loss.
    #[serde(default = "default_rounds")]
    pub rounds: u32,
    /// Delay before the first round, so Disco/sessions establish and
    /// the send path is in its steady production state.
    #[serde(default = "default_delay_secs")]
    pub initial_delay_secs: u64,
    /// Gap between individual probe sends. Spaced so a burst can't trip
    /// transient buffer pressure and poison an otherwise-good shape.
    #[serde(default = "default_spacing_ms")]
    pub spacing_ms: u64,
}

impl Default for EgressProbeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            targets: vec![],
            rounds: default_rounds(),
            initial_delay_secs: default_delay_secs(),
            spacing_ms: default_spacing_ms(),
        }
    }
}

fn default_rounds() -> u32 {
    5
}
fn default_delay_secs() -> u64 {
    15
}
fn default_spacing_ms() -> u64 {
    250
}

/// Human names, indexed by `shape_id - 1`. Keep in sync with
/// `scripts/egress-probe-listener.py`.
pub const SHAPE_NAMES: [&str; 6] = [
    "wg-data-96",
    "flip0-96",
    "ka-32",
    "zero-96",
    "wg-data-110",
    "disco-110",
];

const TRAILER_LEN: usize = 4;
const TRAILER_A: u8 = 0xA5;
const TRAILER_Z: u8 = 0x5A;

/// Deterministic xorshift32 filler, seeded per (shape, round) — repeated
/// runs produce byte-identical probes, so captures are comparable.
fn fill_entropy(buf: &mut [u8], seed: u32) {
    let mut x = seed.wrapping_mul(2654435761) | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = (x >> 24) as u8;
    }
}

/// WG transport-data layout: `[0]=0x04, [1..4]=0, [4..8]=receiver_index,
/// [8..16]=counter (LE u64), [16..]=ciphertext-position bytes`. The
/// receiver_index is entropy-filled (it's effectively random in real
/// traffic); the body is entropy or zeros per `entropy_body`.
fn wg_type4(len: usize, round: u8, shape_id: u8, entropy_body: bool) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 0x04;
    let seed = 0x5747_0000 | ((shape_id as u32) << 8) | round as u32;
    fill_entropy(&mut p[4..8], seed ^ 0xffff_ffff);
    p[8..16].copy_from_slice(&(round as u64).to_le_bytes());
    if entropy_body {
        let end = len - TRAILER_LEN;
        fill_entropy(&mut p[16..end], seed);
    }
    p
}

/// Disco-shaped: real magic prefix, then entropy where the sender key,
/// nonce and sealed box would sit.
fn disco_shape(len: usize, round: u8, shape_id: u8) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[..6].copy_from_slice(&ts_disco::Header::MAGIC);
    let seed = 0x4453_0000 | ((shape_id as u32) << 8) | round as u32;
    let end = len - TRAILER_LEN;
    fill_entropy(&mut p[6..end], seed);
    p
}

/// The untagged battery for one round: `(shape_id, bytes)`.
fn build_battery(round: u8) -> Vec<(u8, Vec<u8>)> {
    let wg96 = wg_type4(96, round, 1, true);
    let mut flip = wg96.clone();
    flip[0] = 0x14; // not WG (0x01-0x04), not Disco ('T'), not STUN (0x00/0x01)
    vec![
        (1, wg96),
        (2, flip),
        (3, wg_type4(32, round, 3, true)),
        (4, wg_type4(96, round, 4, false)),
        (5, wg_type4(110, round, 5, true)),
        (6, disco_shape(110, round, 6)),
    ]
}

/// Stamp the trailer tag: `[0xA5, shape_id | ctx<<4, round, 0x5A]`.
fn tag(mut p: Vec<u8>, shape_id: u8, ctx: u8, round: u8) -> Vec<u8> {
    let n = p.len();
    p[n - 4] = TRAILER_A;
    p[n - 3] = shape_id | (ctx << 4);
    p[n - 2] = round;
    p[n - 1] = TRAILER_Z;
    p
}

#[derive(Default)]
struct Summary {
    sends: u64,
    full: u64,
    short: u64,
    zero: u64,
    err: u64,
}

impl Summary {
    fn count(&mut self, req: usize, ret: &Result<usize, (std::io::ErrorKind, Option<i32>)>) {
        self.sends += 1;
        match ret {
            Ok(n) if *n == req => self.full += 1,
            Ok(0) => self.zero += 1,
            Ok(_) => self.short += 1,
            Err(_) => self.err += 1,
        }
    }
}

fn fmt_ret(ret: &Result<usize, (std::io::ErrorKind, Option<i32>)>) -> String {
    match ret {
        Ok(n) => n.to_string(),
        Err((kind, raw)) => format!("err:{kind:?}:{}", raw.map_or(-1, |e| e)),
    }
}

/// Spawn the probe thread. Fire-and-forget; the thread exits after the
/// last round. `trace` lines are prefixed `wgpr:` and land in
/// phase2-trace.txt on the Vita (plus the normal log on host).
pub fn spawn(
    ctl: MagicSocketCtl,
    cfg: EgressProbeConfig,
    trace: Arc<dyn Fn(&str) + Send + Sync>,
) {
    let mut targets: Vec<SocketAddr> = Vec::new();
    for t in &cfg.targets {
        match t.parse() {
            Ok(a) => targets.push(a),
            Err(_) => {
                warn!(target = %t, "egress_probe.target.unparseable");
                trace(&format!("wgpr: bad target '{t}' skipped"));
            }
        }
    }
    if targets.is_empty() {
        trace("wgpr: enabled but no valid targets; probe not started");
        return;
    }
    // Keep a handle for the failure path — `warn!` alone is invisible
    // in-SUPRX, and a silent no-op probe is indistinguishable from
    // "targets unreachable" without this line.
    let trace_err = Arc::clone(&trace);
    let spawned = vita_thread::Builder::new()
        .name("egress-probe")
        .stack_size(256 * 1024)
        .spawn(move || run(ctl, cfg, targets, trace));
    if let Err(e) = spawned {
        trace_err(&format!("wgpr: probe thread spawn FAILED: {e}"));
        warn!(error = %e, "egress_probe.spawn_failed");
    }
}

fn run(
    ctl: MagicSocketCtl,
    cfg: EgressProbeConfig,
    targets: Vec<SocketAddr>,
    trace: Arc<dyn Fn(&str) + Send + Sync>,
) {
    std::thread::sleep(Duration::from_secs(cfg.initial_delay_secs));
    let rounds = cfg.rounds.min(200) as u8; // round fits the u8 tag byte
    let spacing = Duration::from_millis(cfg.spacing_ms);
    trace(&format!(
        "wgpr: start rounds={rounds} targets={targets:?} spacing_ms={}",
        cfg.spacing_ms
    ));
    info!(?targets, rounds, "egress_probe.start");

    // Flush records that predate the probe so round 0's drain is clean.
    let _ = ctl.take_send_records();
    let _ = wg_engine::selection_log::take();
    let mut sum = Summary::default();

    for round in 0..rounds {
        for (shape_id, base) in build_battery(round) {
            for &dst in &targets {
                // ctx 0 — the PRODUCTION path: enqueue for the worker
                // drain, exactly like every real WG frame. Result is
                // recorded by the worker; harvested below.
                let queued = tag(base.clone(), shape_id, 0, round);
                if let Err(e) = ctl.send_to(dst, &queued) {
                    trace(&format!(
                        "wgpr:enq r={round} s={shape_id} dst={dst} err={e}"
                    ));
                }
                std::thread::sleep(spacing);

                // ctx 1 — direct send from this thread (the STUN
                // context). Synchronous: the true count comes back here.
                let direct = tag(base.clone(), shape_id, 1, round);
                let ret = match ctl.send_direct(dst, &direct) {
                    Ok(n) => Ok(n),
                    Err(e) => Err((e.kind(), e.raw_os_error())),
                };
                sum.count(direct.len(), &ret);
                trace(&format!(
                    "wgpr:direct r={round} s={shape_id} dst={dst} req={} ret={}",
                    direct.len(),
                    fmt_ret(&ret)
                ));
                std::thread::sleep(spacing);
            }
        }

        // Give the worker one more drain window, then harvest the real
        // return counts for everything it sent this round — our ctx-0
        // probes AND any live WG traffic (keepalives, data frames if a
        // peer is pinging). The live-frame records are E3 gold: the
        // first direct observation of sceNet's verdict on real 96-byte
        // data frames.
        std::thread::sleep(Duration::from_millis(200));
        for rec in ctl.take_send_records() {
            sum.count(rec.req, &rec.ret);
            trace(&format!(
                "wgpr:rec r={round} dst={} b0={:02x} req={} ret={}",
                rec.dst,
                rec.byte0,
                rec.req,
                fmt_ret(&rec.ret)
            ));
        }
        // Engine-level attribution: which peer each outbound frame was
        // mapped to, and why pick_addr chose that endpoint.
        for line in wg_engine::selection_log::take() {
            trace(&format!("wgsel: r={round} {line}"));
        }
    }

    trace(&format!(
        "wgpr: done rounds={rounds} sends={} full={} short={} zero={} err={}",
        sum.sends, sum.full, sum.short, sum.zero, sum.err
    ));
    info!(
        sends = sum.sends,
        full = sum.full,
        short = sum.short,
        zero = sum.zero,
        err = sum.err,
        "egress_probe.done"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn battery_shapes_have_documented_layouts() {
        let battery = build_battery(3);
        let lens: Vec<usize> = battery.iter().map(|(_, p)| p.len()).collect();
        assert_eq!(lens, vec![96, 96, 32, 96, 110, 110]);

        let by_id = |id: u8| &battery.iter().find(|(i, _)| *i == id).unwrap().1;
        // Type-4 shapes lead with 0x04 + zero reserved bytes.
        for id in [1u8, 3, 4, 5] {
            let p = by_id(id);
            assert_eq!(p[0], 0x04, "shape {id} byte0");
            assert_eq!(&p[1..4], &[0, 0, 0], "shape {id} reserved");
        }
        // Counter carries the round.
        assert_eq!(&by_id(1)[8..16], &3u64.to_le_bytes());
        // flip0 differs from wg-data-96 ONLY at byte 0.
        assert_eq!(by_id(2)[0], 0x14);
        assert_eq!(&by_id(1)[1..], &by_id(2)[1..]);
        // zero-96 body is all zeros (header + trailer aside).
        assert!(by_id(4)[16..92].iter().all(|&b| b == 0));
        // wg-data-96 body is NOT all zeros (entropy).
        assert!(by_id(1)[16..92].iter().any(|&b| b != 0));
        // disco-110 starts with the real Disco magic.
        assert_eq!(&by_id(6)[..6], &ts_disco::Header::MAGIC);
    }

    #[test]
    fn tag_stamps_trailer() {
        let p = tag(vec![0u8; 96], 5, 1, 7);
        assert_eq!(&p[92..], &[TRAILER_A, 5 | (1 << 4), 7, TRAILER_Z]);
        // Battery + tag reproduce byte-identically across calls
        // (deterministic entropy) — captures stay comparable.
        let a = tag(build_battery(2).remove(0).1, 1, 0, 2);
        let b = tag(build_battery(2).remove(0).1, 1, 0, 2);
        assert_eq!(a, b);
    }

    #[test]
    fn config_defaults() {
        let cfg: EgressProbeConfig = toml::from_str("").unwrap();
        assert!(!cfg.enabled);
        assert!(cfg.targets.is_empty());
        assert_eq!(cfg.rounds, 5);
        assert_eq!(cfg.initial_delay_secs, 15);
        assert_eq!(cfg.spacing_ms, 250);

        let cfg: EgressProbeConfig = toml::from_str(
            "enabled = true\ntargets = [\"192.168.8.101:9999\"]\nrounds = 2",
        )
        .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.targets, vec!["192.168.8.101:9999"]);
        assert_eq!(cfg.rounds, 2);
    }
}
