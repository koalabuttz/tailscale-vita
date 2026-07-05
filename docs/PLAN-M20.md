# M20 — Path stability + Taildrop receive (4–6 days + 24h soak)

The consolidation milestone: every deferred item, bundled into **one SUPRX
build + one reboot**, then a 24-hour soak that gates promoting the plugin
from `*TITLEID` to `*main`.

**Goal.** (1) The direct WG path stops flapping by design: alive paths are
heartbeated like upstream, unadvertised ping sources become candidates, and
`auth_src` gets a trust window — the LAN↔WAN-hairpin flap observed on
2026-07-04 disappears. (2) `tailscale file cp <file> vita:` from any
same-user device drops the file onto the Vita's memory card — AirDrop for
homebrew. (3) 24h soak clean → plugin runs system-wide under `*main`.

**Workstream B (auto re-login on reconnect deauth) is already CLOSED** —
research confirmed M19's supervisor wired it: `bootstrap_control_session` →
`BootstrapOutcome::NeedsInteractiveLogin` (runtime.rs:1799-1806) →
`LoopExit::NeedsRelogin` (runtime.rs:888-906) → `run_supervised` re-runs
`up()` → `interactive_login` publishes the QR and rotates the key on
expiry. No app restart. Full-rebuild (not in-place re-key) is deliberate:
there is no safe in-place WG re-key, and the code says so
(runtime.rs:19-24). Known-and-accepted nuances, documented here so nobody
re-litigates them: a device parked via `/down` that hits mid-session deauth
comes back *running* (the want_running=true forcing at runtime.rs:1368-1372
is the fix for the poisoned-config bug and wins); LocalAPI/ts-ftp have a
brief downtime window during the relogin rebuild (bind-retry guarded).

---

## Workstream A — Disco path-selection parity (ts-magicsock + wg-engine)

### Confirmed current behavior (research 2026-07-04)

- `ping_pump` re-pings only when `stale_ping && dead`
  (ts-magicsock/src/lib.rs:1284-1295): an **alive path is never
  heartbeated**, so `last_pong_at` ages out at `ALIVE_TTL = 30s` (lib.rs:88)
  and `alive_endpoint` flaps 30s-alive/≤5s-dead **by design**. The pump is
  additionally gated at `PING_INTERVAL = 5s` (lib.rs:85, 854-861).
- A disco ping from an **unadvertised src** is ponged (lib.rs:1076-1096) but
  never inserted into `peer.endpoints`/`peer.paths` — it can never be
  validated (pongs update paths keyed by src, lib.rs:1124). Contrast
  `handle_call_me_maybe`, which merges advertised endpoints + creates
  PathStates (lib.rs:1229-1234) — that's the pattern to copy.
- wg-engine `auth_src` (peer.rs:95) has **no timestamp and is never
  cleared**; `pick_addr` (pump.rs:106-141) uses it unconditionally ahead of
  the disco hint. It's refreshed on every authenticated inbound datagram
  (pump.rs:217-221), so it only goes stale across idle gaps — and a stale
  one is exactly how the 2026-07-04 WAN-hairpin flap held for 2½ minutes.
- Upstream Go (`wgengine/magicsock/endpoint.go`): `heartbeatInterval = 3s`,
  `trustUDPAddrDuration = 6.5s`, `de.heartbeat()` re-pings bestAddr so trust
  renews *before* lapse, `de.addCandidateEndpoint(src)` on ping from unknown
  src. (The tailscale-rs reference port has **no path-selection state
  machine at all** — wire types only — so upstream Go semantics are the
  spec here.)

### A1 — Heartbeat alive paths (3s)

- New constant `HEARTBEAT_INTERVAL = 3s` next to lib.rs:85-88.
- `needs_ping` split: alive path → re-ping when `last_ping_at` elapsed ≥
  `HEARTBEAT_INTERVAL`; dead/never-alive candidate → keep the existing
  `PING_INTERVAL` spacing (don't over-ping dead candidates).
- Lower the pump gate (lib.rs:854) from `PING_INTERVAL` to
  `HEARTBEAT_INTERVAL` — free, the recv loop already wakes every 50ms.
- **Keep `ALIVE_TTL = 30s` in M20** (conservative). With a working 3s
  heartbeat it never lapses on a healthy path; shrinking it toward
  upstream's 6.5s trust window is a follow-up only after the heartbeat is
  proven on hardware. (Shrinking it first/alone would flap *faster*.)
- No new state: `PathState.last_ping_at` (lib.rs:157) already suffices.

### A2 — Learn unadvertised ping-src as candidate

In the Ping arm (lib.rs:1076-1096), when the sender resolves to a known
node and `src` isn't in `peer.paths`: `peer.endpoints.push(src)` +
`peer.paths.entry(src).or_insert_with(PathState::new)` — mirroring
lib.rs:1229-1234. Guards: known-node only (spoof bound), cap candidates per
peer (8). The fixed pump then probes it; on pong it becomes eligible in
`alive_endpoint`. This is what lets us reach peers that never advertise
their real LAN address (the ChromeOS test PC).

### A3 — auth_src trust window (6.5s)

- `Peer.auth_src` becomes `ArcSwap<Option<(TransportAddr, Instant)>>`
  (peer.rs:95); `set_auth_src` stamps now (caller pump.rs:219).
- New constant `AUTH_SRC_TRUST = 6.5s` in wg-engine.
- `pick_addr` (pump.rs:110-116): fresh `auth_src` (< 6.5s) → alive disco
  hint → DERP. Stale auth_src is skipped, not cleared (it may refresh on
  the next inbound).

### ⚠ Sequencing (the one landmine)

**A1 and A3 ship atomically.** Today auth_src papers over the disco flap:
expire it without the heartbeat and every idle gap drops selection to DERP
— regressing the currently-working direct path. A2 is independent and
low-risk. None of A touches DERP fallback or the tx-queue machinery.
`cmm_pump` is unaffected (only triggers when NO path is alive,
lib.rs:1363).

### A verification

- Host: unit tests for the `needs_ping` matrix (alive-fresh / alive-stale /
  dead-fresh / dead-stale) and `pick_addr` expiry precedence.
- Hardware (log-based, instrumentation already in-tree at debug):
  `pong.alive` cadence ~3s steady; `alive_endpoint` never flaps across a
  10-minute idle watch; path stays LAN-direct across an idle→active
  transition; the hairpin address never gets picked while LAN is alive.

---

## Workstream C — Taildrop receive (`ts-peerapi`)

### Confirmed protocol (research 2026-07-04; Go-derived, reference port has no peerapi)

- Discovery: sender finds us **only** via `Hostinfo.Services` containing
  `{Proto:"peerapi4", Port:<bound port>, Description:"peerapi"}` in our
  MapRequest, propagated by control into peers' netmaps. No Services entry
  ⇒ `tailscale file cp` says "no targets". **We currently send NO Services
  field at all** — neither `HostinfoWire` (register.rs:364-378) nor
  `MapHostinfoWire` (types.rs:273-291) has one. This is the gating gap.
- Surface: `PUT /v0/put/<url-path-escaped-basename>`, plain HTTP/1.1 over
  the tunnel, body = raw bytes with `Content-Length`. One PUT per file,
  sequential. Reply `200` on success; `400` bad name, `403` sender not
  permitted, `405` non-PUT, `413` too big (our addition), `500` I/O error.
- Convention: stream to `<name>.partial`, rename to final on completion;
  collision → `foo (1).txt` style. Resume/Range: optional — a sender falls
  back to full-PUT-from-0 if we don't support it (ignore offset params).
  No mandatory checksums.
- Sender identity = TCP source IP (already a tailnet IP post-WG-decap) →
  netmap lookup. Receiver-side enforcement is same-user-or-cap; **v1
  posture: the tailnet ACL is the boundary** (same stance as ts-ftp,
  ts-ftp/src/lib.rs:20-24, and the project threat model). Adding
  `user_id` to `PeerSnapshot` (netmap.rs:407-436 currently drops
  `NodeWire.user`) is stretch hardening, not v1.
- IPv4-only netstack (tcp.rs:463) ⇒ advertise `peerapi4` only. Fine:
  senders prefer v4. Peerapi is dialed at our real 100.x address — no
  quad-100 handling.

### C1 — Advertise Services (ts-control)

`ServiceWire { Proto, Port, Description }` + `Services:
Option<Vec<ServiceWire>>` on `MapHostinfoWire` (types.rs:273-291),
`skip_serializing_if` when None; populated in the MapRequest builder from a
new optional field plumbed config → runtime → MapClient. Register-path
Hostinfo untouched. **Wire-shape care**: PascalCase tags, and mind the
TS2021 lesson that control is strict about envelope shape — verify with a
live map session that the stream still establishes before building C2 on
top.

### C2 — `ts-peerapi` crate

Lifecycle clone of ts-ftp (`spawn`/`Drop`-join/accept-loop/reap skeleton,
ts-ftp/src/lib.rs; bind via `TcpListener::bind_handle`, all-addrs accept,
`accept_timeout` gives the source tailnet `SocketAddr` — exactly what
identity needs). HTTP layer: purpose-built reader on `httparse`
(workspace dep) modeled on localapi/http.rs but **streaming**: parse
head, then pipe body → `vita_fs` in chunks honoring `Content-Length`.
The LocalAPI reader buffers ≤8KB in RAM (http.rs:20) — do NOT reuse it
for file bodies.

Handler rules:
- Filename: unescape once → reject empty/`.`/`..`/any `/ \ :`/control
  chars → basename only → join under `dir` (stricter than ts-ftp's vfs —
  Taildrop names are never paths).
- Write: `<name>.partial` → on success rename to collision-free final name
  with the **verify-and-rewrite guard** — `vita_fs::rename` is
  remove-then-rename, NON-atomic (the config_edit.rs:196-208 pattern).
- Failure: best-effort remove `.partial`, `500`. `Content-Length` >
  `max_size` → `413` before reading.

### C3 — Config + runtime wiring + snapshot

- `[taildrop]` section (`enabled` default false, `dir` default
  `ux0:/data/tailscale-vita/taildrop/`, `port` default 8098, `max_size`
  default 256 MB), embedded like `[ftp]` (config.rs pattern + TEMPLATE
  block). Pointing `dir` at `ux0:/vpk/` = the sideload-inbox trick —
  document it in the template comment.
- Runtime: `_ts_peerapi: Option<...>` field + spawn beside ts-ftp
  (runtime.rs:484-493 pattern); bind failure non-fatal.
- `RuntimeSnapshot.recent_taildrops: Vec<TaildropEvent>` (name, size,
  sender, ts, status; capped ~8) pushed directly via the shared
  `Arc<RwLock<>>` (the LocalAPI pattern, runtime.rs:330). Transient by
  design (cleared on park/logout).

### C4 (stretch) — Dashboard inbox

Small "received files" list (Debug tab or peer-detail footer) reading
`recent_taildrops` via LocalAPI. Eboot-only change; can ship after the
SUPRX deploy without a reboot.

### C verification

- Host: sanitization table test (traversal, device tokens, unicode,
  overlong), streaming-write chunk test, collision-rename test.
- Hardware e2e: `tailscale file cp hello.txt vita:` from lewis → file in
  drop dir + 200 at sender + snapshot event. Then a multi-MB VPK to
  measure real throughput. **Throughput expectation**: the stress run
  sustained ~11 KB/s on 64KB transfers (RTT-bound WiFi power-save +
  16KB buffers) — a 10 MB VPK may take minutes. Acceptable for v1;
  bumping the peerapi socket rx buffer is the first lever if it annoys.

---

## Workstream D — 24h soak → `*main` promotion

Gate: A + C deployed and verified. Then:

1. **Soak**: leave the runtime up 24h in normal home-LAN conditions,
   dashboard uptime counter as the clock. Pass criteria: uptime counter
   never resets (no crash/restart), no OOM trend in vita.log, ts-ftp GET +
   taildrop PUT + peer ping all work at hour-24, log volume sane at the
   committed (quiet) levels.
2. **Promote**: move the plugin line in `ur0:tai/config.txt` from
   `*<TITLEID>` to `*main`. Keep the old line commented for one-edit
   rollback. Document the un-brick path in PLUGIN-DEPLOY.md **before**
   promoting (taiHEN skip-plugins boot / safe mode → edit config.txt),
   honoring the boot-risk concern from M11 — the plugin has run only
   under the demo TITLEID so far; `*main` means SceShell-wide.
3. **Post-promotion sanity**: reboot ×3, LiveArea usable, sleep/wake
   cycle, then the runtime reachable without the demo app open (this is
   the payoff: FTP/Taildrop to the Vita while it sits on the LiveArea).

---

## Order of work (maximal bundling, one reboot)

| # | Item | Crates | Independent? |
|---|------|--------|--------------|
| 1 | A2 candidate learning | ts-magicsock | yes — smallest, do first |
| 2 | A1+A3 heartbeat + trust window (atomic pair) | ts-magicsock, wg-engine | pair |
| 3 | C1 Services advertisement | ts-control | yes |
| 4 | C2+C3 ts-peerapi + wiring | new crate, tailscale-vita | after C1 |
| 5 | Host test suite green, build SUPRX **once**, deploy, reboot | — | — |
| 6 | Verify A (log watch) + C (file cp e2e) same session | — | — |
| 7 | C4 dashboard inbox (eboot, no reboot needed) | tailscale-vita-demo | stretch |
| 8 | D soak 24h → promote → post-promotion sanity | — | gate |

Estimated: A ≈ 1–1.5 days, C ≈ 2–3 days, D ≈ 1 day active + 24h wall
clock.

## Risks

- **A regression risk**: mis-sequencing A1/A3 (mitigated: one commit);
  heartbeat traffic is negligible (1 ping/3s per alive path, few peers).
- **C1 wire risk**: control rejecting an unexpected Hostinfo shape mid-map
  — verify stream health immediately after landing C1, before C2.
- **C2 abuse surface**: peerapi accepts writes from any ACL-permitted peer
  — consistent with the project threat model (ACL is the boundary; no
  local consent UX by decision). `max_size` + dedicated default dir bound
  the blast radius; `user_id` enforcement is the documented hardening
  follow-up.
- **D promotion risk**: a crash under SceShell takes down more than the
  demo app. The 24h soak under TITLEID + documented skip-plugins recovery
  is the mitigation; promote only after a clean soak.
