# M21 — tailscaled as a background application (4–6 days + 24h soak)

The re-hosting milestone: the Tailscale runtime moves out of the taiHEN
SUPRX and into a **Vita background application** (bgapp) — a normal
user-mode process that survives leaving the app, browsing LiveArea, and
(non-enlarged-memory) game launches. One bubble ships both halves:
`eboot.bin` (gdc) = the dashboard UI, which also launches `eboot2.bin`
(gdd) = the headless daemon.

**Goal.** (1) `tailscale ping vita`, ts-ftp, and Taildrop all work while
the Vita sits on LiveArea with no app open — daemon alive in the gdd
process. (2) The dashboard opens from the same bubble, reads daemon state
over LocalAPI, and drives login/up/down/logout/ftp toggles cross-process.
(3) 24h soak clean → the bgapp becomes the primary host; the SUPRX path is
deprecated (kept buildable as a fallback).

**Why this is low-risk now — the two proofs already in hand:**

- **Spike 06 PASSED (2026-07-10, commit b7877e5).** A gdd process runs
  headless with a 14 MB heap and answers UDP from the LAN while on
  LiveArea. Root cause of every earlier spawn failure was the missing
  SELF memory budget: a bgapp is a "system mode app" and MUST carry
  `MEMSIZE` (ctrl-info-6 word3, KB) + `ATTRIBUTE` (word1) — vita-make-fself
  `-m`/`-at`. Ceiling is 0x12800 KB ≈ 74 MB. Iterate by **rebuild +
  full REINSTALL only** (appmgr binds the SELF at install; FTP hot-swap
  desyncs and re-throws "could not find application").
- **The daemon-in-a-plain-eboot shape already exists.** The demo's
  `suprx_host_only = false` mode (tailscale-vita-demo/src/main.rs:148-166)
  runs the full runtime in-process via `run_supervised(cfg, should_stop,
  AcceptSession::spawn)` — the M10 configuration, HW-proven for months.
  A gdd is a normal eboot process with a normal crt0: **none of the SUPRX
  scaffolding** (pte shims, `_init_vita_heap` chain, taipool, 30 s boot
  grace, budget preflight) applies. The daemon crate is "the demo minus
  vita2d".

---

## Architecture

```
one VPK / one bubble
├── eboot.bin  (gdc)  tailscale-vita-demo, evolved: vita2d dashboard
│                     + sceBgAppUtilStartBgApp(0) at startup
│                     + "daemon: running/stopped" row + Stop/Start
├── eboot2.bin (gdd)  NEW crate crates/tailscale-vita-daemon:
│                     vita_log → Config::load_or_template →
│                     run_supervised + AcceptSession (demo's M10 path)
│                     + NotificationUtilBgAppInitialize + PowerTick loop
│                     heap 32 MB, SELF budget MEMSIZE 49152 ATTRIBUTE 3
└── sce_sys/param.sfo + param2.sfo   (sfo_make.py clones, real identity)
```

- **IPC = LocalAPI as-is**: daemon binds `127.0.0.1:41112`
  (std::net, localapi.rs:57), dashboard client connects to the same
  (ui/client.rs:27). Today both ends live in one process; cross-process
  loopback is the **single unproven assumption** → Phase A kills it first.
- **Identity**: fresh pair `TSVT00001` (gdc, "Tailscale Vita") /
  `TSVT00002` (gdd, "Tailscale Daemon"), CONTENT_ID
  `HB0000-TSVT00001_00-TAILSCALEVITA000` scheme, gdd INSTALL_DIR_* →
  TSVT00001. The old demo bubble (TVIT00010) stays installable for the dev
  loop; uninstall it (and remove the SUPRX from ur0:tai config) before the
  soak so exactly one runtime owns the KeyStore.
- **Memory budget math**: SUPRX ran the whole runtime in a 16 MB heap.
  Daemon sets `_newlib_heap_size_user = 32 MB` (headroom for netmap
  growth + taildrop buffers) inside `MEMSIZE 49152` (48 MB — spike showed
  budget ≈ heap + ~2 MB overhead, so 48 leaves ~14 MB slack; ceiling 74).
  NOTE: the demo crate never sets `_newlib_heap_size_user` and inherits
  newlib's huge default — fine for a normal app, **fatal in a gdd** (crt0
  heap grant > budget = silent death before main, the round-2 signature).
  The daemon MUST export it explicitly:
  `#[no_mangle] pub static _newlib_heap_size_user: u32 = 32 * 1024 * 1024;`
- **Logging**: two processes must not append the same file. Daemon keeps
  `vita.log` (continuity with all tooling); dashboard-as-gdc switches to
  `dashboard.log`. The raw `phase2-trace.txt` stays SUPRX-only.
- **Lifecycle**: bgapp dies on card-peel or enlarged-memory game launch
  (inherent; document, point at LowMemMode). Manual suspend → resume
  should reconnect via the supervisor (verify). PowerTick
  DISABLE_AUTO_SUSPEND each loop like BGFTP, behind config
  `[power] keep_awake = true` (default true — auto-sleep kills Wi-Fi and
  therefore the daemon; the whole point is staying reachable).

---

## Phase A — cross-process LocalAPI spike (½ day, 1 install cycle)

> **RESULT 2026-07-10: PASSED — `XPROC VERDICT = YES` (HW-verified).**
> Launcher (own sceNet context) connected to the gdd's `127.0.0.1:41112`
> on try 3 (~1.5 s after StartBgApp) and got `HTTP/1.1 200 OK`; gdd
> logged `served hit #1, peer=0x7F000001`. Isolation confirmed from a
> LAN host: TCP :41112 → connection REFUSED (RST), while UDP :31338
> still answered. **The architecture stands unchanged — LocalAPI works
> as dashboard↔daemon IPC as-is.** Piggyback data: notification send
> fails 0x80106301 identically at +0/+1/+31/+61 s after boot with a
> wire shape byte-identical to BGFTP's (zeroed 0x410 buffer, UTF-16
> text at offset 0) — NOT a timing issue; Phase E needs a different
> lead (GrapheneCt SDK's SceNotificationUtilSendParam layout vs
> vitasdk's raw-buffer binding, BGFTP's 18 KB `-pm` phycont, or
> per-app notification settings).

Extend `spikes/06-bgapp` (C, cheap): gdd binds a TCP listener on
`127.0.0.1:41112` and answers one canned HTTP response; the gdc launcher,
before exiting, connects + GETs + logs the verdict line
(`xproc_loopback=YES/NO rc=0x...`). From the host, also confirm :41112 is
NOT reachable via the LAN IP (loopback isolation sanity — LocalAPI must
not become tailnet/LAN-visible by accident).

- **YES** → architecture above stands unchanged. Expected: Vita's sceNet
  is one kernel-side stack (SceNetPs), sockets are kernel objects, so
  loopback should route across processes — but nobody has proven it here.
- **NO** → fallback ladder, decided in the deliverable not re-litigated:
  (1) bind LocalAPI on the LAN IP, keep the `X-Tailscale-Vita-Local`
  action header AND add a peer-addr==own-IP check (reject non-self
  sources); (2) last resort, file-based request/response IPC under
  state_dir (ugly, but vita_fs exists).

Piggyback (free, same install): retry `sceNotificationUtilSendNotification`
with BGFTP's exact init/send sequence to gather data on 0x80106301 for
Phase E.

## Phase B — Rust daemon skeleton in the gdd (1 day)

New workspace member `crates/tailscale-vita-daemon` (bin crate):

- `main()`: `vita_log::init()` → heartbeat log line → spawn a std thread →
  bind a std::net UDP echo on :31338 (the spike's port). This proves Rust
  std / threads / sockets in the gdd partition **before** the full runtime
  goes in.
- `[package.metadata.vita]`: `title_id = "TSVT00002"`,
  `vita_make_fself_flags = ["-m", "49152", "-at", "3"]` (cargo-vita 0.2.2
  passes these through to vita-make-fself).
- `scripts/build-bgapp-vpk.sh`: `cargo vita build vpk` for daemon + demo,
  unzip both VPKs to extract each `eboot.bin` SELF, generate
  param.sfo/param2.sfo via a generalized `sfo_make.py` (lifted out of the
  spike; real identity strings), `vita-pack-vpk` the combined VPK with
  LiveArea assets. **The script must parse the daemon SELF and assert
  ctrl-info-6 word1=3 / word3=49152** (parser method banked in the spike
  notes) — if cargo-vita's flag pass-through misbehaves, fall back to
  re-running vita-make-fself on the .velf manually.
- Deploy + verify: ALIVE line with `heap=32MB`, echo answers, memblock
  ladder shows expected slack. Full reinstall each cycle.

## Phase C — full runtime in the gdd (1–2 days)

Swap the skeleton body for the real daemon:

- Port the demo's in-process path: `Config::load_or_template(CONFIG_PATH)`
  → `run_supervised(cfg, should_stop, AcceptSession::spawn)` on the main
  thread (no UI thread). `AcceptSession` (the tailnet-facing
  `netstack::TcpListener` + `/api/*`→LocalAPI proxy in the demo's
  handler.rs) moves to a shared home — recommend `tailscale-vita` proper —
  so demo, rt, and daemon stop keeping three copies.
- bgapp trimmings: `sceNotificationUtilBgAppInitialize`, PowerTick loop
  (own low-frequency thread or supervisor tick), `[power] keep_awake`
  config, heap/budget constants.
- Config guard: when the dashboard runs as gdc it must NEVER start the
  runtime in-process (two runtimes = KeyStore/port fights). Generalize
  `suprx_host_only` → the dashboard treats "someone else hosts the
  runtime" identically whether that's the SUPRX or the bgapp; keep the old
  key as an alias.
- **Verify (the money shot)**: dashboard closed, Vita on LiveArea — from a
  peer: `tailscale ping` the Vita, ts-ftp login + transfer, Taildrop a
  file. Then: launch a (non-enlarged-memory) game and repeat the ping;
  screen-off and repeat; manual suspend → wake → confirm supervisor
  reconnects. Measure ts-ftp throughput vs. the demo baseline (bgapp runs
  at low priority on the system-reserved core — quantify the hit).

## Phase D — dashboard as launcher (1 day)

- Demo crate: `SceBgAppUtil` FFI (`sceBgAppUtilStartBgApp`, stub link line
  in build.rs), called at startup in bgapp mode. Treat the
  already-running error code as success (log it). Retry/StartBgApp button
  in Settings for the not-running case.
- Dashboard header row: daemon status = LocalAPI reachable (running) /
  connect-refused (stopped) — poll piggybacks on the existing 2 s /status
  worker.
- New endpoint `POST /localapi/v0/quit-daemon` (action header required):
  clean supervisor shutdown → `sceKernelExitProcess`. Settings row "Stop
  background daemon" — so stopping doesn't require card-peel. `/down`
  keeps its meaning (tailnet off, daemon alive).
- Dev loop preserved: the plain single-eboot demo VPK (in-process runtime)
  still builds and runs for fast iteration.

## Phase E — polish + docs (1 day)

- **Notifications (0x80106301)**: root-cause with BGFTP's MIT source as
  the reference-spec (open tools/source only — no leaked SDK). Wire
  state-change notifications: needs-login (QR waiting), tailnet up/down,
  Taildrop file received.
- LiveArea assets: replace BGFTP placeholders with Tailscale-Vita art
  (icon0/bg0/startup/template.xml).
- Docs: new `docs/BGAPP-DEPLOY.md` (install/update = reinstall, stop =
  dashboard button or card-peel, enlarged-mem-game + card-peel caveats,
  LowMemMode pointer, battery note for keep_awake). README updated.
  `PLUGIN-DEPLOY.md` gets a deprecation banner pointing here.
- SUPRX: crates stay in-tree and buildable (fallback host + the pthread
  investigation is historically valuable), no longer the advertised path.

## Soak gate

24 h with the dashboard closed, Vita on LiveArea: heartbeat log clean, a
peer cron-pings the tailnet IP, one ts-ftp transfer + one Taildrop at
start/middle/end. Clean soak = M21 done; bgapp is the primary host.

---

## Risk register

| # | Risk | Mitigation |
|---|------|------------|
| 1 | ~~Cross-process 127.0.0.1 unproven on sceNet~~ **CLOSED: proven 2026-07-10 (Phase A YES + LAN isolation confirmed)** | — |
| 2 | gdd heap grant vs budget (silent pre-main death) | Explicit 32 MB heap export + 48 MB MEMSIZE; skeleton phase re-runs the spike's memory probes |
| 3 | cargo-vita `-m/-at` pass-through unverified | build script parses SELF ctrl-info-6 and asserts; manual vita-make-fself fallback |
| 4 | Low CPU priority → WG/ftp throughput regression | Measure in Phase C; `sceKernelChangeThreadPriority` within allowed band if needed |
| 5 | Dual-runtime conflicts (SUPRX or in-process demo alongside daemon) | Config guard (Phase C) + pre-soak checklist: remove SUPRX from tai config, uninstall TVIT00010 |
| 6 | Concurrent config access (dashboard writes toggles, daemon reads) | Same discipline as today: section-aware line-edit + .bak + verify-restore (vita_fs rename is non-atomic) |
| 7 | Two processes appending one log | Daemon owns vita.log; dashboard logs to dashboard.log |
| 8 | Card-peel / enlarged-mem game kills daemon | Inherent to bgapps — document; dashboard shows "stopped" + Start button on next open |

## Explicitly out of scope (banked)

- **Autostart at console boot** — bgapps don't autostart; a one-line
  taiHEN plugin calling StartBgApp at boot is a possible future opt-in.
- Taildrop **send**, LiveArea live-status widgets, notification actions.
- Any SUPRX `*main` promotion — that door is closed (M20-D take 6).
