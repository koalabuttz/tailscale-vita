# M17-A — On-device dashboard (read-only) (4–6 days)

The demo eboot stops being a black screen. In `suprx_host_only` mode it currently
sleeps forever while the SUPRX runs the tailnet (`main.rs:121-126`); M17-A replaces
that sleep with a vita2d render loop showing node status + a peer list, fed by the
SUPRX's LocalAPI over loopback. This is the first slice of "the Android app": the
SUPRX is the VPN service, the host eboot is the UI process.

**Goal.** Launch the demo bubble and *see* the tailnet: lifecycle state, our
tailnet IP, DERP home, and a scrollable peer list with online/direct-path/RTT per
peer — plus a D-pad-driven disco-ping action. Read-only; zero configuration
writes (that's M17-B).

**Success (hardware-checkable).** With the SUPRX loaded and a second tailnet
member (`lewis`) on the same LAN: within 30 s of launch the screen shows
`Online`, the Vita's 100.x address, and `lewis` with a green dot + `direct N ms`;
selecting `lewis` and pressing ✕ renders a pong RTT. While the UI runs, `ftp
<vita-tailnet-ip>` from lewis still works (the render loop must not starve the
runtime). Tier-2 cross-check: the on-screen peer list agrees with `tailscale
status` on lewis.

**Non-goals for M17-A.** Config writes / restart flow (M17-B); ACL-posture panel
and untagged-key warning UX (M17-C); touch input, LiveArea custom assets,
themes (M17-C); exit-node UI (deliberately unsupported — we filter `/0` routes);
new LocalAPI fields (last_seen, tx/rx bytes — noted below, deferred).

## Architecture

```
┌────────────── TVIT00010 process ──────────────────────────────┐
│  SUPRX (tailscale-vita-rt)          demo eboot (this work)    │
│  Runtime::up ── LocalAPI            main thread: vita2d loop  │
│  127.0.0.1:41112 ◄──── loopback ─── poller thread (2 s GET    │
│  :8080 tailnet HTTP (rt's own)      /localapi/v0/status)      │
└────────────────────────────────────────────────────────────────┘
```

- The eboot in `suprx_host_only` mode stays a **pure LocalAPI client**. It must
  NOT call `Runtime::up` (the SUPRX owns the runtime; two Runtimes in one
  process would fight over sceNet sockets). In normal (non-host) mode the same
  dashboard works against the eboot's own Runtime — the accept loop moves off
  the main thread (S4).
- **Rendering: vita2d** (prebuilt `libvita2d.a` in VitaSDK, GPU 2D) with
  `vita2d_load_default_pgf()` — the system font, antialiased, zero shipped
  assets. Rejected: imgui (`libimgui_vita2d.a` is C++ → drags in g++/libstdc++ +
  hand-written shim, disproportionate); debugScreen (C source needing a `cc`
  build step, monospace bitmap — kept as fallback if PGF disappoints).
- **Input: sceCtrl** (`sceCtrlPeekBufferPositive`, `psp2/ctrl.h`). D-pad
  Up/Down = select peer, ✕ = disco-ping, SELECT = debug page toggle.
- **FFI: hand-rolled `extern "C"`** per house pattern (exemplar
  `crates/vita-fs/src/vita.rs`) — no vitasdk-sys dependency; it doesn't bind
  vita2d anyway.
- **Linking**: the eboot's linker (`arm-vita-eabi-gcc` via cargo-vita)
  auto-links only base Sce stubs — NOT SceGxm/SceDisplay/SceCtrl/ScePgf/vita2d.
  The demo's existing `build.rs` (currently just BUILD_TIMESTAMP) gains:
  `cargo:rustc-link-search=native=$VITASDK/arm-vita-eabi/lib` plus a
  `-Wl,--start-group -lvita2d -lSceGxm_stub -lSceDisplay_stub
  -lSceCommonDialog_stub -lSceAppMgr_stub -lScePgf_stub -lSceCtrl_stub
  --end-group` link-arg (start-group sidesteps static-lib order sensitivity;
  the stub set is what `nm libvita2d.a` actually references).
- **Data contract**: add `#[derive(Deserialize)]` to `RuntimeSnapshot` /
  `PeerView` / `AllowedIpView` / `AclSummary` (snapshot.rs) so the UI
  deserializes the exact structs the server serializes — the "keep in lockstep"
  warning in snapshot.rs:13 becomes compiler-enforced. The client is a plain
  `std::net::TcpStream` GET (reuse the dial pattern from
  `tailscale-vita-demo/src/handler.rs:104-140`, direction reversed).

### Module layout (all inside `crates/tailscale-vita-demo`)

```
src/ui/mod.rs        — UiState, event loop glue
src/ui/client.rs     — LocalAPI poller (loopback GET /status, /ping)
src/ui/viewmodel.rs  — snapshot → render rows (pure; host-tested)
src/ui/render.rs     — vita2d calls (#[cfg(target_os = "vita")])
src/ui/render_host.rs— no-op host stub (println table; keeps host build green)
src/ui/ffi.rs        — vita2d + sceCtrl extern "C" (#[cfg(target_os = "vita")])
```

Threading: main thread renders at vblank (30 fps is plenty — `vita2d_swap`
waits vblank and yields, so runtime threads aren't starved); one poller thread
(`vita_thread`, 128 KB) GETs `/status` every 2 s into `Arc<Mutex<UiState>>`
(snapshot republishes every 3 s, so ~2 s poll ≈ ≤5 s worst-case staleness —
render `updated N s ago` from `updated_at_unix`, amber above 10 s). Ping runs
on the poller thread too (serialized with polls on purpose: LocalAPI has a
single accept thread and `/ping` blocks it up to 5 s — a parallel poll would
just stall; UI shows a `pinging…` spinner meanwhile).

### Screen layout (960×544)

```
┌──────────────────────────────────────────────────────────────┐
│ vita  100.127.67.48        ● Online   DERP nyc(1)   up 2h14m │
│ tags: tag:vita             public 174.x.x.x:41641            │
├──────────────────────────────────────────────────────────────┤
│ ● lewis            100.120.175.14   direct 4 ms          ◄   │
│ ● geralt           100.90.87.43     direct 11 ms             │
│ ● gl-mt3600be      100.71.102.91    relay (derp 1)           │
│ ○ pixel-9a         100.120.240.95   —                        │
│   … 27 more (D-pad to scroll)                                │
├──────────────────────────────────────────────────────────────┤
│ pong from lewis: 4 ms @ 192.168.8.211:54415                  │
│ updated 2 s ago      ↕ select   ✕ ping   SELECT debug        │
└──────────────────────────────────────────────────────────────┘
```

Row rules: online-first then name; green dot = `online`, gray = offline; path
cell = `direct N ms` (green, from `direct_path_rtt_ms`) / `relay (derp R)`
(amber, `home_derp` when no alive direct path) / `—` (offline). Cold-start
states: `lifecycle=Connecting` → "connecting…" splash; loopback connection
refused → "waiting for runtime (SUPRX)…" and, after 30 s, a hint to check
`ur0:tai/config.txt`.

## Stages (commit-sized, M15-A3 style)

**S1 — render+input spike (the de-risker; hardware).** build.rs link plumbing;
`ffi.rs` minimal bindings (`vita2d_init/start_drawing/clear_screen/
end_drawing/swap`, `vita2d_load_default_pgf`, `vita2d_pgf_draw_text`,
`sceCtrlPeekBufferPositive`); replace the host-only sleep loop with: clear,
draw `hello from the eboot @ BUILD_TIMESTAMP`, echo held buttons as text, swap.
*Success:* text on screen while the SUPRX runs (LocalAPI still curl-able via
:8080 proxy from lewis); buttons echo; no GPU/link explosions. This stage
answers the only real unknowns — link order and vita2d init coexisting with a
live SUPRX — before any UI code exists. *Logged:* `ui.init` (vita2d up, font
loaded), `ui.frame.first`.

**S2 — LocalAPI client + types.** `Deserialize` derives on snapshot types (+
serde_json dev-dep fixture round-trip test); `client.rs` loopback GET /status
with 1 s connect timeout, mapping refused→`RuntimeDown`, malformed→`BadJson`;
poller thread + `UiState`. Host tests: fixture JSON (captured from real
`/status`) parses; poller state machine transitions. *Logged:*
`ui.poll.ok seq=…` (debug), `ui.poll.err`.

**S3 — status card + peer list.** `viewmodel.rs` (pure): snapshot → header
struct + sorted `Vec<PeerRow>` + scroll window; `render.rs` draws layout above;
D-pad selection + scrolling with key-repeat. Host tests: row sorting, path-cell
derivation (direct/relay/—), scroll clamping, staleness formatting. *Success on
hw:* live peer list matches `tailscale status` on lewis.

**S4 — ping action + normal-mode coexistence.** ✕ triggers `/ping?ip=` for the
selected peer on the poller thread; result toast (success: `rtt_ms @ endpoint`;
error: the MagicError string verbatim — they're already human-readable);
spinner while blocked. Move the normal-mode accept loop to a worker thread so
the dashboard also renders when the eboot owns the Runtime. *Logged:*
`ui.ping.sent/result`.

**S5 — hardware pass + docs.** Full Tier-1/Tier-2 verification per Success
criterion; update HARDWARE-DEMO.md (the "brief black screen (no UI)" line
finally dies) + README out-of-scope list; screenshot via pngshot for the repo.

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| vita2d/SceGxm init misbehaves with the SUPRX live in-process | High | S1 spike does nothing else; fallback = debugScreen port (SceDisplay-only, no GXM) |
| Static-lib link-order breakage in cargo-vita eboot link | Med | single `--start-group` link-arg from build.rs; S1 catches it day one |
| `/ping` (5 s block) stalls the single-thread LocalAPI, freezing polls | Med | ping serialized on poller thread + spinner; UI tolerates 10 s stale; (M17-B: thread-per-conn in LocalAPI) |
| Render loop starves runtime threads (control plane, ts-ftp) | Med | vblank-synced ≤30 fps (swap blocks/yields); Success criterion includes concurrent ftp |
| PGF default font unavailable/ugly at small sizes | Low | retail firmware ships it; fallback TTF-via-freetype or debugScreen font |
| GPU/CDRAM memory pressure vs runtime heap | Low | vita2d allocates from CDRAM (not the 32 MB newlib heap); no textures beyond the font in M17-A |
| build.rs link args leak into host builds | Low | gate every `cargo:rustc-link-*` behind `CARGO_CFG_TARGET_OS=="vita"` |

## Open questions (deferred, not blocking)

1. Poll `/health` alongside `/status` for `uptime_secs`, or derive from
   `started_at_unix`? (Derive — one endpoint, one poller.)
2. Key-repeat rate for D-pad scroll on 30+ peer tailnets (start 250 ms/120 ms).
3. Does the eboot need its own `:8080` server in host-only mode? No — the rt
   SUPRX already binds one; double-bind would fail. Leave dead code as-is.
4. Show offline peers by default or behind a toggle? (Default show, sorted
   last — the user's tailnet has ~25 offline ghosts; revisit in M17-C.)

## What M17-A deliberately omits

- Any write path (config.toml editor, reconnect button) — M17-B, with the
  relaunch-to-apply flow.
- ACL posture panel + untagged-key warning (threat-model UX priority) — M17-C.
- LocalAPI additions the list wants eventually: `last_seen`, tx/rx bytes,
  exit-node flag on PeerView — server-side change, bundle with M17-B.
- Touch, LiveArea assets, imgui, themes, DERP region *names*.
- The hidden debug page (wgsel/send-ring live view) — sketched via SELECT
  toggle but ships only if S3 lands early; otherwise M17-C.
