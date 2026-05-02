# Phase 0 Results — De-risk

Date: 2026-05-02
Branch: `claude/vita-tailscale-research-yeOGU`
Test environment: headless Linux container; no Vita3K, no hardware.
Final hardware/Vita3K verification deferred to the user.

## Decision Matrix

| Spike | Build | Runtime | Notes |
|---|---|---|---|
| 0 — Toolchain | **PASS** | n/a | Rust nightly 1.97 + `armv7-sony-vita-newlibeabihf` Tier-3 target via `-Z build-std`; VitaSDK 2.539 (gcc 15.2.0); cargo-vita 0.2.2. |
| 1 — Rust hello-world VPK | **PASS** | DEFERRED | 234 KB VPK, std-using `fn main()` builds clean through cargo-vita's pipeline. Run in Vita3K to verify boot. |
| 2 — UDP echo | **PASS** | DEFERRED | 250 KB VPK using `std::net::UdpSocket`. Server-address baked at build time via `env!`. Host-side echo helper at `spikes/02-udp-echo/host/echo.py`. |
| 3 — boringtun compile | **PASS (with patches)** | DEFERRED | 322 KB VPK. Required vendoring boringtun 0.7.1 and applying two small patches (~12 lines) — see `spikes/03-boringtun-compile/PATCHES.md`. ring 0.17.14 builds clean against `vita-rust/ring`'s `v0.17.14-vita` branch. parking_lot, x25519-dalek, chacha20poly1305 all clean. |
| 4 — smoltcp compile | **PASS** | DEFERRED | 262 KB VPK. smoltcp 0.12 + custom `phy::Device` impl builds with no patches. Confirmed `Interface::new` + `SocketSet` + `udp::Socket` API surface. |
| Optional — Headscale | **STAGED** | DEFERRED | docker-compose.yml + config staged in `infra/headscale/`. Not booted here (no docker daemon in the build env); 5-line `docker compose up` runbook in the README. |

## Verdict: GREEN — proceed to Phase 1

Every architectural assumption from `RESEARCH.md` survived contact with
reality:

1. **Rust toolchain works on Vita.** Tier-3 upstream target +
   `-Z build-std` + cargo-vita is a smooth pipeline. ~32 s clean rebuild
   (mostly std).
2. **`std::net::UdpSocket` is available.** No need for `vitasdk-sys`
   `sceNet*` FFI for the UDP transport; a stock std-using crate is
   enough. (Vita3K verification still required.)
3. **BoringTun cross-compiles** with two trivial patches. Notably, the
   modern `parking_lot` and `std::sync::Arc`/`Mutex` work on Vita's
   newlib+pthread shims with no fork.
4. **smoltcp + custom Device trait is straightforward.** No patches.
   API exactly matches what's needed for the Phase 2 BoringTun integration.
5. **`vita-rust/ring v0.17.14-vita` already exists upstream**, removing
   the largest implementation risk we'd worried about.

## Detected risks (none of these block Phase 1)

| Risk | Severity | Plan |
|---|---|---|
| Vita3K may not fully emulate `sceNet*` for the UDP-echo runtime test | Med | If Vita3K fails but compile is clean, defer to on-device. Hardware will be available later. |
| The boringtun patches need to be maintained against upstream | Low | Track upstream releases; consider filing the libc-clock_gettime PR upstream so we don't carry the patch forever. |
| Headscale wire-format compatibility may drift | Low | Pin Headscale to a known release in `infra/headscale/docker-compose.yml`; treat Tailscale's prod control plane as best-effort. |
| `cargo vita`'s default `panic = "unwind"` and `build_std = "std,panic_unwind"` increase binary size | Low | ~250-320 KB binaries are fine for Vita's RAM budget. Optimize with `panic = "abort"` + `build_std = "std,panic_abort"` later if needed. |

## Hardware re-verification checklist (when the Vita is available)

Required before Phase 1 sign-off:

- [ ] Spike 1: `hello-vita.vpk` boots, prints to PrincessLog, exits clean.
- [ ] Spike 2: `udp-echo-vita.vpk` rebuilt with the dev workstation's
  LAN IP as `ECHO_SERVER`; sends and receives 5 echo round-trips against
  `host/echo.py`.
- [ ] Spike 3 (boringtun): `boringtun-compile-spike.vpk` boots and
  prints `boringtun init OK: produced handshake init of 148 bytes` plus
  the `parking_lot` Mutex roundtrip count.
- [ ] Spike 4 (smoltcp): `smoltcp-compile-spike.vpk` boots and prints
  `smoltcp init OK: stack polled, ...`.

Tip: install `PrincessLog` on the Vita first so stdout is visible
without serial-cable acrobatics. cargo-vita has built-in `cargo vita
logs` support that pairs with PrincessLog over LAN.

## Deltas vs. RESEARCH.md

The research doc is broadly correct but two sentences should be
amended:

1. "smoltcp is `no_std`-friendly" — true, **but** for `Instant::now()`
   convenience we enable the `std` feature. Easy to revisit.
2. "BoringTun … exposes a stable C ABI in `wireguard_ffi.h`" — true, but
   we're not using the C-FFI path. Phase 5 will call BoringTun's Rust API
   directly from a Rust crate, then expose *our* C ABI to the
   plugin shim. Cleaner and avoids one layer of indirection.

Both are documentation tweaks, not architectural changes.

## Repo layout after Phase 0

```
tailscale-vita/
├── README.md
├── RESEARCH.md
├── PHASE-0-RESULTS.md            (this file)
├── infra/
│   └── headscale/
│       ├── .gitignore
│       ├── README.md
│       ├── docker-compose.yml
│       └── config/config.yaml    (Headscale upstream example, server_url tweaked)
└── spikes/
    ├── 00-toolchain/README.md
    ├── 01-hello-rust/             (234 KB VPK)
    │   ├── Cargo.toml
    │   ├── README.md
    │   ├── rust-toolchain.toml
    │   └── src/main.rs
    ├── 02-udp-echo/               (250 KB VPK)
    │   ├── Cargo.toml
    │   ├── README.md
    │   ├── host/echo.py
    │   ├── rust-toolchain.toml
    │   └── src/main.rs
    ├── 03-boringtun-compile/      (322 KB VPK; THE keystone spike)
    │   ├── Cargo.toml
    │   ├── PATCHES.md
    │   ├── README.md
    │   ├── rust-toolchain.toml
    │   ├── src/main.rs
    │   └── vendor/boringtun/      (patched)
    └── 04-smoltcp-compile/        (262 KB VPK)
        ├── Cargo.toml
        ├── README.md
        ├── rust-toolchain.toml
        └── src/main.rs
```

## Next: Phase 1

Per the master plan, Phase 1 is "Vita network 'hello world'" — wire up
sceNet/`std::net` from a SUPRX plugin context (vs. the eboot context the
spikes use), confirm the deferred-init pattern, and test sustained UDP
throughput. Spike 2's Rust source is essentially the Phase 1 starting
point.

## Appendix: Vita3K headless attempt

After the initial Phase 0 commit, attempted to run the spike VPKs in
Vita3K headless inside this sandboxed Linux container. **Did not succeed**;
documenting blockers so we don't re-attempt without addressing them.

### Setup attempted

- Vita3K `continuous` Linux release (v0.2.1, build 3967-faa4a632), x86_64.
- Mesa software renderers installed: `mesa-vulkan-drivers` (lavapipe),
  `libgl1-mesa-dri` + `libglx-mesa0` (llvmpipe), plus `vulkan-tools`,
  `mesa-utils`.
- `Xvfb` for display, `SDL_AUDIODRIVER=dummy` for audio, ran as
  unprivileged user `vitatest` (Vita3K refuses to start as root).
- `VK_ICD_FILENAMES` pointed at `lvp_icd.x86_64.json` (lavapipe).

### Blockers

| # | Blocker | Detail |
|---|---|---|
| 1 | **No PSVita firmware** | Vita3K cannot boot any title without `PSVUPDAT.PUP`. Sony's CDN host `h.dl.playstation.net` is not resolvable from this sandbox. |
| 2 | **Vulkan VK_KHR_surface missing** | Lavapipe (CPU-software Vulkan) does not expose `VK_KHR_xlib_surface`. Vita3K's SDL window-creation fails before any code from the VPK runs. Real GPU + driver would solve this. |
| 3 | **OpenGL backend segfaults** | With `backend-renderer: OpenGL`, `LIBGL_ALWAYS_SOFTWARE=1`, llvmpipe via Xvfb: `Vita3K` SIGSEGVs during init before logging is open. Likely a Mesa-GLX-via-indirect-context bug; out of scope to chase. |
| 4 | **Error dialogs hang the process** | On init failure Vita3K opens a modal `SDL_ShowSimpleMessageBox` and waits — no `--no-gui` style flag — so the process hangs until `timeout` SIGKILLs it (exit 124) instead of exiting cleanly with a useful diagnostic. |

### Conclusion

Headless Vita3K in this sandbox is **not feasible** under current
constraints. Two ways forward, both on the user's own machine:

- **Vita3K on the workstation.** Install Vita3K normally, install the
  user's existing PSVita PUP firmware via the GUI's
  `File → Install Firmware` action, then drag-and-drop each spike VPK
  to install it. With a real GPU the display problems go away.
- **Real Vita.** The user's Ensō-modded Vita is the source of truth
  anyway; once available, the on-device verification checklist above is
  the canonical pass criterion.

The Phase 0 verdict (architecture is GREEN, all crates compile + link
cleanly for the Vita target) does not change — it was always a
build-time spike, and runtime verification was deferred from the start.
