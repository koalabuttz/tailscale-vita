# Tailscale on PS Vita — Implementation Research

Research notes for building a Tailscale client that runs as a plugin on the
PlayStation Vita, making the Vita itself a node on a tailnet.

## Goals & constraints

- **Vita as a tailnet node**, not just "Vita reaches things on the tailnet."
  The Vita gets its own 100.x.y.z address; other peers can dial into it.
- **Distribute as a Vita plugin** loadable via taiHEN (`.suprx` and/or
  `.skprx`), targeting HENkaku Ensō CFW.
- **v1 ships DERP-only**; direct-path NAT traversal is v2.
- **Implementation language: Rust** (with C-ABI shim for the Vita plugin).

## Hard constraints discovered during research

1. **No Go runtime exists for Vita.** Stock Go has no `GOOS=vita`. Porting
   the runtime (scheduler, GC, threads, syscalls) is multi-month work.
   `tailscale.com/tsnet` and `libtailscale` are therefore unusable directly.
   TinyGo cannot build `tsnet` either: TinyGo's `net` package is not
   stdlib-compatible, and `tsnet` depends on stdlib `net` plus gVisor
   netstack plus heavy reflection.
2. **No TUN/TAP device on Vita.** `sceNetCtl` is read-only metadata; there
   is no API to create a virtual interface. `SOCK_RAW` is defined in
   `psp2/net/net.h` but unproven in user mode and likely refused by the
   kernel. The userspace-networking model (`tsnet`-style: one process owns
   the WireGuard tunnel, in-process apps talk through a userspace TCP/IP
   stack) is the only viable architecture.
3. **No prior art for VPN on Vita.** Every "PSVita VPN" project found puts
   the VPN on a router or Pi and exposes the tailnet to the Vita as a plain
   LAN. The community has asked for a native client; nobody has shipped
   one. This is greenfield.

## What works in our favor

- Every WireGuard primitive is already shipped on Vita: **libsodium**
  (ChaCha20-Poly1305, X25519, BLAKE2b), **mbedTLS** (BLAKE2s, full TLS),
  **OpenSSL**. All in `vitasdk/packages` via `vdpm`.
- **UDP sockets from a SUPRX plugin are a solved pattern** — proven by
  `xerpi/libftpvita`, `teakhanirons/ftpeverywhere`, `devnoname120/vitacompanion`,
  `TheOfficialFloW/VitaShell`. Recipe is `sceSysmoduleLoadModule(NET)` →
  `sceNetInit(SceNetInitParam)` → `sceNetSocket(AF_INET, SOCK_DGRAM, 0)`.
- **`sceNetEpoll*` exists** with `EPOLL_CTL_ADD/MOD/DEL` and
  `EPOLLIN/OUT/ERR/HUP` — full async socket loop is available, plus
  `SCE_NET_SO_NBIO` for non-blocking and per-call `MSG_DONTWAIT`.
- **Cortex-A9 has NEON.** libsodium's NEON ChaCha20 will saturate Vita
  Wi-Fi (~50 Mbps real-world) without breaking a sweat.
- **BoringTun (Cloudflare)** is deployed on millions of iOS/Android devices
  in exactly the "no kernel TUN, userspace WireGuard" mode we need, and
  exposes a stable C ABI in `wireguard_ffi.h`.
- **Headscale** speaks the same control protocol as Tailscale's coordination
  server, so we can develop and `tcpdump` against a local instance before
  pointing at production.

## Architecture: userspace-networking, single process

```
┌────────────────── Vita SUPRX/eboot.bin ──────────────────┐
│                                                          │
│  ┌─────────────────┐    ┌────────────────────────────┐   │
│  │  Control plane  │    │   App-facing API           │   │
│  │  (Rust)         │    │   ts_dial / ts_listen      │   │
│  │  Headscale/TS   │    │   (mirror libtailscale.h)  │   │
│  │  HTTPS + Noise  │    └─────────────┬──────────────┘   │
│  └────────┬────────┘                  │                  │
│           │ peer keys, allowed IPs    │ TCP/UDP          │
│           ▼                           ▼                  │
│  ┌──────────────────────────────────────────────────┐    │
│  │  BoringTun (WG state machine)  +  smoltcp        │    │
│  │  ChaCha20-Poly1305 / Curve25519 / BLAKE2s        │    │
│  │  (no_std, libcore + liballoc only)               │    │
│  └────────────────────────┬─────────────────────────┘    │
│                           │ UDP datagrams                │
│                           ▼                              │
│  ┌──────────────────────────────────────────────────┐    │
│  │  sceNetSocket(DGRAM)  +  sceNetEpoll worker thr  │    │
│  └──────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
                              │
                              ▼  Wi-Fi (user-supplied)
                  Internet → DERP → peers
```

**Why this shape:**

- Forced on us by the no-TUN reality, but it is the same model `tsnet` uses
  on Linux. We're following an existing pattern, not inventing one.
- Single process: only apps that link against our library can use the
  tunnel. The alternative — a kernel plugin hooking every `sceNetSendto` to
  redirect arbitrary apps' traffic into the tunnel — has zero precedent on
  Vita and would be fragile across firmware revisions. Defer to v2+.
- DERP-only v1: skip STUN, endpoint discovery, port mapping, path probing.
  DERP frames are length-prefixed binary over HTTPS — implementable in a
  few hundred LOC. Cuts months off v1.
- Auth-key registration only: no OAuth UX. User pastes an auth key into a
  config file on `ux0:`.

## DERP-only vs direct paths — practical impact

| Property | DERP-only (v1) | Direct paths (v2) |
|---|---|---|
| Latency overhead | +20–80 ms (relay round-trip) | Wire single-hop |
| Throughput | Rate-limited per-client by relay fleet | Wire rate |
| Implementation cost | Small: HTTPS client + ~5 frame types | Large: STUN + endpoint exchange + probing + upgrade FSM (cf. `magicsock`) |
| NAT/firewall traversal | Anything that allows outbound 443 | Symmetric NAT can defeat it |
| Good for | SSH, file transfer, control-plane | Game streaming, low-latency RPC |
| Bad for | High-bandwidth or latency-sensitive use | — |

For Vita (mobile, often behind hotel/cafe NAT, modest Wi-Fi link):
**DERP-only is good enough for v1**. Game-streaming use cases are the only
ones that meaningfully suffer.

## Why Rust (path D), not pure C (path C) or Go (paths A/B)

- **Go (A, B): not viable.** No Go runtime for Vita. Porting it is
  multi-month work touching scheduler, GC, threads, syscalls, timers.
  TinyGo can't compile `tsnet`.
- **Pure C (C): viable but more work.** Would mean vendoring
  `smartalock/wireguard-lwip` (proven on 64 KB STM32s), libsodium, mbedTLS,
  parson/jansson, and writing the Tailscale control client and DERP client
  by hand in C. Lowest runtime cost. Highest engineering cost.
- **Rust (D): best fit.**
  - **BoringTun** is a deployed, audited userspace WireGuard with a stable
    C-FFI. It does exactly what we need, with no kernel assumptions.
  - **smoltcp** is a `no_std`-friendly userspace TCP/IP stack — the Rust
    analogue of lwIP and the in-tunnel stack `tsnet` users would expect.
  - **Rust no_std** is realistic on the SCE kernel: only libcore and
    liballoc are needed; no porting of std/syscall layer required.
  - Tailscale themselves have a Rust preview (`tailscale-rs`), suggesting
    this approach is well-understood in the upstream community.
  - C-ABI export back into the Vita SUPRX plugin shim is one `extern "C"`
    boundary, modeled on `tailscale.h` from libtailscale.

**Toolchain risk to de-risk early:** Rust on Vita is not officially
supported. There has been community work on an `armv7-sony-vita-newlibeabihf`
target, but it is experimental. **Phase 0 should include a 1–2 day spike**:
build a hello-world Rust SUPRX with `cargo build --target
armv7-sony-vita-newlibeabihf -Zbuild-std=core,alloc`. If that works, path D
is unlocked. If it doesn't, fall back to path C (pure C, wireguard-lwip).

## Phased build plan

### Phase 0 — De-risk (1 week)

1. Stand up Headscale on a Pi/VM. Get a normal client (laptop, phone)
   joining successfully. Sanity check the control protocol with `tcpdump`.
2. **Spike Rust-on-Vita.** Build a minimal SUPRX in Rust that calls one
   `sceNet*` function. If this works, lock in path D. If not, switch to
   path C and continue.
3. **Fallback (path E):** stand up `tailscaled` on the Pi with subnet
   routing as a known-working "Vita on tailnet via LAN" baseline. This
   gives a comparison target and lets dependent work proceed in parallel.

### Phase 1 — Vita network "hello world" (1 week)

- Set up vitasdk + vdpm; install `libsodium`, `mbedtls`, `openssl` packages.
- Build a SUPRX that does `sceSysmoduleLoadModule(NET)` → `sceNetInit` →
  `sceNetSocket(DGRAM)` → send/receive a UDP packet against a known echo
  endpoint. Mirror `vitasdk/samples/net_http`.
- Confirm `sceNetEpoll*` works as expected on a non-blocking socket with
  multiple FDs.
- **Defer net init** until after the host process has loaded
  `SCE_SYSMODULE_NET` (documented gotcha: calling `sceNetInit` too early
  freezes the device). Mirror the `ftpeverywhere` deferred-init pattern.

### Phase 2 — WireGuard data plane in isolation (2 weeks)

- Pull in BoringTun via Cargo. Build the Rust crate against the
  `armv7-sony-vita-newlibeabihf` target.
- Stand up a Linux WireGuard peer on the Pi with static config (no
  Tailscale yet). Hard-code keys.
- Wire BoringTun's `Tunn` to the Vita's UDP socket via Rust async, with
  smoltcp behind it for in-tunnel TCP. Verify bidirectional ping (via an
  in-process echo client/server) works.
- Measure NEON ChaCha20 throughput. Target: ≥10 Mbps sustained.

### Phase 3 — Tailscale control client (3–4 weeks, the hard part)

- Translate `tailscale.com/tailcfg`'s relevant Go structs to Rust types
  with `serde_json`. Fields needed for v1: machine key, node key, hostname,
  endpoints, DERP map, peer list, `AllowedIPs`, DNS config.
- Implement Noise_IK against `controlplane.tailscale.com` (and Headscale)
  using `snow` or hand-rolled with `dalek`/`chacha20poly1305`/`blake2`.
- Implement the long-poll `MapRequest` loop. Parse `MapResponse`. Push
  peer pubkeys + AllowedIPs into BoringTun's peer table.
- **Auth-key flow only.** No OAuth, no interactive login. User config
  format on `ux0:data/tailscale-vita/config.json`:
  ```json
  {
    "auth_key": "tskey-auth-...",
    "control_url": "https://headscale.example.com",
    "hostname": "vita"
  }
  ```
- Test against Headscale first. Promote to `controlplane.tailscale.com`
  once stable.

### Phase 4 — DERP transport (1–2 weeks)

- Rust `rustls` (or `mbedtls-rs`) HTTPS client to a DERP region.
- Implement the DERP frame protocol: `frameType` byte + big-endian length
  + payload. Frame types needed for v1: `ServerKey`, `ClientInfo`,
  `ServerInfo`, `SendPacket`, `RecvPacket`, `KeepAlive`, `PeerGone`.
- Wire DERP into BoringTun as a fallback (always-relay) UDP transport.
- v1 always uses DERP — skip endpoint discovery entirely.

### Phase 5 — App-facing API + packaging (1–2 weeks)

- Rust crate exposes `extern "C"`:
  ```c
  // tailscale_vita.h
  ts_handle_t ts_init(const char *config_path);
  int  ts_up(ts_handle_t h);
  int  ts_dial(ts_handle_t h, const char *host, uint16_t port);
  int  ts_listen(ts_handle_t h, uint16_t port);
  int  ts_accept(int listener);
  void ts_close(ts_handle_t h);
  const char *ts_errmsg(ts_handle_t h);
  ```
  Mirror the libtailscale C API. Conn handles are file-descriptor-like.
- C-side Vita SUPRX shim: thin layer linking the Rust `staticlib`,
  doing module init/teardown, integrating with `taiHEN`, and exposing the
  C API to other homebrew via NID stubs.
- Build a standalone test eboot that opens an HTTP listener on the Vita's
  tailnet IP and serves "hello from vita" — proof the Vita is reachable as
  a node from any other tailnet member.

### Phase 6 (v2) — Direct paths

- Add `magicsock`-style endpoint discovery: bind multiple local UDP
  endpoints, learn public endpoints via STUN, exchange via control plane.
- Path probing and upgrade FSM. Fall back to DERP automatically.
- Optional: UPnP/NAT-PMP/PCP for explicit port mapping.

### Phase 7 (v2+) — Persistence as a kernel plugin

- Move the BoringTun + smoltcp core into a `.skprx` under `*KERNEL` so the
  tunnel survives game launches.
- Export NID stubs for user-mode apps to dial through the kernel plugin.
- Models to study: `xerpi/vita-udcd-uvc` (kernel plugin streaming data
  continuously), `ioPlus`/`kuio` (kernel plugin exposing userland syscalls),
  `xerpi/ds4vita` (kernel plugin running long-lived kernel thread).
- Substantial effort; only attempt after the userspace version is stable.

## Memory & performance budget

- Vita has 512 MB RAM total; SUPRX plugins typically get tens of MB.
- BoringTun + smoltcp + control client + Rust runtime overhead: target
  <8 MB resident.
- DERP HTTPS connection + buffers: ~1 MB.
- Per-peer state: <10 KB. With 32 peers, <320 KB.
- Crypto throughput on Cortex-A9 @ 333–500 MHz with NEON: ≥10 Mbps
  sustained ChaCha20-Poly1305 expected, well above Vita Wi-Fi link rate.

## Top risks and mitigations

| Risk | Mitigation |
|---|---|
| Rust toolchain doesn't work on Vita | Phase 0 spike. Fallback to path C (pure C + wireguard-lwip + libsodium). |
| `sceNetInit` ordering freeze | Defer init until after host process loads `SCE_SYSMODULE_NET`. Mirror `ftpeverywhere` pattern. |
| Tailscale `tailcfg` schema drift | Pin against a Headscale release as primary compat target. Treat `controlplane.tailscale.com` as best-effort. |
| BoringTun/smoltcp depend on `std` somewhere | Verify `no_std` build cleanly in Phase 2. May need light forks for `std::time` / `std::net` shims. |
| Plugin lifecycle: SUPRX dies with host | v1 ships as library + sample eboot. Always-on tunnel is v2 (kernel plugin). |
| Memory pressure during games | Profile in Phase 5. If too heavy in user-mode, kernel-plugin path becomes mandatory. |

## Non-goals for v1

- System-wide VPN that captures arbitrary game/app traffic. Requires kernel
  hooks of `sceNet*` syscalls; no precedent on Vita; defer.
- Direct UDP paths between peers (NAT traversal). DERP-only.
- IPv6. Vita's `SceNet` is `AF_INET` only.
- MagicDNS via system DNS. v1 resolves through our own in-tunnel resolver.
- Interactive OAuth login. Auth keys only.
- Subnet router / exit node functionality. The Vita advertises its own
  100.x address only.

## Reference projects to study

- **tsnet** — `tailscale.com/tsnet`. The architectural blueprint we're
  copying in Rust.
  https://github.com/tailscale/tailscale/blob/main/tsnet/tsnet.go
- **libtailscale** — official C wrapper around tsnet. Our `tailscale_vita.h`
  mirrors its API surface.
  https://github.com/tailscale/libtailscale
- **BoringTun** — Cloudflare's Rust userspace WireGuard. Our data plane.
  https://github.com/cloudflare/boringtun
- **smoltcp** — Rust userspace TCP/IP stack. Our in-tunnel stack.
  https://github.com/smoltcp-rs/smoltcp
- **smartalock/wireguard-lwip** — pure-C reference if path C is needed.
  https://github.com/smartalock/wireguard-lwip
- **Headscale** — open Tailscale control server, our primary dev target.
  https://github.com/juanfont/headscale
- **xerpi/libftpvita** — canonical sceNet socket usage from a plugin.
  https://github.com/xerpi/libftpvita
- **teakhanirons/ftpeverywhere** — always-on background SUPRX networking.
  https://github.com/teakhanirons/ftpeverywhere
- **xerpi/vita-udcd-uvc** — model for v2 kernel-plugin persistence.
  https://github.com/xerpi/vita-udcd-uvc
- **yifanlu/taiHEN** — plugin framework, hook API.
  https://github.com/yifanlu/taiHEN
- **vitasdk/vita-headers** — `psp2/net/net.h`, `netctl.h`.
  https://github.com/vitasdk/vita-headers
- **vitasdk/packages** — vdpm package list (libsodium, mbedtls, openssl).
  https://github.com/vitasdk/packages

## Key protocol references

- **Tailscale TS2021 / control protocol** — Noise_IK + JSON-over-Noise.
  https://tailscale.com/blog/tailscale-key-management
- **DERP servers** — relay protocol overview.
  https://tailscale.com/docs/reference/derp-servers
- **DERP frame protocol** — `tailscale.com/derp` Go package source.
  https://pkg.go.dev/tailscale.com/derp
- **WireGuard protocol** — Noise IK + ChaCha20-Poly1305 + Curve25519 +
  BLAKE2s.
  https://www.wireguard.com/protocol/
- **WireGuard embedding guide** — design constraints for resource-limited
  embedders.
  https://www.wireguard.com/embedding/

## Open questions / TBD

- Exact Vita Rust target triple — is `armv7-sony-vita-newlibeabihf` the
  right choice, or do we need a custom target spec? Decide in Phase 0.
- Whether to vendor BoringTun (allow patching) or depend on the published
  crate. Vendor for v1 — we'll likely need shims for `std::time` and
  network I/O.
- Where to persist machine/node keys. Probably `ur0:data/tailscale-vita/`
  with appropriate file permissions; investigate `sceIo*` ACLs.
- DERP region selection: hard-code nearest, ship the full DERP map and
  pick by latency probe, or take it from `MapResponse`? Latter is
  cleanest, do that.
- Whether the SUPRX should be loaded into `*main` (SceShell) for an
  always-running config UI, or shipped purely as an embeddable library.
  Probably both, eventually.
