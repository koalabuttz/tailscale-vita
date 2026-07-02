# tailscale-vita

A from-scratch Rust implementation of the [Tailscale](https://tailscale.com)
client for the **PlayStation Vita**, distributed as a homebrew `.vpk` eboot.

The Vita joins your tailnet at a `100.x.y.z` address, reachable from every
other tailnet member. In-tunnel TCP/UDP is exposed to other Vita homebrew
through a `std::net`-shaped Rust API; tailnet introspection is exposed to
arbitrary local apps over a loopback HTTP LocalAPI on `127.0.0.1:41112`.

This is a clean-room re-implementation against the published wire
protocols — Noise IK + HTTP/2 control (`ts2021`), DERP relays
(NaCl-box framed), Disco for direct-path discovery, WireGuard for the
data plane — not a port of upstream Go.

> **Status (2026-05-19):** v1 milestones M1–M10 shipped (DERP-only
> tailnet membership). M12 direct-path NAT traversal shipped and verified
> end-to-end against a phone on cellular (68 ms direct UDP through carrier
> NAT). M13/M13.5/M14/M15-B/M15-C shipped. SUPRX background-daemon work
> (M11 / M15-A / M15-A2) is **deferred** — see
> [`docs/SUPRX-PTHREAD-INVESTIGATION.md`](docs/SUPRX-PTHREAD-INVESTIGATION.md).
> The project ships as a foreground eboot until that path is unblocked.

## What works on hardware right now

End-to-end, against either self-hosted Headscale or real `tailscale.com`:

- Auth-key registration; persistent identity across launches
  (`machine.priv` / `node.priv` / `disco.priv` in `ux0:/data/tailscale-vita/`).
- Noise IK + HTTP/2 control stream against `controlplane.tailscale.com:443`
  (TLS) or Headscale (HTTP); long-poll MapResponse + NetInfo update; periodic
  keepalive; exponential-backoff reconnect on disconnect.
- DERP probe (28 regions), home-region pick, persistent DERP connection,
  NaCl-boxed Disco transport over DERP.
- WireGuard data plane via vendored BoringTun, per-peer `Tunn`,
  three-way lookup (`by_pubkey` / `by_idx` / `by_ip`).
- smoltcp-backed in-tunnel netstack: TCP listen/accept, ICMP echo
  auto-reply, UDP, IPv4 (IPv6 in progress under M15-C).
- Direct-path UDP via STUN-derived public endpoints + CallMeMaybe NAT
  punch (M12 Stage 4). Verified Vita-on-WiFi ↔ phone-on-cellular at 68 ms.
- LocalAPI loopback server (`127.0.0.1:41112`): `/status`, `/whois`,
  `/health`, `/netmap`, `/ping`, `/reconnect`.
- Demo eboot runs Tailscale + an in-tunnel HTTP/1.1 server on port 8080.
  From any tailnet peer: `curl http://100.x.y.z:8080/` returns
  `hello from vita`; `/api/<endpoint>` proxies the LocalAPI for verification.

## What's intentionally out of scope (for now)

- **SUPRX background daemon.** Two attempts at running the runtime as a
  taiHEN SUPRX plugin (so Tailscale stays up after the demo eboot exits)
  have foundered on `pthread_init()` crashing from a SUPRX context. The
  fallback — replacing libc-pthread with SCE primitives — works for
  thread spawn but Rust std's `Mutex` / `thread_local!` / panic hook also
  reach into pthread internals on this target. Tracked under M15-A2;
  full forensic writeup in
  [`docs/SUPRX-PTHREAD-INVESTIGATION.md`](docs/SUPRX-PTHREAD-INVESTIGATION.md).
  v1 ships as a foreground eboot.
- IPv6 magicsock (partial under M15-C: outbound v6 send + dual STUN
  probes shipped; Vita home WiFi is v4-only so end-to-end v6 paths are
  unverified).
- Taildrop, MagicDNS, exit-node routing, subnet-route advertisement.
- OAuth / interactive login. Auth key only, in `config.toml`.
- UPnP / NAT-PMP / PCP port-mapping clients.
- Configuration UI. The on-device dashboard (M17-A) is READ-ONLY —
  status + peer list + disco ping. Settings stay `config.toml`-driven,
  restart to apply (a settings editor is M17-B).

See [`PLAN-V1.md`](PLAN-V1.md) for the original strategic scope-cut.

## Architecture

```
┌──────────────── Vita eboot (one process) ──────────────────────┐
│  app (sample/demo)  ──>  tailscale-vita public API             │
│                                                                │
│                ┌──────────── Runtime ─────────────┐            │
│                │  Control plane (Noise + HTTP/2)  │            │
│                │     │                            │            │
│                │     v                            │            │
│                │  Netmap (peers, DERP map, IPs)   │            │
│                │     │                            │            │
│                │     v                            │            │
│                │  WireGuard engine (BoringTun×N)  │            │
│                │     │                            │            │
│                │     v                            │            │
│                │  DualTransport  ── DERP relay    │            │
│                │       └───────── MagicSocket UDP │            │
│                │                                  │            │
│                │  smoltcp netstack (TCP/UDP/ICMP) │            │
│                │  LocalAPI HTTP (loopback :41112) │            │
│                └──────────────────────────────────┘            │
└────────────────────────────────────────────────────────────────┘
```

Concurrency model is threaded blocking (no async runtime — `mio`/`polling`
have no Vita backend, and `tokio`'s I/O reactor is unavailable). All
threads use 256 KiB stacks via `std::thread::Builder` (Vita's default
64 KiB is too small for smoltcp + h2 frame buffers).

## Workspace layout

```
crates/
├── vita-log/                 -- tracing subscriber → ux0:/data/.../log.txt
├── vita-thread/              -- SCE-primitive thread spawn (host: std::thread)
├── vita-sync/                -- in-progress std::sync shim (companion to vita-thread)
├── wg-engine/                -- WireGuard via vendored BoringTun
├── netstack/                 -- smoltcp Interface + TcpListener pool
├── ts-control/               -- Noise IK + HTTP/2 + register + map long-poll
├── ts-derp/                  -- DERP probe + NaCl-box transport
├── ts-disco/                 -- Disco wire format (Ping/Pong/CallMeMaybe)
├── ts-magicsock/             -- direct-path UDP + STUN + CallMeMaybe
├── tailscale-vita/           -- public API: Runtime, Config, LocalAPI
├── tailscale-vita-demo/      -- eboot (loads Config, brings up Runtime,
│                                serves in-tunnel HTTP on :8080)
├── tailscale-vita-rt/        -- staticlib shim for SUPRX (paused, M15-A2)
└── tailscale-vita-plugin/    -- C SUPRX wrapper (paused, M15-A2)
```

Phase-0 spikes (`spikes/01..05`) are excluded from the workspace; they
are kept as standalone crates for reproducibility.

## Building

Cross-compile target is `armv7-sony-vita-newlibeabihf` (nightly,
pinned via [`rust-toolchain.toml`](rust-toolchain.toml)).

Prerequisites:

- [VitaSDK](https://vitasdk.org/) installed; `$VITASDK` set; `$VITASDK/bin`
  on `$PATH`.
- `cargo-vita` installed (`cargo install cargo-vita`).
- A modded Vita with [vitacompanion](https://github.com/devnoname120/vitacompanion)
  FTP enabled on port 1337.

Build + sideload the demo:

```bash
cargo vita build vpk -p tailscale-vita-demo --release
# cargo-vita's exit code lies if the underlying cargo build failed —
# always re-verify by checking the .vpk mtime:
ls -l target/armv7-sony-vita-newlibeabihf/release/tailscale-vita-demo.vpk

curl -T target/armv7-sony-vita-newlibeabihf/release/tailscale-vita-demo.vpk \
    "ftp://$VITA_IP:1337/ux0:/vpk/tailscale-vita-demo.vpk"
```

Then on the Vita, install via VitaShell (triangle → Install) — re-uploading
the `.vpk` does **not** auto-update an already-installed bubble.

The full hardware bring-up runbook, including standing up a local
Headscale dev container, generating auth keys, and the tier-1 / tier-2
verification recipe (peer-side `ping` + `curl` to the Vita's tailnet IP),
lives at [`docs/HARDWARE-DEMO.md`](docs/HARDWARE-DEMO.md).

For tests on the host:

```bash
cargo test --workspace --exclude tailscale-vita-rt --exclude tailscale-vita-plugin
```

(The two excluded crates only build for `armv7-sony-vita-newlibeabihf`.)

## Configuration

The runtime reads `ux0:/data/tailscale-vita/config.toml` on the Vita.
On first launch a template is written; edit it and relaunch.

```toml
# Auth key from `headscale preauthkeys create` or the Tailscale admin console.
auth_key = "tskey-auth-..."

# Control-plane URL. For Headscale dev: http://<host-ip>:8080
# For Tailscale prod: https://controlplane.tailscale.com
control_url = "https://controlplane.tailscale.com"

# Hostname the tailnet sees. Defaults to "vita".
hostname = "vita"

# In-tunnel HTTP demo server port. Default 8080.
demo_port = 8080

# LocalAPI loopback bind. Default 41112 (matches upstream Go's tailscaled).
# Set to 0 / omit to disable.
localapi_port = 41112
```

## Security model

A jailbroken Vita has no OS-level app sandbox: every homebrew app runs at
the same effective privilege. The load-bearing boundary for what the Vita
can reach on your tailnet is **the tailnet ACL itself**, enforced
server-side. Use tags (`--tags=tag:vita`) on the auth key and write an
ACL that scopes the Vita to the peers/ports it actually needs.

Local LocalAPI tiers:

- **Tier 1 (read-only):** `/status`, `/whois`, `/health`, `/netmap` —
  exposed on loopback, unauthenticated.
- **Tier 2 (peer-reach):** `/ping`, `/reconnect` — same exposure; effect
  is constrained by the tailnet ACL.
- **Tier 3 (identity):** `up`, `logout`, control-URL changes — **not
  exposed on LocalAPI**. Config-file only; requires a relaunch.

Full reasoning in the
[`vita_threat_model`](https://github.com/koalabuttz/tailscale-vita/blob/main/docs/) memory writeup.

## Background and provenance

- Phase 0 spikes (cross-compile of BoringTun, smoltcp, `crypto_box`,
  `getrandom`, UDP echo, hello-world) are documented in
  [`PHASE-0-RESULTS.md`](PHASE-0-RESULTS.md).
- Pre-implementation research (wire protocols, threading constraints,
  prior art on Vita Rust homebrew) is in [`RESEARCH.md`](RESEARCH.md).
- Per-milestone strategic plan: [`PLAN-V1.md`](PLAN-V1.md).
- The Vita-targeted `ring` fork used for TLS lives at
  [`vita-rust/ring`](https://github.com/vita-rust/ring) (branch
  `v0.17.14-vita`), pulled in via `[patch.crates-io]`.

## License

MIT. See individual crate `Cargo.toml` files.

This project is not affiliated with, endorsed by, or connected to
Tailscale Inc. or Sony Interactive Entertainment. "Tailscale" and
"PlayStation Vita" are trademarks of their respective owners.
