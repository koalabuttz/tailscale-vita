# Spike 3 — BoringTun compile for Vita

The architectural keystone. RESEARCH.md selected
**BoringTun** (Cloudflare's userspace WireGuard, Rust) as the v1 data
plane. This spike answers: "does it actually build for the Vita target?"

## Result: PASS (with two small patches)

- Build artifact: `target/armv7-sony-vita-newlibeabihf/release/boringtun-compile-spike.vpk` (322 KB)
- BoringTun + every transitive dep (`ring 0.17.14-vita`,
  `chacha20poly1305`, `x25519-dalek`, `parking_lot`, `blake2`, `hmac`,
  `aead`, `chacha20`, `poly1305`, ...) cross-compiled cleanly.
- Patches required: 2 small changes to vendored boringtun (~12 lines).
  See `PATCHES.md`.
- Critically, `parking_lot::Mutex`, `std::sync::Arc`, and `std::thread`
  all link against Vita's pthread shims with no fork required.

## Build

```bash
export VITASDK=/home/user/vitasdk
export PATH=$VITASDK/bin:$PATH
cargo vita build vpk -- --release
```

## What the spike VPK does at runtime

When loaded in Vita3K / on hardware, the spike:

1. Generates a random X25519 keypair for client and server.
2. Constructs `boringtun::noise::Tunn` with those keys.
3. Calls `Tunn::encapsulate(&[], &mut buf)` and confirms it produces a
   148-byte WireGuard handshake-init message (this is the only
   non-trivial deterministic test we can run without a peer).
4. Roundtrips a `parking_lot::Mutex<u32>` 100 times across a thread.
5. Prints all results to stdout.

If the VPK boots and prints `boringtun init OK: produced handshake init
of 148 bytes`, the **entire crypto stack** for the v1 architecture is
confirmed working on Vita.

## Decision gate

PASS — Path D (Rust + BoringTun) is unblocked. Phase 1+ can plan around
this stack. The two patches in `PATCHES.md` are stable and should be
upstreamable; for now we vendor.

## Key dependency versions resolved

| Crate | Version | Notes |
|---|---|---|
| boringtun | 0.7.1 (vendored, patched) | See PATCHES.md |
| ring | 0.17.14 (vita-rust fork) | `[patch.crates-io] ring = { git = "https://github.com/vita-rust/ring", branch = "v0.17.14-vita" }` |
| chacha20poly1305 | 0.10.1 | Pure Rust, works clean |
| x25519-dalek | 2.0.1 | Pure Rust, works clean |
| parking_lot | 0.12.5 | Vita pthread shims |
| blake2 | 0.10.6 | Pure Rust, works clean |
| getrandom | 0.2.17 | Backed by `/dev/urandom` via libc on Vita |

## Notes

- The `device` feature of boringtun (which pulls socket2 + thiserror +
  Linux/Darwin TUN drivers) is **off**. We don't want it — Phase 5 will
  wire UDP transport via `std::net::UdpSocket` directly, modeled on
  `tsnet`'s userspace-networking pattern.
- 8 deprecation warnings come from boringtun's use of older base64 and
  `ring::constant_time::verify_slices_are_equal` APIs. All fine for now;
  upstream BoringTun will modernize these eventually.
- The "vita-rust/ring v0.17.14-vita" branch already exists upstream. We
  did not need to create a new ring fork.
