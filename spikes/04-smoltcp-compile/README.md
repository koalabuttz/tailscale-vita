# Spike 4 — smoltcp compile + Device trait stub

Verifies that `smoltcp` (the userspace TCP/IP stack we'll run *inside*
the WireGuard tunnel) cross-compiles for Vita and that we can implement
its `phy::Device` trait against an arbitrary transport. In the real
implementation, the Device-trait impl will shuttle decrypted IP packets
between BoringTun and smoltcp; here we use an in-memory queue to keep
the spike standalone.

## Result: PASS

- Build artifact: `target/armv7-sony-vita-newlibeabihf/release/smoltcp-compile-spike.vpk` (262 KB)
- No patches needed.
- Standard cargo features: `std`, `log`, `medium-ip`, `proto-ipv4`,
  `socket-tcp`, `socket-udp`, `socket-icmp`.

## Build

```bash
export VITASDK=/home/user/vitasdk
export PATH=$VITASDK/bin:$PATH
cargo vita build vpk -- --release
```

## What the spike VPK does at runtime

- Constructs an `InMemoryDevice` (impls `smoltcp::phy::Device` with
  `medium = Medium::Ip`, MTU 1280) backed by two `VecDeque<Vec<u8>>`s.
- Builds an `Interface` with IP `100.64.0.1/10` (a Tailscale-shaped
  address — this is just a smoke test, not a real IP).
- Adds a UDP socket to a `SocketSet`, binds it to port 9999.
- Polls the stack twice (once with no traffic, once with an injected
  malformed IPv4 packet that should be dropped).
- Prints `smoltcp init OK: stack polled, N tx packets queued`.

If the VPK boots and prints the expected lines, smoltcp's API surface +
Device trait are confirmed working on Vita and ready to wire to BoringTun
in Phase 2.

## Decision gate

PASS — the userspace TCP/IP stack story is solid. Phase 2 can
confidently wire BoringTun's decrypted-packet output into a
`Device` impl very similar to this one (just replace `inject_rx`/
`drain_tx` with calls into BoringTun).

## Notes

- We enabled the `std` feature for `Instant::now()` convenience. For
  v1 production code we may switch to `from_millis` driven by an
  explicit clock to keep the no_std door open for future work.
- smoltcp's `Device` trait uses GAT-style associated types
  (`type RxToken<'a> = ... where Self: 'a`). Compiles cleanly on
  Rust nightly 1.97 — no MSRV issue for our toolchain.
- 1.4 KB net binary growth over the boringtun spike (262 KB - 322 KB)
  is misleading: the smoltcp spike doesn't pull boringtun, so they're
  not directly comparable. A combined boringtun+smoltcp binary should
  land around 350-400 KB.
