# M5a — HTTP/2 over Noise: Plan A vs Plan B

## Decision: **Plan A** (tokio current-thread runtime + `h2` crate)

## Rationale

The M5 wire problem: after the Noise IK handshake completes, every byte
between the Vita and the Tailscale/Headscale control plane is HTTP/2 inside
the encrypted Noise transport stream (per Tailscale's `controlhttp` and
`controlbase` packages). Some HTTP/2 client implementation is unavoidable.

Two candidate approaches were enumerated in
`~/.claude/plans/ticklish-bubbling-key.md`:

- **Plan A** — drive the `h2` crate from a tokio current-thread runtime
  *without* `enable_io` (no `mio` reactor needed; `vita-rust/mio` is
  archived). Our Noise record stream implements
  `tokio::io::AsyncRead + AsyncWrite` over a sync `TcpStream` via a tiny
  background pump thread that translates blocking syscalls into wakers.
  ~700 LOC of crate-author code; ~300 KB binary cost.
- **Plan B** — hand-roll a minimal HTTP/2 client: SETTINGS handshake,
  single-stream-per-connection HEADERS+DATA frames, HPACK via the
  `hpack 0.3` crate. ~1500 LOC; ~80 KB binary cost; no async runtime.

## Spike result (this date)

Cross-compile probe with all Plan A deps in `crates/ts-control/Cargo.toml`:

```
snow              = "0.10"
h2                = "0.4"
tokio             = "1"  (features = rt, macros, sync, time — NO net, io-util, rt-multi-thread)
bytes             = "1"
httparse          = "1"
http              = "1"
crossbeam-channel = "0.5"
```

`cargo vita build vpk -p tailscale-vita-demo --release` finished cleanly in
**1 m 55 s**, all the way through `vita-elf-create` → `vita-make-fself` →
`vita-pack-vpk`. No patches required, no `[patch.crates-io]` entries beyond
the existing `vita-rust/ring` one carried since Phase 0. VPK fits in the
Vita's RAM budget by a wide margin.

Decision criteria from the plan, scored:

1. **Cross-compiles for Vita** — Plan A: ✅ verified above. Plan B not yet
   spiked, but `hpack 0.3` is pure-Rust no_std-with-alloc, low risk.
2. **Wall-clock latency** — both target sub-second on localhost; not a
   differentiator.
3. **Code size** — Plan A's tokio+h2 add ~300 KB, Plan B's hpack adds
   ~80 KB. Both well within Vita's RAM budget; not a differentiator.
4. **Crate-author LOC** — Plan A ≈ 700 LOC, Plan B ≈ 1500 LOC. Plan A
   wins decisively on long-term maintenance.

## What this commits us to

- The `control` thread owns a tokio current-thread `Runtime`, lives for the
  duration of the control session, and re-enters via `block_on` for each
  request.
- A dedicated `noise_pump` thread does blocking sync I/O on the Noise
  socket, signals tokio wakers via stored `Waker` slots in `IoCore`.
- HPACK, flow control, GOAWAY handling, and HTTP/2 framing are all `h2`'s
  problem, not ours.
- If `h2` ever stops compiling for our target (very unlikely — pure-Rust
  upstream), Plan B is documented as the fallback.

Plan B's spike code is **not** kept in tree to avoid bit-rot.
