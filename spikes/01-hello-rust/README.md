# Spike 1 — Rust hello-world VPK

Verifies that a stock Rust binary using `std` builds end-to-end through
`cargo-vita` and produces a loadable VPK.

## Result: PASS

- Build artifact: `target/armv7-sony-vita-newlibeabihf/release/hello-vita.vpk`
- Size: 234 KB (eboot.bin: 514 KB; std-built-from-source includes
  `unwind`, `panic_unwind`, `alloc`, `std`, `compiler_builtins`)
- Build time on a warm host: ~32 s (std is built once and cached)

## Build

```bash
export VITASDK=/home/user/vitasdk
export PATH=$VITASDK/bin:$PATH
cargo vita build vpk -- --release
```

`cargo-vita` invokes:
```
cargo +nightly build \
  -Z build-std=std,panic_unwind \
  --target armv7-sony-vita-newlibeabihf \
  --release
```
…then runs `vita-elf-create`, `vita-make-fself -s`, `vita-mksfoex`,
`vita-pack-vpk` to produce the VPK.

## Run

This Phase 0 environment is headless; the VPK was not executed here.
Copy `hello-vita.vpk` to a workstation running Vita3K and install via the
emulator's package manager. Expected behaviour: title `TVIT00001`
"Tailscale-Vita Hello" appears, runs, prints to stdout (visible in
PrincessLog if configured), exits cleanly after ~3 seconds.

## Notes / gotchas

- The old `psp2-sys = "0.2.2"` from crates.io is broken on current Rust
  nightly (E0740 — union fields need `ManuallyDrop`). Use
  **`vitasdk-sys = "0.3"`** instead. We didn't need any FFI for this
  spike since std covers `println!` + `thread::sleep`.
- The Rust target `armv7-sony-vita-newlibeabihf` is upstream Tier 3;
  `rustup target add` fails for it. `cargo-vita` handles this by passing
  `-Z build-std=std,panic_unwind` and using the `rust-src` component to
  build std from source.
- `panic = "abort"` works but the cargo-vita default `build_std` setting
  expects `panic_unwind`; either flip both or leave both at the default.
  This crate uses the default (`panic = "unwind"` in release profile).
