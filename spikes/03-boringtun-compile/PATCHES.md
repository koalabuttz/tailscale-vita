# BoringTun patches required for Vita

Two minimal changes to `boringtun-0.7.1` (vendored at
`vendor/boringtun/`) are needed to build for `armv7-sony-vita-newlibeabihf`.
Total diff: ~12 lines of code.

## 1. Drop the `nix` dependency

`nix-0.31` does not recognize Vita as a known target. Its `errno::consts`
module is gated to a fixed set of `target_os` values, none of which match
the Vita target, so the entire crate fails to compile with errors like:

```
error[E0432]: unresolved import `self::consts`
  --> nix-0.31.2/src/errno.rs:19:15
```

BoringTun only used `nix` in two places:

| File | Code | Resolution |
|---|---|---|
| `src/sleepyinstant/unix.rs` | `nix::sys::time::TimeSpec` + `nix::time::clock_gettime` | Replaced with raw `libc::clock_gettime` (~10 line patch). |
| `src/device/drop_privileges.rs` | `nix::unistd::User` for setuid/dropping privileges | Inside the `device` feature — not enabled in our build, so no change needed. |

Cargo.toml change (commented out):
```toml
# vita-patch:
# [target."cfg(unix)".dependencies.nix]
# version = "0.31"
# features = ["time", "user"]
```

## 2. Relax `#![forbid(unsafe_code)]` in `sleepyinstant`

The `nix::time::clock_gettime` wrapper hid the unsafe FFI; calling
`libc::clock_gettime` directly requires an `unsafe` block, which the
module-level `#![forbid(unsafe_code)]` rejects.

Changed `src/sleepyinstant/mod.rs`:
```rust
- #![forbid(unsafe_code)]
+ #![deny(unsafe_op_in_unsafe_fn)]
```

`unsafe_op_in_unsafe_fn` is the modern lint that still requires explicit
`unsafe { ... }` annotation but allows it where actually needed.

## Path forward

For Phase 1+ work this fork should live in a proper repo
(`vita-rust/boringtun` or similar) so we can keep up with upstream. For
the spike, vendoring inline is fine.

Upstream BoringTun PR is plausible: a `cfg(any(target_os = "linux",
target_os = "macos", ...))` gate around the nix-using `sleepyinstant`
file plus a libc fallback would keep the existing behaviour for known
platforms while adding portability. Worth filing.
