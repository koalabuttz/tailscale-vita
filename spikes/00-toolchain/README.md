# Spike 0 — Toolchain install

Sets up everything needed to build Vita binaries from Rust on a Linux host.

## Result: PASS

Confirmed working as of 2026-05-02:

| Component | Version |
|---|---|
| rustup | 1.29.0 |
| Rust nightly | 1.97.0-nightly (67bcaa9c4 2026-05-01) |
| cargo-vita | 0.2.2 |
| VitaSDK (vita-toolchain) | 71f37893 (built 2026-04-25) |
| arm-vita-eabi-gcc | 15.2.0 |

## Install steps (Linux)

```bash
# 1. Rust nightly + rust-src component (no prebuilt std for Vita target;
#    we use -Z build-std)
rustup install nightly
rustup +nightly component add rust-src

# 2. VitaSDK
#    The official `vdpm` bootstrap script uses the GitHub API to find the
#    latest release URL, which fails behind a low-rate-limit proxy.
#    Direct-download the latest Linux toolchain tarball instead:
export VITASDK=/home/user/vitasdk
mkdir -p "$VITASDK"
TAG=master-linux-v2.539     # check https://github.com/vitasdk/autobuilds/releases for newer
URL="https://github.com/vitasdk/autobuilds/releases/download/$TAG/vitasdk-x86_64-linux-gnu-2026-04-25_10-54-14.tar.bz2"
curl -fsSL "$URL" -o /tmp/vitasdk.tar.bz2
tar -xjf /tmp/vitasdk.tar.bz2 -C "$VITASDK" --strip-components=1
export PATH="$VITASDK/bin:$PATH"

# Persist these in ~/.bashrc:
#   export VITASDK=/home/user/vitasdk
#   export PATH=$VITASDK/bin:$PATH

# 3. cargo-vita
cargo +nightly install cargo-vita --locked
```

## Verification

```bash
arm-vita-eabi-gcc --version          # gcc 15.2.0
which vita-elf-create                # /home/user/vitasdk/bin/vita-elf-create
rustc +nightly --version             # 1.97.x-nightly
cargo vita --version                 # cargo-vita 0.2.2
```

## Notes

- The Rust target `armv7-sony-vita-newlibeabihf` is upstream Tier 3.
  `rustup target add` for it fails ("no prebuilt artifacts available").
  This is expected — `cargo-vita` builds std from source via
  `-Z build-std=std,panic_unwind` (default) using the `rust-src` component.
- VitaSDK's `vdpm` bootstrap script depends on the GitHub API (rate-limited
  to 60 req/h unauthenticated). On rate-limited networks, download the
  toolchain tarball directly from a release page as shown above.
- Vita3K (the emulator) is a GUI app — install on the developer's
  workstation, not the build host. This Phase 0 work runs in a headless
  container; the produced VPK is copied to the dev workstation for testing.

## Decision gate result

PASS — toolchain assumptions in `RESEARCH.md` hold. `cargo-vita` exists,
the upstream Rust target compiles via `build-std`, VitaSDK is current.
Proceed to Spike 2.
