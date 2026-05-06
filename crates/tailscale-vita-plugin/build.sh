#!/bin/bash
# tailscale-vita-plugin — build the .suprx.
#
# Two-phase build:
#   1. cargo: produce libtailscale_vita_rt.a for armv7-sony-vita-newlibeabihf.
#   2. cmake: link the .a into a SUPRX via vitasdk's vita-elf-create +
#      vita-make-fself.
set -euo pipefail

export VITASDK="${VITASDK:-/home/david/vitasdk}"
export PATH="$VITASDK/bin:$PATH"

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_ROOT="$(cd "$PLUGIN_DIR/../.." && pwd)"

echo "==> cargo build (tailscale-vita-rt staticlib)"
# Mirror cargo-vita's env injection so cc-rs (ring's build.rs) picks up
# the vitasdk cross-compiler instead of the host toolchain. mio cfgs
# disable the epoll/eventfd code paths tokio's mio dep would otherwise
# enable on `cfg(target_os = "linux")`.
export TARGET_CC=arm-vita-eabi-gcc
export TARGET_CXX=arm-vita-eabi-g++
export RUSTFLAGS="${RUSTFLAGS:-} --cfg mio_unsupported_force_poll_poll --cfg mio_unsupported_force_waker_pipe"

(cd "$WORKSPACE_ROOT" && \
  cargo build \
    --profile staticlib \
    --target armv7-sony-vita-newlibeabihf \
    -Z build-std=std,panic_unwind \
    -p tailscale-vita-rt)

echo "==> cmake / vita-elf-create / vita-make-fself"
mkdir -p "$PLUGIN_DIR/build"
cd "$PLUGIN_DIR/build"
cmake .. >/dev/null
make -j

ls -lh tailscale_vita_plugin.suprx
echo "OK: $(realpath tailscale_vita_plugin.suprx)"
