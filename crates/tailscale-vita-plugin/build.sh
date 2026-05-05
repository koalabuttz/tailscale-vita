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
(cd "$WORKSPACE_ROOT" && \
  cargo build \
    --profile staticlib \
    --target armv7-sony-vita-newlibeabihf \
    -Z build-std=core,alloc,panic_abort \
    -p tailscale-vita-rt)

echo "==> cmake / vita-elf-create / vita-make-fself"
mkdir -p "$PLUGIN_DIR/build"
cd "$PLUGIN_DIR/build"
cmake .. >/dev/null
make -j

ls -lh tailscale_vita_plugin.suprx
echo "OK: $(realpath tailscale_vita_plugin.suprx)"
