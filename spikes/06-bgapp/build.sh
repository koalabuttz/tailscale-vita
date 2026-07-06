#!/bin/bash
# M21 spike — build + package the two-eboot bgapp VPK.
#
# Layout replicated from BGFTP v3.24's released VPK (built here with
# open tools only — vitasdk cmake + vita-mksfoex + vita-pack-vpk):
#   eboot.bin              launcher (gdc)
#   eboot2.bin             background service (gdd)
#   sce_sys/param.sfo      launcher SFO
#   sce_sys/param2.sfo     bgapp SFO (own TITLE_ID, INSTALL_DIR_* -> launcher)
set -euo pipefail

export VITASDK="${VITASDK:-/home/david/vitasdk}"
export PATH="$VITASDK/bin:$PATH"

SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD="$SPIKE_DIR/build"

echo "==> cmake (two selfs)"
mkdir -p "$BUILD"
cd "$BUILD"
cmake .. >/dev/null
make -j

echo "==> param.sfo (launcher, gdc) + param2.sfo (bgapp, gdd)"
# Structural clones of BGFTP's released SFO pair (see sfo_make.py) —
# round 1's mksfoex output (empty CONTENT_ID etc.) launched the
# launcher fine but the bgapp spawn failed "could not find application"
# despite complete app.db registration.
python3 "$SPIKE_DIR/sfo_make.py" "$BUILD"

echo "==> vita-pack-vpk"
vita-pack-vpk \
  -s "$BUILD/param.sfo" \
  -b "$BUILD/eboot.bin" \
  -a "$BUILD/eboot2.bin=eboot2.bin" \
  -a "$BUILD/param2.sfo=sce_sys/param2.sfo" \
  -a "$SPIKE_DIR/assets/icon0.png=sce_sys/icon0.png" \
  -a "$SPIKE_DIR/assets/bg0.png=sce_sys/livearea/contents/bg0.png" \
  -a "$SPIKE_DIR/assets/startup.png=sce_sys/livearea/contents/startup.png" \
  -a "$SPIKE_DIR/assets/template.xml=sce_sys/livearea/contents/template.xml" \
  "$BUILD/ts-bgapp-spike.vpk"

ls -lh "$BUILD/ts-bgapp-spike.vpk"
echo "OK: $BUILD/ts-bgapp-spike.vpk"
