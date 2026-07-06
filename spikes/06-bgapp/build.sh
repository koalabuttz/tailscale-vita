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
# ATTRIBUTE values lifted verbatim from BGFTP's released param.sfo pair:
# launcher 0x1009000 (+ATTRIBUTE_MINOR 0x11), bgapp 0x81000.
vita-mksfoex \
  -s CATEGORY=gdc -s TITLE_ID=TVBG00001 \
  -d ATTRIBUTE=16814080 -d ATTRIBUTE_MINOR=17 \
  "TS BGApp Spike" "$BUILD/param.sfo"
vita-mksfoex \
  -s CATEGORY=gdd -s TITLE_ID=TVBG00002 \
  -s INSTALL_DIR_ADDCONT=TVBG00001 -s INSTALL_DIR_SAVEDATA=TVBG00001 \
  -d ATTRIBUTE=528384 \
  "TS BG Service" "$BUILD/param2.sfo"

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
