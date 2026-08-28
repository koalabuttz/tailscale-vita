#!/bin/bash
# M21 — build + package the Tailscale-Vita bgapp VPK (docs/PLAN-M21.md).
#
# One VPK / one bubble, two eboots (layout proven by the M21 spike):
#   eboot.bin   gdc launcher — Phase B: the spike's C launcher (calls
#               StartBgApp + runs the cross-process 127.0.0.1:41112
#               probe). Phase D swaps in the dashboard eboot here.
#   eboot2.bin  gdd service — the Rust daemon (cargo-vita build; SELF
#               carries MEMSIZE/ATTRIBUTE in control-info-6 via
#               vita_make_fself_flags, asserted below).
#
# Iterate by rebuild + full REINSTALL — never FTP hot-swap an installed
# eboot (appmgr binds the SELF at install time; M21 spike lesson).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export VITASDK="${VITASDK:-/home/david/vitasdk}"
export PATH="$VITASDK/bin:$PATH"

OUT="$ROOT/target/bgapp"
mkdir -p "$OUT"

GDC_ID="TSVT00001";  GDC_TITLE="Tailscale Vita"
GDD_ID="TSVT00002";  GDD_TITLE="Tailscale Daemon"
CONTENT_TAIL="TAILSCALEVITA000"
MEMSIZE_KB=49152; ATTRIBUTE=3   # must match tailscale-vita-daemon/Cargo.toml

echo "==> gdd: cargo-vita build (tailscale-vita-daemon)"
(cd "$ROOT" && cargo vita build vpk -p tailscale-vita-daemon --release)
DAEMON_VPK="$ROOT/target/armv7-sony-vita-newlibeabihf/release/tailscale-vita-daemon.vpk"
python3 - "$DAEMON_VPK" "$OUT/eboot2.bin" <<'EOF'
import pathlib, sys, zipfile

archive, output = map(pathlib.Path, sys.argv[1:])
with zipfile.ZipFile(archive) as vpk:
    output.write_bytes(vpk.read("eboot.bin"))
EOF

echo "==> assert gdd SELF control-info-6 budget"
python3 - "$OUT/eboot2.bin" "$ATTRIBUTE" "$MEMSIZE_KB" <<'EOF'
import struct, sys
path, attr, memsize = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
d = open(path, "rb").read()
pat = struct.pack("<4I", 1, attr, 0, memsize)
i = d.find(pat)
if i < 0:
    sys.exit(f"FATAL: {path} missing ctrl-info-6 [1, ATTRIBUTE={attr}, 0, "
             f"MEMSIZE={memsize}KB] — cargo-vita did not apply "
             "vita_make_fself_flags; re-run vita-make-fself -m/-at manually "
             "on the .velf (see docs/PLAN-M21.md Phase B)")
print(f"    ctrl-info-6 OK at {i:#x}: ATTRIBUTE={attr} MEMSIZE={memsize}KB")
EOF

echo "==> gdc: spike C launcher (Phase D: the dashboard)"
cmake -S "$ROOT/spikes/06-bgapp" -B "$OUT/launcher-build" >/dev/null
make -C "$OUT/launcher-build" -j >/dev/null
cp "$OUT/launcher-build/eboot.bin" "$OUT/eboot.bin"

echo "==> param.sfo / param2.sfo (BGFTP-clone structure)"
python3 "$ROOT/scripts/sfo_make.py" \
  --ref "$ROOT/spikes/06-bgapp/reference" --out "$OUT" \
  --gdc-id "$GDC_ID" --gdc-title "$GDC_TITLE" \
  --gdd-id "$GDD_ID" --gdd-title "$GDD_TITLE" \
  --tail "$CONTENT_TAIL"

echo "==> vita-pack-vpk"
ASSETS="$ROOT/spikes/06-bgapp/assets"   # BGFTP MIT placeholders; Phase E replaces
vita-pack-vpk \
  -s "$OUT/param.sfo" \
  -b "$OUT/eboot.bin" \
  -a "$OUT/eboot2.bin=eboot2.bin" \
  -a "$OUT/param2.sfo=sce_sys/param2.sfo" \
  -a "$ASSETS/icon0.png=sce_sys/icon0.png" \
  -a "$ASSETS/bg0.png=sce_sys/livearea/contents/bg0.png" \
  -a "$ASSETS/startup.png=sce_sys/livearea/contents/startup.png" \
  -a "$ASSETS/template.xml=sce_sys/livearea/contents/template.xml" \
  "$OUT/tailscale-vita-bgapp.vpk"

ls -lh "$OUT/tailscale-vita-bgapp.vpk"
echo "OK: $OUT/tailscale-vita-bgapp.vpk"
