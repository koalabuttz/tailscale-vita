# Spike 06 — background application (M21)

**Question:** can we build, package, and run a PS Vita *background
application* (the `sceBgAppUtilStartBgApp` / `eboot2.bin` mechanism that
BGFTP and ElevenMPV-A use) with **open tools only** (vitasdk + cargo-vita —
no leaked SCE SDK)?

**Why:** M20-D proved a Tailscale daemon cannot live in SceShell (`*main`):
boot-time mapping freezes the shell ~4/5 boots, and post-boot loading is
impossible (SceShell partition has 0 bytes free from ~12 s onward, measured).
A bgapp is a *sanctioned* background process with its own memory budget that
survives launcher exit, LiveArea browsing, games (except enlarged-memory
titles, which LowMemMode lifts), and screen-off. BGFTP demonstrates
14 MB heap + 6 MB buffers in exactly this mechanism.

**Packaging convention** (extracted from BGFTP v3.24's released VPK):
one VPK, one bubble — `eboot.bin`+`sce_sys/param.sfo` (CATEGORY `gdc`,
ATTRIBUTE `0x1009000`) is the visible launcher; `eboot2.bin`+
`sce_sys/param2.sfo` (CATEGORY `gdd`, ATTRIBUTE `0x81000`, own TITLE_ID,
`INSTALL_DIR_ADDCONT/SAVEDATA` pointing at the launcher's TITLE_ID) is the
background service. `sceBgAppUtilStartBgApp` launches eboot2.bin. LiveArea
assets in `assets/` are from BGFTP (MIT, GrapheneCt) — spike-only
placeholders.

**What the bgapp probes** (log: `ux0:data/tailscale-vita/bgapp-spike.log`):
1. survival — 30 s heartbeats + boot notification
2. memory — 14 MB newlib heap, malloc-touch 10 MB, memblock ladder to ceiling
3. network — SceNet up, IP logged, UDP echo on **:31338**
4. stay-awake — `sceKernelPowerTick(DISABLE_AUTO_SUSPEND)` per loop (console
   will NOT auto-sleep while it runs; peel the LiveArea card to stop)

**Test from a LAN host:**
```
echo hi | timeout 3 socat - udp:<VITA_IP>:31338   # expect "bgapp up=..s echoes=N"
```
…then launch a game and run it again. Also: `sceBgAppUtilStartBgApp` mode
arg — BGFTP passes 0, vitasdk docs say "must be 1"; launcher tries 0 then 1
and logs both, settling the question.

Build: `./build.sh` → `build/ts-bgapp-spike.vpk`, FTP to `ux0:/vpk/`,
install via VitaShell, launch the bubble.
