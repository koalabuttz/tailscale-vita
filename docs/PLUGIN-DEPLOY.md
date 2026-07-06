# Deploying the tailscale-vita-plugin (.suprx)

This guide covers installing, updating, and recovering the Tailscale plugin on a modded Vita. The plugin runs Tailscale as a background daemon under taiHEN so it stays up across the demo app's lifecycle (no longer dies when you back out to LiveArea).

## Prerequisites

- Modded Vita with taiHEN + HENkaku (or h-encore²) installed.
- VitaShell installed and FTP enabled (we use port 1337 — `vitacompanion`).
- Either VitaSDK installed locally OR a pre-built `.suprx` from CI.
- `ux0:/data/tailscale-vita/config.toml` already set up (same file the demo uses). Set `suprx_host_only = true` in there so the demo's eboot skips its own `Runtime::up` and lets the plugin own the daemon.

## First install (one-time)

1. **Build the plugin:**
   ```
   cd crates/tailscale-vita-plugin
   ./build.sh
   ```
   Produces `build/tailscale_vita_plugin.suprx` (~1.7 MB).

2. **FTP the plugin to `ur0:tai/`.** taiHEN/Ensō reads its config and loads
   plugins from `ur0:tai/` (the standard plugins — henkaku, vitacompanion, … —
   live there too), NOT `ux0:tai/`. Push to the same path the config stanza
   references:
   ```
   curl -T crates/tailscale-vita-plugin/build/tailscale_vita_plugin.suprx \
        "ftp://$VITA_IP:1337/ur0:/tai/tailscale-vita-plugin.suprx"
   ```

3. **Append the taiHEN config stanza.** The file at `ur0:/tai/config.txt` controls which plugins taiHEN loads at boot. Pull it, append the contents of `taihen-config-fragment.txt`, push it back:
   ```
   curl -s "ftp://$VITA_IP:1337/ur0:/tai/config.txt" -o /tmp/config.txt
   cat taihen-config-fragment.txt >> /tmp/config.txt
   curl -T /tmp/config.txt "ftp://$VITA_IP:1337/ur0:/tai/config.txt"
   ```

4. **Reboot the Vita.** taiHEN only re-reads its config at boot — there's no hot-reload that affects new plugin loads safely.

5. **Verify on first launch.** Launch the tailscale-vita-demo app. The plugin's `module_start` fires during the demo's process bringup. Check the log at `ux0:/data/tailscale-vita/log.txt` (FTP-pull it) for these lines:
   ```
   tailscale_vita_rt: vita_rt.start (plugin module_start)
   tailscale_vita_rt: bootstrap.thread.running
   tailscale_vita::runtime: runtime.up.start ... hostname=vita
   tailscale_vita::localapi: localapi.bound bound_addr=127.0.0.1:41112
   ```

6. From a tailnet peer, `curl http://<vita-tailnet-ip>:8080/api/status` — same JSON as before, but now sourced from the plugin's address space.

## Updating the plugin

After a code change:

1. Rebuild: `crates/tailscale-vita-plugin/build.sh`.
2. FTP the new `.suprx` to `ur0:/tai/tailscale-vita-plugin.suprx` (overwrites the old one).
3. **Reboot.** taiHEN won't reload an existing plugin's binary mid-session — the running plugin keeps the old code in memory. Full reboot is the cleanest way to swap binaries.

You can technically `taiHEN unload`/`load` via `taiReloadConfig` from a payload, but that path is fragile and the plugin's own threads / heap won't tear down cleanly. Reboot is faster + safer.

## Brick recovery

If the plugin crashes during `module_start` or otherwise misbehaves:

- **Demo dies, Vita stays alive**: this is the intended behavior of `*TVIT00010` staging. Just don't relaunch the demo. The plugin only loads inside that title's process.
- **If `module_start` hangs (Vita appears frozen on demo launch)**: hold the power button to force-shutdown. On next boot, immediately enter VitaShell BEFORE launching the demo. Remove the plugin file: `delete ur0:/tai/tailscale-vita-plugin.suprx`. Or edit `ur0:/tai/config.txt` to comment-out the `*TVIT00010` stanza. Reboot.
- **If somehow promoted to `*main` and breaks SceShell** (NOT the default — only if you edited the stanza): boot into Safe Mode (hold L + R + Start + PS during boot to recover). From Safe Mode you can re-flash HENkaku or restore via Vita Update Blocker.

The default `*TVIT00010` config is intentionally low-risk: a misbehaving plugin can only break the one app that loads it.

## Promoting to *main (M20-D — gated on a clean 24h soak)

Staging under `*main` means the plugin runs in SceShell's address space and stays up even when our demo isn't launched. That's the goal — a Tailscale daemon that survives game launches, reachable (FTP/Taildrop/LocalAPI-via-demo) while the Vita sits on the LiveArea.

**Gate**: a clean 24-hour run under `*TVIT00010` — dashboard uptime counter
never resets, no OOM trend in `ux0:data/tailscale-vita/vita.log`, ts-ftp +
taildrop + peer ping still working at hour 24.

**Procedure** (edit `ur0:/tai/config.txt` over FTP, then reboot):

1. **Comment out — don't delete — the `*TVIT00010` stanza** and add the same
   `ur0:tai/tailscale-vita-plugin.suprx` line under `*main`. Keeping the old
   stanza commented makes rollback a two-character edit (swap which one has
   the `#`).
2. **NEVER leave both stanzas active.** SceShell and the demo would EACH load
   the plugin: two runtimes, two node-key users, both binding port 21/8098/
   41112 on the same stack — undefined and definitely broken.
3. Reboot ×3 back-to-back; confirm LiveArea is responsive each time, then
   sleep/wake once. Only then trust it.
4. Post-promotion sanity: with the demo CLOSED, ts-ftp answers on the tailnet
   and a Taildrop PUT lands. That's the payoff proof.

**Rollback / recovery** (in escalating order):
- Boot works, plugin misbehaves: FTP in (vitacompanion is SceShell-side and
  independent of our plugin), swap the `#` between the two stanzas, reboot.
- Boot loops / SceShell dies before FTP: hold **L during boot** — taiHEN
  skips `ur0:tai/config.txt` entirely for that boot (henkaku "skip plugins"
  path); then fix config.txt via VitaShell or FTP and reboot normally.
- Worst case: Safe Mode (hold L + R + Start + PS at power-on) → re-flash
  HENkaku / restore. Never observed; listed for completeness.

## Heap / thread budget (current — M20-D take 6 diet)

- 16 MB newlib heap (`_newlib_heap_size_user`, main.c) — backs ALL Rust
  allocation (Global = System) since S7. Was 32 MB; halved for SceShell fit.
- 1 MB taipool (vestigial reservation, not Rust's allocator since S7).
- 2 MB bootstrap-thread stack (was 4 MB; the demo eboot runs the same
  bring-up on its ~1 MB main thread, so 2 MB keeps 2x margin).
- ~5 runtime threads at 256 KB stack each (~1.3 MB total).
- Estimated Rust crate heap use: 3-5 MB (magicsock + DERP + smoltcp + boringtun + h2).
- Total steady-state demand ≈ 21 MB + the ~2.3 MB module image.
- `heavy_init_and_start` preflights `sceKernelGetFreeMemorySize` (needs
  heap+taipool+1 MB slack) before grabbing anything, so a load into a
  cache-filled SceShell logs `c2m`/`c2n` and retries instead of crashing.

## *main two-stage loader (take 6)

Under `*main`, config.txt lists ONLY `ur0:tai/tailscale-vita-loader.suprx`
(~6 KB). Boot-time mapping of the fat module froze SceShell (takes 1-4);
a single post-boot load at +60 s hit a cache-filled partition (take 5).
The take-6 loader instead:

- logs free-memory probes at uptime 12/20/30 s (no load),
- attempts `sceKernelLoadStartModule` on a ladder at 40/50/62/75/90/120/
  180/240/300/360 s, logging `sceKernelGetFreeMemorySize` before each try,
- writes everything to `ux0:data/tailscale-vita/loader-trace.txt`
  (truncated per boot; separate from phase2-trace.txt, which the fat
  module truncates when it starts).

Even a fully failed boot yields SceShell's free-memory curve — the data
that picks the next lever (earlier rung, image diet, kubridge).
