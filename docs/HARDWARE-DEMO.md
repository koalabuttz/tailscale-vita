# Tailscale-on-Vita — hardware demo recipe

Step-by-step for bringing the v1 Tailscale-on-Vita demo up on a real
PSVita against a self-hosted Headscale, then pinging the Vita from a
second tailnet member.

This is the runbook for verifying M1–M9 end-to-end. M10 will
package this into a redistributable demo eboot.

## Prerequisites

- **Vita**: HENkaku/h-encore-modded, vitacompanion installed (FTP on
  port 1337), `$VITA_IP` is the Vita's WiFi IP.
- **Dev host**: Linux/macOS with `cargo`, `rustup` (nightly toolchain
  pinned via `rust-toolchain.toml`), the
  [VitaSDK](https://vitasdk.org/), and `cargo-vita`.
- **Headscale dev container**: docker pulling
  `headscale/headscale:0.26`, exposing TCP `8080` (control) and `9090`
  (metrics) on the host LAN. See `infra/headscale/`.
- **Tailnet peer** (for the ping verification): a Linux box on the
  same LAN with Tailscale 1.70+ installed. ChromeOS Crostini works
  too; see "Tier-2 verification" below.

## Variables

```bash
export VITASDK=/home/david/vitasdk
export PATH=$VITASDK/bin:$PATH

VITA_IP=192.168.8.107            # your Vita's WiFi IP
HEADSCALE_HOST_IP=192.168.8.147  # the dev host's LAN IP
```

Update both `crates/tailscale-vita-demo/src/main.rs`'s `HEADSCALE_URL`
constant **and** `infra/headscale/config/config.yaml`'s `server_url`
when these change. They must agree (Tailscale's TS2021 protocol pins
the server's URL).

## 1. Bring up Headscale

```bash
docker run -d --name tailscale-vita-headscale \
    -p 8080:8080 -p 9090:9090 \
    -v $(pwd)/infra/headscale/config:/etc/headscale \
    -v $(pwd)/infra/headscale/lib:/var/lib/headscale \
    headscale/headscale:0.26 serve
```

Verify:

```bash
docker exec tailscale-vita-headscale headscale users list
# (creates the user on first run)
docker exec tailscale-vita-headscale headscale users create vita
docker exec tailscale-vita-headscale headscale users list
# Expect: ID 1 | vita
```

## 2. Generate auth key for the Vita

```bash
AUTH_KEY=$(docker exec tailscale-vita-headscale headscale preauthkeys \
    create --user 1 -e 720h --reusable | tail -1)
echo "$AUTH_KEY"
# 48 hex chars on Headscale 0.26 (bare hex, no `tskey-auth-` prefix)
```

Stage a single-line auth-key file:

```bash
echo "$AUTH_KEY" > /tmp/auth-key.txt
```

## 3. Sideload Vita state files

```bash
# auth-key
curl -s -Q "DELE ux0:/data/tailscale-vita/auth-key.txt" \
    "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/" 2>/dev/null
curl -T /tmp/auth-key.txt \
    "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/auth-key.txt"
```

(Persistent priv keys, server-key.bin, last_seq, session_handle are
auto-created on first run; nothing to sideload here.)

## 4. Build + sideload the demo VPK

```bash
cargo vita build vpk -p tailscale-vita-demo --release

# Verify build succeeded — cargo-vita's exit code lies sometimes:
ls -l target/armv7-sony-vita-newlibeabihf/release/tailscale-vita-demo.vpk
# Check mtime is fresh.

curl -s -Q "DELE ux0:/vpk/tailscale-vita-demo.vpk" \
    "ftp://$VITA_IP:1337/ux0:/vpk/" 2>/dev/null
curl -T target/armv7-sony-vita-newlibeabihf/release/tailscale-vita-demo.vpk \
    "ftp://$VITA_IP:1337/ux0:/vpk/tailscale-vita-demo.vpk"
```

## 5. Install + launch on the Vita

⚠️ **Important: VitaShell does NOT auto-update an installed app when
you re-upload its VPK.** You must re-install via VitaShell each time:

1. Open VitaShell → browse to `ux0:/vpk/`.
2. Tap `tailscale-vita-demo.vpk` → press triangle → **Install**.
3. Confirm "overwrite existing app" if prompted.
4. Press PS → launch the **Tailscale-Vita Demo** bubble.

The demo runs for ~120 seconds, then exits cleanly. Watch for:

- LiveArea launch screen flashes briefly.
- Brief black screen while the demo runs (no UI; logging only).
- Auto-return to LiveArea ~120 s later.

## 6. Pull the log

```bash
curl -s "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/log.txt" -o /tmp/vita.log
less /tmp/vita.log
```

You should see (in roughly this order):

```
INFO vita_log: log initialized path=ux0:/data/tailscale-vita/log.txt
INFO startup{milestone="M9" ...}: binary build timestamp build="..."
INFO ts_control::server_key: control.key.fetched key=mkey:...
INFO ts_control::keystore: control.keystore.loaded
        machine_pub=mkey:...
        node_pub=nodekey:...
        disco_pub=discokey:...
INFO control.noise.handshake.complete handshake_hash=...
INFO control.early_payload len=N body_preview=...
INFO ts_control::http2: control.http2.handshake.complete
INFO ts_control::register: control.register.ok machine_authorized=true
INFO wg-engine pump starting peers=0
INFO netstack: netstack started local_ip=None
INFO netstack::poll: netstack poll loop starting
INFO ts_derp::probe: derp.probe.start total=28
INFO ts_derp::probe: derp.probe.winner region=N rtt_ms=N
INFO ts_derp::handshake: derp.tls.handshake.ok region=N
INFO ts_derp::handshake: derp.upgrade.101 region=N leftover=45
INFO ts_derp::handshake: derp.server_key.received server_pub=...
INFO ts_derp::handshake: derp.server_info.decrypted version=2
INFO ts_derp::conn: derp.handshake.ok region=N node=Nb is_home=true
INFO derp.home.changed prev=0 new=N
INFO derp.home.selected home=N regions=28
INFO netstack.local_addrs.from_mapresponse addrs=[Cidr { address: 100.64.0.1, prefix_len: 32 }]
INFO netstack: netstack.local_addrs.set addrs=[...]
INFO lifecycle.transition prev=Connecting new=Online first_map_seen=true first_derp_seen=true
INFO lifecycle.heartbeat state=Online peer_count=0 alive_regions=1
INFO control.map.keepalive seq=0 count=1
INFO lifecycle.heartbeat state=Online ...
INFO M9 demo done peer_count=N snapshots=N keepalives=N
        derp_alive_regions=[N] lifecycle_state=Online
INFO netstack poll loop exiting
INFO wg-engine pump exiting
```

If `lifecycle_state` is `Online` and there's no panic dump (no
`PANIC:` lines), the M1–M9 path is healthy.

## 7. Verify on Headscale

```bash
docker exec tailscale-vita-headscale headscale nodes list
```

Expect ID 1 / hostname `vita` / `100.64.0.1` / Last seen recent (the
demo's exit timestamp).

## Tier-2 verification: ping → Vita

For the actual M9 success criterion (`ping 100.64.0.1` returns
replies), you need a second tailnet member.

### Option A: Tailscale on a Linux box on the LAN

```bash
# On the Linux peer:
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up \
    --login-server=http://${HEADSCALE_HOST_IP}:8080 \
    --auth-key="$AUTH_KEY" \
    --hostname=lan-peer
```

The `--login-server` flag accepts plain HTTP for dev Headscale.

### Option B: Tailscale on ChromeOS Crostini

⚠️ Crostini install can be unstable
([tailscale/tailscale#12090](https://github.com/tailscale/tailscale/issues/12090)).
Snapshot your Crostini container first if possible (ChromeOS Settings
→ Linux → Backup).

Same install + login as Option A, run inside the Crostini terminal.

### Run the ping

```bash
# On the Linux/Crostini peer, with Vita demo bubble launched:
ping -c 5 -W 2 100.64.0.1
# Expect: 5/5 replies, RTT 80–500 ms (DERP-relayed).

tailscale status | grep vita
# Expect: 100.64.0.1 vita (online)
```

On the Vita's `log.txt` after the run, expect:

- `wg.handshake.complete peer=<peer_pubkey>` — WG keypair derived.
- `wg.tun.rx peer_pub=... n=84` — 5 inbound ICMP echoes (84 B IPv4+ICMP
  for default `ping` payload size).
- The auto-reply sent by smoltcp's `iface.process_icmpv4` doesn't log
  per-packet; the only signal is the peer's successful pings.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `derp.handshake.fail error=io: failed to fill whole buffer` | Server EOF after our ClientInfo. JSON case mismatch (M8 bringup bug) or other wire-format issue. | Verify `ClientInfoWire` field renames. See `derp_protocol_gotchas` memory. |
| `M9 demo done` shows `lifecycle_state=Connecting` | First MapResponse never arrived OR DERP handshake never succeeded. | Check `control.register.ok` line + `derp.home.selected`. If neither, network path issue. |
| Vita's IP not in headscale | Auth key wrong or missing | Re-generate via `headscale preauthkeys create`; re-upload `auth-key.txt`. |
| `build_unix=` in logs doesn't match recent build | VitaShell ran a stale install. Re-uploaded VPK doesn't auto-update installed app. | Re-install via VitaShell triangle→Install, confirm overwrite. |
| No reply to ping | smoltcp's `iface.ip_addrs` doesn't include the dst | Check log for `netstack.local_addrs.set addrs=[...100.64.0.1...]`. Should fire from first MapResponse. |
| `[ERROR] cargo build failed` but VPK mtime fresh | cargo-vita's exit-code-via-pipe lies about errors | Re-read the build log carefully; the actual error is upstream of the pipe. M8 hit this with `simd-adler32`. |

## Cleanup

```bash
# Stop Headscale (state persists in infra/headscale/lib/):
docker stop tailscale-vita-headscale

# Reset Vita state (fresh keys + auth-key on next run):
curl -Q "DELE ux0:/data/tailscale-vita/machine.priv" "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/"
curl -Q "DELE ux0:/data/tailscale-vita/node.priv"    "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/"
curl -Q "DELE ux0:/data/tailscale-vita/disco.priv"   "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/"
curl -Q "DELE ux0:/data/tailscale-vita/server-key.bin" "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/"
curl -Q "DELE ux0:/data/tailscale-vita/last_seq"     "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/"
curl -Q "DELE ux0:/data/tailscale-vita/session_handle" "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/"
```

(Auth key stays — regenerate manually if needed.)
