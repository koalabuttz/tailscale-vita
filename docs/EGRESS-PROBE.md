# Fork-B egress-shape probe (E2/E3)

Diagnostic for the WG data-plane bug: Vita→peer WireGuard transport-DATA
frames (byte0=0x04, len>32) never reach any peer, while keepalives
(0x04/32 B), handshakes (0x01/148, 0x02/92) and Disco (0x54…/110-124)
sent through the **same** `sendto` do. The 2026-07-02 in-SUPRX crypto
self-test (`wgst:`) exonerated the AEAD; the send path is byte-identical
for all frame types. Two hypotheses remain:

- **H1 — on-path middlebox** (carrier CGNAT DPI / phone tether path)
  drops WG-data-shaped UDP in the upstream direction only.
- **H2 — sceNet itself** accepts the `sendto` (returns ≥ 0) but never
  transmits payload-carrying type-4 frames.

Two facts make the old evidence insufficient: (1) the `Ok` the engine
logs is *synthetic* (`MagicSocketCtl::send_to` returns `Ok(len)` at
enqueue; the real syscall's returned count was discarded), and (2) every
peer ever tested sits behind a NAT middlebox — there has never been a
same-LAN data test.

This probe closes both gaps in one deploy.

## What it does

`[egress_probe]` in `config.toml` (off by default) makes the runtime,
~15 s after startup, send a battery of 6 tagged UDP shapes to each
configured target — through the **production** send path
(`send_to` → tx_queue → v4 worker drain → `sceNetSendto`) *and* through
a direct send (the STUN context, known-delivering) — for N rounds:

| id | shape         | bytes | why it exists                                        |
|----|---------------|-------|------------------------------------------------------|
| 1  | `wg-data-96`  | 96    | exact WG transport-data layout — the failing shape   |
| 2  | `flip0-96`    | 96    | byte-identical to 1 except byte0=0x14 — isolates byte0 |
| 3  | `ka-32`       | 32    | keepalive layout — positive control (delivers in prod) |
| 4  | `zero-96`     | 96    | like 1, all-zero body — isolates content entropy     |
| 5  | `wg-data-110` | 110   | type-4 at a size PROVEN to deliver (as Disco) — size vs type |
| 6  | `disco-110`   | 110   | real Disco magic — positive control at shape 5's size |

Every probe's last 4 bytes are `[0xA5, shape_id | ctx<<4, round, 0x5A]`
(ctx 0 = queue, 1 = direct) — random-looking to a DPI, decodable by the
listener.

It also instruments **every** drain-path send (probe or live WG frame)
with the ACTUAL byte count `sceNetSendto` returned, emitted as
`wgpr:rec` trace lines — the first direct observation of sceNet's
verdict on real 96-byte data frames.

## Running it

### 1. Listener host(s)

Same-LAN arm (no carrier in path — the decisive arm): a host on the
Vita's Wi-Fi network. On the Chromebook, remember Crostini needs the
one-time ChromeOS port-forward (Settings → Linux → Port forwarding,
UDP 9999), and prefer confirming arrivals with a capture on the
Chromebook's real NIC if results look odd — the in-batch positive
controls (shapes 3/6) tell you whether the forward itself works.

```
python3 scripts/egress-probe-listener.py --port 9999 --rounds 5
```

Optional carrier arm: the same listener on a host across the carrier
(public VM), or point a target at a live peer endpoint and capture
there with tcpdump/Wireshark.

### 2. Vita config (`ux0:/data/tailscale-vita/config.toml`)

```toml
[egress_probe]
enabled            = true
targets            = ["<listener-ip>:9999"]
rounds             = 5
initial_delay_secs = 15
spacing_ms         = 250
```

### 3. Deploy + run

Build and push the SUPRX to **`ur0:tai/`** (NOT `ux0:tai/` — see
PLUGIN-DEPLOY.md), relaunch the demo app, wait ~1 min
(delay + 5 rounds ≈ 45 s), then pull the trace:

```
curl -s "ftp://$VITA_IP:1337/ux0:/data/tailscale-vita/phase2-trace.txt"
```

## Reading the results

Vita-side trace lines:

- `wgpr:direct r=<round> s=<shape> dst=… req=<n> ret=<m|err:…>` —
  synchronous result of each direct send.
- `wgpr:rec r=<round> dst=… b0=<hex> req=<n> ret=<m|err:…>` — the real
  return count of every drain-path send (probes AND live traffic).
- `wgpr: done … full=… short=… zero=… err=…` — totals.

Listener-side: the arrival matrix (per shape × queue/direct, out of N
rounds).

Interpretation:

| observation | verdict |
|---|---|
| `ret < req` or `ret=0` for 96-B sends (`wgpr:rec`/`direct`) | **H2 confirmed & localized**: sceNet under-accepts in the `sendto` accept path. The discarded-usize gap was the whole story. |
| shape 1 absent on the **same-LAN** listener while shapes 3/6 arrive, `ret == req` | **H2 confirmed**: sceNet (or the Wi-Fi driver) accepts then never transmits — no middlebox exists on a LAN path. Next: taiHEN hook on `sceNetSendto` / socket-option sweep (`SO_SNDBUF=0x80000`). |
| shape 1 arrives on LAN but not across the carrier | **H1 confirmed**: on-path middlebox. Shape 2 vs 1 tells you whether byte0 is its classifier; shape 5 vs 1 whether length matters. Mitigation: DERP fallback for data / padding-obfuscation. |
| shape 1 arrives everywhere | The synthetic shape isn't the trigger — something about *live-session* frames is. Escalate to E1 (synchronized peer capture during real pings) and compare the `wgpr:rec` lines for live frames. |
| queue and direct columns differ | Thread/send-context matters after all — revisit the M16 worker-drain architecture with this as evidence. |

Cross-checks built into the battery: shapes 3/6 arriving proves the
listener/NAT/capture works (a false "everything dropped" is impossible
to misread); shape 4 vs 1 isolates entropy; shape 5 vs 6 isolates
byte0 at equal length.

## Cleanup

Set `enabled = false` (or delete the `[egress_probe]` section). The
send-record ring in ts-magicsock stays — it's bounded (256 entries) and
costs nothing when nothing drains it; the `short_send` warn it enables
is production-worthy.
