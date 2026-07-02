# M17-B / M17-C — dashboard settings, detail, touch, debug (5–7 days)

Builds on the M17-A read-only dashboard: a tabbed interface (Peers /
Settings / Debug), a peer-detail overlay, touch + analog-stick input,
and the first WRITE paths (config toggles + reconnect). Plus the small
control-plane plumbing to surface **key-expiry** — the silent
tailnet-drop-off warning that's the single most valuable settings item.

**Goal.** From the couch: switch tabs with L/R, tap peers, toggle ts-ftp
on/off, hit Reconnect, and see a red warning when the node's auth key is
about to expire — all without a config-file round-trip through a PC.

## Interaction model

- **L / R**: cycle tab `Peers | Settings | Debug` (tab bar in header).
- **Peers tab**: Up/Down or left-stick select; **✕** ping selected;
  **○** open peer-detail overlay (○ or △ closes).
- **Settings tab**: Up/Down select row; **✕** activate — toggle
  `ts-ftp enabled`, toggle `ts-ftp read-only`, or **Reconnect now**.
  Toggles rewrite config.toml and show "saved — relaunch to apply".
- **Debug tab**: read-only scroll of runtime internals.
- **Touch** (front panel, coords /2 → 960×544): tap a tab label to
  switch; tap a peer row to select it.

## Scope

### M17-B
1. **Reconnect action** — `POST /localapi/v0/reconnect` (confirmed live:
   ForceReconnect → event loop tears down + rebuilds the session at zero
   backoff). Refused (409) in fatal states; the UI shows the reason.
2. **Config toggles** (ts-ftp enabled / read-only) — Config has no
   `Serialize` and the template is comment-heavy, so we **line-edit**
   the raw file: locate `[ftp]`, rewrite the single `enabled`/`read_only`
   line before the next `[section]` (never touching `[egress_probe]
   enabled`), write atomically via tmp + `vita_fs::rename`. Pure
   toggle logic is host-tested; only the next launch picks it up
   (SUPRX reads config once at boot) → "relaunch to apply" prompt.
3. **Key-expiry + last-seen plumbing** — add `KeyExpiry`/`LastSeen`
   (`Option<String>`, RFC3339) to `NodeWire` (they're on the wire,
   currently dropped). Capture **self** key-expiry into
   `RuntimeSnapshot.our_key_expiry`; thread peer `last_seen`/`key_expiry`
   into `PeerView`. A pure `days_until(rfc3339, now)` renders "expires in
   N days" / "never" (zero-value `0001-…`) / "EXPIRED".
4. **Analog-stick scroll** + **peer-detail overlay** (endpoints, DERP,
   allowed-IPs, node-id, key-expiry, last-seen).

### M17-C
5. **ACL posture panel** — the `acl.tags` / `has_tags` data rendered
   prominently (Settings tab header): green "tag:vita" or a red
   "UNTAGGED — full untagged-node ACL reach" badge (threat-model UX).
6. **Touch input** — new `SceTouch` FFI (`sceTouchPeek`,
   `sceTouchSetSamplingState(FRONT, START)` once at init), `SceTouch_stub`
   added to build.rs, `/2` coordinate scaling, tap→select/tab-switch.
7. **Debug page** — renders `/status` fields the main card omits
   (`fatal_reason`, `alive_derp_regions`, `magic_local`,
   `public_endpoint`, `peer_count`, self key-expiry) plus build info. No
   new server endpoint (the destructive ring-drain endpoint is skipped —
   it would fight `egress_probe` for the same rings, and the data-plane
   bug it served is fixed).

## Deliberately deferred
- **thread-per-conn LocalAPI** — low value (the sole client already
  serializes /ping ahead of /status) and lands in the fragile SUPRX
  thread-spawn area. The single accept thread stays.
- **Custom LiveArea bubble art** — needs binary PNG assets; low
  value/effort. Default template stays.
- **Config editor beyond the two ts-ftp toggles** — no free-text auth_key
  editing on-device (no keyboard UX; stays PC-side).
- **Send-from Taildrop, exit-node UI, MagicDNS** — out of M17 entirely.

## Stages
- **S1** wire plumbing (ts-control KeyExpiry/LastSeen → snapshot →
  runtime publish) + `days_until` — host tests, no UI yet.
- **S2** config-toggle pure module (section-aware line edit) — host tests.
- **S3** tab state machine + Settings tab (toggles + reconnect) + stick.
- **S4** touch FFI + tap routing; peer-detail overlay.
- **S5** Debug tab + ACL panel; docs; hardware pass.

## Risks
| Risk | Sev | Mitigation |
|---|---|---|
| Config line-edit corrupts auth_key / wrong section | High | section-aware matcher + atomic tmp+rename; pure fn host-tested incl. the `[egress_probe] enabled` decoy |
| ts-control wire change breaks control-plane parse | Med | additive `#[serde(default)]` fields only; existing netmap tests must stay green |
| Touch coords/range wrong (1920×1088 is community, not header) | Low | flat /2; only used for hit-testing rects, off-by-a-bit is harmless |
| Toggling ts-ftp then not relaunching confuses the user | Low | explicit "relaunch to apply" + the live value still reflects the running config until then |
| RFC3339 zero-value shown as "expired" | Low | `days_until` returns None for `0001-…` → "never" |
