# M19 — Lifecycle spine: logout, tailnet on/off, mid-life re-login, identity card

## Context

M18 gave us interactive QR login, but only at boot: `interactive_login` runs once inside
`Runtime::up` and the runtime has no way to leave or re-enter the logged-in/connected
state afterwards. Three user-facing gaps all trace to that one missing capability:

1. **No logout.** The only way to log out is deleting `node.priv` over FTP.
2. **No tailnet on/off toggle.** The runtime is connected whenever it's alive.
3. **Reconnect-time `NodeKeyExpired` requires an app restart** (known M18 deferral:
   `bootstrap_control_session` returns a Transport error "restart to re-login" at
   `runtime.rs:1347-1358`, which classifies Transient, so the loop backs off forever
   with a dead key).

M19 builds the spine once — *a lifecycle that can leave and re-enter the connected and
logged-in states without a process restart* — and hangs all three off it, plus the
Android-parity identity card (who am I / which tailnet) that logout makes necessary.

Threat-model note (`vita_threat_model`): tier-3 stays config-file-only where it means
*identity/config mutation* (auth keys, control URL, routes). The four new endpoints are
all **zero-parameter POSTs**: `/down` and `/logout` are access-revoking, `/up` and
`/login-interactive` resume/request a previously-user-approved state and grant nothing
that wasn't already granted. On a sandbox-less device they add no exposure a local
file-write couldn't already achieve. The eboot's logout row gets an on-device confirm
overlay (fat-finger protection, honestly not a security boundary).

### Upstream semantics we mirror (recon-verified)

- **`tailscale down`/`up`** = flip `ipn.Prefs.WantRunning` (persisted). Daemon stays
  alive, login/node key untouched, engine emptied; state shows **Stopped**. Bare `up`
  changes no auth — it only resumes. (The tailscale-rs clone has *no* ipn/prefs layer;
  this state machine is greenfield for us.)
- **`tailscale logout`** = a RegisterRequest with `Expiry` set to *now* and
  `NodeKey` = the **current** key — no separate RPC. Reference doc
  (`refs/tailscale-rs/ts_control_serde/src/register.rs:82-87`): "If expiry is in the
  past and node_key is the current node key for this node, the node key is expired
  immediately." The node then shows **expired** in the admin console (not deleted) —
  *unless the node is ephemeral, in which case it is deleted.*
- **Key lifecycle:** machine key survives logout; node key is expired at logout and
  regenerated at the **next login** (never at logout time — control must be able to
  match the current key to expire it). Our M18 `interactive_login` already regenerates
  on `NodeKeyExpired`, so post-logout re-login works with zero KeyStore surgery.
- **`POST /localapi/v0/login-interactive`** is upstream's LocalAPI name for "start an
  interactive login now" — we reuse it verbatim.

### Ephemeral hazard (must fix first)

`ts-control/src/register.rs:83` hardcodes `ephemeral: true`. Ephemeral nodes are
garbage-collected by control after disconnect and would be **deleted** (not expired) by
logout, losing the node's identity/IP. M19 S1 flips this to `false` so the Vita is a
persistent tailnet citizen: survives long offline stretches, and logout leaves a
re-authorizable "expired" node in the admin console.

## Goals

1. `POST /localapi/v0/logout` + Settings row with confirm overlay.
2. `POST /localapi/v0/up` / `POST /localapi/v0/down` — a `WantRunning` bit with a new
   `OnlineState::Stopped`, persisted in config.toml (default on).
3. Mid-life interactive login: `POST /localapi/v0/login-interactive`, auto-triggered on
   reconnect-time `NodeKeyExpired`/deauth (closes the M18 deferral), and used
   post-logout via a "press ✕ to log in" screen.
4. Identity card: tailnet **Domain** (already parsed, just plumbed) + **user login
   name** (new `UserProfiles`/`Node.User` wire parsing) surfaced in the dashboard
   header.
5. UI: Stopped header state, Tailnet toggle row, real Re-authenticate row (today's
   "Re-login" row secretly just POSTs /reconnect), logout confirm modal.

**Free win banked during recon:** peers-sorted-online-first already ships
(`viewmodel.rs:171` + test `rows_sort_online_first_then_name`). No work.

## Non-goals

- **Taildrop** (banked, natural M20), **exit nodes** (needs system-wide sceNet hooking
  — its own epic), ***main promotion** (gated on soak, not code).
- `OldNodeKey` rotation on re-login after logout. Consequence (documented): logout +
  re-login may create a fresh node entry rather than rotating in place. Acceptable —
  identical to what the M18 QR test already did.
- Config-file `auth_key` interplay with logout: if a non-empty `auth_key` is configured,
  a post-logout login will silently re-register with it (logout becomes key rotation).
  Interactive-default installs have `auth_key = ""`, so just document it.
- Multi-account/profile switching, MagicDNS.

## Stages

### S1 — ts-control: logout wire + ephemeral flip

`crates/ts-control/src/register.rs`:

- Add to `RegisterRequestWire` (:197): `#[serde(rename = "Expiry",
  skip_serializing_if = "Option::is_none")] expiry: Option<String>` (RFC3339, same
  `time` formatting as the existing `Timestamp` field :80). Existing callers pass
  `None` — wire bytes unchanged for register (serde test to prove it).
- New `pub fn logout(conn, node_pub, nl_pub, backend_log_id, hostname, host_authority)
  -> Result<(), ControlError>`: same body-build + POST `/machine/register` plumbing as
  `register()` (factor a shared body builder), but `Auth = None`, `Followup = None`,
  `Expiry = Some(now)`. Success = response has no server `Error`; control replying
  `NodeKeyExpired = true` **is** success (that's the point). Do **not** touch the
  KeyStore here.
- Flip `ephemeral: true` → `false` (:83) + update the three test sites (:277, :305,
  :324 expects `v["Ephemeral"] == true` — becomes absent, since the field is
  skip-if-false).

Tests: logout body shape (Expiry present + RFC3339-parseable, Auth/Followup absent,
NodeKey = current); logout response interpretation (Error → Err, NodeKeyExpired/empty
→ Ok); register unchanged with `expiry: None`.

### S2 — ts-control: identity wire (UserProfiles + Node.User)

`crates/ts-control/src/types.rs`:

- `UserProfileWire { #[serde(rename="ID")] id: i64, #[serde(rename="LoginName",
  default)] login_name: String, #[serde(rename="DisplayName", default)] display_name:
  String }`.
- `MapResponseWire` (:309): `#[serde(rename="UserProfiles", default,
  deserialize_with="null_or_default")] user_profiles: Vec<UserProfileWire>` (capver
  ≥ 138 sends `null` for empty seqs — reuse helper at :203).
- `NodeWire` (:337): `#[serde(rename="User", default)] user: i64`.

`crates/ts-control/src/netmap.rs`:

- `NetMap.user_profiles: HashMap<i64, UserProfile>` — **delta-upsert** in `apply()`
  (UserProfiles sends only new/changed profiles since CapVer 5; copy the Peers
  HashMap idiom at :180, NOT wholesale replace).
- `NetMap.our_user_id: Option<i64>` captured in the self-node block (:134-169) with the
  guarded pattern of `our_key_expiry` (:165) — **not** the unguarded `our_tags` pattern
  (:157), so a peers-only frame can't blank it.
- `pub fn our_login_name(&self) -> Option<&str>`: resolve `our_user_id` against
  `user_profiles` lazily (id and profile may arrive in different frames). Tagged nodes
  map `Node.User` to a tag pseudo-user with no human profile — returns None; UI falls
  back to hostname.

Tests: delta merge survives profile-less frames; self login resolves when id/profile
arrive out of order; tagged/missing-profile → None; Domain untouched.

### S3 — runtime: the lifecycle spine

`crates/tailscale-vita/src/lifecycle.rs`:

- `OnlineState::Stopped` + `set_stopped()`/`clear_stopped()` (mirror the NeedsLogin
  pair :142/:152). `compute_next_state` short-circuits on Stopped exactly like the
  fatal states (:259) so `tick()` can't drive a parked runtime back to
  Connecting/Offline. Non-sticky: only `clear_stopped` leaves it.

`crates/tailscale-vita/src/runtime.rs`:

- `ControlSignal` (:106) gains `SetWantRunning(bool)`, `Logout`, `LoginInteractive`.
  One command channel, no parallel flags — all drained at the existing seam (:527).
- Factor `finish_session(conn, backend_log_id) -> Result<MapClient>` from the
  duplicated `MapClient::start` tails (up :334-344 ≡ bootstrap :1366-1376) so first
  boot, reconnect, and mid-life re-login produce `map_opt` identically.
- **Stop-aware `interactive_login`:** add an `abort: &mut dyn FnMut() ->
  Option<LoginAbort>` parameter checked each loop pass (2 s cadence). `Runtime::up`
  passes a no-op (boot behavior unchanged); the event loop passes a closure that
  peeks `signal_rx` + `should_stop` so a `/down` or shutdown can abort an unapproved
  login instead of blocking forever (recon risk: today only process death interrupts
  it). Also: generate `backend_log_id` in `up()` unconditionally (move it out of
  `interactive_login`) so a parked boot has one.
- **want_running / park:** `Runtime.want_running: bool` seeded from
  `config.tailnet.want_running`. Event loop, when false: skip the reconnect block
  (:557) and `next_event` (:640); drain signals only; state = Stopped. Transition
  **down**: `map_opt = None` (control session closes), clear engine peers
  (`engine.remove_peer` over current peers — data plane goes quiet; recon risk:
  dropping `map_opt` alone leaves WG peers live), `set_stopped()`. Transition **up**:
  `clear_stopped()` + `map_opt = None` + `reconnect_attempt = 0` — the normal
  bootstrap resumes and the first full MapResponse re-populates the engine through the
  existing Snapshot→engine sync (same as any reconnect).
- **Parked boot:** `Runtime::up` with `want_running = false` skips `interactive_login`
  + `MapClient::start` but builds magicsock/DERP/engine/stack as usual, publishes
  Stopped. The first `/up` drives the standard reconnect bootstrap; if the node isn't
  authorized yet, that path now escalates to interactive login (next bullet), so a
  fresh-install-parked boot converges too.
- **Mid-life login entry (closes the M18 deferral):** redirect
  `bootstrap_control_session`'s NodeKeyExpired/pending-auth early-returns (:1347-1358)
  and the new `LoginInteractive` signal into stop-aware `interactive_login` (it's
  already a free fn taking `&mut ks` — reachable from the loop's `&mut self`), then
  `finish_session` → `map_opt = Some`. Auto-trigger at most once per reconnect cycle
  (the login loop's own 2 s repoll is the backoff; don't hammer register).
- **Logout signal:** `establish_control_conn` fresh → `ts_control::logout` → on
  success: `map_opt = None`, clear engine peers, delete `last_seq` +
  `session_handle` (map.rs:54 — stale session state must not leak into the next
  identity), `set_needs_login` + publish `auth_url = None`, `login_in_progress =
  false`. **Parked logged-out: no auto re-login** — the user explicitly left
  (asymmetric with expiry, matching upstream). On failure: log + stay in prior state
  (no local wipe unless control confirmed the expiry). Node key is left in place —
  the next login sends it, control answers expired/AuthURL, and the existing M18
  regenerate branch takes over.

`crates/tailscale-vita/src/snapshot.rs` (all `#[serde(default)]` — SUPRX and eboot are
independently versioned binaries sharing this struct):

- `tailnet_domain: Option<String>`, `user_login: Option<String>`,
  `login_in_progress: bool`. Update `empty()` (:147) and the handlers.rs:249 test
  literal. Populate domain/login in `publish_snapshot` from the NetMap (mirror
  `our_key_expiry` at :1750) — sourced from persistent NetMap state, so the 3 s
  full-replace republish (:1753) can't blank them. `publish_login_state` (:1613) sets
  `login_in_progress` at login start/end.

Tests: Stopped park/clear + tick-can't-clobber; signal handling for
SetWantRunning/Logout/LoginInteractive at whatever seams the existing 52 host tests
already exercise; snapshot field defaults.

### S4 — LocalAPI: four POST endpoints

`router.rs:34`: arms for `POST /localapi/v0/{up,down,logout,login-interactive}`.
`handlers.rs`: clone the `reconnect` template (:162) — fatal-state gate → 409
`{ok:false,error}`, `ctx.controller.send(signal)` → **202** `{ok:true}`, send-err
(loop dead) → 503. Zero-parameter, body ignored — required anyway because the port-8080
tailnet proxy forces `Content-Length: 0`, so peers can drive these via `/api/<name>`
for free. 202 = "accepted, watch /status" (fire-and-forget channel has no ack; the UI
polls /status at 2 s).

Polish while touching: `reason_phrase` (http.rs:197) gains `202 => "Accepted"`,
`409 => "Conflict"` (reconnect already emits both as "Unknown").

Tests: router dispatch for the four paths; handler status codes; test-literal updates.

### S5 — config + line-editor

`crates/tailscale-vita/src/config.rs`:

- New `TailnetConfig { #[serde(default = "default_true")] want_running: bool }`, added
  as `#[serde(default)] pub tailnet: TailnetConfig` (mirror the `ftp` section :87).
  **Default true is load-bearing** — bare `#[serde(default)]` on a bool is false and
  would boot every upgrading user into Stopped. TEMPLATE (:140) gains
  `[tailnet]\nwant_running = true`. A `[tailnet]` *section* (not a top-level key) is
  required because the line-editor cannot address top-level keys.

`crates/tailscale-vita-demo/src/ui/config_edit.rs`:

- `set_bool(text, section, key, value)` — `/up`//`/down` are explicit sets; the
  existing `toggle_bool` only flips and would write the wrong value on a no-op press.
- **Insert path** (the critical piece): when `[section]` or the key is missing, append
  the section header + `key = value` instead of failing. Every config.toml already on
  a device lacks `[tailnet]` — without insert, the first toggle press errors
  (`missing_key_returns_none` currently locks in the failure). `apply_set` file-op
  wrapper keeps the `.bak` + `.tmp` + verify-restore dance verbatim (vita_fs::rename
  is non-atomic).
- Eboot stays the **sole** config.toml writer (runtime only writes the template when
  the file is absent — recon-audited; no clobber risk). Live state travels via POST;
  the config write is only next-boot persistence.

Tests: set-when-already-set is a no-op write; insert-into-missing-section;
insert-key-into-existing-section; alongside the existing 8.

### S6 — demo UI

`viewmodel.rs` / `dashboard.rs` / `render.rs` / `client.rs`:

- `SettingRow::ALL` becomes 6: `[FtpEnabled, FtpReadOnly, TailnetToggle, Reconnect,
  Reauthenticate, Logout]`. Today's `Relogin` row (which silently POSTs /reconnect,
  dashboard.rs:222-223) becomes a real `Reauthenticate` → `POST /login-interactive`.
  **Layout:** `SET_ROW_H` 44 → 36 (6 rows: 232 + 6·36 = 448 < FOOTER_TOP 484; today's
  44 would overflow at 496).
- `TailnetToggle` activation: if lifecycle == Stopped → `apply_set(want_running=true)`
  + `POST /up`; else `apply_set(false)` + `POST /down`. Value cell renders from
  lifecycle (`on` / `off`).
- **Modal enum** `{None, PeerDetail(String), ConfirmLogout}` replacing bare
  `detail_key` (dashboard.rs:86) so exactly one overlay owns input (guard at :153).
  ConfirmLogout overlay reuses the `detail_overlay` panel style: "Log out? This
  expires the device's key at control. ✕ confirm · ○ cancel" — ✕ sends
  `UiAction::Logout`.
- `UiAction` gains `TailnetUp/TailnetDown/Logout/LoginInteractive`; each a
  `do_reconnect`-template fn (client.rs:218) + inflight label + `run_action` arm.
  `http_req` already does empty-body POST.
- **Stopped header:** `lifecycle_display` (viewmodel.rs:398) arm → `("Stopped",
  Tone::Dim)`. Header renders it automatically.
- **Identity in header:** `HeaderVm.right` is computed but never drawn
  (viewmodel.rs:146, render.rs ignores it) — start drawing it right-aligned at y=74
  and set it to `login · domain` when known (fallback: the current DERP/uptime
  string). One draw call + one viewmodel change; the DERP/uptime info stays visible in
  Debug.
- **login_frame three modes** (NeedsLogin full-screen, dashboard.rs:244):
  `Some(url)` → QR (unchanged); `None && login_in_progress` → "starting login...";
  `None && !login_in_progress` → **logged-out parked**: "Logged out — press ✕ to log
  in" (✕ → `LoginInteractive`). While any full-screen lifecycle view is up, gate the
  normal input block (recon: input currently runs un-gated under the QR screen, so ✕
  could invisibly activate Settings rows — pre-existing quirk, fix while here).

Tests: SettingRow render arms; modal input routing; lifecycle_display Stopped;
viewmodel identity fallback (existing 33-test suite style).

### S7 — build, deploy, hardware verify

Host: `cargo test` all crates green; `cargo build` workspace. Cross: SUPRX via
`crates/tailscale-vita-plugin/build.sh` → `ur0:/tai/`; demo VPK → `ux0:/vpk/` (FTP,
DELE-before-STOR). Update `docs/HARDWARE-DEMO.md`.

Hardware matrix (user drives; log = `ux0:data/tailscale-vita/vita.log`, SUPRX trace =
`phase2-trace.txt`):

1. **Regression:** normal boot → Online, peer ping + ts-ftp still work, header shows
   `login · domain` after the first full map.
2. **Toggle:** Settings → Tailnet ✕ → header Stopped within ~3 s; peer ping from
   lewis stops; admin console shows offline. Relaunch app → boots Stopped
   (persistence). Toggle ✕ again → Online, ping resumes — all without restart.
3. **Logout** ⚠️ *expires the current node's key (same consent as the M18 QR test —
   confirm with user first):* confirm overlay → admin console shows the node
   **expired** (not deleted — the ephemeral flip at work); Vita shows logged-out
   screen; ✕ → QR appears → phone scan → approve → Online.
4. **Reconnect-expiry auto-relogin:** not triggerable on demand (needs a key to
   expire mid-session); covered by host tests + shares the exact `LoginInteractive`
   code path exercised in (3).

## Pinned integration contract

- Endpoints: `POST /localapi/v0/up | /down | /logout | /login-interactive` — all
  zero-parameter, body ignored; 202 `{"ok":true}` accepted / 409 `{"ok":false,
  "error":…}` refused / 503 loop-dead. Reachable from tailnet peers via
  `/api/up` etc. through the 8080 proxy.
- `ControlSignal::{ForceReconnect, SetWantRunning(bool), Logout, LoginInteractive}`.
- `OnlineState::Stopped` (serialized `"Stopped"`), set/cleared out-of-band, tick-proof.
- `RuntimeSnapshot` additions (all `#[serde(default)]`): `tailnet_domain:
  Option<String>`, `user_login: Option<String>`, `login_in_progress: bool`.
- Config: `[tailnet] want_running = true` (missing key/section ⇒ true). Eboot is the
  sole writer; runtime reads at boot only.
- `ts_control::logout()` = register with `Expiry = now`, current NodeKey, no Auth, no
  Followup. `ephemeral` is now `false` for all registrations.
- SettingRow order: FtpEnabled, FtpReadOnly, TailnetToggle, Reconnect, Reauthenticate,
  Logout. `SET_ROW_H = 36`.

## Risks

- **Blocking login loop** — mitigated by the abort closure; a `/down` or shutdown
  during an unapproved QR wait must abort within one 2 s repoll (test this seam).
- **Config editor insert** is the highest-impact implementation detail: every
  on-device config lacks `[tailnet]`; a missed insert path = toggle dead on arrival.
- **publish_snapshot full-replace** (:1753): identity fields must be re-read from
  NetMap every publish (they are, by design) — never written only via partial
  publishers or they vanish on the next 3 s republish.
- **UserProfiles delta**: replace-not-merge would blank the identity card on every
  no-change map frame. Merge is mandatory (CapVer ≥ 5).
- **Ephemeral flip** changes control-side behavior for *all* registrations, not just
  logout. Expected effect is strictly good (persistence), but verify the existing
  node re-registers cleanly on first boot after deploy.
- **Stopped exhaustiveness**: every `match` on OnlineState across both crates must
  gain an arm (compiler enforces); health `ok` and Tone semantics need deliberate
  choices (Stopped is "ok", tone Dim). SUPRX + eboot must ship together (shared serde
  enum).
- **Fresh-boot-parked converges via bootstrap→interactive escalation** — new
  interaction; covered by the S3 redirect but worth a trace marker (`park1`/`park2`
  style) for hardware debugging.
