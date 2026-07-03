# M18 — Interactive QR-code login (5–7 days)

Make `auth_key = ""` the plug-and-play default: on first run with no key,
register interactively, show the control server's AuthURL **as a QR code**
on the Vita screen, and let the user scan it with a phone to approve the
node. After approval the persisted node key works forever — no auth-key
file ever needed. A non-empty `auth_key` remains as an automation override.

**Goal.** Boot a fresh Vita with no auth key → it shows "Scan to log in"
+ a QR + the URL text → scan with phone, approve on Tailscale → the
dashboard flips to Online. Next boot: straight to Online, no QR.

## Confirmed protocol (research)
Same `POST /machine/register`, same node key throughout:
1. **Trigger**: send RegisterRequest with the `Auth` struct **omitted**
   (empty auth key) → control replies with a non-empty `AuthURL` and
   `MachineAuthorized=false`.
2. **Wait**: re-POST the same request with `Followup: <AuthURL>` set →
   Tailscale/Headscale **long-poll** (block) until the user authenticates,
   then reply `MachineAuthorized=true`, empty `AuthURL`, empty `Error`.
   (Fallback: a plain re-poll every ~2 s with no Followup also works —
   the reference port does this. We use Followup + a re-poll safety timer.)
3. **Done**: node key is authorized server-side; steady-state map begins.
   `NodeKeyExpired=true` → regenerate the node key and re-enter login.

**Hands-free caveat**: QR-scan completes hands-free on real Tailscale
(login.tailscale.com OAuth) and Headscale+OIDC. On default non-OIDC
Headscale the AuthURL page needs a `headscale ...` CLI step — so the UI
must ALSO show the URL as scrollable text, not only a QR.

## Architecture
Registration runs in the SUPRX (`Runtime::up`). The eboot dashboard is a
pure LocalAPI reader and cannot register — so the AuthURL flows
**SUPRX Runtime → `RuntimeSnapshot.auth_url` → LocalAPI `/status` →
dashboard**, which just renders it.

**The blocker + fix**: today register runs inside `Runtime::up`
(runtime.rs:271) *before* LocalAPI spawns (runtime.rs:291), and a
non-empty AuthURL becomes `Err(AuthRejected)` that aborts up(). M18
reworks bootstrap so pending-auth is NOT fatal: create the snapshot +
spawn LocalAPI *early*, publish `NeedsLogin { auth_url }`, then run an
interactive register wait-loop until authorized before continuing to
engine/stack/map bringup.

## Integration contract (pinned names — build agents MUST use these)
- **ts-control `register.rs`**:
  - `RegisterRequestWire.auth`: `Option<RegisterAuthWire>`,
    `#[serde(rename="Auth", skip_serializing_if="Option::is_none")]` —
    omitted when the auth key is empty.
  - add `RegisterRequestWire.followup: Option<String>`,
    `#[serde(rename="Followup", skip_serializing_if="Option::is_none")]`.
  - `register(...)` gains a `followup: Option<&str>` param.
  - `RegistrationOutcome.pending_auth_url: Option<String>` — set (Ok, not
    Err) when the response has a non-empty AuthURL and not authorized.
    Keep `AuthRejected` only for genuine rejections (auth key supplied but
    refused), not the interactive path.
- **lifecycle.rs**: add `OnlineState::NeedsLogin`.
- **snapshot.rs**: add `RuntimeSnapshot.auth_url: Option<String>`
  (`#[serde(default)]`); set in `empty()` and every literal.
- **runtime.rs**: interactive wait-loop; publish NeedsLogin + auth_url;
  proceed on MachineAuthorized; `NodeKeyExpired` → regenerate node key +
  re-login (not sticky AuthFailed).
- **config default**: delete the empty-auth aborts at
  `tailscale-vita-rt/src/lib.rs:363-366` and demo `main.rs:133-140`;
  empty key → interactive login; update the config TEMPLATE comment.
- **demo `ui/qr.rs`** (NEW): `qrcodegen = "1.8"`; `encode(&str) ->
  Option<Qr>` where `Qr { size: usize, dark: Vec<bool> }` (row-major,
  `dark[y*size+x]`), ECC Low. Pure — host-tested against a known matrix.
- **demo dashboard/render**: full-screen Login view when
  `snapshot.lifecycle == NeedsLogin` — big QR (quiet-zone border, ~10-12
  px/module, centered) + the URL as text + "waiting for approval…"
  spinner. A Settings **Re-login** row for the expired-key case.

## Stages
- **S1** ts-control register: Auth-omit + Followup + PendingAuth outcome.
- **S2** lifecycle NeedsLogin + snapshot auth_url + config abort removal.
- **S3** runtime bootstrap restructure + interactive wait-loop.
- **S4** QR module (qrcodegen) + host tests.
- **S5** dashboard Login view + Settings Re-login.
- **S6** host tests + cross-compile + hardware pass.

## Risks
| Risk | Sev | Mitigation |
|---|---|---|
| Register wait-loop hangs or busy-spins | High | Followup long-poll + bounded re-poll timer; the loop checks a shutdown flag; never block the whole runtime uninterruptibly |
| Runtime::up restructure breaks steady-state bringup | High | LocalAPI/snapshot created early but engine/stack/map order unchanged after auth; existing tests must stay green |
| `OnlineState` enum change breaks LocalAPI JSON back-compat | Med | additive variant; `#[serde(default)]` on the new snapshot field; old clients tolerate the new state string |
| QR crate won't cross-compile | Med | qrcodegen is zero-dep/std-only, builds under -Z build-std; prove in S4 before wiring |
| Node key not persisted → re-QR every boot | Med | verify KeyStore persists the authorized node key; next boot registers and gets MachineAuthorized immediately |
| AuthURL is a bearer capability shown on-screen | Low | approval still requires an authenticated tailnet admin; net-better than an auth_key in a plaintext file (threat model) |

## Deliberately deferred
- Send-side login (we only RECEIVE approval).
- OIDC-specific niceties; SSO provider detection.
- Re-keying automation beyond the NodeKeyExpired → re-login path.
