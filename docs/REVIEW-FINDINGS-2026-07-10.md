# Code-review findings — 2026-07-10 hardening change set

Deep review of the security-hardening change set (WireGuard inbound packet-filter
ACL enforcement, FTP auth + transfer caps + jail-by-default, Taildrop in-flight
limits, HTTP-control Noise-key pinning, LocalAPI CSRF header). 15 findings total.

## Fixed in this pass

| # | File | Fix |
|---|------|-----|
| 1 | `crates/wg-engine/src/policy.rs` | **ICMP wrongly denied.** `rule_matches` required an exact `0-0` port range for portless protocols; Tailscale encodes `*` ports as `0..=65535` and treats ICMP as port 0 matched by containment. Now the `None` branch is `port_first == 0`, so a `*` rule admits ICMP (peer ping) while a ports-only rule still denies it. |
| 2 | `crates/ts-ftp/src/session.rs` | **Pre-auth OOM.** `read_line`'s `MAX_COMMAND_BYTES` guard only ran between `read_until` calls, so a fast no-newline stream grew the buffer without bound. Each read is now bounded with `Take` to the remaining budget. |
| 3 | `crates/ts-ftp/src/session.rs` | **RETR OOM.** The size cap was skipped when `file_size()` returned `None`, then the whole file was read into RAM. RETR now fails closed (`550`) on unknown size. |
| 4 | `crates/ts-ftp/src/{session,lib}.rs` | **STOR corruption.** Fixed `{real}.upload.partial` name let two concurrent same-name uploads interleave + cross-delete. Now a shared `Ctx.partial_seq` gives each upload a unique `{real}.{id:016x}.upload.partial` (mirrors ts-peerapi). |
| 5 (partial) | `crates/tailscale-vita/src/runtime.rs` | **Deny-by-default black-hole diagnosability.** Added a one-shot `warn!` when peers are present but no PacketFilter has arrived (see #5 below for the remaining risk). |

## Deferred — documented, not yet fixed

Severity key: **High** = breaks a real path / exploitable; **Med** = latent trap or
robustness gap; **Low** = perf/cleanup.

### #5 — Deny-by-default has no fallback (Med)
`Engine` starts `InboundPolicy::DenyAll` (`wg-engine/src/lib.rs`) and is only
replaced under `if delta.packet_filter_changed` (`runtime.rs` `push_delta_to_engine`).
If a control server never sends a parseable IPv4 PacketFilter — a custom/minimal
control, or an ACL whose rules all reduce to empty after `filter_rule_from_wire`
drops IPv6-only/malformed rules — the data plane is permanently silent. Real
Tailscale/standard Headscale always send a filter, and the `Engine` is reused
across ordinary reconnects (only the `MapClient` is rebuilt), so this is bounded
to cold-start / full re-login. A `warn!` now flags it (fix #5). Deeper options:
a bounded "no filter after first netmap" timeout, or an explicit config opt-in
for a permissive default on trusted control.

### #6 — Stateless filter drops service ports under a scoped ACL (High, by design)
The local filter has no reply/related-flow tracking, so a peer-initiated inbound
connection to a service port the ACL doesn't grant is dropped. Concretely: an ACL
granting only `vita:21` lets FTP login succeed but every PASV data connection
(ports 30000–30009) is dropped → transfers hang at `425`; likewise the demo
`:8080` and Taildrop peerapi port. This is *correct* ACL enforcement, not a bug,
but it's a sharp edge shipped alongside ts-ftp's fixed PASV range. Documented in
`README.md` (Security model) and the `[ftp]` config template. No code change
unless we later add reply-flow tracking.

### #7 — Only legacy `PacketFilter` parsed, not `PacketFilters` map (Med)
`MapResponseWire` (`ts-control/src/types.rs`) parses only the deprecated singular
`PacketFilter`; the reference port (`refs/tailscale-rs` `map_stream.rs`) applies
both the base `PacketFilter` and the keyed `PacketFilters` grant map, and
`capver = 138` advertises grant support. Grant-based rules delivered via
`PacketFilters` are silently not applied → grant-authorized peers dropped by the
engine. Standard port-based ACLs still arrive via the singular field, so this is
"grants unsupported," not a black-hole. Fix: also deserialize `PacketFilters` and
merge (base then keyed), matching the reference.

### #9 — Enabling FTP without a password is a silent no-op (Med, UX)
`FtpConfig.password` defaults to `""` and `TsFtpServer::spawn` returns `None`
(warn-only) when it's empty. A user who flips `[ftp] enabled = true` — especially
via the M17-B dashboard toggle, which section-edits `enabled`/`read_only` but
**cannot set a password** — gets a "saved" UI and no running server; existing
pre-password configs upgrade into a silently-disabled FTP. Documented in README +
config template. Fix options: surface the refusal in the runtime snapshot so the
dashboard can show it, or have the dashboard refuse to enable without a password.

### #10 — PacketFilter is now hard-parsed → a bad shape aborts the whole map (Med)
`deserialize_packet_filter` (`ts-control/src/types.rs`) propagates serde errors
with `?`, so a PacketFilter value of an unexpected shape (an object/string where a
list/null is expected, or an `IPProto` element outside `u8`) fails the entire
`MapResponseWire` deserialization. `classify_control_error` maps decode failures
to `Transient` → endless reconnect loop with no netmap. Previously PacketFilter
was parsed-and-dropped and could never break the frame. Fix: deserialize the
field leniently (per-rule best-effort, `IPProto` as `i64` then range-check),
never aborting the frame on a malformed rule.

### #11 — IPv4 fragment offset ignored in `parse_ipv4_meta` (Low)
`parse_ipv4_meta` (`wg-engine/src/pump.rs`) never inspects the fragment-offset /
MF flags (IPv4 bytes 6–7), so a non-first fragment's payload bytes at `ihl+2..4`
are read as the L4 destination port. Fragmented allowed flows lose their trailing
fragments, and it's a fragmentation-based filter-evasion surface. Fail-closed and
low-impact today (smoltcp doesn't reassemble v4 fragments; Tailscale manages MTU).
Fix: treat `offset > 0` as portless, or drop it explicitly.

### #12 — Per-chunk `vita_fs::append` fsyncs flash on every 8 KB (Low, perf)
`stream_to_file` (`ts-ftp/src/session.rs`) calls `vita_fs::append` per 8 KB chunk,
and each `append` (`vita-fs/src/vita.rs`) does open + write + `sceIoSyncByFd` +
close — ~4096 fsyncs to slow flash per 32 MiB upload (ts-peerapi shares this via
the same primitive). Fix: add a streaming-append handle to vita-fs (open once,
write chunks, sync+close once), or drop the per-chunk fsync (close flushes).

### #13 — Hot-path `trace!` allocates per dropped packet (Low, perf)
`vita-log` builds the formatted `String` (including `short_hex(&peer.pubkey)`,
a heap alloc) as an argument to `__emit`, evaluated before `__emit`'s
`FILTER_LEVEL` gate. The new drop-path `trace!` calls in `handle_inbound`
(`wg-engine/src/pump.rs`) therefore allocate + format per dropped packet even at
the production Info level. Fix: guard those logs behind a cheap level check.

### #14 — Snapshot deep-clones the packet filter every map event (Low, perf)
`NetMapSnapshot { packet_filter: self.netmap.packet_filter.clone(), .. }`
(`ts-control/src/map.rs`) deep-clones the whole `Vec<FilterRule>` on every map
event, while the only consumer reads it under `if delta.packet_filter_changed`.
Fix: store it as `Arc<PacketFilter>` (clone = refcount bump) or populate the
snapshot field only when the change flag is set.

### #15 — Duplicate filter types + dead variant + stale comment (Low, cleanup)
`ts_control::{FilterRule, NetPortRange, AllowedIp}` and
`wg_engine::{FilterRule, NetPortRange, Ipv4Cidr}` are field-identical twins
bridged by the hand-written `engine_packet_filter` copy (`runtime.rs`); a new
field on either side silently drops in the ACL path with no compile error.
wg-engine is a lower crate ts-control could depend on to reuse `InboundPolicy`
directly. Separately, `InboundPolicy::AllowAll` (`policy.rs`) is never
constructed (dead), and the `do_list` comment (`session.rs`) still describes the
removed device-list special case.
