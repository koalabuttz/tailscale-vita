# Tailscale-on-Vita v1 — Implementation Plan

Implementation plan for the full v1 (Tier 4): a Rust Tailscale client running
on PSVita, registering against Headscale primarily (Tailscale prod
best-effort), DERP-only transport, auth-key registration, exposing an
in-tunnel `std::net`-shaped API to other Vita homebrew. Distributed as an
eboot — SUPRX is **out of scope for v1** per scope-cut on 2026-05-03.

This document is the strategic plan. File-level / function-level / type-level
detail per milestone (the actual coding-time reference) lives in
`~/.claude/plans/ticklish-bubbling-key.md`.

This plan is grounded in six rounds of source-level research that produced
the citations and code sketches reused below; see "Research provenance"
at the end for which findings are upstream-cited and which are inferred.

## Done already (do not re-do in v1)

Phase 0 has hardware-confirmed:

- Rust toolchain on Vita (`armv7-sony-vita-newlibeabihf`, nightly 1.97,
  `cargo-vita`).
- `std::net::UdpSocket` works on hardware (5/5 echo round-trips).
- `std::fs` works with `ux0:/...` paths.
- BoringTun 0.7.1 (vendored, two-line patch) cross-compiles and runs;
  produces a canonical 148-byte handshake init on hardware. `parking_lot`,
  `x25519-dalek`, `ring`-via-`vita-rust/ring`, `chacha20poly1305`,
  `blake2`, `getrandom 0.2.17` all confirmed.
- smoltcp 0.12 cross-compiles cleanly with a custom `phy::Device` impl;
  `Interface::poll` works on hardware.

What Phase 0 did **not** do but commonly assumed: a full WireGuard
handshake completing peer-to-peer. We only confirmed the handshake init
**is generated**, not that the round-trip succeeds. M2 below is where
that gets verified.

## Hard architectural decisions (locked)

1. **eboot only.** No SUPRX, no taiHEN integration, no NID exports in v1.
   Sample apps statically link the `tailscale-vita` Rust crate.
2. **Threaded blocking model**, not async. `vita-rust/mio` is archived;
   `polling` (for smol/async-std) does not have a Vita backend; tokio's
   I/O reactor is therefore unavailable. Threads + `parking_lot::Mutex` +
   `crossbeam-channel` is the concurrency stack.
3. **Headscale primary, Tailscale prod best-effort.** All wire-format
   choices are validated against Headscale 0.26 first.
4. **DERP-only transport.** No STUN, no endpoint discovery, no NAT
   traversal, no `magicsock`. Everything traverses TLS-over-443 to a DERP
   relay. Latency cost: +20–80 ms; throughput cost: per-relay rate limit.
5. **Auth-key registration only.** No OAuth, no interactive login. Auth
   key sits in `ux0:/data/tailscale-vita/config.toml`.
6. **Logging is text-only**, file-mirrored. `tracing` + a custom
   subscriber that writes to `ux0:/data/tailscale-vita/log.txt` and
   stdout. No PrincessLog, no UDP broadcast in v1. (Path may be
   added later; do not block on it.)
7. **Plain HTTP for Headscale; TLS only for DERP.** Headscale serves
   `/key`, `/ts2021`, `/derp` over HTTP by design; the Noise IK tunnel
   inside `/ts2021` is what actually authenticates the server. Tailscale
   prod requires HTTPS on `/key` — keep TLS code paths even though dev
   workflow uses cleartext.

## Architecture

```
┌──────────────── Vita eboot (one process) ──────────────────────┐
│                                                                │
│  ┌───────────────────┐    ┌────────────────────────────────┐   │
│  │  Sample app       │    │  Public API (Rust)             │   │
│  │  (statically      │◀──▶│  ts::dial, ts::listen,         │   │
│  │   linked)         │    │  ts::up, ts::status            │   │
│  └───────────────────┘    └─────────────────┬──────────────┘   │
│                                             │                  │
│                                             ▼                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  Tailscale runtime                       │  │
│  │                                                          │  │
│  │  ┌────────────────┐    ┌─────────────────────────────┐   │  │
│  │  │ control client │───▶│  netmap state               │   │  │
│  │  │ (Noise+HTTP/2) │    │  (peers, AllowedIPs,        │   │  │
│  │  │                │    │   DERPMap, DNS, my IPs)     │   │  │
│  │  └───────┬────────┘    └──────────┬──────────────────┘   │  │
│  │          │                        │                      │  │
│  │          ▼                        ▼                      │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │  WireGuard engine (BoringTun ⨯ N peers)            │  │  │
│  │  │  Mutex<Tunn> per peer; by_pubkey + by_idx + by_ip  │  │  │
│  │  └────────────┬─────────────────────────┬─────────────┘  │  │
│  │               │ encrypted WG datagrams  │ plaintext IPv4 │  │
│  │               ▼                         ▼                │  │
│  │  ┌─────────────────────┐    ┌────────────────────────┐   │  │
│  │  │ DERP transport      │    │ smoltcp Interface +    │   │  │
│  │  │ (HTTPS/443 frame    │    │ SocketSet              │   │  │
│  │  │  loop, per region)  │    │ (TCP/UDP in-tunnel)    │   │  │
│  │  └────────┬────────────┘    └────────┬───────────────┘   │  │
│  │           │                          │                   │  │
│  │  ┌────────▼─────────┐         ┌──────▼─────────────┐     │  │
│  │  │ rustls + ring    │         │ WgDevice (phy)     │     │  │
│  │  │ TcpStream:443    │         │ rx/tx VecDeque<Vec>│     │  │
│  │  └────────┬─────────┘         └────────────────────┘     │  │
│  │           │                                              │  │
│  └───────────┼──────────────────────────────────────────────┘  │
│              │                                                 │
└──────────────┼─────────────────────────────────────────────────┘
               ▼ Wi-Fi
       Internet → DERP → peer
```

**Threading model** (12 pthreads worst-case at full v1 scale; many fewer in early milestones):

| Thread | Owns | Blocks on | Wakeup |
|---|---|---|---|
| `app` (main) | `smoltcp::Interface`, `SocketSet`, in-tunnel sockets | Condvar w/ `iface.poll_delay()` timeout | `wg_engine` notify on rx queue |
| `wg_engine` | `HashMap<PublicKey, Mutex<Tunn>>`, both queues | Condvar w/ 250 ms timeout | `derp_conn` notify, `app` notify, timer |
| `net_rx` (M2 only) | `std::net::UdpSocket` read side | blocking `recv_from` w/ 50 ms timeout | network |
| `control` | Noise tunnel + HTTP/2 client + map state | Blocking long-poll read | Network keepalive (~60 s) |
| `noise_pump` (Plan A) | Background sync I/O for the Noise socket; pumps tokio AsyncRead/Write wakers | blocking `read`/`write` w/ short timeout | network or `tx_buf` push |
| `log` | File handle for `ux0:/data/.../log.txt` | crossbeam-channel recv | Any `tracing` event |
| `derp_conn × N` (N ≤ 8, M8+) | One thread per DERP region, single-threaded I/O loop with `select_biased!{ pong | tx | tls_readable }` | 100 ms recv_timeout + non-blocking TLS poll | channel push or network |

All threads spawn with `std::thread::Builder::new().stack_size(256 * 1024)` — Vita's default 64 KiB pthread stack is too small for smoltcp poll + listener pool + h2 frame buffers.

Locks — formal acquire-order invariant; **never reverse**:

1. `Engine.by_pubkey` / `by_idx` / `by_ip` (`RwLock`, read-mostly; write only on `upsert_peer`/`remove_peer`).
2. `Peer.tunn` (`Mutex<Tunn>`, only ever held on `wg_engine` thread; never across I/O or FS).
3. `WgDevice.rx_q` / `tx_q` *= shared `Arc<Mutex<VecDeque>>` with `EngineRunning.tun_rx`/`tun_tx`*. Held only across single `pop_front`/`push_back`. **`WgDevice::receive`/`transmit` use `try_lock`** — on contention, return `None` so smoltcp polls again; this prevents the `app` thread deadlocking against `wg_engine` holding the same Arc.
4. `StackInner.iface` (`Mutex<Interface>`, only on `app` thread).
5. `StackInner.sockets` (`Mutex<SocketSet>`) — always after `iface`.
6. `StackInner.handles` (`Mutex<HashMap<SocketHandle, HandleSlot>>`).
7. Per-handle Condvar mutex — held only across condition mutation; `sockets` lock must drop before parking on it.

## Workspace layout

Cargo workspace at the repo root. Existing `spikes/` directory stays as
historical reference; v1 lives under `crates/`.

```
tailscale-vita/
├── Cargo.toml                         # workspace
├── PLAN-V1.md                         # this file
├── RESEARCH.md
├── PHASE-0-RESULTS.md
├── crates/
│   ├── vita-log/                      # tracing layer + file mirror
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── ts-control/                    # Noise + HTTP/2 + map client
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, noise.rs, http2.rs, register.rs, map.rs, types.rs}
│   ├── ts-derp/                       # DERP frame loop + TLS upgrade
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, frame.rs, client.rs}
│   ├── wg-engine/                     # multi-peer BoringTun host
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, peer.rs, dispatch.rs}
│   ├── netstack/                      # smoltcp wrap, std::net-ish API
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, device.rs, tcp.rs, udp.rs}
│   ├── tailscale-vita/                # public API + Runtime glue
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, runtime.rs, api.rs, config.rs}
│   └── tailscale-vita-demo/           # eboot: hello-listener on tailnet IP
│       ├── Cargo.toml
│       └── src/main.rs
├── infra/headscale/                   # already in tree
└── vendor/
    └── boringtun/                     # already in tree (patched)
```

## Dependency manifest (workspace `Cargo.toml`)

Every crate listed below has been cross-compile-evaluated for
`armv7-sony-vita-newlibeabihf`. Anything ambiguous is flagged in the
risk register.

```toml
[workspace.dependencies]
# --- Phase-0 baseline (proven on hardware) ---
boringtun        = { path = "vendor/boringtun", default-features = false }
x25519-dalek     = { version = "2", features = ["static_secrets"] }
chacha20poly1305 = "0.10"
blake2           = "0.10"
hkdf             = "0.12"
getrandom        = "0.2"   # pinned to 0.2; revisit if snow needs 0.3
rand_core        = { version = "0.6", features = ["getrandom"] }
subtle           = "2"
parking_lot      = "0.12"
smoltcp = { version = "0.12", default-features = false, features = [
  "std", "log", "medium-ip", "proto-ipv4",
  "socket-tcp", "socket-udp", "socket-icmp",
] }

# --- Noise IK ---
snow = { version = "0.10", default-features = false, features = [
  "use-curve25519", "use-chacha20poly1305", "use-blake2", "std",
] }

# --- TLS + HTTPS ---
rustls           = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }
rustls-pki-types = "1"
webpki-roots     = "1"
ureq             = { version = "3",  default-features = false, features = ["rustls", "tls-rustls-webpki-roots", "json", "gzip"] }
httparse         = { version = "1",  default-features = false, features = ["std"] }

# --- HTTP/2 inside Noise (see M5; choose one fork) ---
h2   = "0.4"     # async crate; will be driven from a tokio current-thread runtime, no enable_io
tokio = { version = "1", default-features = false, features = ["rt", "macros", "sync", "time"] }

# --- Concurrency (no async runtime for the rest of the system) ---
crossbeam-channel = "0.5"

# --- JSON / serialization ---
serde      = { version = "1", features = ["derive"] }
serde_json = "1"

# --- Compression (Headscale gzips MapResponse bodies) ---
flate2 = { version = "1", default-features = false, features = ["rust_backend"] }

# --- Logging ---
tracing            = "0.1"
tracing-subscriber = { version = "0.3", default-features = false, features = ["fmt", "registry", "std"] }

# --- Helpers ---
base64    = { version = "0.22", default-features = false, features = ["alloc"] }
bytes     = "1"
time      = { version = "0.3", default-features = false, features = ["macros", "parsing", "formatting", "serde", "alloc"] }
thiserror = "1"
arc-swap  = "1"
toml      = { version = "0.8", default-features = false, features = ["parse"] }

# --- DERP NaCl box (M8). RustCrypto family; spike at head of M8 ---
crypto_box = { version = "0.9", default-features = false, features = ["alloc", "salsa20"] }

[patch.crates-io]
ring = { git = "https://github.com/vita-rust/ring", branch = "v0.17.14-vita" }
```

## Wire protocols summary

### Headscale `/key` (cleartext HTTPS or HTTP)

`GET /key?v=90 HTTP/1.1` → `OverTLSPublicKeyResponse{PublicKey: "mkey:<32B hex>"}`.
Persist as the server's Noise static; on subsequent runs, refuse to
proceed if the server returns a different key (loud warning, fail).

### TS2021 control protocol — Noise IK tunnel + HTTP/2

Open `POST /ts2021` with:

```
POST /ts2021 HTTP/1.1
Host: <server>
Connection: Upgrade
Upgrade: tailscale-control-protocol
X-Tailscale-Handshake: <base64(2B BE proto-version=1 || 1B msgType=0x01 || 2B BE len=96 || 96B Noise-IK init)>
```

Server returns `101 Switching Protocols` + 51-byte Noise response on the
upgraded socket: `1B msgType=0x02 || 2B BE len=48 || 48B Noise IK response`.
Finalize Noise to derive transport cipherstates. After that, every record
is `1B msgType=0x04 || 2B BE len || ChaCha20-Poly1305 ciphertext`.

The cleartext **inside** the Noise tunnel is **HTTP/2 (h2c)**. Tailscale
servers and Headscale 0.26 both speak HTTP/2 here. We multiplex
`/machine/register` and `/machine/map` on a single Noise connection.

Prologue mixed into the Noise transcript:
`b"Tailscale Control Protocol v" || u16_be(1)`. Bind protocol version
into the handshake hash.

### `/machine/register` (POST inside Noise/HTTP/2)

Body: JSON `tailcfg.RegisterRequest`. Required fields for v1:
`Version: 90`, `NodeKey: "nodekey:<hex>"`, `OldNodeKey: ""`,
`Auth: { AuthKey: "<bare hex from headscale or tskey-auth-... from prod>" }`,
`Hostinfo: { Hostname, OS: "linux", IPNVersion: "tailscale-vita/0.1" }`,
`Timestamp: <RFC3339>`, `Ephemeral: false`, `NLKey: ""`,
`NodeKeySignature: ""`, `DeviceCert: null`.

Response: `RegisterResponse{ MachineAuthorized: true, AuthURL: "" }`.
**Hard-fail if `AuthURL != ""`** — that means the auth key was rejected
and interactive login was offered, which v1 cannot do.

### `/machine/map` (POST inside Noise/HTTP/2, long-poll)

Body: `MapRequest{ Version: 90, NodeKey, DiscoKey, Hostinfo,
Endpoints: [], Stream: true, ReadOnly: false, OmitPeers: false,
Compress: "" }`. (`DiscoKey` is generated and never used in DERP-only;
the server requires it set.)

Response: a stream of `[4B little-endian length][JSON MapResponse body]`
chunks. If `MapRequest.Compress == "zstd"` was negotiated, body is
zstd-compressed; v1 sends `Compress: ""` and skips that. Headscale also
**gzips the entire HTTP/2 DATA stream** by default — the `flate2` dep is
not optional.

`MapResponse` fields v1 must parse:
`KeepAlive` (bool — if true, ignore everything else); `ControlTime`
(`*time.Time`); `Node` (own node, includes `Addresses` = own tailnet IPs);
`Peers` / `PeersChanged` / `PeersRemoved` / `PeersChangedPatch`; `DERPMap`;
`DNSConfig`; `PacketFilter` / `PacketFilters`; `Domain`; `Seq`.

`Node` fields: `ID`, `StableID`, `Name`, `Key` (= peer pubkey),
`Addresses`, `AllowedIPs`, `DERP` (legacy `127.3.3.40:<region>` magic
string), `HomeDERP` (capver ≥ 111: int region directly).

Long-poll watchdog: 2 minutes since last frame → kill connection,
exponential backoff (cap 30 s), reconnect, send `MapSessionSeq` = last
seen `Seq` to resume.

Keepalive cadence: server sends `MapResponse{KeepAlive: true}` every
~50–60 s on idle.

### DERP relay protocol

Connection bring-up (`ts-derp`):

1. Pick home region: TCP-RTT-probe `Nodes[0].HostName:443` of each
   region in the DERP map; pick lowest. Cache for 5 min.
2. TCP+TLS to `Nodes[0]` of home region. ServerName = `node.HostName`.
   No ALPN. TLS 1.3 preferred.
3. Send custom HTTP/1.1 upgrade:
   ```
   GET /derp HTTP/1.1
   Host: <node.HostName>
   Upgrade: DERP
   Connection: Upgrade
   User-Agent: tailscale-vita/0.1
   ```
4. Read `101 Switching Protocols`, then start consuming DERP frames.

Frame layout: `1B frameType || 4B BE length || payload`. Max 64 KiB per
frame. ProtocolVersion = 2.

Frame types v1 implements:

| Hex  | Name | Direction | What we do |
|------|------|-----------|------------|
| 0x01 | `ServerKey`     | S→C | Read server's NodePublic. Verify magic prefix `"DERP🔑"` (8B). |
| 0x02 | `ClientInfo`    | C→S | Send client pubkey + 24B nonce + NaCl-box(JSON `{"version":2,"CanAckPings":true}`). |
| 0x03 | `ServerInfo`    | S→C | NaCl-box-open. Ignore rate-limit fields. |
| 0x04 | `SendPacket`    | C→S | Per outbound WG datagram destined to peer pubkey B: `B_pub(32B) || wg_bytes`. |
| 0x05 | `RecvPacket`    | S→C | Inbound: `src_pub(32B) || wg_bytes` (in protocol v2). |
| 0x06 | `KeepAlive`     | S→C | No-op; just refresh dead-conn timer. **Server-only, no reply.** |
| 0x07 | `NotePreferred` | C→S | Send once after handshake: 1B `0x01` to mark this DERP as our home. |
| 0x08 | `PeerGone`      | S→C | Clear cached state for that peer. |
| 0x12 | `Ping`          | S→C | **Reply with `Pong (0x13)`** echoing the 8B payload. |
| 0x13 | `Pong`          | C→S (reply) | as above. |
| 0x14 | `Health`        | S→C | Log only. |
| 0x15 | `Restarting`    | S→C | Reconnect after `ReconnectIn` ms. |

Authentication is **implicit** in the NaCl box: no separate signed
challenge. Read timeout 120 s; on timeout, drop and reconnect.

Cross-region peers (deferred): if a peer's `HomeDERP` differs from ours,
we'd need a second DERP connection to that region. v1 punts and assumes
all peers share our home, OR we open one DERP connection per distinct
peer-home seen in `MapResponse.Peers`. The latter is small extra code.

### WireGuard data plane (`wg-engine`)

Using BoringTun's `Tunn` directly (the `device` feature stays off).
Three indices required:

```rust
struct Engine {
    by_pubkey: RwLock<HashMap<PublicKey, Arc<Peer>>>,
    by_idx:    RwLock<HashMap<u32,         Arc<Peer>>>, // for inbound dispatch
    by_ip:     RwLock<AllowedIps<Arc<Peer>>>,           // for outbound routing
    next_idx:  AtomicU32,
}
struct Peer {
    tunn:           Mutex<Tunn>,                 // !Sync
    transport_addr: ArcSwap<TransportAddr>,      // current DERP region or UDP endpoint
    pubkey:         PublicKey,
    our_index:      u32,                         // matches what we passed to Tunn::new
    allowed_ips:    Vec<IpCidr>,
}
```

Inbound dispatch trick: bytes `4..8` of every WG datagram (msg types 2,
3, 4) are the **receiver index = the index *we* assigned**. O(1) lookup
in `by_idx`. Type 1 (handshake init) is rare and small enough to broadcast
across all `Tunn`s — Tailscale's control plane gives us peer pubkeys
ahead of time, so we pre-create one `Tunn` per known peer.

Hot loop in `wg_engine` (sketch):

```rust
fn pump_one(engine: &Engine, net_rx: &Q, net_tx: &Q,
            tun_rx: &mut WgDevice, tun_tx: &mut WgDevice) {
    let mut buf = [0u8; 1500 + 32];

    while let Some((src_addr, datagram)) = net_rx.try_recv() {
        let peer = match engine.route_inbound(&datagram) { Some(p) => p, None => continue };
        let mut t = peer.tunn.lock();
        let mut res = t.decapsulate(src_addr, &datagram, &mut buf);
        loop {
            match res {
                TunnResult::Done => break,
                TunnResult::Err(_) => break,
                TunnResult::WriteToNetwork(pkt) => {
                    net_tx.send(*peer.transport_addr.load(), pkt.to_vec());
                    res = t.decapsulate(None, &[], &mut buf); // drain queued
                }
                TunnResult::WriteToTunnelV4(pkt, _src) => {
                    tun_rx.push_rx(pkt.to_vec()); break;
                }
                TunnResult::WriteToTunnelV6(_,_) => break,  // v1 ignores
            }
        }
    }

    while let Some(ip_pkt) = tun_tx.pop_tx() {
        let dst_ip = parse_ipv4_dst(&ip_pkt);
        let peer = match engine.peer_for_ip(dst_ip) { Some(p) => p, None => continue };
        let mut t = peer.tunn.lock();
        match t.encapsulate(&ip_pkt, &mut buf) {
            TunnResult::WriteToNetwork(pkt) => {
                net_tx.send(*peer.transport_addr.load(), pkt.to_vec());
            }
            TunnResult::Done | TunnResult::Err(_) => {}
            _ => unreachable!(),
        }
    }

    // 250 ms timer tick.
    for (_, peer) in engine.peers_iter() {
        let mut t = peer.tunn.lock();
        if let TunnResult::WriteToNetwork(pkt) = t.update_timers(&mut buf) {
            net_tx.send(*peer.transport_addr.load(), pkt.to_vec());
        }
    }
}
```

`Tunn::update_timers` cadence: 250 ms across all peers.

### Userspace netstack (`netstack`)

`WgDevice` is the bridge between the WG engine and smoltcp:

```rust
pub struct WgDevice {
    rx: Arc<Mutex<VecDeque<Vec<u8>>>>,   // pushed by wg_engine; drained by RxToken
    tx: Arc<Mutex<VecDeque<Vec<u8>>>>,   // pushed by TxToken; drained by wg_engine
    notify_tx: Notifier,                 // wakes wg_engine
    mtu: usize,                          // 1280 (WG path-MTU minus 32B overhead)
}

impl smoltcp::phy::Device for WgDevice { /* Medium::Ip */ }
```

`Medium::Ip` is critical — bare IPv4, no Ethernet header. Tokens own a
`Vec<u8>` to avoid holding the device mutex across `consume`.

In-tunnel `std::net`-shaped types (`netstack::tcp::TcpStream`,
`netstack::tcp::TcpListener`, `netstack::udp::UdpSocket`) wrap a
`SocketHandle` plus an `Arc<Stack>`. Operations: take `SocketSet` lock,
mutate the smoltcp socket, call `iface.poll`, park on per-handle Condvar
when blocking. `accept` allocates one TCP socket per concurrent
connection (smoltcp has no backlog — pre-allocate a pool).

Reference: `aramperes/onetun` is the closest existing implementation
(boringtun + smoltcp + tokio). Strip the tokio layer; the structure
ports cleanly. ~300 LOC for the netstack crate.

## Logging strategy

A single `vita-log` crate. One public `init(path: &str)` that:

1. Opens an append-only writer to `ux0:/data/tailscale-vita/log.txt`
   with daily-rotation behavior (truncate when > 10 MB).
2. Installs a `tracing_subscriber::Registry::default()` with two layers:
   - `fmt::Layer::new().with_writer(std::io::stdout)` — for development.
   - A custom `FileLayer` that formats into a `String` and pushes it to a
     `crossbeam-channel` consumed by a dedicated `log` thread.
3. The `log` thread is the **only** writer to `log.txt`. Flushes after
   every event so a crash shows up.
4. Installs the same panic hook from Phase 0's `logger.rs` so panics land
   in the file.
5. `tracing` levels controlled by `TS_VITA_LOG=trace,h2=warn,...` env-style
   filter, defaulting to `info`.

Span context to propagate: `peer_pubkey` (short hex), `derp_region`,
`map_session_seq`. Use `tracing::Span::current().record(...)` at the
right boundaries so every log line carries enough context to debug.

## Milestones

Each milestone has: **goal**, **success criterion** (concrete, checkable
on hardware), **estimated effort** (developer-days), and **what gets
logged**. Milestones are sequential except where noted.

### M1 — Workspace + logging foundation (1–2 days)

**Goal.** Stand up the Cargo workspace, the `vita-log` crate, and a
`tailscale-vita-demo` eboot that exercises logging end-to-end.

**Tasks.**
- Convert the existing per-spike `logger.rs` into a `vita-log` crate
  exposing `init()`, `log_line()`, panic hook installer.
- Wire `tracing_subscriber` with the file layer described above.
- Create the workspace; move `spikes/` references but don't rebuild
  them (they keep working as standalone crates).
- Demo eboot: `tracing::info_span!("startup")` + a few events, exit.

**Success.** `ux0:/data/tailscale-vita/log.txt` shows structured lines
with span context after running the demo eboot. Panic via
`panic!("test")` produces a `PANIC: test` line.

**Logged.** All later milestones use these spans: `startup`, `config`,
`runtime`. `vita-log::init` itself emits `INFO log initialized at <path>`.

### M2 — WireGuard handshake to a Linux peer (4–7 days)

**Goal.** Close the open Phase-0 question: prove BoringTun on Vita can
complete a real 4-message WireGuard handshake with a peer and exchange
encrypted data through the tunnel. **Direct UDP transport, no DERP, no
control plane.**

**Tasks.**
- Build `wg-engine` crate skeleton: `Engine`, `Peer`, the three indices,
  `route_inbound`, `peer_for_ip`, the pump loop.
- For M2, single-peer hardcoded: read peer pubkey + endpoint from
  `ux0:/data/tailscale-vita/wg.toml`.
- Stand up Linux peer with vanilla `wg-quick`, hard-coded keys.
- `net_rx` thread = `std::net::UdpSocket` directly with 50 ms read timeout. No DERP yet.
- Run `wg_engine` thread with 250 ms timer; `Tunn::encapsulate(&[], ...)`
  primes the handshake at startup per peer.
- **M2-only test harness** (`wg-engine/src/icmp.rs`, ~110 LOC): hand-craft
  IPv4+ICMP-echo packets, push into `tun_tx`, expect echo-reply on `tun_rx`.
  Validates that data actually flows through the tunnel — not just that
  handshake-init is generated. **Deleted in M3** when smoltcp owns the
  in-tunnel IP layer.
- Wrap every `Tunn::decapsulate`/`encapsulate` in `catch_unwind` so a
  panic on a malformed datagram becomes `wg.error{kind="panic"}` and a
  drop, not a process abort.

**Success.** Vita logs show `boringtun: handshake complete`,
`encapsulated: 84 B → 132 B`, `decapsulated: 132 B → 84 B`, and `ICMP echo
reply from <peer_ip>`. `wg show` on the Linux peer shows the Vita's
pubkey with non-zero `transfer:`.

**Logged.** `wg.handshake.complete{peer=...}`, `wg.tx{peer, len}`,
`wg.rx{peer, len}`, `wg.error{peer, kind}`.

### M3 — smoltcp wired in-tunnel; std::net-shaped API (5–7 days)

**Goal.** Apps inside the eboot can `dial`/`listen` against the Vita's
tunnel-side IP, just as they would with `std::net::TcpStream`.

**Tasks.**
- Build `netstack` crate with `WgDevice`, `Stack`, `TcpStream`,
  `TcpListener`, `UdpSocket`.
- Wire `wg_engine` ↔ `WgDevice` (the BoringTun→smoltcp queues described
  earlier).
- `app` thread runs the smoltcp poll loop with `iface.poll_delay()`
  -driven sleep + Condvar wakeup from `wg_engine`.
- Demo eboot: open a TCP connection from inside the tunnel to an HTTP
  server bound on the Linux peer's WG IP; read response.

**Success.** Vita's demo logs `HTTP 200 OK\r\n... <body>` from a
`netstack::tcp::TcpStream::connect`. Linux peer's HTTP server logs the
GET.

**Logged.** `netstack.tcp.connect{remote, handle}`,
`netstack.tcp.read{handle, n}`, `netstack.poll.delay{ms}`.

### M4 — Headscale `/key` (1–2 days)

**Goal.** Vita talks HTTP to a real Headscale instance and persists the
server's Noise pubkey.

**Tasks.**
- Bring up the staged docker-compose (add
  `HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH=/var/lib/headscale/mapdump` and
  `log.level: trace` for protocol debugging).
- `ts-control`: `fetch_server_key(server_url, capver) -> MachinePublic`.
  Use `ureq 3` with default rustls; for HTTP-only Headscale dev, also
  accept `http://`.
- Persist to `ux0:/data/tailscale-vita/server-key.bin`.

**Success.** Demo eboot prints + logs the 32-byte server pubkey.
`docker compose logs headscale` shows the GET hitting `KeyHandler`.

**Logged.** `control.key.fetched{server=..., key=mkey:...}`,
`control.key.changed{old=..., new=...}` (warning, fail-loud).

### M5 — Noise tunnel + minimal HTTP/2 client (7–10 days) ⚠️ HIGHEST RISK

**Goal.** Open a Noise IK tunnel to `/ts2021` and speak HTTP/2 inside it
well enough to issue one request and receive a response.

**Tasks.**
- `ts-control::noise`: drive `snow` for the Noise IK initiator, with the
  Tailscale-specific prologue and the X-Tailscale-Handshake encoding.
- TLS layer: blocking `rustls::ClientConnection` over `std::net::TcpStream`
  for the HTTPS path; for cleartext HTTP, just the TCP stream.
- HTTP/1.1 upgrade exchange (write request, parse `101` with `httparse`).
- After upgrade: wrap socket as a record framer (1B/2B-len/ChaCha20-Poly1305).
- HTTP/2 client choice (decide in M5a):
  - **Plan A:** drive the `h2` async crate from a tokio current-thread
    runtime *without* `enable_io()` (so no mio dependency). Our Noise
    record stream implements `tokio::io::AsyncRead + AsyncWrite` over a
    background thread that does blocking sync I/O on the actual socket.
    `block_on` from the `control` thread to issue requests.
  - **Plan B (fallback):** hand-roll a minimal HTTP/2 client (SETTINGS
    handshake, single-stream-per-connection, HEADERS+DATA, HPACK via the
    `hpack 0.3` crate). ~1500 LOC. No async.

**M5a (1–2 days, gating).** Spike both Plan A and Plan B. Decision criteria, in priority order:

1. Cross-compiles for `armv7-sony-vita-newlibeabihf` without patches.
2. Wall-clock latency from "M5 start" → first HTTP/2 response (< 5 s on localhost).
3. Code size (`.text` section).
4. Crate-author LOC in our repo (Plan A ≈ 700, Plan B ≈ 1500 — maintenance favors A).

Default decision: **Plan A primary, Plan B kept as feature-gated fallback** (`feature = "http2-handrolled"`). Outcome recorded in `crates/ts-control/M5a-DECISION.md`.

Tokio features locked at workspace level: `["rt", "macros", "sync", "time"]` only. **No `net`, no `io-util`, no `rt-multi-thread`** — would pull `mio` which is unavailable on Vita.

**Success.** Vita establishes a Noise tunnel to a Headscale instance,
issues a trivial `POST /machine/whoami` (501 Not Implemented response is
fine — we just need a successful HTTP/2 round-trip), and reads the
response headers + body.

**Logged.** `control.noise.handshake.complete{hash=<blake2s>}`,
`control.http2.settings{...}`, `control.http2.request{method, path}`,
`control.http2.response{status, len}`.

### M6 — `/machine/register` (2–3 days)

**Goal.** The Vita appears in `headscale nodes list`.

**Tasks.**
- `ts-control::register`: build the `RegisterRequest` JSON (with persistent
  `MachinePrivate` + `NodePrivate` + `DiscoPrivate` from `ux0:/data/...`).
- POST it through the M5 tunnel, parse `RegisterResponse`.
- Hard-fail on `AuthURL != ""` or `MachineAuthorized != true`.
- Auth-key field: try the input verbatim; do not strip `tskey-auth-`
  prefix (Tailscale prod expects it; Headscale 0.26 ignores it).

**Success.** `docker compose exec headscale headscale nodes list` shows
the Vita's hostname, NodeKey, and a `100.x.y.z` address.

**Logged.** `control.register.sent{node_key, hostname}`,
`control.register.ok{user_id, machine_authorized=true}`,
`control.register.fail{reason}`.

### M7 — `/machine/map` long-poll → BoringTun peer table (4–6 days)

**Goal.** Vita's local netmap matches the server's view of the tailnet,
and BoringTun has a `Tunn` per peer ready to handshake.

**Tasks.**
- `ts-control::map`: send `MapRequest{Stream:true}`, read 4-byte LE
  length-prefixed JSON frames in a loop.
- `flate2` to gunzip the HTTP/2 DATA stream.
- Parse `MapResponse`. Apply `Peers`, `PeersChanged`, `PeersRemoved`,
  `PeersChangedPatch` deltas to a local `NetMap` struct.
- For each peer: call `wg_engine.upsert_peer(pubkey, allowed_ips,
  derp_region)`. Engine creates a fresh `Tunn` if absent.
- Persist `last_seq`. On reconnect, send `MapSessionSeq = last_seq`.
- Watchdog: 2 min; exponential backoff 30 s cap.
- Keepalive frames: parsed and ignored.

**Success.** `mapdump/*.json` on the Headscale side shows the same node
list the Vita logs (compare via `jq` + a tiny diff). `wg_engine` shows
N `Tunn`s alive matching `headscale nodes list` count.

**Logged.** `control.map.frame{seq, type, len}`,
`control.map.netmap{node_count, derp_count}`,
`control.map.peer.upsert{pubkey, allowed_ips}`,
`control.map.keepalive`, `control.map.reconnect{reason, attempt}`.

### M8 — DERP transport (5–7 days)

**Goal.** WireGuard datagrams flow Vita ↔ peer over DERP. Replaces
M2's direct UDP transport.

**Pre-M8 spike (1 day).** `crypto_box 0.9` is RustCrypto's NaCl-box
(XSalsa20-Poly1305) wrapper — different cipher family from the
ChaCha20-Poly1305 we proved in Phase 0. Build a minimal `box-spike`
eboot importing `SalsaBox::new(...)` + `encrypt`/`decrypt` on hardcoded
vectors; verify cross-compile. **Fallback:** hand-rolled
`xsalsa20poly1305 0.10` + `salsa20 0.10`. Document outcome in
`PHASE-0-RESULTS.md`.

**Tasks.**
- `ts-derp::frame`: encoder/decoder for the 12 frame types listed above.
  **Cap allocation at `MAX_PACKET_SIZE` (64 KiB)** when reading length
  prefixes — a malformed `0x00FFFFFF` length must not OOM the Vita.
- `ts-derp::client`: TCP+TLS dial, HTTP/1.1 `Upgrade: DERP` exchange,
  `ServerKey` ↔ `ClientInfo` ↔ `ServerInfo` handshake.
- **One I/O thread per `DerpConn`**, *not* split read/write. rustls is
  single-threaded internally; the thread runs an explicit
  `crossbeam_channel::select_biased!{ pong | tx | tls_readable }` with
  100 ms recv_timeout + non-blocking TLS read poll. Pong always wins
  (servers tear down within ~10 s without it). Cap: 8 conns → 8 threads.
- Home-region selection: TCP-RTT probe at startup; revisit every 5 min.
- Bridge: `wg_engine::net_tx` packets get wrapped as `FrameSendPacket`
  to the right DERP. `FrameRecvPacket` payloads get fed to
  `wg_engine.handle_inbound(src_pubkey, wg_bytes)`.
- Per-region connection pool: open a second DERP connection if a peer's
  `HomeDERP` differs from ours (lazy + LRU eviction at cap).
- Handle `FramePing` → `FramePong`. Handle `FramePeerGone` →
  log + clear cached state.
- `FrameRestarting` → schedule reconnect after `ReconnectIn` ms.

**Success.** Linux peer (also a Tailscale node, via real Tailscale or
Headscale) successfully WG-handshakes the Vita and exchanges encrypted
ICMP. `wg_engine` logs `wg.handshake.complete` with the peer's pubkey,
**without** the M2 hardcoded UDP transport.

**Logged.** `derp.connect{region, host}`,
`derp.handshake.ok{server_key}`, `derp.tx{dst_pubkey, len}`,
`derp.rx{src_pubkey, len}`, `derp.ping`, `derp.pong`, `derp.reconnect`.

### M9 — End-to-end demo: ping the Vita over the tailnet (2–3 days)

**Goal.** From any other tailnet member, `ping 100.x.y.z` reaches the
Vita; `tailscale status` shows the Vita as `online`.

**Tasks.**
- Wire smoltcp's ICMP socket to respond to inbound pings. Bind
  `IcmpEndpoint::Ident(0)` and drive replies manually via `recv_slice`
  + `send_slice` from the `app` thread *after* `iface.poll`. smoltcp
  does **not** auto-reply — verify in code that `Ident(0)` matches all
  idents in smoltcp 0.12; **fallback path** if not: intercept echoes
  directly in `WgDevice::receive` and synthesize replies into `tx_q`
  (~50 LOC; bypasses smoltcp ICMP entirely).
- Add `OnlineState` lifecycle: `Online` after first MapResponse + first
  DERP `derp.rx`; `Degraded` after 60 s without either; `Offline` after
  5 consecutive control or DERP reconnects. Logged once per transition;
  10 min Offline → full diag dump at WARN.
- Tighten timeouts and reconnect logic across all crates.
- Document the on-Vita demo recipe (`docs/HARDWARE-DEMO.md`).

**Success.** `ping 100.x.y.z` from a peer Linux box shows replies under
500 ms (DERP-relayed; this is normal). `tailscale status` shows the Vita
in the peer list with its tailnet IP.

**Logged.** `netstack.icmp.echo{from, seq}`.

### M10 — Demo eboot + packaging polish (3–5 days)

**Goal.** A redistributable demo eboot that listens on the Vita's
tailnet IP and serves "hello from vita" — proof the Vita is reachable
**as** a tailnet node, not just **on** one.

**Tasks.**
- `tailscale-vita-demo`: HTTP listener via `netstack::tcp::TcpListener`
  bound on `:8080` of the tunnel-side IP, returning a static body.
- Config sample: `ux0:/data/tailscale-vita/config.toml` template,
  documented.
- Error messages: every fail path produces an actionable log line.
- Build pipeline doc: `cargo vita build vpk -- --release` from the
  workspace root.

**Success.** From any tailnet peer: `curl http://100.x.y.z:8080` returns
`hello from vita`.

**Logged.** `demo.listen{ip, port}`, `demo.accept{remote}`,
`demo.served{remote, status}`.

## Total estimated effort

Sum of midpoint estimates: **~36 working days = 7–10 calendar weeks**
solo, with M5 the dominant uncertainty (could blow the schedule by 1–2
weeks if Plan A and Plan B both stumble on Vita-specific tokio or HPACK
issues). The original RESEARCH.md's 8–11 week estimate stands; this
plan just shows where the time goes.

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| `h2` crate's tokio runtime can't run without `enable_io()` (Plan A of M5 fails) | **High** | Plan B: hand-roll minimal HTTP/2. Spike both in M5a. |
| `hpack 0.3` crate fails to cross-compile | Medium | It's pure Rust + no_std-with-alloc; very low risk. If it breaks, hand-roll the static-table-only path (no dynamic table). |
| `snow 0.10` pulls `getrandom 0.3`, conflicts with our 0.2.17 baseline | Medium | Force `getrandom = "0.2"` via patch; or use snow's `ring-resolver` feature. |
| `rustls 0.23` requires native cert store on some platforms | Low | We use `webpki-roots` (Mozilla CA bundle); zero platform deps. |
| Headscale's CapVer floor moves above 90 mid-development | Low | Pin Headscale to 0.26 in docker-compose. |
| Tailscale prod's `controlplane.tailscale.com` rejects our CapVer | Low | We support Headscale primary; prod is best-effort. |
| BoringTun `Tunn` panics on a malformed datagram | Medium | Wrap every `decapsulate` in `catch_unwind`. The panic hook captures it to `log.txt`. |
| smoltcp poll loop blocks on a Mutex held by `wg_engine` | Medium | Strict lock-ordering rule; `WgDevice` mutexes held only across single pop/push. |
| DERP connection drops mid-handshake | Low | Standard reconnect with backoff; BoringTun re-handshakes naturally. |
| Headscale ships a server-pushed `PingRequest`, we don't reply, server drops us | Low | Stub the response — issue HTTP GET to the URL, ignore body. ~10 LOC. |
| Vita Wi-Fi flakes; long-poll dies frequently | Medium | Watchdog + exponential backoff. Surface as `WARN` in logs after 3+ consecutive reconnects. |
| Disk fills with `log.txt` | Low | Daily rotate-on-size; keep last 3 files. |
| Persisted node key gets corrupted (Vita unsafe-shutdown) | Low | Atomic write via tmp+rename pattern. Crash recovery: regenerate keys + re-register. |
| `flate2` `rust_backend` can't decode Headscale's gzip | Low | It's the standard pure-Rust impl. If broken, swap to zstd by negotiating `Compress: "zstd"` (requires the `zstd` crate, which we'd need to verify cross-compiles). |
| `crypto_box 0.9` (XSalsa20-Poly1305) doesn't cross-compile for Vita | Medium | 1-day spike at head of M8. Fallback: hand-rolled `xsalsa20poly1305 0.10` + `salsa20 0.10`. |
| smoltcp 0.12 `IcmpEndpoint::Ident(0)` doesn't match all idents | Low | Verify in M9; if bind doesn't behave, intercept echoes directly in `WgDevice::receive` (~50 LOC). |
| `WgDevice::receive`/`transmit` deadlocks against `wg_engine` holding the same `Arc<Mutex<VecDeque>>` | Medium | **try_lock semantics** on all `WgDevice` queue access; on contention, return `None` (smoltcp polls again next tick). |
| Vita pthread default stack (64 KiB) too small for smoltcp poll + listener pool | Low | Spawn `app`/`wg_engine` and other working threads with 256 KiB stacks via `Builder::stack_size`. |
| Headscale 0.26 sends bare-hex auth keys; Tailscale prod sends `tskey-auth-...`; v1 supports both | Low | Pass user input verbatim; never strip prefix. Trim whitespace once at config-load only. |

## Open questions / decisions deferred

These do not block starting M1. Resolve as they come up.

1. **HTTP/2 client choice (M5a).** Spike `h2`-without-`enable_io()` and
   the hand-rolled minimal client; pick one. This is the single biggest
   technical decision in the whole plan.
2. **Persistent key encryption.** Should `MachinePrivate` and friends be
   encrypted at rest on `ux0:`? v1 says no (no key derived from user
   secret), but document the threat (anyone with FTP access reads them).
3. **DERP region selection.** TCP-RTT probe vs cached preferred region
   from MapResponse vs hard-coded. Decide in M8.
4. **Multi-DERP concurrency.** v1 opens one DERP connection per distinct
   peer-home-region encountered. Cap = 8? Cap = unlimited?
5. **In-tunnel TCP backlog.** smoltcp has no `accept` backlog — pre-allocate
   how many concurrent inbound TCP sockets? Plan: 4 for v1.
6. **Auth-key prefix-stripping.** Tailscale prod `tskey-auth-...` vs
   Headscale 0.26 bare hex vs Headscale 0.28+ `hskey-auth-...`. Plan:
   pass the user-provided string verbatim, don't parse.
7. **Hostinfo `OS` field.** Tailscale's enum is `linux|macos|windows|...`;
   no `vita` value. Send `"linux"` for v1; petition upstream later.
8. **MagicDNS resolver.** Implement a minimal DNS resolver bound to the
   tunnel-side IP that answers `*.<domain>` from `MapResponse.DNSConfig`?
   Or ignore (apps use IPs only)? v1 ignores.
9. **`PingRequest` handler.** Stub a no-op HTTP fetch in v1 (issue GET
   to the supplied URL). ~10 LOC.
10. **Subnet routes / exit nodes.** Skip v1; `MapResponse.Peers[].AllowedIPs`
    drives WG routing, but we don't *advertise* any.
11. **Headscale dev-image pinning.** Already pinned to 0.26 in
    `infra/headscale/docker-compose.yml`. Keep through M9.
12. **Demo app port.** TCP `:8080` on the tailnet IP. Bikeshed-able.

## Test strategy

Per-crate unit tests where practical (Vita target compiles tests too;
running them on hardware is awkward but doable with a thin "test
runner" eboot that walks a list of `#[test]` functions). Integration
tests run against a host-side build (the Cargo workspace also targets
the host triple) — same Rust source, different target.

Each milestone has a hardware-verification step. Use the
file-logger + FTP-pull pattern from PHASE-0-RESULTS.md for getting logs
back to the dev host.

A long-running integration test ("does the Vita stay online overnight?")
runs the demo eboot for 8+ hours and checks for unexpected reconnects in
`log.txt`. Defer to after M10.

## Research provenance

Every wire-format claim in §"Wire protocols summary" is grounded in
upstream source. Citation summary:

- **Tailscale TS2021:** `tailscale.com/control/controlbase/handshake.go`,
  `.../messages.go`; `.../controlhttp/{client.go, constants.go}`;
  `.../controlclient/direct.go`; `tailscale.com/tailcfg/tailcfg.go`;
  `.../types/key/{machine.go, node.go}`. Current `CurrentCapabilityVersion = 138`.
- **Headscale:** `juanfont/headscale@v0.26.0`, packages
  `hscontrol/{app.go, handlers.go, noise.go, auth.go, poll.go}` and
  `hscontrol/mapper/{mapper.go, builder.go}`,
  `hscontrol/capver/capver.go` (`MinSupportedCapabilityVersion = 88`),
  `hscontrol/db/preauth_keys.go` (bare-hex keys). HTTP/2-over-Noise
  confirmed in `noise.go`'s server bring-up.
- **DERP:** `tailscale.com/derp/derp.go` (`Magic = "DERP🔑"`,
  `ProtocolVersion = 2`, all `Frame*` constants, `FrameHeaderLen = 5`,
  `MaxPacketSize = 65536`); `derp/derp_client.go` (handshake,
  `recvTimeout(120s)`); `derp/derphttp/derphttp_client.go` (HTTP/1.1
  upgrade, `dialNodeTimeout = 1500ms`); `tailcfg/derpmap.go` (DERPMap
  JSON shape); `net/netcheck/netcheck.go` (home-region algorithm,
  hysteresis).
- **BoringTun + smoltcp:** `cloudflare/boringtun` `noise/mod.rs` (Tunn
  API); `device/mod.rs` (three-index pattern); `smoltcp-rs/smoltcp` `phy`
  module (`Device` trait, `Medium::Ip`); `aramperes/onetun` (closest
  prior-art reference).
- **Rust crates:** crates.io metadata + each crate's GitHub for
  cross-compile feasibility; verified against the Phase-0 baseline of
  what already cross-compiles for `armv7-sony-vita-newlibeabihf`.

## What this plan deliberately omits

- Direct UDP paths (NAT traversal, STUN, endpoint discovery,
  `magicsock`-shaped path probing). All deferred to a v2.
- IPv6. Vita's `SceNet` is IPv4-only; smoltcp `proto-ipv4` only.
- MagicDNS as a real resolver. v1 punts.
- Exit-node / subnet-router behavior.
- Interactive OAuth login. Auth-key only.
- A long-running `*KERNEL` plugin for system-wide capture. v2+.
- Always-on tunnel surviving game launches. The eboot dies with the host
  process; that's the v1 contract.
- Tailscale SSH, Funnel, Serve, Taildrop. None.
- Network-lock (TKA) signatures. `NLKey`/`NodeKeySignature` always empty.
