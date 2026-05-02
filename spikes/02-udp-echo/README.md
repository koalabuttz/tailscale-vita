# Spike 2 — UDP echo from Rust

Verifies that `std::net::UdpSocket` works on Vita: bind, `send_to`,
`recv_from`, timeouts. This is the lowest-level network primitive
Tailscale-on-Vita will need (the WireGuard tunnel rides on a single host
UDP socket).

## Result: PASS (host build) / DEFERRED (on-device verification)

- **Compile + link:** PASS. `std::net::UdpSocket` compiles cleanly for
  `armv7-sony-vita-newlibeabihf`. Build artifact:
  `target/armv7-sony-vita-newlibeabihf/release/udp-echo-vita.vpk` (250 KB).
- **Runtime end-to-end:** Deferred until the user's Vita is available.
  Run-instructions below; results to be filled into `PHASE-0-RESULTS.md`.

## Build

```bash
export VITASDK=/home/user/vitasdk
export PATH=$VITASDK/bin:$PATH
ECHO_SERVER="<host-lan-ip>:9999" cargo vita build vpk -- --release
```

The server address is baked at build time via `env!("ECHO_SERVER")`.
Replace `<host-lan-ip>` with the LAN IP of the workstation running the
echo helper (e.g. `192.168.1.100:9999`). Vita3K's emulated network NATs
through the host, so the host's own LAN IP works.

## Run

1. **Start the host echo server** on the workstation:
   ```bash
   python3 host/echo.py 9999
   ```
   It prints every datagram it receives and echoes back `b"echo: " + data`.

2. **Install the VPK in Vita3K** (or sideload via VitaShell on a real
   Vita) and launch the `TVIT00002 Tailscale-Vita UDP Echo` bubble.

3. **Expected behaviour:** for `i` in 0..5, the Vita prints `sent N
   bytes: "ping i from vita"` and then `recv M bytes from <addr>:
   "echo: ping i from vita"`. Visible in PrincessLog or via the host's
   echo.py stdout.

## Decision gate

- All five round-trips succeed → spike passes; std-on-Vita network stack
  is usable; Phase 1+ can plan around `std::net`.
- Sends succeed but receives time out → likely a Vita3K NAT issue
  (emulator restricts inbound). Re-test on real hardware.
- Bind/send fails → `std::net` may be incompletely wired into the Vita
  newlib shims; fall back to `vitasdk-sys` `sceNet*` calls. The spike's
  source can be ported in ~50 lines of FFI.

## Notes

- `vita_make_fself_flags = []` is set in `Cargo.toml` to drop the default
  `-s` (safe mode) flag. Safe mode disables some networking permissions
  on a hacked Vita; we want full network access.
- The 250 KB binary size is from the std build — same baseline as Spike 1
  plus a ~16 KB delta for `std::net` and `UdpSocket`.
