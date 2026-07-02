#!/usr/bin/env python3
"""UDP listener for the tailscale-vita egress-shape probe (Fork-B E2).

Pair of crates/tailscale-vita/src/egress_probe.rs — run this on each
probe target host, point the Vita's `[egress_probe] targets` at it, and
watch which shapes arrive. See docs/EGRESS-PROBE.md for the full runbook.

Every probe datagram carries a trailer tag in its last 4 bytes:
    [0xA5, shape_id | ctx<<4, round, 0x5A]
ctx 0 = Vita's production tx_queue drain path, ctx 1 = direct send
(the STUN context). Untagged datagrams are printed raw (they may be
real WG/Disco traffic if you pointed a live peer endpoint here).

Usage:
    python3 egress-probe-listener.py [--port 9999] [--rounds 5]

Ctrl-C prints the arrival matrix. With --rounds N the expected count
per (shape, ctx) cell is N; cells at 0/N are the dropped shapes.
"""

import argparse
import socket
import sys
import time
from collections import defaultdict

SHAPES = {
    1: "wg-data-96",
    2: "flip0-96",
    3: "ka-32",
    4: "zero-96",
    5: "wg-data-110",
    6: "disco-110",
}
CTX = {0: "queue", 1: "direct"}
TRAILER_A, TRAILER_Z = 0xA5, 0x5A


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--rounds", type=int, default=5,
                    help="expected rounds, for the matrix denominator")
    ap.add_argument("--summary-every", type=float, default=15.0,
                    help="seconds between periodic matrix prints (0 = off)")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    sock.settimeout(1.0)
    print(f"listening on {args.bind}:{args.port} — Ctrl-C for final matrix",
          flush=True)

    # (shape_id, ctx) -> set of rounds seen
    seen = defaultdict(set)
    untagged = 0
    last_summary = time.monotonic()

    def matrix() -> str:
        lines = ["", f"{'shape':<14}{'queue':>10}{'direct':>10}"]
        for sid, name in SHAPES.items():
            q = len(seen[(sid, 0)])
            d = len(seen[(sid, 1)])
            lines.append(f"{name:<14}{q:>7}/{args.rounds}{d:>7}/{args.rounds}")
        lines.append(f"untagged datagrams: {untagged}")
        lines.append("")
        return "\n".join(lines)

    try:
        while True:
            try:
                data, src = sock.recvfrom(65535)
            except socket.timeout:
                if args.summary_every and \
                        time.monotonic() - last_summary >= args.summary_every \
                        and any(seen.values()):
                    print(matrix(), flush=True)
                    last_summary = time.monotonic()
                continue
            ts = time.strftime("%H:%M:%S")
            tag = data[-4:] if len(data) >= 4 else b""
            if len(tag) == 4 and tag[0] == TRAILER_A and tag[3] == TRAILER_Z:
                sid = tag[1] & 0x0F
                ctx = (tag[1] >> 4) & 0x0F
                rnd = tag[2]
                name = SHAPES.get(sid, f"shape-{sid}?")
                seen[(sid, ctx)].add(rnd)
                print(f"{ts} {src[0]}:{src[1]} len={len(data)} "
                      f"b0={data[0]:02x} shape={name} ctx={CTX.get(ctx, ctx)} "
                      f"round={rnd}", flush=True)
            else:
                untagged += 1
                head = data[:16].hex()
                b0 = f"{data[0]:02x}" if data else "--"
                print(f"{ts} {src[0]}:{src[1]} len={len(data)} "
                      f"b0={b0} UNTAGGED head={head}", flush=True)
    except KeyboardInterrupt:
        print(matrix(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
