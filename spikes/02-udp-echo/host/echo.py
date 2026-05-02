#!/usr/bin/env python3
"""Tiny UDP echo server for the Vita UDP-echo spike.

Usage:
    python3 echo.py [port]   # default port 9999

Binds 0.0.0.0:<port>, prints every received datagram, and echoes it back
to the sender prefixed with "echo: ".
"""
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", port))
print(f"listening on udp/{port}")
while True:
    data, addr = s.recvfrom(2048)
    print(f"recv from {addr}: {data!r}")
    s.sendto(b"echo: " + data, addr)
