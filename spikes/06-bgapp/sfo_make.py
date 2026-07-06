#!/usr/bin/env python3
"""Generate the spike's param.sfo/param2.sfo as structural clones of
BGFTP v3.24's released SFO pair (reference/), swapping only the values
that identify the title. Round 1 used vita-mksfoex, which produced a
superset of keys with an EMPTY CONTENT_ID (and a forced ATTRIBUTE_MINOR
on the gdd sfo); the bgapp then failed to launch with "could not find
application" even though app.db registration was complete. Cloning the
exact key set / fmt / dmax of a known-working package removes every
structural variable at once.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent


def read_sfo(path):
    d = path.read_bytes()
    magic, ver, kofs, dofs, n = struct.unpack("<IIIII", d[:20])
    assert magic == 0x46535000, path
    entries = []
    for i in range(n):
        ko, fmt, dlen, dmax, do = struct.unpack("<HHIII", d[20 + i * 16 : 36 + i * 16])
        key = d[kofs + ko : d.index(b"\0", kofs + ko)].decode()
        entries.append({"key": key, "fmt": fmt, "dmax": dmax,
                        "data": d[dofs + do : dofs + do + dlen]})
    return entries


def write_sfo(entries, path):
    key_table = b""
    key_offsets = []
    for e in entries:
        key_offsets.append(len(key_table))
        key_table += e["key"].encode() + b"\0"
    while len(key_table) % 4:
        key_table += b"\0"

    data_table = b""
    index = b""
    for e, ko in zip(entries, key_offsets):
        do = len(data_table)
        data = e["data"]
        assert len(data) <= e["dmax"], f"{e['key']} exceeds dmax"
        index += struct.pack("<HHIII", ko, e["fmt"], len(data), e["dmax"], do)
        data_table += data + b"\0" * (e["dmax"] - len(data))

    kofs = 20 + len(index)
    dofs = kofs + len(key_table)
    hdr = struct.pack("<IIIII", 0x46535000, 0x101, kofs, dofs, len(entries))
    path.write_bytes(hdr + index + key_table + data_table)


def set_str(entries, key, value):
    for e in entries:
        if e["key"] == key:
            e["data"] = value.encode() + b"\0"
            return
    raise KeyError(key)


def main(build_dir):
    build = Path(build_dir)

    launcher = read_sfo(HERE / "reference" / "bgftp_param.sfo")
    set_str(launcher, "APP_VER", "01.00")
    set_str(launcher, "CONTENT_ID", "HB0000-TVBG00001_00-TSVITABGSPIKE000")
    set_str(launcher, "STITLE", "TS BGApp Spike")
    set_str(launcher, "TITLE", "TS BGApp Spike")
    set_str(launcher, "TITLE_ID", "TVBG00001")
    write_sfo(launcher, build / "param.sfo")

    bgapp = read_sfo(HERE / "reference" / "bgftp_param2.sfo")
    set_str(bgapp, "APP_VER", "01.00")
    set_str(bgapp, "CONTENT_ID", "HB0000-TVBG00002_00-TSVITABGSPIKE000")
    set_str(bgapp, "INSTALL_DIR_ADDCONT", "TVBG00001")
    set_str(bgapp, "INSTALL_DIR_SAVEDATA", "TVBG00001")
    set_str(bgapp, "STITLE", "TS BG Service")
    set_str(bgapp, "TITLE", "TS BG Service")
    set_str(bgapp, "TITLE_ID", "TVBG00002")
    write_sfo(bgapp, build / "param2.sfo")
    print(f"wrote {build}/param.sfo + param2.sfo (BGFTP-clone structure)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else HERE / "build")
