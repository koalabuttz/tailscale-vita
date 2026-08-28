#!/usr/bin/env python3
"""Generate a bgapp VPK's param.sfo (gdc launcher) + param2.sfo (gdd
service) as structural clones of BGFTP v3.24's released SFO pair.

Why cloning, not vita-mksfoex: from-scratch SFOs (M21 spike round 1)
registered fine in app.db but the bgapp spawn failed; cloning the exact
key set / fmt / dmax of a known-working package removes every structural
variable at once. Only identity values are swapped. The reference pair
lives in spikes/06-bgapp/reference/ (dumped from the installed BGFTP).

CONTENT_ID scheme (BGFTP-faithful): HB0000-<TITLE_ID>_00-<TAIL>, TAIL a
16-char suffix shared by both halves; the installer normalizes the gdd's
CONTENT_ID to the parent's at install time. INSTALL_DIR_ADDCONT/SAVEDATA
on the gdd point back at the gdc's TITLE_ID.
"""
import argparse
import struct
from pathlib import Path


def read_sfo(path):
    d = path.read_bytes()
    magic, _ver, kofs, dofs, n = struct.unpack("<IIIII", d[:20])
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


def content_id(title_id, tail):
    return f"HB0000-{title_id}_00-{tail}"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ref", required=True, type=Path,
                    help="dir holding bgftp_param.sfo + bgftp_param2.sfo")
    ap.add_argument("--out", required=True, type=Path,
                    help="dir to write param.sfo + param2.sfo into")
    ap.add_argument("--gdc-id", required=True, help="launcher TITLE_ID (9 chars)")
    ap.add_argument("--gdc-title", required=True)
    ap.add_argument("--gdd-id", required=True, help="service TITLE_ID (9 chars)")
    ap.add_argument("--gdd-title", required=True)
    ap.add_argument("--tail", required=True,
                    help="16-char CONTENT_ID suffix shared by both halves")
    ap.add_argument("--app-ver", default="01.00")
    args = ap.parse_args()

    assert len(args.gdc_id) == 9 and len(args.gdd_id) == 9, "TITLE_ID must be 9 chars"
    assert len(args.tail) == 16, "--tail must be exactly 16 chars"

    launcher = read_sfo(args.ref / "bgftp_param.sfo")
    set_str(launcher, "APP_VER", args.app_ver)
    set_str(launcher, "CONTENT_ID", content_id(args.gdc_id, args.tail))
    set_str(launcher, "STITLE", args.gdc_title)
    set_str(launcher, "TITLE", args.gdc_title)
    set_str(launcher, "TITLE_ID", args.gdc_id)
    write_sfo(launcher, args.out / "param.sfo")

    bgapp = read_sfo(args.ref / "bgftp_param2.sfo")
    set_str(bgapp, "APP_VER", args.app_ver)
    set_str(bgapp, "CONTENT_ID", content_id(args.gdd_id, args.tail))
    set_str(bgapp, "INSTALL_DIR_ADDCONT", args.gdc_id)
    set_str(bgapp, "INSTALL_DIR_SAVEDATA", args.gdc_id)
    set_str(bgapp, "STITLE", args.gdd_title)
    set_str(bgapp, "TITLE", args.gdd_title)
    set_str(bgapp, "TITLE_ID", args.gdd_id)
    write_sfo(bgapp, args.out / "param2.sfo")

    print(f"wrote {args.out}/param.sfo ({args.gdc_id} \"{args.gdc_title}\") + "
          f"param2.sfo ({args.gdd_id} \"{args.gdd_title}\")")


if __name__ == "__main__":
    main()
