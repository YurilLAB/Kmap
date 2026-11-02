#!/usr/bin/env python3
"""--topo-export failure contracts on offline topology fixtures.

A corrupt store, an unwritable output and a filter that matches nothing must
fail instead of reporting a (smaller or empty) graph as written; ASN filters
take the full unsigned 32-bit range.

Run from any directory: python3 tests/topo_export_contracts.py ./kmap --artifacts DIR
"""

import argparse
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

A, B, C = (int(ipaddress.IPv4Address(ip)) for ip in ("192.0.2.2", "192.0.2.3", "192.0.2.4"))


def export(binary, data, target, *flags):
    return subprocess.run([binary, "--data-dir", str(data), "--topo-export", str(target), *flags],
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/topo-export"))
    args = parser.parse_args()
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary = str(args.binary.resolve())

    # Let Kmap create the schema, then add a 3-node chain A -> B -> C.
    good = out / "good"
    good.mkdir()
    first = export(binary, good, out / "empty.json")
    assert first.returncode == 1 and "no nodes match" in first.stderr, first.stderr
    with contextlib.closing(sqlite3.connect(good / "topo.db")) as db:
        db.executemany("INSERT INTO topo_nodes(ip_u32, asn, role, path_count, last_seen) "
                       "VALUES(?,?,?,?,?)",
                       [(A, 64500, "hop", 1, 1), (B, 4200000000, "hub", 2, 1), (C, 64501, "target", 1, 1)])
        db.executemany("INSERT INTO topo_edges(from_u32, to_u32, path_count, last_seen) "
                       "VALUES(?,?,1,1)", [(A, B), (B, C)])
        db.commit()

    ok = export(binary, good, out / "around.json", "--topo-around", "192.0.2.3")
    assert ok.returncode == 0, ok.stderr
    nodes = {n["ip"] for n in json.loads((out / "around.json").read_text())["nodes"]}
    assert nodes == {"192.0.2.2", "192.0.2.3", "192.0.2.4"}, nodes

    asn = export(binary, good, out / "asn.json", "--topo-asn", "4200000000")
    assert asn.returncode == 0, asn.stderr
    assert [n["ip"] for n in json.loads((out / "asn.json").read_text())["nodes"]] == ["192.0.2.3"]

    missing = export(binary, good, out / "missing.json", "--topo-around", "198.51.100.9")
    assert missing.returncode == 1 and "no nodes match" in missing.stderr, missing.stderr

    if os.name == "posix" and Path("/dev/full").exists():
        full = export(binary, good, "/dev/full")
        assert full.returncode == 1 and "cannot write" in full.stderr, full.stderr

    # Overwrite the reverse-edge index page: in-neighbour reads now fail.
    corrupt = out / "corrupt"
    shutil.copytree(good, corrupt)
    with contextlib.closing(sqlite3.connect(corrupt / "topo.db")) as db:
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        root = db.execute("SELECT rootpage FROM sqlite_master WHERE name='idx_topo_edges_to'").fetchone()[0]
    with open(corrupt / "topo.db", "r+b") as f:
        f.seek((root - 1) * page_size)
        f.write(b"\xff" * page_size)
    bad = export(binary, corrupt, out / "corrupt.json", "--topo-around", "192.0.2.3")
    assert bad.returncode == 1 and "cannot read" in bad.stderr, (bad.returncode, bad.stderr)
    assert not (out / "corrupt.json").exists(), "a failed read left an export behind"
    print(f"topo export contracts: passed; artifacts: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
