#!/usr/bin/env python3
"""Option contracts for --net-scan and --watchlist on owned loopback fixtures.

Covers exclusion files that cannot be read, phase flags with --watchlist,
duplicate and excluded watchlist targets, watchlist --rate, enrichment when
stale eligible rows outnumber the live ones, and --fast/--efficient with an
explicit host-group size.

Run from any directory: python3 tests/net_option_contracts.py ./kmap --artifacts DIR
"""

import argparse
import contextlib
import http.server
import os
from pathlib import Path
import socket
import sqlite3
import sys
import threading
import time
import traceback

from runtime_smoke import Runner, require


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # Kmap's probes close with RST; that is not a fixture failure.


@contextlib.contextmanager
def http_server():
    server = Server(("127.0.0.1", 0), Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def closed_ports(count):
    """Loopback ports reserved without listening, so connects are refused."""
    sockets = []
    for _ in range(count):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        sockets.append(s)
    return sockets, [s.getsockname()[1] for s in sockets]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/net-options"))
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    root = runner.artifacts
    binary = str(args.binary.resolve())
    source = str(Path(__file__).resolve().parent.parent)
    os.environ.update({"KMAP_NO_ASN": "1", "KMAP_NO_DNS": "1", "KMAP_RAWSYN": "0",
                       "KMAP_ASYNC_ENRICH": "0", "KMAP_PROBE_TIMEOUT_MS": "200",
                       "KMAP_ENRICH_CONNECT_TIMEOUT_MS": "1000"})
    os.environ.pop("KMAP_ARGS", None)
    base = [binary, "--unprivileged", "-n", "--datadir", source]

    def text(name, stream="stdout"):
        return (root / f"{name}.{stream}.log").read_text(errors="replace")

    def store(name):
        (root / name).mkdir(exist_ok=True)
        return ["--data-dir", str(root / name / "data"), "--findings-dir", str(root / name / "f")]

    status = "failed"
    error = None
    try:
        (root / "excl.txt").write_text("127.0.0.1/32\n")
        with http_server() as port:
            port = str(port)
            # A mistyped exclusion file must stop the sweep, not void the list.
            runner.run("netscan-missing-exclude", base + [
                "--net-scan", "127.0.0.1/32", "--no-builtin-excludes", "--discover-only",
                "-p", port, "--exclude-file", str(root / "excl-typo.txt")] + store("ns1"),
                timeout=60, expect_success=False)
            require("cannot open exclude file" in text("netscan-missing-exclude", "stderr"),
                    "missing exclude file was not reported")
            require("Packets sent" not in text("netscan-missing-exclude"),
                    "net-scan probed with a missing exclude file")

            # Watchlist: overlapping lines are one target; excluded IPs are skipped.
            (root / "targets.txt").write_text("127.0.0.1\n127.0.0.1/32\n\t127.0.0.1\r\n127.0.0.2\n")
            (root / "excl2.txt").write_text("127.0.0.2/32\n")
            runner.run("watchlist-dedup", base + [
                "--net-scan", "--watchlist", str(root / "targets.txt"), "-p", port,
                "--exclude-file", str(root / "excl2.txt")] + store("wl1"), timeout=120)
            require("Watchlist mode -- 1 targets" in text("watchlist-dedup"),
                    "duplicate or excluded watchlist targets were probed")
            with contextlib.closing(sqlite3.connect(root / "wl1/data/watchlist.db")) as db:
                rows = db.execute("SELECT ip, scan_count FROM hosts").fetchall()
            require(rows == [("127.0.0.1", 1)], f"unexpected watchlist rows {rows}")

            runner.run("watchlist-missing-exclude", base + [
                "--net-scan", "--watchlist", str(root / "targets.txt"), "-p", port,
                "--exclude-file", str(root / "excl-typo.txt")] + store("wl2"),
                timeout=60, expect_success=False)
            require("Probing" not in text("watchlist-missing-exclude"),
                    "watchlist probed with a missing exclude file")

            runner.run("watchlist-report-only", base + [
                "--net-scan", "--watchlist", str(root / "targets.txt"), "--report-only",
                "-p", port] + store("wl3"), timeout=60, expect_success=False)
            require("Probing" not in text("watchlist-report-only"),
                    "--report-only with --watchlist touched the network")

            # Stale eligible rows must not crowd out this run's discovery.
            single = root / "single.txt"
            single.write_text("127.0.0.1\n")
            wl4 = base + ["--net-scan", "--watchlist", str(single), "-p", port] + store("wl4")
            runner.run("watchlist-seed", wl4, timeout=120)
            with contextlib.closing(sqlite3.connect(root / "wl4/data/watchlist.db")) as db:
                db.executemany("INSERT INTO hosts(ip, port, first_seen, last_seen) VALUES(?,?,?,?)",
                               [(f"10.0.{i >> 8}.{i & 255}", 80, 1, 1) for i in range(10001)])
                db.execute("UPDATE hosts SET service=NULL, version=NULL, enriched=0 "
                           "WHERE ip='127.0.0.1'")
                db.commit()
            time.sleep(1.1)
            runner.run("watchlist-stale-rows", wl4, timeout=180)
            with contextlib.closing(sqlite3.connect(root / "wl4/data/watchlist.db")) as db:
                row = db.execute("SELECT service, enriched FROM hosts WHERE ip='127.0.0.1'").fetchone()
            require(row is not None and row[1] == 1 and row[0],
                    f"live host not enriched behind stale rows: {row}")

            # Narrowing -p is not a closure: unprobed ports keep their baseline.
            with http_server() as second:
                scope = base + ["--net-scan", "--watchlist", str(single)] + store("wl6")
                diffs = root / "wl6" / "f" / "watchlist"

                def latest_diff():
                    return max(diffs.glob("diff_*.txt"), key=lambda p: p.stat().st_mtime).read_text()
                runner.run("scope-both", scope + ["-p", f"{port},{second}"], timeout=120)
                runner.run("scope-narrow", scope + ["-p", port], timeout=120)
                require("[CLOSED]" not in latest_diff(), "unprobed port reported closed")
                runner.run("scope-restored", scope + ["-p", f"{port},{second}"], timeout=120)
                require("[NEW PORT]" not in latest_diff(), "unprobed port re-reported as new")

            # --net-resume keeps the totals an earlier session recorded.
            resume = store("ns2")
            data = root / "ns2" / "data"
            data.mkdir()
            (data / ".net-scan-checkpoint").write_text("0\n500\n7\n123456789\n1700000000\n")
            runner.run("netscan-resume", base + [
                "--net-scan", "127.0.0.1/32", "--no-builtin-excludes", "--discover-only",
                "-p", port, "--net-resume"] + resume, timeout=60)
            sent, found = (data / ".net-scan-checkpoint").read_text().split()[1:3]
            require(int(sent) == 501 and int(found) == 8,
                    f"resumed totals {sent}/{found}, expected 501/8")

        # Watchlist --rate paces connection attempts like --net-scan.
        held, ports = closed_ports(20)
        try:
            start = time.monotonic()
            runner.run("watchlist-rate", base + [
                "--net-scan", "--watchlist", str(single), "--rate", "10",
                "-p", ",".join(map(str, ports))] + store("wl5"), timeout=120)
            elapsed = time.monotonic() - start
        finally:
            for s in held:
                s.close()
        require(elapsed >= 1.5, f"20 probes at --rate 10 took {elapsed:.2f}s")

        # An explicit host-group size wins over --fast/--efficient tuning.
        for name, flags in (("fast-max-hostgroup", ["--fast", "--max-hostgroup", "8"]),
                            ("efficient-min-hostgroup", ["--efficient", "--min-hostgroup", "32"])):
            runner.run(name, base + ["-sT", "-Pn", *flags, "-p", "1", "127.0.0.1"], timeout=60)
        status = "passed"
    except Exception:
        error = traceback.format_exc()
        print(error, file=sys.stderr)
    finally:
        runner.save(status=status, error=error)
    print(f"net option contracts: {status}; artifacts: {runner.artifacts}")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
