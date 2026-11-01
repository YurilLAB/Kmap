#!/usr/bin/env python3
"""Actual-CLI regressions for SQLite path limits, using owned local fixtures.

Queries use inert SQLite values. Discovery/watchlist cases name only an owned
loopback listener and must reject storage paths before connecting or writing.
Long filesystem fixtures are POSIX-only; portable helper coverage is included
in net_db_regression_test.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import traceback

from query_smoke import LEGACY_SCHEMA
from runtime_smoke import Runner, require


def long_directory(base, length=600):
    path = base
    while len(str(path)) < length:
        remaining = length - len(str(path))
        path /= "x" * max(1, min(60, remaining - 1))
    path.mkdir(parents=True)
    return path


def snapshot(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob("*") if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    if os.name != "posix":
        runner.save(status="skipped", reason="POSIX long-filesystem-path fixture; portable helper unit covers the VFS")
        print("shard path CLI: skipped POSIX filesystem fixture")
        return 0
    binary = args.binary.resolve()
    source = Path(__file__).resolve().parents[1]
    original = runner.artifacts / "original.db"
    with closing(sqlite3.connect(original)) as db:
        db.executescript(LEGACY_SCHEMA)
        db.execute("INSERT INTO hosts(ip,port,service,cves,first_seen,last_seen,enriched) "
                   "VALUES('192.0.2.1',443,'https','[]',100,200,1)")
        db.commit()
    populated = long_directory(runner.artifacts / "populated")
    empty = long_directory(runner.artifacts / "empty")
    # The bundled Unix VFS has a 512-byte pathname limit. A 505-byte shard
    # filename fits its resolution buffer but leaves no room for -journal.
    journal_empty = long_directory(runner.artifacts / "journal-empty", 492)
    shutil.copyfile(original, populated / "shard_024.db")
    before = snapshot(populated)
    watchlist = runner.artifacts / "watchlist.txt"
    watchlist.write_text("127.0.0.1\n", encoding="ascii")
    cases = []
    deadline = time.monotonic() + 120
    environment = dict(os.environ, KMAP_NO_ASN="1", KMAP_NO_DNS="1", KMAP_RAWSYN="0", LC_ALL="C")

    def reject(name, options, directory=populated, relative=False):
        target = runner.artifacts / (name + ".json")
        sentinel = b"previous complete export\n"
        target.write_bytes(sentinel)
        if "--net-query" in options:
            options = [*options, "--nq-format", "json", "--nq-output", str(target)]
        elif "--search" in options:
            options = [*options, "--search-format", "json", "--search-output", str(target)]
        command = [str(binary), "--unprivileged", "-n", "--datadir", str(source),
                   "--data-dir", "." if relative else str(directory), *options]
        remaining = deadline - time.monotonic()
        require(remaining > 0, "120-second suite budget exhausted")
        with (runner.artifacts / (name + ".stdout.log")).open("wb") as stdout, \
                (runner.artifacts / (name + ".stderr.log")).open("wb") as stderr:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    cwd=directory if relative else runner.artifacts, env=environment,
                                    timeout=min(15, remaining))
        runner.results.append(dict(name=name, command=command, returncode=result.returncode))
        require(result.returncode == 1, f"{name}: unsupported path returned {result.returncode}")
        diagnostic = (runner.artifacts / (name + ".stderr.log")).read_text(encoding="utf-8", errors="replace")
        require("error" in diagnostic.lower() and "sqlite" in diagnostic.lower(),
                name + ": expected an explicit SQLite path error")
        require(target.read_bytes() == sentinel, name + ": failed operation replaced an export")
        require(snapshot(populated) == before, name + ": invalid storage path caused writes")
        require(not list(empty.iterdir()), name + ": invalid empty storage path caused writes")
        require(not list(journal_empty.iterdir()), name + ": invalid journal path caused writes")

    def case(name, check):
        try:
            check()
            cases.append(dict(name=name, status="passed"))
        except Exception:
            cases.append(dict(name=name, status="failed", error=traceback.format_exc()))
        runner.save(cases=cases)

    # A valid short-path control proves the copied fixture contains one row.
    short = runner.artifacts / "short"
    short.mkdir()
    shutil.copyfile(original, short / "shard_024.db")
    runner.run("short-control", [str(binary), "--net-query", "--data-dir", str(short),
                                 "--nq-format", "json"], timeout=15)
    control = json.loads((runner.artifacts / "short-control.stdout.log").read_text(encoding="utf-8"))
    require(len(control) == 1 and control[0]["ip"] == "192.0.2.1", "invalid short-path control")
    for name, options, directory, relative in [
        ("query-populated", ["--net-query"], populated, False),
        ("search-populated", ["--search", "https"], populated, False),
        ("query-empty", ["--net-query"], empty, False),
        ("search-empty", ["--search", "https"], empty, False),
        ("query-journal", ["--net-query"], journal_empty, False),
        ("search-journal", ["--search", "https"], journal_empty, False),
        ("query-relative", ["--net-query"], empty, True),
        ("search-relative", ["--search", "https"], empty, True),
        ("report-only", ["--net-scan", "--report-only"], populated, False),
        ("enrich-only", ["--net-scan", "--enrich-only"], populated, False),
    ]:
        case(name, lambda n=name, o=options, d=directory, r=relative: reject(n, o, d, r))

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.05)
        port = str(listener.getsockname()[1])

        def collection(name, options):
            reject(name, ["--net-scan", "--no-builtin-excludes", "-p", port, *options])
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                return
            connection.close()
            raise RuntimeError(name + ": network collection began before path validation")

        case("discover-preflight", lambda: collection("discover-preflight", ["--discover-only", "127.0.0.1"]))
        case("watchlist-preflight", lambda: collection("watchlist-preflight", ["--watchlist", str(watchlist)]))

    passed = all(c["status"] == "passed" for c in cases)
    runner.save(status="passed" if passed else "failed", cases=cases,
                scope="Owned filesystem and loopback only; no collection should start",
                directory_length=len(str(populated)), fixture_before=before, fixture_after=snapshot(populated))
    print(f"shard path CLI: {sum(c['status'] == 'passed' for c in cases)}/{len(cases)} passed; {runner.artifacts}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
