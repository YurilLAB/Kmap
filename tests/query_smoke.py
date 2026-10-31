#!/usr/bin/env python3
"""Exercise the actual --net-query CLI against isolated, offline SQLite files.

No scan options or network targets are passed. The IPs below are inert fixture
values in documentation ranges. Fixtures and command logs are retained for
reproduction, including when a case fails.
"""

import argparse
from contextlib import closing
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback

from runtime_smoke import Runner, require


LEGACY_SCHEMA = """
CREATE TABLE hosts (
    ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT DEFAULT 'tcp',
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
    service TEXT, version TEXT, cves TEXT, web_title TEXT,
    web_server TEXT, web_headers TEXT, web_paths TEXT,
    enriched INTEGER DEFAULT 0, PRIMARY KEY(ip,port));
"""
TITLE = 'Café 東京 "quoted"\nsecond line'
CVES = [{"id": "CVE-2000-0001", "cvss": 7.5, "severity": "HIGH", "desc": "benign fixture"}]


def make_fixture(directory, rows):
    directory.mkdir(parents=True)
    shards = {}
    for ip, port, service, cves, title in rows:
        shard = int(ipaddress.IPv4Address(ip)) >> 27
        shards.setdefault(shard, []).append((ip, port, service, cves, title))
    for shard, values in shards.items():
        with closing(sqlite3.connect(directory / f"shard_{shard:03}.db")) as db:
            db.executescript(LEGACY_SCHEMA)
            db.executemany("INSERT INTO hosts(ip,port,service,cves,web_title,first_seen,last_seen,enriched) "
                           "VALUES(?,?,?,?,?,100,200,1)", values)
            db.commit()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/query"))
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    fixtures = Path(tempfile.mkdtemp(prefix="fixtures-", dir=runner.artifacts))
    cases = []
    binary = str(args.binary.resolve())
    normal = fixtures / "normal"
    malformed = fixtures / "malformed"
    bom = fixtures / "bom"
    corrupt = fixtures / "corrupt"
    make_fixture(normal, [
        ("192.0.2.10", 443, "https", "[]", "ten"),
        ("192.0.2.2", 80, "http", "[]", TITLE),
        ("192.0.2.2", 22, "ssh", json.dumps(CVES), ""),
        ("203.0.113.3", 443, "https", "[]", "other shard"),
    ])
    make_fixture(malformed, [("192.0.2.9", 80, "http", "[", "truncated CVE metadata")])
    make_fixture(bom, [("192.0.2.9", 80, "http", "\ufeff[]", "imported JSON with a BOM")])
    unicode_directory = fixtures / "caf\u00e9"
    shutil.copytree(normal, unicode_directory)
    corrupt.mkdir()
    (corrupt / "shard_024.db").write_bytes(b"This is not a SQLite database.\n")

    def query(name, directory=normal, options=(), expect_success=True, expected_returncodes=None):
        runner.run(name, [binary, "--net-query", "--data-dir", str(directory),
                          "--nq-format", "json", *options], timeout=15,
                   expect_success=expect_success, expected_returncodes=expected_returncodes)
        return (runner.artifacts / (name + ".stdout.log")).read_text(encoding="utf-8")

    def case(name, check):
        try:
            detail = check()
            cases.append({"name": name, "status": "passed", **({"detail": detail} if detail else {})})
        except Exception:
            error = traceback.format_exc()
            cases.append({"name": name, "status": "failed", "error": error})
            print(name + ": " + error, file=sys.stderr)

    expected_order = [("192.0.2.2", 22), ("192.0.2.2", 80),
                      ("192.0.2.10", 443), ("203.0.113.3", 443)]

    def check_rows():
        rows = json.loads(query("rows"))
        require([(r["ip"], r["port"]) for r in rows] == expected_order,
                "IP/port results are incomplete or not sorted numerically across shards")
        require(rows[1]["web_title"] == TITLE, "Unicode or escaped text changed in JSON output")
        require(rows[0]["cves"] == CVES, "valid structured CVEs changed in JSON output")

    case("numeric-order-unicode-json", check_rows)

    def check_unicode_directory():
        text = query("unicode-directory", directory=unicode_directory,
                     expected_returncodes=(0, 1) if os.name == "nt" else (0,))
        if runner.results[-1]["returncode"] == 0:
            rows = json.loads(text)
            require([(r["ip"], r["port"]) for r in rows] == expected_order,
                    "Unicode directory query lost rows")
            return {"outcome": "all fixture rows returned"}
        # Narrow Windows argv/file paths and SQLite UTF-8 paths are not yet
        # consistently converted. A diagnostic error is acceptable for that
        # existing limitation; an exception/crash or silent empty success is not.
        diagnostic = (runner.artifacts / "unicode-directory.stderr.log").read_text(
            encoding="utf-8", errors="replace")
        require(any(word in diagnostic.lower() for word in ("error", "cannot", "failed")),
                "unsupported Windows path lacks an error diagnostic")
        return {"outcome": "controlled error", "limitation": "Windows Unicode path unsupported"}

    case("unicode-directory-no-crash", check_unicode_directory)
    case("count", lambda: require(json.loads(query("count", options=["--nq-count"])) == {"count": 4},
                                  "count differs from fixture row count"))

    def check_port():
        rows = json.loads(query("port-filter", options=["--nq-port", "443"]))
        require([(r["ip"], r["port"]) for r in rows] == expected_order[2:], "port filter is wrong")

    case("port-filter", check_port)
    case("no-matches", lambda: require(json.loads(query("no-matches", options=["--nq-port", "65534"])) == [],
                                       "no-match query must be an empty JSON array"))

    def check_range():
        rows = json.loads(query("cidr-filter", options=["--nq-ip-range", "192.0.2.0/24"]))
        require([(r["ip"], r["port"]) for r in rows] == expected_order[:3], "CIDR filter is wrong")

    case("cidr-filter", check_range)

    def check_export():
        target = runner.artifacts / "export.json"
        query("file-export", options=["--nq-output", str(target)])
        require(json.loads(target.read_text(encoding="utf-8")) == json.loads(query("export-reference")),
                "file export differs from stdout JSON")

    case("file-export", check_export)

    def check_invalid_range():
        text = query("invalid-cidr", options=["--nq-ip-range", "192.0.2.1junk/24"], expect_success=False)
        text += (runner.artifacts / "invalid-cidr.stderr.log").read_text(encoding="utf-8")
        require("invalid" in text.lower() and "range" in text.lower(), "missing invalid-range diagnostic")

    case("invalid-cidr", check_invalid_range)

    def check_malformed():
        rows = json.loads(query("malformed-cves", directory=malformed))
        require(len(rows) == 1 and rows[0]["cves"] == "[",
                "malformed stored CVEs must survive as a quoted JSON string, not corrupt the document")

    case("malformed-cves", check_malformed)

    def check_bom():
        rows = json.loads(query("bom-cves", directory=bom))
        require(len(rows) == 1 and rows[0]["cves"] == [],
                "accepted array fragments must not embed a BOM inside the JSON document")

    case("bom-cves", check_bom)

    def check_closed_stdout():
        command = [binary, "--net-query", "--data-dir", str(normal), "--nq-format", "json"]
        record = {"name": "closed-stdout", "command": command, "timeout_seconds": 15,
                  "stdout": "pipe with no reader"}
        runner.results.append(record)
        start = time.monotonic()
        try:
            read_fd, write_fd = os.pipe()
            os.close(read_fd)  # Closed before starting the child: no timing race.
            with os.fdopen(write_fd, "wb", buffering=0) as sink, \
                    (runner.artifacts / "closed-stdout.stderr.log").open("wb") as diagnostic:
                completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=sink,
                                           stderr=diagnostic, timeout=15,
                                           env={**os.environ, "LC_ALL": "C"})
            record["returncode"] = completed.returncode
            expected = (1,) if os.name == "nt" else (1, -signal.SIGPIPE)
            require(completed.returncode in expected,
                    f"closed stdout was reported as success or crashed: {completed.returncode}")
            if completed.returncode == 1:
                diagnostic = (runner.artifacts / "closed-stdout.stderr.log").read_text(
                    encoding="utf-8", errors="replace")
                require(any(word in diagnostic.lower() for word in ("output", "stdout")) and
                        "error" in diagnostic.lower(),
                        "closed stdout lacks an output-error diagnostic")
            record["status"] = "passed"
        except Exception as error:
            record.update(status="failed", error=str(error))
            raise
        finally:
            record["elapsed_seconds"] = round(time.monotonic() - start, 3)
            runner.save()

    case("closed-stdout", check_closed_stdout)

    def check_store_error(name, directory):
        text = query(name, directory=directory, expect_success=False)
        text += (runner.artifacts / (name + ".stderr.log")).read_text(encoding="utf-8")
        require(any(word in text.lower() for word in ("error", "cannot", "failed")),
                "missing storage-error diagnostic")

    case("corrupt-shard", lambda: check_store_error("corrupt-shard", corrupt))
    case("missing-directory", lambda: check_store_error("missing-directory", fixtures / "missing"))
    # Individual absent shard files in the normal fixture are legitimate: the
    # database only creates shards containing observations. The cases above
    # must pass with 30 missing shards, while a bad data directory must fail.
    passed = all(c["status"] == "passed" for c in cases)
    runner.save(status="passed" if passed else "failed", cases=cases, fixtures=str(fixtures))
    print(f"query smoke: {sum(c['status'] == 'passed' for c in cases)}/{len(cases)} cases passed; "
          f"artifacts: {runner.artifacts}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
