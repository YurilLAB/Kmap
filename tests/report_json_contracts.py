#!/usr/bin/env python3
"""Stored CVE/path JSON must agree between query, findings and patch status.

Runs report-only on inert documentation addresses; no probes or DNS lookups.
"""
import argparse
from contextlib import closing
import json
from pathlib import Path
import re
import sqlite3
import sys
import traceback

from query_performance import fixture
from runtime_smoke import Runner


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    entry = {"id": "CVE-2000-0001", "cvss": 9.1, "epss": 0.75,
             "severity": "CRITICAL", "kev": True, "remote": True, "desc": "Owned fixture"}
    compact = json.dumps([entry], separators=(",", ":"))
    variants = [compact, json.dumps([entry], indent=2), compact.replace("CVE-", "\\u0043VE-"),
                json.dumps([dict(details={"id": "CVE-2000-9999"}, **entry)], separators=(",", ":")),
                json.dumps([dict(entry, epss=5e-05, desc="a" * 66 + "é" + "z" * 10)]),
                '[{"id":"CVE-2000-0001"', '["{\\"id\\":\\"CVE-2000-9999\\"}"]']
    data = runner.artifacts / "data"
    rows = [dict(ip=f"192.0.2.{i}", port=80, service="http", raw_cves=raw,
                 web_title="Owned\n\n  TARGET: forged-host\r\n\x1b[31m title")
            for i, raw in enumerate(variants, 1)]
    fixture(data, rows)
    with closing(sqlite3.connect(data / "shard_024.db")) as db:
        db.executescript("ALTER TABLE hosts ADD COLUMN prev_cves TEXT;"
                         "ALTER TABLE hosts ADD COLUMN prev_enriched_at INTEGER;"
                         "ALTER TABLE hosts ADD COLUMN scan_count INTEGER;")
        db.execute("UPDATE hosts SET prev_cves=?,prev_enriched_at=100,scan_count=2,web_paths=?",
                   (compact, json.dumps([{"path": "/owned-path", "status": 200}], indent=2)))
        db.commit()
    assertions, error = [], None
    try:
        findings = runner.artifacts / "findings"
        runner.run("report", [str(args.binary.resolve()), "--net-scan", "--report-only",
                              "--data-dir", str(data), "--findings-dir", str(findings)])
        text = "\n".join(path.read_text(encoding="utf-8") for path in sorted(findings.glob("*.txt")))
        assertions.append({"check": "stored title cannot forge a target section",
                           "passed": "\n  TARGET: forged-host" not in text and "\x1b" not in text})
        sections = re.split(r"(?m)^  TARGET: ", text)[1:]
        for index, section in enumerate(sections, 1):
            checks = {"path rendered": "[200] /owned-path" in section,
                      "no nested/string CVE": "CVE-2000-9999" not in section}
            if index <= 5:
                checks.update({"CVE retained": "CVE-2000-0001" in section,
                               "persisting": bool(re.search(r"PERSISTING:\s+CVE-2000-0001", section)),
                               "not patched": not re.search(r"PATCHED:\s+CVE-2000-0001", section),
                               "KEV flag": "[KEV]" in section,
                               "remote flag": "[REMOTE]" in section})
                if index == 5:
                    checks["scientific EPSS"] = "EPSS:0.0%" in section
            else:
                checks["malformed is not patched"] = "fully patched since last scan" not in section
            for name, passed in checks.items():
                assertions.append({"row": index, "check": name, "passed": passed})
        assertions.append({"check": "all fixture hosts rendered", "passed": len(sections) == len(rows)})
        runner.run("search", [str(args.binary.resolve()), "--search", "http", "--search-format", "text",
                              "--data-dir", str(data)])
        search = (runner.artifacts / "search.stdout.log").read_text(encoding="utf-8")
        assertions.append({"check": "stored titles render on one search line",
            "passed": "Owned TARGET: forged-host [31m title" in search and "\x1b" not in search
                      and "\n  TARGET: forged-host" not in search})
    except Exception:
        error = traceback.format_exc()
    failed = [item for item in assertions if not item["passed"]]
    runner.save(status="failed" if failed or error else "passed", assertions=assertions, error=error)
    for item in failed:
        print("FAIL:", item, file=sys.stderr)
    if error:
        print(error, file=sys.stderr)
    print(f"report JSON: {len(assertions) - len(failed)} passed, {len(failed)} failed; {runner.artifacts}")
    return int(bool(failed or error))


if __name__ == "__main__":
    sys.exit(main())
