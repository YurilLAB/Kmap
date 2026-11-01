#!/usr/bin/env python3
"""An upgraded service must lose the CVEs it no longer has.

Runs the --net-scan pipeline twice against an owned loopback SSH banner: first
an affected OpenSSH release, then one the shipped kmap-cve.db matches nothing
for. The stored list must be replaced by an empty one, so queries stop
reporting the host and the report marks the CVEs patched.

Run from any directory: python3 tests/cve_upgrade_contracts.py ./kmap --artifacts DIR
"""

import argparse
import contextlib
import os
from pathlib import Path
import socketserver
import sys
import threading
import time
import traceback

from runtime_smoke import Runner, require

BANNERS = [b"SSH-2.0-OpenSSH_7.4p1\r\n", b"SSH-2.0-OpenSSH_10.3p1\r\n"]
FIXED_CVE = "CVE-2023-38408"  # affects OpenSSH before 9.3p2


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    banner = BANNERS[0]


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        with contextlib.suppress(OSError):
            self.request.sendall(self.server.banner)
            self.request.recv(4096)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/cve-upgrade"))
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    binary = str(args.binary.resolve())
    source = str(Path(__file__).resolve().parent.parent)
    data = runner.artifacts / "data"
    findings = runner.artifacts / "findings"
    # Loopback only: no ASN/DNS lookups, connect-mode discovery.
    os.environ.update({"KMAP_NO_ASN": "1", "KMAP_NO_DNS": "1", "KMAP_RAWSYN": "0",
                       "KMAP_ASYNC_ENRICH": "0", "KMAP_PROBE_TIMEOUT_MS": "200"})
    os.environ.pop("KMAP_ARGS", None)
    status = "failed"
    error = None
    try:
        server = Server(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            port = str(server.server_address[1])
            scan = [binary, "--unprivileged", "-n", "--datadir", source, "--net-scan",
                    "127.0.0.1/32", "--no-builtin-excludes", "-p", port,
                    "--data-dir", str(data), "--findings-dir", str(findings)]
            query = [binary, "--net-query", "--data-dir", str(data), "--nq-cve", FIXED_CVE]
            runner.run("scan-affected", scan, timeout=120)
            runner.run("query-affected", query, timeout=30)
            text = (runner.artifacts / "query-affected.stdout.log").read_text(errors="replace")
            require(FIXED_CVE in text, f"{FIXED_CVE} not stored for the affected release")
            # Re-enrichment needs last_seen to pass the previous enriched_at.
            time.sleep(1.2)
            server.banner = BANNERS[1]
            runner.run("scan-upgraded", scan, timeout=120)
        finally:
            server.shutdown()
            server.server_close()
        runner.run("query-upgraded", query, timeout=30)
        text = (runner.artifacts / "query-upgraded.stdout.log").read_text(errors="replace")
        require("0 result(s)" in text, f"upgraded host still reported for {FIXED_CVE}")
        runner.run("report", [binary, "--report-only", "--data-dir", str(data),
                              "--findings-dir", str(findings)], timeout=60)
        reports = "".join(p.read_text(errors="replace") for p in findings.rglob("*") if p.is_file())
        require("fully patched since last scan" in reports, "report did not mark the host patched")
        status = "passed"
    except Exception:
        error = traceback.format_exc()
        print(error, file=sys.stderr)
    finally:
        runner.save(status=status, error=error)
    print(f"cve upgrade contracts: {status}; artifacts: {runner.artifacts}")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
