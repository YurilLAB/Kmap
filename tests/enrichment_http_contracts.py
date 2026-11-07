#!/usr/bin/env python3
"""Compare sync/async HTTP collection using owned, bounded loopback fixtures."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import socketserver
import sqlite3
import sys
import threading
import traceback

from runtime_smoke import Runner, require


@contextlib.contextmanager
def endpoint(response):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            with contextlib.suppress(OSError):
                self.request.sendall(response)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = False
        allow_reuse_address = True

    with Server(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02})
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(3)
            require(not thread.is_alive(), "HTTP fixture failed to stop")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    source = Path(__file__).resolve().parents[1]
    os.environ.update(KMAP_NO_ASN="1", KMAP_NO_DNS="1", KMAP_RAWSYN="0",
                      KMAP_WATCHLIST_CONCURRENCY="1", KMAP_WATCHLIST_ENRICH_CONCURRENCY="1",
                      KMAP_HOST_PORT_PARALLELISM="1", KMAP_PROBE_TIMEOUT_MS="200",
                      KMAP_ENRICH_CONNECT_TIMEOUT_MS="300", KMAP_HOST_ENRICH_BUDGET_MS="2000")
    body = (b"<title>Owned fixture</title>\nServer: forged-body-server\n"
            b"X-Powered-By: forged-body-runtime\nX-Generator: forged-body-generator\n"
            b"Location: https://forged.invalid/\nX-Frame-Options: forged-body-policy\n")
    cases = [
        ("body-headers", b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body,
         {"web_title": "Owned fixture", "web_server": "", "powered_by": "",
          "x_generator": "", "redirect_target": ""}, 200),
        ("lf-only", b"HTTP/1.1 200 OK\nServer:\tOwnedServer \t\nContent-Type: text/html\n\n"
         b"<title>LF fixture</title>",
         {"web_title": "LF fixture", "web_server": "OwnedServer"}, 200),
        ("informational", b"HTTP/1.1 103 Early Hints\r\nServer: interim-server\r\n\r\n"
         b"HTTP/1.1 200 OK\r\nServer: OwnedServer\r\nContent-Type: text/html\r\n\r\n"
         b"<title>Final response</title>",
         {"web_title": "Final response", "web_server": "OwnedServer"}, 200),
    ]
    assertions, errors = [], []
    targets = runner.artifacts / "targets.txt"
    targets.write_text("127.0.0.1\n", encoding="ascii")
    try:
        for label, response, expected, status in cases:
            for mode in ("0", "1"):
                name = label + ("-async" if mode == "1" else "-sync")
                os.environ["KMAP_ASYNC_ENRICH"] = mode
                data = runner.artifacts / name
                with endpoint(response) as port:
                    runner.run(name, [str(args.binary.resolve()), "--unprivileged", "-n",
                        "--datadir", str(source), "--net-scan", "--watchlist", str(targets),
                        "--data-dir", str(data), "--findings-dir", str(data / "findings"),
                        "-p", str(port), "--rate", "10"], timeout=20)
                with contextlib.closing(sqlite3.connect(data / "watchlist.db")) as db:
                    db.row_factory = sqlite3.Row
                    rows = db.execute("SELECT * FROM hosts WHERE ip='127.0.0.1' AND port=?", (port,)).fetchall()
                    require(len(rows) == 1, name + ": fixture row missing")
                    row = dict(rows[0])
                (runner.artifacts / (name + ".row.json")).write_text(json.dumps(row, indent=2), encoding="utf-8")
                for key, value in expected.items():
                    actual = row[key] or ""
                    assertions.append({"case": name, "field": key, "actual": actual,
                                       "expected": value, "passed": actual == value})
                headers = json.loads(row["web_headers"] or "{}")
                assertions.append({"case": name, "field": "headers exclude body values",
                    "passed": all("forged-body" not in str(value) for value in headers.values())})
                paths = json.loads(row["web_paths"] or "[]")
                assertions.append({"case": name, "field": "final status",
                    "actual": paths, "passed": len(paths) == 1 and paths[0].get("status") == status})
                log = (data / "kmap.log").read_text(encoding="utf-8", errors="replace")
                assertions.append({"case": name, "field": "scan completion logged",
                                   "passed": "scan complete" in log.lower()})
    except Exception:
        errors.append(traceback.format_exc())
    failed = [item for item in assertions if not item["passed"]]
    runner.save(status="failed" if failed or errors else "passed", assertions=assertions, errors=errors)
    for item in failed:
        print("FAIL:", item, file=sys.stderr)
    for error in errors:
        print(error, file=sys.stderr)
    print(f"enrichment HTTP: {len(assertions) - len(failed)} passed, {len(failed)} failed; {runner.artifacts}")
    return int(bool(failed or errors))


if __name__ == "__main__":
    sys.exit(main())
