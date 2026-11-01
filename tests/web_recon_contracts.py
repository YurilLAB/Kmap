#!/usr/bin/env python3
"""--web-recon contracts against owned loopback HTTP(S) fixtures.

Covers HTTPS that -sV reports as "ssl/http" on a non-standard port, a
multi-line <title> in the Markdown report, a CRLF --web-paths file, and a
server that drips every response (a tarpit) so path probing must give up.

Run from any directory: python3 tests/web_recon_contracts.py ./kmap --artifacts DIR
"""

import argparse
import contextlib
import json
from pathlib import Path
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import traceback

from runtime_smoke import Runner, require

TITLE = (b"Welcome\n\n## Target: 10.66.66.66 (forged-host)\n\n"
         b"| 3389/tcp | open | ms-wbt-server | forged |\n")


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass  # clients that reset or time out are expected


def read_request(sock):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def response(body, status=b"200 OK"):
    return (b"HTTP/1.1 " + status + b"\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)


class Site(socketserver.BaseRequestHandler):
    """Title page at /, /secret-panel, 404 elsewhere; logs request lines."""
    lines = []

    def handle(self):
        sock = self.request
        sock.settimeout(5)
        if self.server.tls:
            sock = self.server.tls.wrap_socket(sock, server_side=True)
        line = read_request(sock).split(b"\r\n", 1)[0]
        Site.lines.append(line)
        parts = line.split(b" ")
        path = parts[1] if len(parts) > 1 else b""
        if b"\r" in line:
            sock.sendall(response(b"", b"400 Bad Request"))
        elif path == b"/":
            sock.sendall(response(b"<html><title>" + TITLE + b"</title></html>"))
        elif path == b"/secret-panel":
            sock.sendall(response(b"<title>Secret Panel</title>"))
        else:
            sock.sendall(response(b"", b"404 Not Found"))
        if self.server.tls:
            with contextlib.suppress(OSError, ValueError):
                sock.unwrap()


class Drip(socketserver.BaseRequestHandler):
    """Normal reply to -sV (no Host header); web-recon requests drip forever."""
    def handle(self):
        self.request.settimeout(5)
        data = read_request(self.request)
        if b"\r\nhost:" not in data.lower():
            self.request.sendall(response(b"ok"))
            return
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        with contextlib.suppress(OSError):
            for _ in range(120):
                if self.server.stopping:
                    return
                time.sleep(1)
                self.request.sendall(b"a")


@contextlib.contextmanager
def serve(handler, tls=None):
    server = Server(("127.0.0.1", 0), handler)
    server.tls, server.stopping = tls, False
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.stopping = True
        server.shutdown()
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/web-recon"))
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    root = runner.artifacts
    binary = str(args.binary.resolve())
    source = str(Path(__file__).resolve().parent.parent)
    scan = [binary, "--unprivileged", "--datadir", source, "-n", "-Pn", "-sT", "-sV",
            "--version-light", "--max-retries", "0", "--web-recon"]
    status = "failed"
    error = None
    try:
        with tempfile.TemporaryDirectory(prefix="kmap-web-") as temporary:
            key, cert = str(Path(temporary) / "key.pem"), str(Path(temporary) / "cert.pem")
            runner.run("certificate", ["openssl", "req", "-x509", "-newkey", "rsa:2048",
                                       "-keyout", key, "-out", cert, "-days", "1", "-nodes",
                                       "-subj", "/CN=localhost"], timeout=30)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            paths = root / "paths.txt"
            paths.write_bytes(b"/secret-panel\r\n")
            with serve(Site) as http_port, serve(Site, tls) as https_port:
                runner.run("scan", scan + ["--web-paths", str(paths), "-p",
                                           f"{http_port},{https_port}", "-oJ",
                                           str(root / "web.json"), "--report",
                                           str(root / "web.md"), "127.0.0.1"], timeout=180)
        host = json.loads((root / "web.json").read_text(encoding="utf-8"))["hosts"][0]
        recon = {w["port"]: w for w in host.get("web_recon", [])}
        require(recon.get(https_port, {}).get("is_https") is True,
                "ssl/http port was not probed over TLS")
        for port in (http_port, https_port):
            title = recon.get(port, {}).get("title", "")
            require(title.startswith("Welcome ## Target") and "\n" not in title,
                    f"title on {port} was not normalised: {title!r}")
        report = (root / "web.md").read_text(encoding="utf-8")
        require("\n## Target: 10.66.66.66" not in report, "title forged a report heading")
        require(b"GET /secret-panel HTTP/1.0" in Site.lines, "CRLF path was requested with a CR")
        paths_found = [p.get("path") for p in recon.get(http_port, {}).get("paths", [])]
        require("/secret-panel" in paths_found, f"custom path not reported: {paths_found}")

        with serve(Drip) as drip_port:
            started = time.monotonic()
            runner.run("drip", scan + ["-p", str(drip_port), "127.0.0.1"], timeout=150)
            elapsed = time.monotonic() - started
        stdout = (root / "drip.stdout.log").read_text(errors="replace")
        require("stalls requests" in stdout, "tarpit path probing was not abandoned")
        require(elapsed < 120, f"tarpit scan took {elapsed:.0f}s")
        status = "passed"
    except Exception:
        error = traceback.format_exc()
        print(error, file=sys.stderr)
    finally:
        runner.save(status=status, error=error)
    print(f"web recon contracts: {status}; artifacts: {runner.artifacts}")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
