#!/usr/bin/env python3
"""Verify HTTP metadata against owned loopback responses with header-like bodies."""
import argparse
import contextlib
import http.server
import json
import socket
import sys
import threading
import traceback
from pathlib import Path

from runtime_smoke import Handler, Runner, require


class MetadataHandler(Handler):
    def do_GET(self):
        # The hostless Nmap identification probe gets the usual known fixture
        # banner. Recon requests include Host and exercise the response below.
        if not self.headers.get("Host"):
            return super().do_GET()
        body = (b"<html><title>Kmap local test fixture</title></html>\r\n"
                b"Server: body-only-server\r\n"
                b"X-Powered-By: body-only-runtime\r\n"
                b"X-Generator: body-only-generator\r\n"
                b"Strict-Transport-Security: max-age=123\r\n"
                b"Content-Security-Policy: default-src 'none'\r\n"
                b"X-Frame-Options: DENY\r\n"
                b"Location: https://body-only.invalid/\r\n"
                b"Set-Cookie: bodycookie=secret; Secure; HttpOnly; SameSite=Strict\r\n")
        code = 200 if self.path == "/" else 302 if self.path == "/admin" else 404
        # send_response_only deliberately omits the automatic Server header.
        self.send_response_only(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/":
            self.send_header("Set-Cookie", "sid=SameSite=Strict; Securely; HttpOnlySuffix")
            self.send_header("Set-Cookie", "actual=secret; Secure; HttpOnly; SameSite=Lax")
        self.end_headers()
        if self.command != "HEAD":
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

    do_HEAD = do_GET

    def do_OPTIONS(self):
        body = b"Allow: DELETE\r\n"
        self.send_response_only(200)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(body)


@contextlib.contextmanager
def fixture(artifacts):
    with (artifacts / "http-server.log").open("w", encoding="utf-8") as log:
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), MetadataHandler) as server:
            server.daemon_threads = False
            server.log_file, server.log_lock = log, threading.Lock()
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05})
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    response = b""
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    require(b"\r\n\r\n" in response and b"body-only-server" in response,
                            "metadata fixture did not serve injection response")
                yield server.server_address[1]
            finally:
                server.shutdown()
                thread.join(timeout=5)
                require(not thread.is_alive(), "metadata fixture did not stop")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/http-metadata"))
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    status, error = "failed", None
    try:
        source = Path(__file__).resolve().parents[1]
        output = runner.artifacts / "scan.json"
        with fixture(runner.artifacts) as port:
            runner.run("web-recon", [str(args.binary.resolve()), "--unprivileged", "--datadir", str(source),
                                    "-n", "-Pn", "-sT", "-sV", "--version-light", "--web-recon",
                                    "--max-retries", "0", "--host-timeout", "30s", "-p", str(port),
                                    "-oJ", str(output), "127.0.0.1"], timeout=90)
        document = json.loads(output.read_text(encoding="utf-8"))
        require(len(document["hosts"]) == 1, "expected one loopback host")
        recon = document["hosts"][0].get("web_recon", [])
        require(len(recon) == 1 and recon[0]["port"] == port, "HTTP recon did not run on the fixture")
        row = recon[0]
        require(row.get("title") == "Kmap local test fixture", "body title was not retained")
        for key in ("server", "powered_by", "generator", "security_headers"):
            require(key not in row, f"response body forged {key} metadata")
        require(row.get("cookie_flags") == ["sid", "actual (Secure, HttpOnly, SameSite=Lax)"],
                "cookie attributes were inferred from values, partial tokens or body lines")
        require(row.get("allowed_methods") == ["GET", "HEAD"], "OPTIONS header was not preserved")
        redirect = next((p for p in row.get("paths", []) if p["path"] == "/admin"), None)
        require(redirect is not None and redirect["status"] == 302, "redirect control path was not collected")
        require("redirect_to" not in redirect, "response body forged redirect location")
        status = "passed"
    except Exception:
        error = traceback.format_exc()
        print(error, file=sys.stderr)
    finally:
        runner.save(status=status, error=error)
    print(f"HTTP metadata smoke: {status}; artifacts: {runner.artifacts}")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
