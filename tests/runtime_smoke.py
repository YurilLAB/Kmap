#!/usr/bin/env python3
"""Bounded CLI smoke tests; every network endpoint is a local owned fixture.

Run from any directory: python3 tests/runtime_smoke.py ./kmap --artifacts DIR
The binary is executed as an unprivileged TCP client, with DNS disabled. No
raw sockets, public targets, NSE scripts, credential probes or net-scan mode.
The artifact directory must be new so separate runs cannot overwrite evidence.
"""

import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import traceback
import xml.etree.ElementTree as ET


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Runner:
    def __init__(self, artifacts):
        self.artifacts = artifacts.resolve()
        # Atomic creation rejects both prior runs and simultaneous writers.
        self.artifacts.mkdir(parents=True, exist_ok=False)
        self.results = []

    def run(self, name, command, timeout=45, expect_success=True, expected_returncodes=None):
        record = {"name": name, "command": list(map(str, command)), "timeout_seconds": timeout}
        self.results.append(record)
        start = time.monotonic()
        with (self.artifacts / (name + ".stdout.log")).open("wb") as stdout, \
                (self.artifacts / (name + ".stderr.log")).open("wb") as stderr:
            try:
                # subprocess.run kills and reaps the child on TimeoutExpired.
                completed = subprocess.run(command, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr,
                                           timeout=timeout, env={**os.environ, "LC_ALL": "C"})
                record["returncode"] = completed.returncode
                require(completed.returncode >= 0, name + " terminated by a signal")
                accepted_codes = expected_returncodes if expected_returncodes is not None else \
                    ((0,) if expect_success else (1, 2))
                require(completed.returncode in accepted_codes,
                        f"{name}: unexpected exit status {completed.returncode}")
                record["status"] = "passed"
            except Exception as error:
                record["status"] = "failed"
                record["error"] = str(error)
                raise
            finally:
                record["elapsed_seconds"] = round(time.monotonic() - start, 3)
                self.save()

    def save(self, **extra):
        (self.artifacts / "results.json").write_text(
            json.dumps({"commands": self.results, **extra}, indent=2) + "\n", encoding="utf-8")


class Handler(http.server.BaseHTTPRequestHandler):
    # Keep a familiar, deterministic HTTP banner for service detection.
    server_version = "SimpleHTTP/0.6"
    sys_version = "Python/3"

    def setup(self):
        super().setup()
        # The scanner's initial NULL probe waits for a server-first banner.
        # Closing sooner than its tcpwrapped threshold would misidentify this
        # HTTP fixture before it sends an HTTP request.
        self.connection.settimeout(10)

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            # A connect-scan closes its first connection without a request.
            pass

    def do_GET(self):
        body = b"<html><title>Kmap local test fixture</title></html>\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # Service detection can close once it has read the banner.
                pass

    do_HEAD = do_GET

    def log_message(self, format_string, *args):
        with self.server.log_lock:
            self.server.log_file.write((format_string % args) + "\n")
            self.server.log_file.flush()


@contextlib.contextmanager
def http_fixture(artifacts):
    class Server(http.server.ThreadingHTTPServer):
        # server_close joins these threads; each accepted socket has a timeout.
        daemon_threads = False

    with (artifacts / "http-server.log").open("w", encoding="utf-8") as log:
        with Server(("127.0.0.1", 0), Handler) as server:
            server.log_lock = threading.Lock()
            server.log_file = log
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
            thread.start()
            try:
                # A real HTTP exchange verifies readiness, not just a guessed delay.
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    response = b""
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    require(response.startswith(b"HTTP/1.0 200") and b"Kmap local test fixture" in response,
                            "HTTP fixture not ready")
                yield server.server_address[1]
            finally:
                server.shutdown()
                thread.join(timeout=5)
                require(not thread.is_alive(), "HTTP fixture did not stop")


def verify_scan(xml_path, json_path, open_port, closed_port):
    root = ET.parse(xml_path).getroot()
    require(root.find("runstats/finished").get("exit") == "success", "XML scan did not finish")
    hosts = root.findall("host")
    require(len(hosts) == 1, "expected exactly one XML host")
    require(hosts[0].find("address").get("addr") == "127.0.0.1", "unexpected XML target")
    ports = {int(p.get("portid")): p for p in hosts[0].findall("ports/port")}
    require(ports[open_port].find("state").get("state") == "open", "listener not reported open")
    require(ports[closed_port].find("state").get("state") == "closed", "unused port not reported closed")
    require(ports[open_port].find("service").get("name") == "http", "HTTP service not identified")
    require(ports[open_port].find("service").get("method") == "probed", "HTTP service was only guessed")
    document = json.loads(json_path.read_text(encoding="utf-8"))
    require(len(document["hosts"]) == 1, "expected exactly one JSON host")
    json_ports = {p["portid"]: p for p in document["hosts"][0]["ports"]}
    require(json_ports[open_port]["state"]["state"] == "open", "JSON listener state differs")
    require(json_ports[closed_port]["state"]["state"] == "closed", "JSON closed state differs")
    require(json_ports[open_port]["service"]["name"] == "http", "JSON HTTP service differs")


def check_cancellation(runner, binary, source):
    """Interrupt an executing scan only after its owned listener accepts it."""
    record = {"name": "cancellation"}
    runner.results.append(record)
    if os.name == "nt":
        # Console control delivery depends on the Windows terminal host. Do
        # not label TerminateProcess (forced kill) as graceful cancellation.
        record.update(status="skipped", reason="POSIX SIGINT test; Windows console cancellation not validated")
        return
    accepted = threading.Event()
    stop = threading.Event()

    class StallHandler(socketserver.BaseRequestHandler):
        def handle(self):
            accepted.set()
            stop.wait(15)

    class StallServer(socketserver.ThreadingTCPServer):
        daemon_threads = False

    process = None
    start = time.monotonic()
    try:
        with StallServer(("127.0.0.1", 0), StallHandler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
            thread.start()
            try:
                command = [binary, "--unprivileged", "--datadir", source, "-n", "-Pn", "-sT", "-sV",
                           "--max-retries", "0", "--host-timeout", "30s", "-p",
                           str(server.server_address[1]), "127.0.0.1"]
                record["command"] = command
                with (runner.artifacts / "cancellation.stdout.log").open("wb") as stdout, \
                        (runner.artifacts / "cancellation.stderr.log").open("wb") as stderr:
                    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                               env={**os.environ, "LC_ALL": "C"})
                    require(accepted.wait(10), "scan did not reach the local cancellation fixture")
                    require(process.poll() is None, "scan exited before cancellation could be tested")
                    process.send_signal(signal.SIGINT)
                    result = process.wait(timeout=5)
                    record["returncode"] = result
                    require(result in (-signal.SIGINT, 0, 1), f"abnormal cancellation exit: {result}")
                record["status"] = "passed"
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                stop.set()
                server.shutdown()
                thread.join(timeout=5)
                require(not thread.is_alive(), "cancellation fixture did not stop")
    except Exception as error:
        record.update(status="failed", error=str(error))
        raise
    finally:
        record["elapsed_seconds"] = round(time.monotonic() - start, 3)
        runner.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/runtime"))
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    binary = str(args.binary.resolve())
    source = str(Path(__file__).resolve().parent.parent)
    status = "failed"
    error = None
    try:
        runner.run("version", [binary, "--version"], timeout=10)
        # kmap.cc's getopt '?' branch deliberately calls exit(-1). The C
        # runtime exposes that as 255 on POSIX and 0xffffffff on Windows.
        # Allow that one documented code, not arbitrary Windows NTSTATUSes.
        runner.run("invalid-option", [binary, "--kmap-test-invalid-option"], timeout=10,
                   expect_success=False, expected_returncodes=(1, 2, 0xffffffff if os.name == "nt" else 255))
        diagnostic = (runner.artifacts / "invalid-option.stderr.log").read_text(encoding="utf-8", errors="replace")
        require("unrecognized option" in diagnostic and "--kmap-test-invalid-option" in diagnostic,
                "invalid option did not produce its expected diagnostic")
        runner.run("invalid-port", [binary, "--unprivileged", "-n", "-Pn", "-sT",
                                    "-p", "invalid-port", "127.0.0.1"], timeout=10, expect_success=False)
        # A --fast share implies --fast, so --efficient conflicts in either order.
        for index, flags in enumerate((["--efficient", "--fast-cpu-percent", "85"],
                                       ["--fast-mem-percent", "60", "--efficient"])):
            name = f"perf-conflict-{index}"
            runner.run(name, [binary, *flags, "--unprivileged", "-n", "-Pn", "-sT",
                              "-p", "1", "127.0.0.1"], timeout=10, expect_success=False)
            diagnostic = (runner.artifacts / (name + ".stderr.log")).read_text(
                encoding="utf-8", errors="replace")
            require("mutually exclusive" in diagnostic,
                    f"{' '.join(flags)} was not rejected as conflicting")
        with http_fixture(runner.artifacts) as open_port, socket.socket() as reserved:
            # Reserve a port WITHOUT listening, preventing another process from
            # claiming it while Kmap verifies connection-refused handling.
            reserved.bind(("127.0.0.1", 0))
            closed_port = reserved.getsockname()[1]
            for iteration in (1, 2):
                name = f"scan-{iteration}"
                xml_path = runner.artifacts / (name + ".xml")
                json_path = runner.artifacts / (name + ".json")
                runner.run(name, [binary, "--unprivileged", "--datadir", source,
                                  "-n", "-Pn", "-sT", "-sV", "--version-light",
                                  "--max-retries", "0", "--host-timeout", "30s",
                                  "-p", f"{open_port},{closed_port}", "-oX", str(xml_path),
                                  "-oJ", str(json_path), "127.0.0.1"])
                verify_scan(xml_path, json_path, open_port, closed_port)
        check_cancellation(runner, binary, source)
        status = "passed"
    except Exception:
        error = traceback.format_exc()
        print(error, file=sys.stderr)
    finally:
        runner.save(status=status, error=error)
    print(f"runtime smoke: {status}; artifacts: {runner.artifacts}")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
