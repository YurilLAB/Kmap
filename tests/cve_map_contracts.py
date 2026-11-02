#!/usr/bin/env python3
"""Check --cve-map matches against the shipped kmap-cve.db for owned loopback
services: OpenSSH portable releases, non-OpenSSH SSH servers and Nmap's
"3.X - 4.X" unknown-version placeholder.

Run from any directory: python3 tests/cve_map_contracts.py ./kmap --artifacts DIR
"""

import argparse
import contextlib
import json
from pathlib import Path
import socket
import socketserver
import sys
import threading
import traceback

from runtime_smoke import Runner, require

SMB_NEGOTIATE_REPLY = (
    b"\0\0\0\x55" + b"\xffSMBr" + b"\0\0\0\0" + b"\x88" + b"\x01\x40" +
    b"\0" * 14 + b"@\x06" + b"\0\0" + b"\x01\0" + b"\x11" + b"\x06\0" +
    b"\x03\x32" + b"\0\x01\0" + b"\x04\x11" + b"\0\0" + b"\x01\x02\x03" +
    b"\0" + b"\x05\x06" + b"\0\0" + b"W\0O\0R\0K\0G\0R\0O\0U\0P\0\0\0")

# banner -> (CVEs that must match, CVEs that must not match); None = no CVEs.
SSH_CASES = {
    b"SSH-2.0-OpenSSH_9.7p1\r\n": ({"CVE-2024-6387"}, set()),
    b"SSH-2.0-OpenSSH_9.8p1\r\n": (set(), {"CVE-2024-6387"}),
    b"SSH-2.0-OpenSSH_9.3p1\r\n": ({"CVE-2023-38408"}, set()),
    b"SSH-2.0-OpenSSH_9.1p1\r\n": ({"CVE-2023-25136"}, set()),
    b"SSH-2.0-OpenSSH_7.4p1\r\n": (set(), {"CVE-2016-10009", "CVE-2016-10012",
                                         "CVE-2016-10708"}),
    b"SSH-2.0-Cisco-1.25\r\n": None,
    b"SSH-2.0-libssh_0.9.6\r\n": None,
}


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def banner_handler(banner):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            with contextlib.suppress(OSError):
                self.request.sendall(banner)
                self.request.recv(4096)
    return Handler


class SmbHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(6)
        with contextlib.suppress(OSError):
            if b"\xffSMBr" in self.request.recv(4096):
                self.request.sendall(SMB_NEGOTIATE_REPLY)
                self.request.recv(4096)


def smb_server():
    # The SMB negotiate probe is rare, so -sV --version-light sends it only to
    # ports listed for it in kmap-service-probes (27000-27010 among them).
    for port in range(27000, 27011):
        with contextlib.suppress(OSError):
            return Server(("127.0.0.1", port), SmbHandler)
    raise RuntimeError("no free loopback port in 27000-27010 for the SMB fixture")


@contextlib.contextmanager
def serve(handlers):
    servers = [Server(("127.0.0.1", 0), handler) for handler in handlers]
    servers.append(smb_server())
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads:
        thread.start()
    try:
        yield [s.server_address[1] for s in servers]
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/cve-map"))
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    binary = str(args.binary.resolve())
    source = str(Path(__file__).resolve().parent.parent)
    status = "failed"
    error = None
    try:
        banners = list(SSH_CASES)
        handlers = [banner_handler(b) for b in banners]
        with serve(handlers) as ports:
            out = runner.artifacts / "scan.json"
            runner.run("scan", [binary, "--unprivileged", "--datadir", source,
                                "-n", "-Pn", "-sT", "-sV", "--version-light",
                                "--max-retries", "0", "--host-timeout", "60s",
                                "--cve-map", "-p", ",".join(map(str, ports)),
                                "--color=always", "-oN", str(runner.artifacts / "scan.nmap"),
                                "-oJ", str(out), "127.0.0.1"], timeout=120)
        # Color is for the terminal only; the -oN log must stay plain text.
        require("\x1b[" in (runner.artifacts / "scan.stdout.log").read_text(errors="replace"),
                "--color=always did not color the terminal output")
        require("\x1b" not in (runner.artifacts / "scan.nmap").read_text(errors="replace"),
                "ANSI escapes were written to the -oN file")
        hosts = json.loads(out.read_text(encoding="utf-8"))["hosts"]
        require(len(hosts) == 1, "expected one scanned host")
        matched = {}
        for cve in hosts[0].get("cves", []):
            matched.setdefault(cve["port"], set()).add(cve["cve_id"])
        services = {p["portid"]: p.get("service", {}) for p in hosts[0]["ports"]}
        for port, banner in zip(ports, banners):
            label = banner.decode().strip()
            got = matched.get(port, set())
            expected = SSH_CASES[banner]
            if expected is None:
                require(not got, f"{label}: matched OpenSSH CVEs {sorted(got)}")
                continue
            required, forbidden = expected
            require(required <= got, f"{label}: missing {sorted(required - got)}")
            require(not (forbidden & got), f"{label}: matched fixed {sorted(forbidden & got)}")
        smb_port = ports[-1]
        require(services.get(smb_port, {}).get("version") == "3.X - 4.X",
                f"SMB fixture not fingerprinted as Samba 3.X - 4.X: {services.get(smb_port)}")
        require(not matched.get(smb_port), f"Samba 3.X - 4.X matched {sorted(matched.get(smb_port, []))}")
        status = "passed"
    except Exception:
        error = traceback.format_exc()
        print(error, file=sys.stderr)
    finally:
        runner.save(status=status, error=error)
    print(f"cve-map contracts: {status}; artifacts: {runner.artifacts}")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
