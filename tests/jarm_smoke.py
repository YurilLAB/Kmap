#!/usr/bin/env python3
"""Exercise the JARM driver against an owned loopback OpenSSL TLS listener."""

import argparse
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import traceback

from runtime_smoke import Runner, require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("driver", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/jarm"))
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    status = "failed"
    error = None
    try:
        with tempfile.TemporaryDirectory(prefix="kmap-jarm-") as temporary:
            key = str(Path(temporary) / "key.pem")
            cert = str(Path(temporary) / "cert.pem")
            runner.run("certificate", ["openssl", "req", "-x509", "-newkey", "rsa:2048",
                                       "-keyout", key, "-out", cert, "-days", "1", "-nodes",
                                       "-subj", "/CN=localhost"], timeout=30)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            with (runner.artifacts / "server.log").open("wb") as log:
                server = subprocess.Popen(["openssl", "s_server", "-accept", f"127.0.0.1:{port}",
                                           "-cert", cert, "-key", key, "-www", "-quiet"],
                                          stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        require(server.poll() is None, "OpenSSL server failed to start (see server.log)")
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                                break
                        except OSError:
                            require(time.monotonic() < deadline, "OpenSSL readiness timed out")
                            time.sleep(0.05)
                    fingerprints = []
                    for iteration in (1, 2):
                        runner.run(f"jarm-{iteration}", [str(args.driver.resolve()), "127.0.0.1", str(port)],
                                   timeout=45)
                        require(server.poll() is None, "OpenSSL server exited during fingerprinting")
                        fingerprint = (runner.artifacts / f"jarm-{iteration}.stdout.log").read_text().strip()
                        require(re.fullmatch(r"[0-9a-f]{62}", fingerprint) is not None,
                                "JARM must contain exactly 62 lowercase hex characters")
                        require(fingerprint != "0" * 62, "JARM returned the no-response sentinel")
                        fingerprints.append(fingerprint)
                    require(fingerprints[0] == fingerprints[1], "JARM changed between repeated runs")
                finally:
                    if server.poll() is None:
                        server.terminate()
                        try:
                            server.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            server.kill()
                            server.wait(timeout=3)
        status = "passed"
    except Exception:
        error = traceback.format_exc()
        print(error, file=sys.stderr)
    finally:
        runner.save(status=status, error=error)
    print(f"JARM smoke: {status}; artifacts: {runner.artifacts}")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
