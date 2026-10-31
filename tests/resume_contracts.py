#!/usr/bin/env python3
"""Production resume CLI contracts using owned loopback sockets only.

Tests parse immutability and forced-process interruption/recovery. No service
detection, NSE, raw scanning, external lookup, or power-loss claim is involved.
"""
import argparse
from collections import Counter
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import threading
import time
import traceback

HOSTS = ["127.0.0.%d" % index for index in range(1, 9)]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(path, ports):
    """Only complete grepable port records establish the recovery boundary."""
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines(keepends=True):
        if not line.endswith("\n"):
            continue
        match = re.match(r"Host: (127\.0\.0\.[1-8]) \([^)]*\)\tPorts: ([^\t\r\n]+)", line)
        if not match:
            continue
        values = []
        for item in match.group(2).split(", "):
            parts = item.split("/")
            if len(parts) >= 3 and parts[0].isdigit():
                values.append((int(parts[0]), parts[1]))
        if set(port for port, _ in values) == set(ports) and len(values) == len(ports):
            rows.append((match.group(1), tuple(sorted(values))))
    return rows


@contextlib.contextmanager
def fixture():
    sockets, selector, stop, errors = [], selectors.DefaultSelector(), threading.Event(), []
    thread = None
    info = {"accepted": 0, "socket_count": 0, "joined": False}
    def serve():
        try:
            while not stop.is_set():
                for key, _ in selector.select(.02):
                    client, _ = key.fileobj.accept()
                    client.close()
                    info["accepted"] += 1
                    require(info["accepted"] <= 200, "fixture connection budget exceeded")
        except BaseException:
            errors.append(traceback.format_exc())
    try:
        open_port = closed_port = 0
        for host in HOSTS:
            listener = socket.socket()
            sockets.append(listener)
            listener.bind((host, open_port))
            open_port = listener.getsockname()[1]
            listener.listen(8)
            listener.setblocking(False)
            selector.register(listener, selectors.EVENT_READ)
            closed = socket.socket()
            sockets.append(closed)
            closed.bind((host, closed_port))
            closed_port = closed.getsockname()[1]
        thread = threading.Thread(target=serve, name="resume-owned-listeners")
        thread.start()
        for host in HOSTS:
            with socket.create_connection((host, open_port), timeout=2):
                pass
        info.update({"open_port": open_port, "closed_port": closed_port, "hosts": HOSTS, "socket_count": len(sockets)})
        yield info
    finally:
        stop.set()
        if thread:
            thread.join(3)
            require(not thread.is_alive(), "owned listener thread did not join")
        selector.close()
        for sock in sockets:
            sock.close()
        info["joined"] = True
        info["closed_sockets"] = len(sockets)
        require(not errors, "fixture failed: " + str(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--offline-only", action="store_true", help="Parse tests only; no sockets or interruption test")
    args = parser.parse_args()
    binary, root, out = args.binary.resolve(), args.repo.resolve(), args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    start = time.monotonic()
    deadline = start + 70
    result = {"status": "running", "cases": [], "binary_sha256": digest(binary),
              "driver_sha256": digest(Path(__file__)), "scope": __doc__,
              "offline_only": args.offline_only, "budget_seconds": 70}
    env = {**os.environ, "LC_ALL": "C", "KMAP_NO_ASN": "1", "KMAP_NO_DNS": "1"}
    env.pop("KMAP_ARGS", None)
    def save():
        result["elapsed_seconds"] = round(time.monotonic() - start, 4)
        (out / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    def run(name, command):
        case = {"name": name, "command": list(map(str, command))}
        result["cases"].append(case)
        with (out / (name + ".stdout.log")).open("wb") as stdout, (out / (name + ".stderr.log")).open("wb") as stderr:
            completed = subprocess.run(command, cwd=out, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, timeout=min(15, max(.1, deadline-time.monotonic())))
        case["returncode"] = completed.returncode
        save()
        return case
    try:
        # --version prevents synthetic log tests from initiating a scan even
        # if the malformed-input oracle unexpectedly accepts an input.
        header = b"# Kmap test scan initiated as: kmap --version --unprivileged -n\n"
        ipv4 = b"Host: 127.0.0.1 ()\tPorts: 1/closed/tcp/////\n"
        xml_ipv4 = b'<address addr="127.0.0.1" addrtype="ipv4"/>\n'
        rejection_patterns = {
            # Empty mappings fail before the parser, with platform-specific
            # diagnostics. A crash or an unrelated exit 1 must never pass.
            "empty": r"Could not mmap\(\)|CreateFileMapping\(\)",
            "short": r"is too short -- no use resuming",
            "missing-header": r"Unable to parse supposed log file.*Are you sure",
            "unclosed-program-quote": r"unclosed quote",
            "truncated-header": r"ends with an incomplete line -- cannot safely resume",
            "truncated-record": r"ends with an incomplete line -- cannot safely resume",
            "invalid-address": r"Unable to parse ip \(not-an-ip\)",
            "missing-address-delimiter": r"Unable to parse supposed log file.*Sorry",
            "missing-address-parenthesis": r"missing address parenthesis",
            "embedded-nul": r"contains a NUL byte -- cannot safely resume",
        }
        cases = [
            ("empty", b"", False),
            ("short", b"bad\n", False),
            ("missing-header", b"x" * 40 + b"\n", False),
            ("unclosed-program-quote", b'# Kmap as: "kmap --version\n', False),
            ("truncated-header", header.rstrip(b"\n"), False),
            ("truncated-record", header + ipv4.rstrip(b"\n"), False),
            ("invalid-address", header + b"Host: not-an-ip ()\tPorts: 1/closed/tcp/////\n", False),
            ("missing-address-delimiter", header + b"Host: 127.0.0.1\n", False),
            ("missing-address-parenthesis", header + b"Kmap scan report for local (127.0.0.1\n", False),
            ("embedded-nul", header + ipv4 + b"\x00\n", False),
            ("zero-completed-hosts", header, True),
            ("valid-grepable", header + ipv4, True),
            ("valid-normal", header + b"Kmap scan report for 127.0.0.1\n", True),
            ("valid-normal-hostname", header + b"Kmap scan report for local (127.0.0.1)\n", True),
            ("valid-xml", header + xml_ipv4, True),
            ("valid-ipv6", header.replace(b" -n", b" -6 -n") + b"Host: ::1 ()\tPorts: 1/closed/tcp/////\n", True),
            ("valid-crlf-grepable", (header + ipv4).replace(b"\n", b"\r\n"), True),
            ("valid-crlf-normal", (header + b"Kmap scan report for 127.0.0.1\n").replace(b"\n", b"\r\n"), True),
            ("valid-crlf-normal-hostname", (header + b"Kmap scan report for local (127.0.0.1)\n").replace(b"\n", b"\r\n"), True),
            ("valid-quoted-program", header.replace(b" as: kmap ", b' as: "C:/Program Files/Kmap/kmap.exe" ') + ipv4, True),
            ("valid-xml-comment-header", b'<!-- Kmap test as: &quot;C:/Program Files/Kmap/kmap.exe&quot; --version --unprivileged -n -->\n' + xml_ipv4, True),
            ("valid-xml-trailing-mac", header + xml_ipv4 + b'<address addr="00:00:00:00:00:01" addrtype="mac"/>\n', True),
            ("valid-xml-trailing-other-family", header + xml_ipv4 + b'<address addr="::1" addrtype="ipv6"/>\n', True),
        ]
        for name, content, expected_success in cases:
            path = out / (name + ".log")
            path.write_bytes(content)
            (out / (name + ".original")).write_bytes(content)
            case = run(name, [str(binary), "--resume", str(path)])
            case.update({"expected_success": expected_success,
                         "input_unchanged": path.read_bytes() == content,
                         "input_sha256_before": hashlib.sha256(content).hexdigest(), "input_sha256_after": digest(path)})
            if expected_success:
                accepted = case["returncode"] == 0
            else:
                diagnostic = (out / (name + ".stderr.log")).read_text(encoding="utf-8", errors="replace")
                case["expected_diagnostic_pattern"] = rejection_patterns[name]
                case["expected_diagnostic_found"] = bool(re.search(rejection_patterns[name], diagnostic)) and str(path) in diagnostic
                case["ordinary_failure_exit"] = case["returncode"] == 1
                accepted = case["ordinary_failure_exit"] and case["expected_diagnostic_found"]
            case["status"] = "passed" if case["input_unchanged"] and accepted else "failed"
            save()
        require(all(case["status"] == "passed" for case in result["cases"]), "resume parser contract failed")
        if not args.offline_only:
            run_live(binary, root, out, result, env, deadline, run, save)
        result["status"] = "passed"
    except BaseException:
        result["status"] = "failed"
        result["error"] = traceback.format_exc()
    finally:
        result["binary_sha256_after"] = digest(binary)
        result["driver_sha256_after"] = digest(Path(__file__))
        if result["binary_sha256_after"] != result["binary_sha256"] or result["driver_sha256_after"] != result["driver_sha256"]:
            result["status"] = "failed"
            result["binding_error"] = "binary or test driver changed during execution"
        save()
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "results": str(out / "results.json")}))
    return 0 if result["status"] == "passed" else 1


def run_live(binary, root, out, result, env, deadline, run, save):
    with fixture() as info:
        result["fixture"] = info
        ports = (info["open_port"], info["closed_port"])
        expected = Counter((host, tuple(sorted(((ports[0], "open"), (ports[1], "closed"))))) for host in HOSTS)
        targets = out / "targets.txt"
        targets.write_text("\n".join(HOSTS) + "\n", encoding="ascii")
        targets_hash = digest(targets)
        path = out / "interrupted.gnmap"
        command = [str(binary), "--unprivileged", "--datadir", str(root), "-n", "-Pn", "-sT", "-r",
                   "--max-retries", "0", "--max-hostgroup", "1", "--max-parallelism", "1",
                   "--scan-delay", "80ms", "-p", ",".join(map(str, ports)), "-iL", str(targets), "-oG", str(path)]
        case = {"name": "forced-interruption", "command": command}
        result["cases"].append(case)
        child = None
        try:
            with (out / "interrupted.stdout.log").open("wb") as stdout, (out / "interrupted.stderr.log").open("wb") as stderr:
                child = subprocess.Popen(command, cwd=out, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
                interrupt_deadline = min(deadline, time.monotonic()+12)
                while child.poll() is None:
                    require(time.monotonic() < interrupt_deadline, "interruption boundary timed out")
                    if len(records(path, ports)) >= 2:
                        child.kill()
                        child.wait(timeout=3)
                        case["forced_process_crash"] = True
                        break
                    time.sleep(.01)
            require(case.get("forced_process_crash"), "scan exited before interruption")
        finally:
            if child and child.poll() is None:
                child.kill()
                child.wait(timeout=3)
        partial = records(path, ports)
        require(1 <= len(partial) < len(HOSTS), "invalid partial boundary")
        (out / "before-resume.gnmap").write_bytes(path.read_bytes())
        case.update({"status": "passed", "returncode": child.returncode, "complete_hosts": [row[0] for row in partial]})
        saved_header = path.read_text(encoding="utf-8").splitlines()[0]
        require(all(flag in saved_header for flag in ("--unprivileged", " -n ", " -sT ", " -Pn ")), "unsafe restored arguments")
        require(targets.read_text().splitlines() == HOSTS, "target list changed")
        for name in ("resume-interrupted", "resume-completed-again"):
            case = run(name, [str(binary), "--resume", str(path)])
            require(case["returncode"] == 0, name + " failed")
            require(Counter(records(path, ports)) == expected, "recovery omitted, duplicated or changed a host/port record")
            require(digest(targets) == targets_hash, "resume changed targets")
            case.update({"status": "passed", "verified_host_count": len(HOSTS), "verified_port_count": len(HOSTS)*2})
            save()
        # Retain the completed recovery before exercising a valid log with
        # only its original header. This must restart at the first target.
        (out / "complete-before-zero-host.gnmap").write_bytes(path.read_bytes())
        path.write_bytes((saved_header + "\n").encode("utf-8"))
        case = run("resume-zero-completed-hosts", [str(binary), "--resume", str(path)])
        require(case["returncode"] == 0, "zero-host restart failed")
        require(Counter(records(path, ports)) == expected, "zero-host restart omitted or duplicated records")
        require(digest(targets) == targets_hash, "zero-host restart changed targets")
        case.update({"status": "passed", "verified_host_count": len(HOSTS), "verified_port_count": len(HOSTS)*2})
        save()


if __name__ == "__main__":
    raise SystemExit(main())
