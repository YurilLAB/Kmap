#!/usr/bin/env python3
"""Resume complete host records across deterministic cuts of real local logs.

TCP checks use only owned loopback listeners. List and -Pn ping modes are
network-free. Cuts simulate saved-record boundaries, not a power-loss test.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
import traceback


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def status_records(path):
    return Counter(re.findall(r"^Host: (127\.0\.0\.[1-8]) \([^\r\n]*\)\tStatus: (Up|Unknown)\r?$",
                              path.read_text(encoding="utf-8"), re.MULTILINE))


def port_records(path, ports):
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"Host: (127\.0\.0\.[1-8]) \([^)]*\)\tPorts: (.*)", line)
        if not match:
            continue
        fields = match.group(2).split("\t")
        values = []
        for item in fields[0].split(", "):
            pieces = item.split("/")
            if len(pieces) >= 3 and pieces[0].isdigit():
                values.append((int(pieces[0]), pieces[1]))
        if not values and len(ports) == 1 and fields[1:] == ["Ignored State: closed (1)"]:
            values = [(ports[0], "closed")]
        if set(p for p, _ in values) == set(ports) and len(values) == len(ports):
            rows.append((match.group(1), tuple(sorted(values))))
    return Counter(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--offline-only", action="store_true")
    args = parser.parse_args()
    binary, repo, out = args.binary.resolve(), args.repo.resolve(), args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    helper_path = repo / "tests/resume_contracts.py"
    spec = importlib.util.spec_from_file_location("resume_contract_helpers", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    inputs = [Path(__file__).resolve(), helper_path, repo / "kmap.cc"]
    source_before = {str(p): digest(p) for p in inputs}
    start = time.monotonic()
    deadline = start + 120
    result = {"status": "running", "scope": __doc__, "budget_seconds": 120,
              "binary_sha256": digest(binary), "source_inputs": source_before,
              "offline_only": args.offline_only, "cases": []}
    env = {**os.environ, "LC_ALL": "C", "KMAP_NO_ASN": "1", "KMAP_NO_DNS": "1"}
    env.pop("KMAP_ARGS", None)
    # Exercise the same GNU-style ordering on machines with a different shell
    # environment; POSIXLY_CORRECT is not part of the saved command contract.
    env.pop("POSIXLY_CORRECT", None)
    targets = out / "targets.txt"
    targets.write_text("\n".join(helper.HOSTS) + "\n", encoding="ascii")
    targets_hash = digest(targets)

    def save():
        result["elapsed_seconds"] = round(time.monotonic() - start, 4)
        (out / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    def run(name, command, limit=15):
        case = {"name": name, "command": list(map(str, command)), "status": "failed"}
        result["cases"].append(case)
        remaining = deadline - time.monotonic()
        require(remaining > 0, "total runtime budget exhausted")
        with (out / (name + ".stdout.log")).open("wb") as stdout, (out / (name + ".stderr.log")).open("wb") as stderr:
            try:
                child = subprocess.run(command, cwd=out, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, timeout=min(limit, remaining))
                case["returncode"] = child.returncode
            except subprocess.TimeoutExpired:
                case.update(returncode=124, timed_out=True)
        save()
        return case

    def capture(name, log, mode, ports=None):
        command = [str(binary), "--unprivileged", "--datadir", str(repo), "-n", *mode,
                   "--max-hostgroup", "1", "-iL", str(targets), "-oG", str(log)]
        if ports:
            command += ["-r", "--max-retries", "0", "--max-parallelism", "1",
                        "-p", ",".join(map(str, ports))]
        case = run(name, command)
        require(case["returncode"] == 0, name + " collection failed")
        case["status"] = "passed"
        captured = log.read_bytes()
        (out / (name + ".captured.gnmap")).write_bytes(captured)
        return captured

    def cut_after(content, address, field):
        lines = content.splitlines(keepends=True)
        for index, line in enumerate(lines):
            if line.startswith(("Host: " + address + " ").encode()) and field in line:
                return b"".join(lines[:index+1])
        raise RuntimeError("capture missing requested boundary " + address + repr(field))

    def recovery(name, log, content, oracle, expected):
        log.write_bytes(content)
        (out / (name + ".before.gnmap")).write_bytes(content)
        for suffix in ("", "-again"):
            case = run(name + suffix, [str(binary), "--resume", str(log)])
            actual = oracle(log)
            case.update(expected_count=sum(expected.values()), actual_count=sum(actual.values()),
                        missing=[repr(row) for row in (expected-actual).elements()],
                        extra=[repr(row) for row in (actual-expected).elements()])
            case["status"] = "passed" if case["returncode"] == 0 and actual == expected else "failed"
            (out / (name + suffix + ".after.gnmap")).write_bytes(log.read_bytes())
            require(digest(targets) == targets_hash, "resume changed the target list")
            save()

    try:
        # Unknown/ambiguous long options can fail without advancing optind.
        # An invalid short cluster also leaves private parser state: it must
        # be rejected before an ordinary second parse can skip the bad byte.
        for name, option in (("unknown-option", "--not-a-kmap-option"),
                             ("ambiguous-option", "--nq-"),
                             ("invalid-short-cluster", "-zq")):
            log = out / (name + ".gnmap")
            content = ("# Kmap test as: kmap " + option + " --version --unprivileged -n\n"
                       "Host: 127.0.0.1 ()\tStatus: Up\n").encode()
            log.write_bytes(content)
            case = run(name, [str(binary), "--resume", str(log)], limit=3)
            diagnostic = (out / (name + ".stderr.log")).read_text(encoding="utf-8", errors="replace")
            case["input_unchanged"] = log.read_bytes() == content
            case["diagnostic_found"] = bool(re.search("unrecognized option|ambiguous|illegal option|invalid option", diagnostic, re.I))
            # parse_options deliberately exits -1 for invalid CLI options.
            expected_exit = 0xffffffff if os.name == "nt" else 255
            case["expected_returncode"] = expected_exit
            case["status"] = "passed" if case["returncode"] == expected_exit and case["diagnostic_found"] and case["input_unchanged"] else "failed"
            save()

        # An address-looking option value is data, not a family selector.
        # --version provides an offline oracle without scanning either address.
        for name, options, address in (
                ("ipv4-option-value-is-6", "--data-string -6", "127.0.0.1"),
                ("ipv6-option-value-is-4", "-6 --data-string -4", "::1")):
            log = out / (name + ".gnmap")
            content = ("# Kmap test as: kmap --version --unprivileged -n " + options +
                       "\nHost: " + address + " ()\tPorts: 1/closed/tcp/////\n").encode()
            log.write_bytes(content)
            case = run(name, [str(binary), "--resume", str(log)], limit=3)
            stdout = (out / (name + ".stdout.log")).read_text(encoding="utf-8", errors="replace")
            case["input_unchanged"] = log.read_bytes() == content
            case["version_found"] = "Kmap version" in stdout
            case["status"] = "passed" if case["returncode"] == 0 and case["version_found"] and case["input_unchanged"] else "failed"
            save()

        # Real no-port output must retain its status-only completion contract.
        # -Pn eliminates discovery traffic; -n eliminates reverse lookups.
        for name, mode, state in (("list", ["-sL"], "Unknown"),
                                  ("ping", ["-sn", "-Pn"], "Up"),
                                  ("legacy-ping", ["-sP", "-Pn"], "Up"),
                                  ("combined-list", ["-sLn", "-Pn"], "Unknown")):
            log = out / (name + ".gnmap")
            content = capture(name + "-capture", log, mode)
            expected = Counter((ip, state) for ip in helper.HOSTS)
            require(status_records(log) == expected, name + " capture oracle failed")
            partial = cut_after(content, "127.0.0.3", b"\tStatus:")
            recovery(name + "-partial", log, partial, status_records, expected)

        if not args.offline_only:
            with helper.fixture() as info:
                result["fixture"] = info
                ports = (info["open_port"], info["closed_port"])
                expected = Counter((ip, tuple(sorted(((ports[0], "open"), (ports[1], "closed"))))) for ip in helper.HOSTS)
                oracle = lambda p: port_records(p, ports)
                log = out / "ports.gnmap"
                captured = capture("ports-capture", log, ["-Pn", "-sT"], ports)
                require(oracle(log) == expected, "port capture oracle failed")
                first = cut_after(captured, "127.0.0.1", b"\tStatus: Up")
                third = cut_after(captured, "127.0.0.3", b"\tStatus: Up")
                cases = [
                    ("first-status", first), ("third-status", third),
                    ("complete-second", cut_after(captured, "127.0.0.2", b"\tPorts:")),
                    ("complete-log", captured),
                    ("crlf-status", third.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")),
                    ("option-value-is-sn", first.replace(b" -sT ", b" -sT --data-string -sn ", 1)),
                    ("single-dash-long", third.replace(b" -sT ", b" -sT -scan-delay 1ms ", 1)),
                ]
                for name, content in cases:
                    recovery(name, log, content, oracle, expected)
                # Terminal status records are synthetic boundary fixtures;
                # they do not claim an actual host timeout/down event.
                for state in ("Down", "Timeout"):
                    terminal = third.rsplit(b"\tStatus: Up", 1)
                    content = terminal[0] + ("\tStatus: " + state).encode() + terminal[1]
                    without_third = expected.copy()
                    del without_third[("127.0.0.3", tuple(sorted(((ports[0], "open"), (ports[1], "closed")))))]
                    recovery("terminal-" + state.lower(), log, content, oracle, without_third)
                log = out / "ignored.gnmap"
                closed_ports = (info["closed_port"],)
                captured = capture("ignored-capture", log, ["-Pn", "-sT"], closed_ports)
                expected_closed = Counter((ip, ((closed_ports[0], "closed"),)) for ip in helper.HOSTS)
                closed_oracle = lambda p: port_records(p, closed_ports)
                require(closed_oracle(log) == expected_closed, "ignored-state capture oracle failed")
                recovery("ignored-status", log, cut_after(captured, "127.0.0.3", b"\tStatus: Up"), closed_oracle, expected_closed)
        result["status"] = "passed" if all(case["status"] == "passed" for case in result["cases"]) else "failed"
    except BaseException:
        result.update(status="failed", error=traceback.format_exc())
    finally:
        result["binary_sha256_after"] = digest(binary)
        result["source_inputs_after"] = {str(p): digest(p) for p in inputs}
        if result["binary_sha256_after"] != result["binary_sha256"] or result["source_inputs_after"] != source_before:
            result.update(status="failed", binding_error="binary or source input changed during execution")
        save()
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "results": str(out / "results.json")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
