#!/usr/bin/env python3
"""Offline CLI contracts for preserving output files on unsupported resume.

Uses only --unprivileged -n -sL with two numeric loopback addresses: no sockets,
service detection, NSE, enrichment, or external lookups. Existing live resume
contracts separately exercise collection and interruption recovery. This driver
checks fresh JSON/TXT/MD output, explicit append rejection, completed-log resume
rejection, and supported grepable-only append/resume behavior.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import traceback


HOSTS = ["127.0.0.1", "127.0.0.2"]
DIAGNOSTIC = "--append-output and --resume are not supported with -oJ or --report"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def file_state(paths):
    return {path.name: {"exists": path.exists(), "is_file": path.is_file(),
                        "sha256": digest(path) if path.is_file() else None,
                        "bytes": path.stat().st_size if path.is_file() else None}
            for path in paths}


def grepable_hosts(path):
    return re.findall(r"^Host: ([^ ]+) ", path.read_text(encoding="utf-8"), re.M)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    binary, repo, out = args.binary.resolve(), args.repo.resolve(), args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    started, budget = time.monotonic(), 45
    deadline = started + budget
    sources = [repo / name for name in ("kmap.cc", "main.cc", "output_json.cc", "KmapOps.cc")]
    result = {"status": "running", "scope": __doc__, "budget_seconds": budget,
              "binary_sha256_before": digest(binary), "driver_sha256_before": digest(Path(__file__)),
              "source_sha256_before": {str(path): digest(path) for path in sources}, "cases": []}
    env = {**os.environ, "LC_ALL": "C", "KMAP_NO_ASN": "1", "KMAP_NO_DNS": "1"}
    env.pop("KMAP_ARGS", None)
    base = [str(binary), "--unprivileged", "--datadir", str(repo), "-n", "-sL"]

    def save():
        result["elapsed_seconds"] = round(time.monotonic() - started, 4)
        (out / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    def run(name, directory, command, checks):
        case = {"name": name, "command": list(map(str, command))}
        result["cases"].append(case)
        try:
            require(time.monotonic() < deadline, "driver time budget exceeded")
            with (directory / (name + ".stdout.log")).open("wb") as stdout, (directory / (name + ".stderr.log")).open("wb") as stderr:
                proc = subprocess.run(command, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                                      stdout=stdout, stderr=stderr, timeout=min(10, deadline-time.monotonic()))
            case["returncode"] = proc.returncode
            checks(case, directory / (name + ".stderr.log"))
            case["status"] = "passed"
        except Exception:
            case.update(status="failed", error=traceback.format_exc())
        save()
        return case

    def expect_rejection(paths, before):
        def check(case, stderr):
            case["contract"] = "explicit unsupported JSON/report append/resume; no output mutation"
            case["files_before"] = before
            case["files_after"] = file_state(paths)
            case["files_unchanged"] = case["files_after"] == before
            case["diagnostic_found"] = DIAGNOSTIC in stderr.read_text(encoding="utf-8", errors="replace")
            require(case["returncode"] == 1, "unsupported output combination must exit 1, not succeed or crash")
            require(case["diagnostic_found"], "missing explicit unsupported-output diagnostic")
            require(case["files_unchanged"], "rejected request modified or created an output file")
        return check

    def expect_parse_rejection(paths, before, resume_path, diagnostic_pattern):
        def check(case, stderr):
            case["contract"] = "malformed resume input; input and all preexisting outputs preserved"
            case["files_before"] = before
            case["files_after"] = file_state(paths)
            case["files_unchanged"] = case["files_after"] == before
            diagnostic = stderr.read_text(encoding="utf-8", errors="replace")
            case["diagnostic_found"] = bool(re.search(diagnostic_pattern, diagnostic)) and str(resume_path) in diagnostic
            require(case["returncode"] == 1, "malformed resume input must exit 1, not succeed or crash")
            require(case["diagnostic_found"], "missing input-specific resume diagnostic")
            require(case["files_unchanged"], "malformed resume changed its input or an output file")
        return check

    try:
        # Real fresh output is retained through two rejected resumes. The
        # original saved command exercises --resume restoring -oJ/--report.
        for suffix in (".txt", ".MD"):
            directory = out / ("fresh-" + suffix[1:].lower())
            directory.mkdir()
            paths = [directory / "scan.gnmap", directory / "scan.json", directory / ("scan"+suffix)]
            command = base + ["-oG", str(paths[0]), "-oJ", str(paths[1]), "--report", str(paths[2]), *HOSTS]
            def fresh(case, stderr):
                require(case["returncode"] == 0, "fresh output failed")
                document = json.loads(paths[1].read_text(encoding="utf-8"))
                json_hosts = [next(address["addr"] for address in host["addresses"] if address["addrtype"] == "ipv4")
                              for host in document["hosts"]]
                require(Counter(json_hosts) == Counter(HOSTS), "fresh JSON omitted or duplicated a host")
                require(document["stats"]["hosts_total"] == len(HOSTS), "fresh JSON total is incorrect")
                require(all(host["status"]["state"] == "unknown" for host in document["hosts"]), "list-only hosts must have unknown state")
                report = paths[2].read_text(encoding="utf-8")
                report_hosts = re.findall(r"(?:^  TARGET: |^## Target: )([^\s]+)", report, re.M)
                require(Counter(report_hosts) == Counter(HOSTS), "fresh report omitted or duplicated a host")
                require(Counter(grepable_hosts(paths[0])) == Counter(HOSTS), "fresh grepable identities disagree")
                case["verified_host_count_per_format"] = len(HOSTS)
            case = run(directory.name, directory, command, fresh)
            require(case["status"] == "passed", "fresh-output prerequisite failed")
            before = file_state(paths)
            for path in paths:
                (directory / (path.name + ".original")).write_bytes(path.read_bytes())
            for number in (1, 2):
                run(directory.name + "-resume-%d" % number, directory,
                    [str(binary), "--resume", str(paths[0])], expect_rejection(paths, before))

        # Cover each option independently, both file states, uppercase report
        # suffixes and legacy outputs which must not be opened before rejection.
        for mode in ("json", "txt", "markdown", "both", "mixed"):
            for existing in (False, True):
                name = "append-%s-%s" % (mode, "existing" if existing else "missing")
                directory = out / name
                directory.mkdir()
                paths = [directory / "scan.gnmap", directory / "scan.nmap", directory / "scan.xml"]
                command = base + ["--append-output", "-oG", str(paths[0]), "-oN", str(paths[1]), "-oX", str(paths[2])]
                if mode in ("json", "both", "mixed"):
                    path = directory / "scan.json"
                    paths.append(path)
                    command += ["-oJ", str(path)]
                if mode in ("txt", "markdown", "both", "mixed"):
                    path = directory / ("scan.MD" if mode == "markdown" else "scan.txt")
                    paths.append(path)
                    command += ["--report", str(path)]
                if mode == "mixed":
                    command = base + ["-oJ", str(paths[3]), "--report", str(paths[4]),
                                      "-oG", str(paths[0]), "--append-output",
                                      "-oN", str(paths[1]), "-oX", str(paths[2])]
                if existing:
                    for path in paths:
                        path.write_bytes(("PREVIOUS OUTPUT: " + path.name + "\r\n").encode("ascii"))
                        (directory / (path.name + ".original")).write_bytes(path.read_bytes())
                before = file_state(paths)
                run(name, directory, command + HOSTS, expect_rejection(paths, before))

        # Failures before argument restoration must preserve the input plus
        # every potential output too. The synthetic saved command is list-only
        # even if a malformed-input regression accidentally accepts the log.
        for kind in ("empty", "invalid-address", "truncated"):
            name = "resume-" + kind
            directory = out / name
            directory.mkdir()
            paths = [directory / filename for filename in
                     ("scan.gnmap", "scan.nmap", "scan.xml", "scan.json", "scan.txt")]
            for path in paths:
                path.write_bytes(("PRESERVE: " + path.name + "\r\n").encode("ascii"))
            resume_path = directory / "resume.log"
            saved_args = base + ["-oJ", str(paths[3]), "--report", str(paths[4]),
                                 "-oG", str(paths[0]), "-oN", str(paths[1]), "-oX", str(paths[2]), *HOSTS]
            require(all('"' not in value and "\n" not in value and "\r" not in value for value in saved_args),
                    "fixture path cannot be represented by the resume command format")
            saved_command = " ".join('"' + value + '"' if any(char.isspace() for char in value) else value for value in saved_args)
            header = ("# Kmap test initiated as: " + saved_command + "\n").encode("utf-8")
            if kind == "empty":
                payload, pattern = b"", r"CreateFileMapping\(\)|Could not mmap\(\)"
            elif kind == "invalid-address":
                payload, pattern = header + b"Host: invalid-address ()\tStatus: Up\n", r"Unable to parse ip \(invalid-address\)"
            else:
                payload, pattern = header + b"Host: 127.0.0.1 ()\tStatus: Up", r"ends with an incomplete line -- cannot safely resume"
            resume_path.write_bytes(payload)
            paths.append(resume_path)
            for path in paths:
                (directory / (path.name + ".original")).write_bytes(path.read_bytes())
            before = file_state(paths)
            run(name, directory, [str(binary), "--resume", str(resume_path)],
                expect_parse_rejection(paths, before, resume_path, pattern))

        # Legacy-only output remains supported: appending another invocation
        # retains its prefix; resuming a completed file must add no host rows.
        directory = out / "legacy"
        directory.mkdir()
        path = directory / "scan.gnmap"
        def legacy_fresh(case, stderr):
            require(case["returncode"] == 0, "legacy fresh scan failed")
            require(Counter(grepable_hosts(path)) == Counter(HOSTS), "legacy fresh identities disagree")
        run("legacy-fresh", directory, base + ["-oG", str(path), *HOSTS], legacy_fresh)
        require(path.is_file(), "legacy output prerequisite failed")
        for number in (1, 2):
            before_bytes = path.read_bytes()
            def legacy_resume(case, stderr):
                require(case["returncode"] == 0, "supported legacy resume failed")
                require(path.read_bytes().startswith(before_bytes), "legacy resume changed prior bytes")
                require(Counter(grepable_hosts(path)) == Counter(HOSTS), "completed legacy resume repeated or lost a host")
            run("legacy-resume-%d" % number, directory, [str(binary), "--resume", str(path)], legacy_resume)
        before_bytes = path.read_bytes()
        def legacy_append(case, stderr):
            require(case["returncode"] == 0, "supported legacy append failed")
            require(path.read_bytes().startswith(before_bytes), "legacy append changed prior bytes")
            require(Counter(grepable_hosts(path)) == Counter(HOSTS + HOSTS), "legacy append omitted or duplicated a new invocation")
        run("legacy-append", directory, base + ["--append-output", "-oG", str(path), *HOSTS], legacy_append)
        result["status"] = "passed" if all(case["status"] == "passed" for case in result["cases"]) else "failed"
    except BaseException:
        result.update(status="failed", error=traceback.format_exc())
    finally:
        result["binary_sha256_after"] = digest(binary)
        result["driver_sha256_after"] = digest(Path(__file__))
        result["source_sha256_after"] = {str(path): digest(path) for path in sources}
        result["bindings_stable"] = result["binary_sha256_before"] == result["binary_sha256_after"] and result["driver_sha256_before"] == result["driver_sha256_after"] and result["source_sha256_before"] == result["source_sha256_after"]
        if not result["bindings_stable"]:
            result["status"] = "failed"
        save()
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "results": str(out / "results.json")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
