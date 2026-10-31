#!/usr/bin/env python3
"""Bounded offline process-crash checks for checkpoint_persistence_test.

The child exits abruptly at six file-I/O boundaries. Complete old/new records
must survive; this tests process crashes, not power loss or disk durability.
Only the checkpoint unit executable is supported; it spawns no descendants.
All logs and fixtures are retained in a fresh test-owned artifact directory.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


OLD = b"17\n33\n5\n777\n1700000000\n"
NEW = b"29\n61\n9\n888\n1700000001\n"
CASES = (
    ("partial-write", "partial-write", True, "old", OLD, b"29\n61\n"),
    ("after-flush", "after-flush", True, "old", OLD, NEW),
    ("after-close", "after-close", True, "old", OLD, NEW),
    ("before-replace", "before-replace", True, "old", OLD, NEW),
    ("after-replace", "after-replace", True, "new", NEW, None),
    ("first-after-close", "after-close", False, "new", None, NEW),
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_suite(command, artifacts, timeout=10.0, total_timeout=90.0):
    """Run the fixed plan. A command prefix permits inert driver self-checks."""
    artifacts = Path(artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + total_timeout
    document = dict(status="running", completed=False, commands=[], cases=[],
                    command=list(map(str, command)), driver_sha256=digest(__file__),
                    executable_sha256=digest(command[0]),
                    coverage="six abrupt process exits; no power-loss durability claim")

    def save():
        document["elapsed_seconds"] = round(time.monotonic() - started, 4)
        temporary = artifacts / "results.json.tmp"
        temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        temporary.replace(artifacts / "results.json")

    def child(name, arguments, directory, expected):
        remaining = deadline - time.monotonic()
        record = dict(name=name, command=[*map(str, command), *arguments],
                      cwd=str(directory), expected_returncode=expected,
                      timeout_seconds=max(0.0, min(timeout, remaining)), status="running")
        document["commands"].append(record)
        save()
        process = None
        child_started = time.monotonic()
        try:
            if remaining <= 0:
                raise TimeoutError("suite time budget exhausted")
            env = {**os.environ, "TMPDIR": str(directory / "tmp"),
                   "TMP": str(directory / "tmp"), "TEMP": str(directory / "tmp")}
            with (directory / (name + ".stdout.log")).open("wb") as out, \
                 (directory / (name + ".stderr.log")).open("wb") as err:
                # Inherit an enclosing runner's process group so its timeout
                # can also terminate this unit child if Python is killed.
                process = subprocess.Popen(record["command"], cwd=directory, env=env,
                                           stdin=subprocess.DEVNULL, stdout=out, stderr=err)
                record["returncode"] = process.wait(timeout=record["timeout_seconds"])
            if record["returncode"] != expected:
                raise RuntimeError(f"exit {record['returncode']}, expected {expected}")
            record["status"] = "passed"
        except (OSError, RuntimeError, subprocess.TimeoutExpired, TimeoutError) as error:
            record.update(status="failed", error=str(error))
        except BaseException:
            record.update(status="failed", error="driver interrupted")
            raise
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
                record["returncode"] = process.returncode
                record["terminated_after_timeout_or_interrupt"] = True
            record["elapsed_seconds"] = round(time.monotonic() - child_started, 4)
            save()
        return record["status"] == "passed"

    save()
    try:
        for name, stage, prior, expected, main_bytes, temp_bytes in CASES:
            case = dict(name=name, stage=stage, expected_recovery=expected, status="running")
            document["cases"].append(case)
            directory = artifacts / name
            directory.mkdir()
            (directory / "tmp").mkdir()
            checkpoint = directory / ".net-scan-checkpoint"
            if prior:
                checkpoint.write_bytes(OLD)
            save()
            try:
                if not child("crash", ["--crash", str(directory), stage], directory, 73):
                    raise RuntimeError("crash child failed its expected-exit contract")
                for path, wanted in ((checkpoint, main_bytes),
                                     (Path(str(checkpoint) + ".tmp"), temp_bytes)):
                    actual = path.read_bytes().replace(b"\r\n", b"\n") if path.exists() else None
                    if actual != wanted:
                        raise RuntimeError(f"unexpected file state at {stage}: {path.name}")
                if not child("verify", ["--verify", str(directory), expected], directory, 0):
                    raise RuntimeError("checkpoint recovery verification failed")
                output = (directory / "verify.stdout.log").read_text(encoding="utf-8").strip()
                if output != f"recovery={expected} ok=1":
                    raise RuntimeError(f"missing complete-record recovery assertion: {output!r}")
                case["status"] = "passed"
            except (OSError, RuntimeError, UnicodeError) as error:
                case.update(status="failed", error=str(error))
            # Artifact uploaders commonly omit dotfiles. Keep visible, exact
            # copies as well so failed checkpoint states survive CI upload.
            try:
                case["snapshots"] = {}
                for label, source in (("main", checkpoint),
                                      ("temporary", Path(str(checkpoint) + ".tmp"))):
                    if source.exists():
                        contents = source.read_bytes()
                        target = directory / ("checkpoint-" + label + ".snapshot")
                        target.write_bytes(contents)
                        case["snapshots"][label] = dict(path=str(target), size=len(contents),
                                                       sha256=hashlib.sha256(contents).hexdigest())
                    else:
                        case["snapshots"][label] = None
            except OSError as error:
                case.update(status="failed", artifact_error=str(error))
            save()
        document["completed"] = True
    finally:
        document["status"] = "passed" if document["completed"] and all(
            case["status"] == "passed" for case in document["cases"]) else "failed"
        save()
    print(f"checkpoint crash recovery: {sum(c['status'] == 'passed' for c in document['cases'])}"
          f"/{len(CASES)} passed; {artifacts}", flush=True)
    return document["status"] == "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="built checkpoint_persistence_test executable")
    parser.add_argument("--artifacts", type=Path, help="must not already exist")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--total-timeout", type=float, default=90.0)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
        parser.error("--timeout must be finite and within (0, 60] seconds")
    if not math.isfinite(args.total_timeout) or not 0 < args.total_timeout <= 600:
        parser.error("--total-timeout must be finite and within (0, 600] seconds")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"unit executable does not exist: {binary}")
    artifacts = args.artifacts
    if artifacts is None:
        parent = Path("test-results/checkpoint-recovery")
        parent.mkdir(parents=True, exist_ok=True)
        # mkdtemp reserves an isolated parent; run_suite exclusively creates run.
        artifacts = Path(tempfile.mkdtemp(prefix="run-", dir=parent)) / "run"
    return 0 if run_suite([str(binary)], artifacts, args.timeout, args.total_timeout) else 1


if __name__ == "__main__":
    sys.exit(main())
