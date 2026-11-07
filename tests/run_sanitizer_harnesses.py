#!/usr/bin/env python3
"""Run the standalone harness manifest under Linux ASan/UBSan.

Each command gets its own retained working directory, including TMPDIR, so
fixed-name SQLite/checkpoint fixtures cannot overwrite the checkout or another
test. Results, compiler diagnostics and failing inputs are kept below --output.
The manifest distinguishes production-linked tests from copied models/parsers;
passing a copied harness does not establish production-code coverage.
"""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time


@dataclass(frozen=True)
class Harness:
    source: str
    links: tuple = ()
    runs: tuple = ((),)
    sqlite: bool = False
    coverage: str = "copied model/parser; not production linkage"
    headers: tuple = ()  # Explicit production headers included by new regressions.
    postchecks: tuple = ()  # Mandatory Python drivers using the built unit executable.


SEEDED = (("1",), ("1337",))
GUARDED = (("1", "300000"), ("1337", "300000"))

# This dictionary is BOTH the coverage inventory and the executable plan.
# A name in a comment cannot satisfy inventory validation or cause a test run.
HARNESSES = {
    **{name: Harness("fuzz/" + name + ".cc", runs=SEEDED) for name in (
        "test_cidr_parse", "test_discover_bail", "test_admit_reentry",
        "test_lowwater", "test_sha256", "test_watchlist_diff", "test_ratelimit",
        "test_csum_patch", "test_header_extract", "test_checkpoint",
        "test_excludes", "test_throughput", "test_asn_prefix", "fuzz_text",
        "fuzz_query", "test_vercmp")},
    **{name: Harness("fuzz/" + name + ".cc", runs=SEEDED,
                     coverage="production header included") for name in (
        "test_json_escape", "test_banner_classify", "test_banner_mutate")},
    "test_linger": Harness("fuzz/test_linger.cc", runs=SEEDED,
                           coverage="owned loopback socket fixture; not production linkage"),
    **{name: Harness("fuzz/" + name + ".cc", ("net_hash_helpers.cc",),
                     coverage="production source linked") for name in (
        "test_mmh3", "test_favicon", "test_cpe")},
    "test_governor": Harness("fuzz/test_governor.cc", ("cpu_meter.cc",),
                             coverage="production source linked"),
    "test_hassh": Harness("fuzz/test_hassh.cc", ("ssh_hassh.cc",), SEEDED,
                          coverage="production source linked"),
    "test_host_tags": Harness("fuzz/test_host_tags.cc",
                              ("host_tags.cc", "net_hash_helpers.cc"), SEEDED,
                              coverage="production source linked"),
    "test_jarm": Harness("fuzz/test_jarm.cc", ("jarm.cc",), SEEDED,
                         coverage="production parser/builder/hash linked; network leg not called"),
    "test_cloud_match": Harness("fuzz/test_cloud_match.cc", ("cloud_map.cc",),
                                coverage="production source linked; offline range fixture"),
    **{name: Harness("fuzz/" + name + ".cc", runs=GUARDED) for name in (
        "fuzz_dns", "fuzz_proto", "fuzz_core")},
    **{name: Harness("fuzz/" + name + ".cc", ("net_db.cc",), sqlite=True,
                     coverage="production storage + bundled SQLite linked") for name in (
        "test_netdb", "test_search", "test_asn_update")},
    "test_entity_graph": Harness("fuzz/test_entity_graph.cc",
                                 ("entity_graph.cc", "net_db.cc"), sqlite=True,
                                 coverage="production graph/storage + bundled SQLite linked"),
    "test_netquery": Harness("fuzz/test_netquery.cc", sqlite=True,
                             coverage="copied query/filter logic + real SQLite; not CLI coverage"),
    "test_cve_limit": Harness("fuzz/test_cve_limit.cc", sqlite=True,
                              coverage="copied query logic + real SQLite"),
    "test_osprofile": Harness("fuzz/test_osprofile.cc", ("os_profile.cc",),
                              coverage="production request-formatting source linked; no network"),
    "net_db_regression_test": Harness("tests/net_db_regression_test.cc",
                                      ("net_db.cc",), sqlite=True,
                                      coverage="production storage + bundled SQLite linked"),
    "entity_graph_json_test": Harness("tests/entity_graph_json_test.cc",
                                      ("entity_graph.cc", "net_db.cc"), sqlite=True,
                                      coverage="production graph JSON emitter; strict independent UTF-8 oracle"),
    "graph_read_test": Harness("tests/graph_read_test.cc",
                               ("entity_graph.cc", "net_db.cc"), sqlite=True,
                               coverage="production graph depth and read failures; small seeded graph distance oracle",
                               headers=("entity_graph.h", "net_db.h", "json_escape.h")),
    "topology_assemble_test": Harness("tests/topology_assemble_test.cc",
                                      ("net_db.cc",), sqlite=True,
                                      coverage="production topology assembly/persistence + storage; recorded traces only",
                                      headers=("topology_assemble.h", "topology_store.h", "tracemap.h", "net_db.h")),
    "checkpoint_persistence_test": Harness("tests/checkpoint_persistence_test.cc",
                                          coverage="production checkpoint parsing/atomic file replacement; owned local fixtures",
                                          headers=("scan_checkpoint.h",),
                                          postchecks=("tests/checkpoint_recovery.py",)),
    "scheduler_progress_test": Harness("tests/scheduler_progress_test.cc",
                                      coverage="production work ownership/checkpoint helper; bounded offline threads",
                                      headers=("work_progress.h",)),
    "joined_workers_test": Harness("tests/joined_workers_test.cc",
                                   coverage="production worker exception/join helper; inert jobs and injected startup failure",
                                   headers=("joined_workers.h",)),
    "net_db_failure_test": Harness("tests/net_db_failure_test.cc", ("net_db.cc",), sqlite=True,
                                   coverage="production storage errors/atomic bulk rollback + real SQLite",
                                   headers=("net_db.h",)),
    "net_db_bind_test": Harness("tests/net_db_bind_test.cc", ("net_db.cc", "net_fp_helpers.cc"),
                                sqlite=True, coverage="production bind-error handling and enrichment rollback; bounded SQLite length limit, no network",
                                headers=("net_db.h", "enrichment_store.h", "net_enrich.h", "net_fp_helpers.h", "topology_store.h", "tracemap.h")),
    "net_db_lifecycle_test": Harness("tests/net_db_lifecycle_test.cc", ("entity_graph.cc", "net_db.cc"),
                                     sqlite=True, coverage="production storage/graph lifecycle and recovery + real SQLite",
                                     headers=("net_db.h", "entity_graph.h", "json_escape.h", "third-party/nlohmann/json.hpp")),
    "persistence_boundary_test": Harness("tests/persistence_boundary_test.cc",
                                        coverage="production commit/checkpoint ordering + joined workers; owned fixtures",
                                        headers=("persistence_boundary.h", "scan_checkpoint.h", "joined_workers.h")),
    "enrichment_store_test": Harness("tests/enrichment_store_test.cc",
                                     ("net_db.cc", "net_fp_helpers.cc"), sqlite=True,
                                     coverage="production enrichment storage handoff; inert records and real SQLite, no network",
                                     headers=("enrichment_store.h", "net_db.h", "net_enrich.h", "net_fp_helpers.h")),
    "watchlist_state_test": Harness("tests/watchlist_state_test.cc", ("net_db.cc",), sqlite=True,
                                    coverage="production completed-watchlist membership; offline SQLite failure/recovery fixtures",
                                    headers=("watchlist_state.h", "net_db.h")),
    "watchlist_targets_test": Harness("tests/watchlist_targets_test.cc", ("net_db.cc",), sqlite=True,
                                      coverage="production watchlist target parser; offline IPv4/CIDR inputs",
                                      headers=("watchlist_targets.h", "net_db.h")),
    "http_headers_test": Harness("tests/http_headers_test.cc",
                                 coverage="production HTTP header/cookie parser; offline response fixtures",
                                 headers=("http_headers.h",)),
    "stored_json_test": Harness("tests/stored_json_test.cc",
                                coverage="production stored JSON depth, escapes and structure; offline byte mutations",
                                headers=("stored_json.h", "json_escape.h", "third-party/nlohmann/json.hpp")),
    "net_db_diff_test": Harness("tests/net_db_diff_test.cc", ("net_db.cc",), sqlite=True,
                                coverage="production CVE diff and stored JSON parser; malformed and equivalent lists",
                                headers=("net_db.h", "stored_json.h", "json_escape.h", "third-party/nlohmann/json.hpp")),
}


def validate_manifest(root):
    actual = {p.relative_to(root).as_posix() for p in (root / "fuzz").glob("*.cc")}
    planned = {h.source for h in HARNESSES.values() if h.source.startswith("fuzz/")}
    missing, stale = sorted(actual - planned), sorted(planned - actual)
    if missing or stale:
        raise ValueError(f"Harness inventory mismatch: unregistered={missing}, missing files={stale}")
    for name, harness in HARNESSES.items():
        if not harness.runs:
            raise ValueError(f"{name} has no scheduled executions")
        for source in (harness.source, *harness.links, *harness.headers, *harness.postchecks):
            if not (root / source).is_file():
                raise ValueError(f"{name} source is missing: {source}")


class Recorder:
    def __init__(self, output, total_timeout, metadata=None):
        self.output = output.resolve()
        # A fresh output directory prevents stale successes or corpus reuse.
        self.output.mkdir(parents=True, exist_ok=False)
        self.started = time.monotonic()
        self.deadline = self.started + total_timeout
        self.document = {"status": "running", "metadata": metadata or {}, "commands": []}
        self.save()

    def save(self):
        self.document["elapsed_seconds"] = round(time.monotonic() - self.started, 3)
        target = self.output / "results.json"
        temporary = self.output / "results.json.tmp"
        temporary.write_text(json.dumps(self.document, indent=2) + "\n", encoding="utf-8")
        temporary.replace(target)

    def skip(self, name, reason):
        self.document["commands"].append({"name": name, "status": "skipped", "reason": reason})
        self.save()

    def run(self, name, command, timeout):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self.skip(name, "total runner time budget exhausted")
            return False
        timeout = min(timeout, remaining)
        work = self.output / name
        work.mkdir()
        scratch = work / "tmp"
        scratch.mkdir()
        command = list(map(str, command))
        record = {"name": name, "command": command, "cwd": str(work),
                  "timeout_seconds": round(timeout, 3), "status": "running"}
        self.document["commands"].append(record)
        self.save()
        print(f"{name}: starting (timeout {timeout:.0f}s)", flush=True)
        env = {**os.environ, "TMPDIR": str(scratch), "TMP": str(scratch), "TEMP": str(scratch)}
        started = time.monotonic()
        process = None
        try:
            with (work / "output.log").open("wb") as log:
                process = subprocess.Popen(command, cwd=work, env=env,
                                           stdin=subprocess.DEVNULL, stdout=log,
                                           stderr=subprocess.STDOUT,
                                           start_new_session=(os.name == "posix"))
                record["returncode"] = process.wait(timeout=timeout)
                record["status"] = "passed" if record["returncode"] == 0 else "failed"
        except subprocess.TimeoutExpired:
            record.update(status="failed", error="command timed out")
        except OSError as error:
            record.update(status="failed", error=str(error))
        except BaseException:
            record.update(status="failed", error="runner interrupted")
            raise
        finally:
            if process is not None and process.poll() is None:
                # g++ may have spawned cc1plus. Kill/reap the whole command
                # group on Linux after a timeout or an interruption handled
                # by Python. Forced runner termination may prevent cleanup.
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
                record["returncode"] = process.returncode
            record["elapsed_seconds"] = round(time.monotonic() - started, 3)
            self.save()
        print(f"{name}: {record['status']} ({record['elapsed_seconds']}s); {work / 'output.log'}",
              flush=True)
        return record["status"] == "passed"

    def finish(self, completed=True):
        self.document["plan_completed"] = completed
        self.document["status"] = "passed" if completed and all(
            c["status"] == "passed" for c in self.document["commands"]) else "failed"
        self.save()
        return self.document["status"] == "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("test-results/fuzz"))
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--only", action="append", choices=sorted(HARNESSES),
                        help="Run an explicitly reported subset locally; CI omits this")
    parser.add_argument("--build-timeout", type=int, default=180)
    parser.add_argument("--run-timeout", type=int, default=120)
    parser.add_argument("--total-timeout", type=int, default=1500)
    args = parser.parse_args()
    if min(args.build_timeout, args.run_timeout, args.total_timeout) <= 0:
        parser.error("timeouts must be positive")
    root = Path(__file__).resolve().parents[1]
    validate_manifest(root)
    selected = args.only or list(HARNESSES)
    if len(selected) != len(set(selected)):
        parser.error("--only cannot repeat a harness")
    if args.validate_only:
        print(json.dumps({"inventory_valid": True,
                          "fuzz_sources": sum(h.source.startswith("fuzz/") for h in HARNESSES.values()),
                          "selected": {name: asdict(HARNESSES[name]) for name in selected}}, indent=2))
        return 0
    if os.name != "posix":
        parser.error("the sanitizer build plan requires Linux; use --validate-only on other platforms")
    flags = ["-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
             "-fno-omit-frame-pointer"]
    cc = shlex.split(os.environ.get("CC", "cc"))
    cxx = shlex.split(os.environ.get("CXX", "g++"))
    sources = {source for name in selected
               for source in (HARNESSES[name].source, *HARNESSES[name].links,
                              *HARNESSES[name].headers, *HARNESSES[name].postchecks)}
    if any(HARNESSES[name].sqlite for name in selected):
        sources.add("sqlite/sqlite3.c")
    metadata = {"selected_harnesses": {name: asdict(HARNESSES[name]) for name in selected},
                "source_sha256": {source: hashlib.sha256((root / source).read_bytes()).hexdigest()
                                  for source in sorted(sources)},
                "complete_inventory_run": args.only is None,
                "sanitizer_flags": flags, "sqlite_defines": ["SQLITE_THREADSAFE=0", "SQLITE_ENABLE_FTS5"],
                "network_scope": "test_linger uses an owned 127.0.0.1 listener; all others offline",
                "asan_options": os.environ.get("ASAN_OPTIONS", "runtime defaults"),
                "ubsan_options": os.environ.get("UBSAN_OPTIONS", "runtime defaults")}
    runner = Recorder(args.output, args.total_timeout, metadata)
    binaries = runner.output / "bin"
    binaries.mkdir()
    completed = False
    try:
        compiler_ok = runner.run("c-version", [*cc, "--version"], 10)
        compiler_ok = runner.run("cxx-version", [*cxx, "--version"], 10) and compiler_ok
        sqlite_object = binaries / "sqlite3.o"
        sqlite_ok = True
        if any(HARNESSES[name].sqlite for name in selected):
            sqlite_ok = compiler_ok and runner.run("build-sqlite", [*cc, *flags,
                "-DSQLITE_THREADSAFE=0", "-DSQLITE_ENABLE_FTS5", "-c", root / "sqlite/sqlite3.c",
                "-o", sqlite_object], args.build_timeout)
        for name in selected:
            harness = HARNESSES[name]
            if not compiler_ok or (harness.sqlite and not sqlite_ok):
                runner.skip("build-" + name, "compiler/SQLite prerequisite failed")
                for index in range(len(harness.runs)):
                    runner.skip(f"{name}-run-{index + 1}", "build prerequisite failed")
                for index in range(len(harness.postchecks)):
                    runner.skip(f"{name}-postcheck-{index + 1}", "build prerequisite failed")
                continue
            binary = binaries / name
            command = [*cxx, *flags, "-std=gnu++17", "-pthread", "-I" + str(root),
                       "-I" + str(root / "nbase"), root / harness.source,
                       *(root / source for source in harness.links)]
            if harness.sqlite:
                command.extend([sqlite_object, "-ldl"])
            command.extend(["-o", binary])
            built = runner.run("build-" + name, command, args.build_timeout)
            for index, arguments in enumerate(harness.runs, 1):
                if built:
                    runner.run(f"{name}-run-{index}", [binary, *arguments], args.run_timeout)
                else:
                    runner.skip(f"{name}-run-{index}", "harness build failed")
            for index, driver in enumerate(harness.postchecks, 1):
                label = f"{name}-postcheck-{index}"
                if built:
                    runner.run(label, [sys.executable, root / driver, binary,
                        "--artifacts", runner.output / label / "recovery",
                        "--total-timeout", str(min(90, max(0.1, args.run_timeout - 5)))],
                        args.run_timeout)
                else:
                    runner.skip(label, "harness build failed")
        completed = True
    finally:
        passed = runner.finish(completed)
    print(f"sanitizer harnesses: {'passed' if passed else 'failed'}; {runner.output / 'results.json'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
