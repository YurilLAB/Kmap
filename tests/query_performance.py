#!/usr/bin/env python3
"""Bounded OFFLINE actual-CLI query contracts and paired benchmark driver.

Only --help, --version, and --net-query are invoked. Fixture IP addresses are
inert database values, never network targets. Prepare/contracts and benchmark
are separate phases so timing can be coordinated with other work.
"""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import statistics
import subprocess
import sys
import time

SCHEMA = """CREATE TABLE hosts (
ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT DEFAULT 'tcp',
first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
service TEXT, version TEXT, cves TEXT, web_title TEXT, web_server TEXT,
web_headers TEXT, web_paths TEXT, enriched INTEGER DEFAULT 0,
asn INTEGER DEFAULT 0, country TEXT, PRIMARY KEY(ip,port));"""
BASE_CVE = {"id": "CVE-2000-0001", "cvss": 7.5, "epss": 0.75, "kev": 1}
MAX_BYTES = 100 * 1024 * 1024
BASE_COMMIT = "87c5980571cfaa304eab166372f0b657bef3572f"


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def normalized_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")).hexdigest()


def expected_row(index):
    row = {"ip": str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("198.18.0.1")) + index)),
           "port": 443 if index % 2 == 0 else 22, "proto": "tcp",
           "service": "https" if index % 2 == 0 else "ssh",
           "asn": 64512 + index % 7,
           "country": ("US", "DE", "AU", "GB")[index % 4],
           "web_title": f"Fixture {index:05d}",
           "device_class": "web" if index % 2 == 0 else "ssh"}
    if index % 2 == 0:
        row["web_server"] = "nginx"
    if index % 8 == 0:
        row["cves"] = [BASE_CVE]
        row["tags"] = ["kev", "vuln"]
    return row


def fixture(directory, rows):
    directory.mkdir(parents=True, exist_ok=False)
    groups = {}
    for row in rows:
        shard = int(ipaddress.IPv4Address(row["ip"])) >> 27
        cves = row.get("raw_cves", json.dumps(row.get("cves", []), separators=(",", ":")))
        groups.setdefault(shard, []).append((row["ip"], row["port"], row["service"],
                  cves, row.get("web_title", ""), row.get("web_server", ""),
                  row.get("asn", 0), row.get("country", "")))
    for shard, values in groups.items():
        db = sqlite3.connect(directory / f"shard_{shard:03d}.db")
        try:
            db.executescript(SCHEMA)
            db.executemany("INSERT INTO hosts(ip,port,service,cves,web_title,web_server,asn,country,first_seen,last_seen,enriched) "
                           "VALUES(?,?,?,?,?,?,?,?,100,200,1)", values)
            db.commit()
        finally:
            db.close()


def advanced_rows():
    compact = {"id": "CVE-2000-0001", "cvss": 9.1, "epss": 0.9, "kev": 1}
    definitions = [
        ("compact", json.dumps([compact], separators=(",", ":")), 64512),
        ("scientific-low-epss", '[{"id":"CVE-2000-0002","cvss":4.0,"epss":5e-05,"kev":0}]', 64513),
        ("pretty-equivalent", json.dumps([compact], indent=2), 64512),
        ("newline-equivalent", json.dumps([compact], indent=2).replace(": ", ":\n "), 64512),
        ("id-in-description", '[{"id":"CVE-2000-0002","desc":"CVE-2000-0001","cvss":4.0,"epss":0.1,"kev":0}]', 64513),
        ("four-byte-asn", "[]", 4000000000),
        ("no-cves", "[]", 64514),
    ]
    return [dict(ip=f"192.0.2.{i+1}", port=443, service="https", web_title=name,
                 raw_cves=cves, cves=json.loads(cves), asn=asn, country="US")
            for i, (name, cves, asn) in enumerate(definitions)]


class OwnedProcessMetrics:
    """Query only the child PID returned by this driver's Popen call.

    Official APIs: GetProcessTimes, GetProcessMemoryInfo,
    GetProcessHandleCount. No process enumeration or CIM.
    """
    def __init__(self, pid):
        self.handle = None
        self.result = {"peak_working_set_bytes": None, "sampled_max_handles": None,
                       "cpu_user_seconds": None, "cpu_kernel_seconds": None,
                       "samples": 0, "errors": []}
        if os.name != "nt":
            self.result["errors"].append("Windows resource APIs unavailable")
            return
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        self.kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]

        class Memory(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize",
                "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        self.Memory = Memory
        self.psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
        self.handle = self.kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        if not self.handle:
            self.result["errors"].append(f"OpenProcess(child={pid}): {ctypes.get_last_error()}")

    def sample(self):
        if not self.handle:
            return
        self.result["samples"] += 1
        memory = self.Memory()
        memory.cb = ctypes.sizeof(memory)
        if self.psapi.GetProcessMemoryInfo(self.handle, ctypes.byref(memory), memory.cb):
            self.result["peak_working_set_bytes"] = max(self.result["peak_working_set_bytes"] or 0,
                                                         memory.PeakWorkingSetSize)
        handles = wintypes.DWORD()
        if self.kernel.GetProcessHandleCount(self.handle, ctypes.byref(handles)):
            self.result["sampled_max_handles"] = max(self.result["sampled_max_handles"] or 0, handles.value)

    def close(self):
        if self.handle:
            values = [wintypes.FILETIME() for _ in range(4)]
            if self.kernel.GetProcessTimes(self.handle, *(ctypes.byref(value) for value in values)):
                for key, value in zip(("cpu_kernel_seconds", "cpu_user_seconds"), values[2:]):
                    self.result[key] = ((value.dwHighDateTime << 32) | value.dwLowDateTime) / 10_000_000
            else:
                self.result["errors"].append(f"GetProcessTimes: {ctypes.get_last_error()}")
            self.kernel.CloseHandle(self.handle)
            self.handle = None
        return self.result


class Driver:
    def __init__(self, args):
        self.args = args
        self.binary = args.binary.resolve()
        self.output = args.artifacts.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        # Different phases share fixtures; repeated/concurrent runs of one
        # phase must never replace their logs or a completed result.
        if (self.output / f"{args.phase}-results.json").exists():
            raise RuntimeError("phase results already exist; use a fresh artifacts directory")
        with (self.output / f"{args.phase}.started").open("x", encoding="utf-8") as marker:
            marker.write(f"pid={os.getpid()}\n")
        self.fixtures = self.output / "fixtures"
        self.records = []
        self.start = time.monotonic()
        self.metadata = {"baseline_commit": BASE_COMMIT, "binary": str(self.binary),
                         "binary_sha256": digest(self.binary), "driver_sha256": digest(__file__),
                         "python": sys.version, "platform": platform.platform(),
                         "params": vars(args).copy(), "metric_sampling_seconds": 0.005,
                         "metric_scope": "only launched child process; handles are sampled, not a leak proof",
                         "official_api_docs": [
                             "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes",
                             "https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo",
                             "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesshandlecount"]}

    def save(self, **extra):
        data = {**self.metadata, **extra, "records": self.records}
        (self.output / f"{self.args.phase}-results.json").write_text(
            json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")

    def run(self, name, flags, data=None):
        if time.monotonic() - self.start > self.args.budget_seconds:
            raise TimeoutError("total driver time budget exhausted")
        command = [str(self.binary)]
        if data is not None:
            command += ["--net-query", "--data-dir", str(data)]
        command += list(flags)
        out = self.output / (name + ".stdout.log")
        err = self.output / (name + ".stderr.log")
        started = time.perf_counter()
        metrics = None
        record = {"name": name, "command": command}
        self.records.append(record)
        with out.open("wb") as stdout, err.open("wb") as stderr:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       env={**os.environ, "LC_ALL": "C"})
            try:
                metrics = OwnedProcessMetrics(process.pid)
                deadline = min(started + 20, started + self.args.budget_seconds - (time.monotonic() - self.start))
                while process.poll() is None:
                    metrics.sample()
                    if time.perf_counter() > deadline:
                        process.kill()
                        process.wait(timeout=5)
                        raise TimeoutError("owned query child exceeded deadline")
                    time.sleep(0.005)
                metrics.sample()
                record["returncode"] = process.returncode
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                record["wall_seconds"] = time.perf_counter() - started
                if metrics:
                    record.update(metrics.close())
                self.save()
        record.update(stdout_sha256=digest(out), stderr_sha256=digest(err), stdout_bytes=out.stat().st_size)
        return record, out, err

    def prepare(self):
        if self.fixtures.exists():
            raise RuntimeError("fixture directory already exists; use a fresh artifacts directory")
        self.fixtures.mkdir()
        for count in self.args.sizes:
            fixture(self.fixtures / str(count), (expected_row(i) for i in range(count)))
        fixture(self.fixtures / "accuracy", advanced_rows())
        self.save(status="prepared", fixture_bytes=self.fixture_bytes(), fixture_hashes=self.fixture_hashes())

    def fixture_bytes(self):
        total = sum(p.stat().st_size for p in self.fixtures.rglob("*") if p.is_file())
        if total > MAX_BYTES:
            raise RuntimeError("fixture data exceeded 100 MiB budget")
        return total

    def fixture_hashes(self):
        return {str(p.relative_to(self.output)): digest(p) for p in self.fixtures.rglob("*.db")}

    def contracts(self):
        cases = []
        def case(name, options, expected=None, error=False, directory="accuracy", text=False):
            record, out, err = self.run(name, options if text else ["--nq-format", "json", *options],
                                        self.fixtures / directory)
            try:
                if error:
                    assert record["returncode"] == 1, f"expected controlled exit1, got {record['returncode']}"
                    assert re.search(r"error|invalid|range|must|illegal", (out.read_text(errors="replace") + err.read_text(errors="replace")), re.I)
                else:
                    assert record["returncode"] == 0, f"unexpected exit {record['returncode']}"
                    actual = json.loads(out.read_text(encoding="utf-8"))
                    if isinstance(expected, list):
                        actual = [(row["ip"], row["port"]) for row in actual]
                    assert actual == expected, f"expected {expected!r}; actual {actual!r}"
                record["contract"] = "passed"
            except (AssertionError, ValueError) as failure:
                record.update(contract="failed", failure=str(failure))
            cases.append(record)
        identity = lambda nums: [(f"192.0.2.{n}", 443) for n in nums]
        case("accuracy-all", [], identity(range(1, 8)))
        case("accuracy-cvss", ["--nq-min-cvss", "8"], identity([1, 3, 4]))
        case("accuracy-epss", ["--nq-min-epss", "0.5"], identity([1, 3, 4]))
        case("accuracy-kev", ["--nq-kev"], identity([1, 3, 4]))
        case("accuracy-kev-tag", ["--nq-tag", "kev"], identity([1, 3, 4]))
        case("accuracy-cve-id", ["--nq-cve", "CVE-2000-0001"], identity([1, 3, 4]))
        case("accuracy-four-byte-asn", ["--nq-asn", "4000000000"], identity([6]))
        case("accuracy-country-case", ["--nq-country", "us"], identity(range(1, 8)))
        case("accuracy-combined", ["--nq-country", "US", "--nq-asn", "64513"], identity([2, 5]))
        case("accuracy-no-match", ["--nq-port", "65535"], [])
        case("accuracy-count", ["--nq-count"], {"count": 7})
        for name, options in [
            ("port-zero", ["--nq-port", "0"]), ("port-overflow", ["--nq-port", "65536"]),
            ("cvss-bounds", ["--nq-min-cvss", "10.1"]), ("epss-bounds", ["--nq-min-epss", "1.1"]),
            ("epss-nan", ["--nq-min-epss", "nan"]), ("asn-overflow", ["--nq-asn", "4294967296"]),
            ("country-digits", ["--nq-country", "12"]), ("format", ["--nq-format", "yaml"])]:
            case("bounds-" + name, options, error=True)
        for name, flag in [("version", "--version"), ("help", "--help")]:
            record, out, _ = self.run(name, [flag])
            record["contract"] = "passed" if record["returncode"] == 0 and out.stat().st_size > 0 else "failed"
            cases.append(record)
        self.save(status="passed" if all(c["contract"] == "passed" for c in cases) else "failed",
                  fixture_bytes=self.fixture_bytes(), fixture_hashes=self.fixture_hashes())
        print(f"contracts: {sum(c['contract'] == 'passed' for c in cases)}/{len(cases)} passed")
        return 0 if all(c["contract"] == "passed" for c in cases) else 1

    def benchmark(self):
        summaries = []
        for count in self.args.sizes:
            expected = [expected_row(i) for i in range(count)]
            workloads = [
                ("full-json", ["--nq-format", "json"], expected),
                ("count", ["--nq-format", "json", "--nq-count"], {"count": count}),
                ("filter", ["--nq-format", "json", "--nq-service", "http", "--nq-country", "us"],
                 [row for row in expected if row["country"] == "US" and "http" in row["service"]]),
                ("export", ["--nq-format", "json", "--nq-output", str(self.output / f"{count}-export.json")], expected),
            ]
            for workload, options, oracle in workloads:
                measurements = []
                for repeat in range(self.args.repeats + 1):
                    name = f"{count}-{workload}-{'warmup' if repeat == 0 else repeat}"
                    record, out, err = self.run(name, options, self.fixtures / str(count))
                    payload = self.output / f"{count}-export.json" if workload == "export" else out
                    try:
                        assert record["returncode"] == 0, "nonzero query exit"
                        actual = json.loads(payload.read_text(encoding="utf-8"))
                        assert actual == oracle, "full normalized result differs from independent fixture oracle"
                        record.update(contract="passed", normalized_sha256=normalized_digest(actual), warmup=(repeat == 0))
                    except (AssertionError, ValueError) as failure:
                        record.update(contract="failed", failure=str(failure))
                        self.save(status="failed", summaries=summaries)
                        return 1  # Never time/claim success for semantically wrong output.
                    if repeat:
                        measurements.append(record)
                    # Retain fixtures, digests and one final export, not duplicate
                    # multi-megabyte successful stdout copies. Failures stay intact.
                    out.unlink()
                    if err.stat().st_size == 0:
                        err.unlink()
                    self.fixture_bytes()
                summaries.append({"rows": count, "workload": workload,
                                  "median_wall_seconds": statistics.median(r["wall_seconds"] for r in measurements),
                                  "min_wall_seconds": min(r["wall_seconds"] for r in measurements),
                                  "max_wall_seconds": max(r["wall_seconds"] for r in measurements),
                                  "repeats": len(measurements)})
                self.save(status="running", summaries=summaries)
        self.save(status="passed", summaries=summaries, fixture_bytes=self.fixture_bytes(), fixture_hashes=self.fixture_hashes())
        print(json.dumps(summaries, indent=2))
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "contracts", "benchmark"))
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 50000])
    parser.add_argument("--repeats", type=int, choices=range(3, 6), default=3)
    parser.add_argument("--budget-seconds", type=int, default=300)
    args = parser.parse_args()
    if not args.sizes or min(args.sizes) < 1 or max(args.sizes) > 50000 or sum(args.sizes) > 61000:
        parser.error("sizes must total at most 61000 rows, each at most 50000")
    if not 1 <= args.budget_seconds <= 300:
        parser.error("budget must be 1..300 seconds")
    driver = Driver(args)
    if args.phase == "prepare":
        driver.prepare()
        return 0
    if not driver.fixtures.is_dir():
        parser.error("run prepare first with the same artifacts directory")
    try:
        return driver.contracts() if args.phase == "contracts" else driver.benchmark()
    except Exception as error:
        driver.save(status="error", error=repr(error))
        raise


if __name__ == "__main__":
    sys.exit(main())
