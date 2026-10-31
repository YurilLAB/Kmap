#!/usr/bin/env python3
"""Actual ordinary-scan output contracts with offline/owned-loopback fixtures.

No raw sockets, service detection, NSE, enrichment, or public targets. A failed
fixture prerequisite fails the run. Every child has a deadline and is reaped;
logs and output files remain in a fresh artifact directory on success/failure.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import subprocess
import threading
import time
import traceback
import xml.etree.ElementTree as ET


IPS = ("127.0.0.1", "127.0.0.2")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@contextlib.contextmanager
def listeners():
    """Two listening endpoints plus reserved non-listening endpoints.

    The third address has only non-listening sockets and supplies the --open
    filtering oracle. Binding every closed endpoint prevents port reuse races.
    """
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            with self.server.lock:
                self.server.accepted += 1

    class Server(socketserver.TCPServer):
        allow_reuse_address = False

        def __init__(self, address):
            self.lock = threading.Lock()
            self.accepted = 0
            super().__init__(address, Handler)

    servers, running, threads, reservations = [], [], [], []
    try:
        first = Server((IPS[0], 0))
        servers.append(first)
        open_port = first.server_address[1]
        servers.append(Server((IPS[1], open_port)))
        for server in servers:
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": .02})
            thread.start()
            running.append(server)
            threads.append(thread)
        # Readiness is an actual connection to each owned listener.
        for ip in IPS:
            with socket.create_connection((ip, open_port), timeout=2):
                pass
        closed_port = 0
        for ip in (*IPS, "127.0.0.3"):
            reservation = socket.socket()
            reservations.append(reservation)
            reservation.bind((ip, closed_port))
            closed_port = reservation.getsockname()[1]
        reservation = socket.socket()
        reservations.append(reservation)
        reservation.bind(("127.0.0.3", open_port))
        yield open_port, closed_port
    finally:
        for server in servers:
            if server in running:
                server.shutdown()
            server.server_close()
        for reservation in reservations:
            reservation.close()
        for thread in threads:
            thread.join(3)
            require(not thread.is_alive(), "owned fixture did not stop")


@contextlib.contextmanager
def timeout_ports():
    """A bounded, no-NSE delay fixture; no host response is needed."""
    sockets = []
    try:
        for _ in range(16):
            reservation = socket.socket()
            sockets.append(reservation)
            reservation.bind((IPS[0], 0))
        yield sorted(s.getsockname()[1] for s in sockets)
    finally:
        for reservation in sockets:
            reservation.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/output"))
    parser.add_argument("--total-timeout", type=float, default=120)
    parser.add_argument("--only", choices=("offline", "timeout"),
                        help="Explicit local subset; normal CI omits this")
    parser.add_argument("--include-timeout", action="store_true",
                        help="Also require the timeout oracle in an explicitly selected offline subset")
    args = parser.parse_args()
    if args.total_timeout <= 0:
        parser.error("--total-timeout must be positive")
    source, binary = args.source.resolve(), args.binary.resolve()
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + args.total_timeout
    results = {
        "scope": "ordinary scan output; offline files and owned IPv4 loopback only",
        "complete_default_run": args.only is None,
        "timeout_oracle_required": args.only is None or args.include_timeout or args.only == "timeout",
        "budget_seconds": args.total_timeout,
        "binary": str(binary), "binary_sha256_start": digest(binary),
        "driver_sha256_start": digest(Path(__file__)),
        "source_inputs": {p: digest(source / p) for p in
                          ("kmap.cc", "output_json.cc", "output_json.h", "output.cc", "Target.h")},
        "cases": [], "unsupported_optional_checks": [],
    }
    saved_outputs = {}

    def save():
        results["elapsed_seconds"] = round(time.monotonic() - started, 3)
        temporary = out / "results.json.tmp"
        temporary.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        temporary.replace(out / "results.json")

    def run(name, options, targets=IPS, emitted=None, suffix=".txt", states=None,
            bad_json=False, bad_report=False, full_device=None, timedout=False):
        case_dir = out / name
        case_dir.mkdir()
        xml = case_dir / "scan.xml"
        js = case_dir / "scan.json"
        report = case_dir / ("scan" + suffix)
        if bad_json:
            js.mkdir()
        if bad_report:
            report.mkdir()
        if full_device == "json":
            js = Path("/dev/full")
        if full_device == "report":
            report = Path("/dev/full")
        expect_error = bad_json or bad_report or full_device is not None
        expected_ips = list(targets if emitted is None else emitted)
        command = [str(binary), "--datadir", str(source), "--unprivileged", "-n", *options,
                   "-oX", str(xml), "-oJ", str(js), "--report", str(report), *targets]
        row = {"name": name, "command": command, "oracles": []}
        results["cases"].append(row)

        def check(name, expected, actual):
            passed = actual == expected
            row["oracles"].append({"name": name, "expected": expected,
                                   "actual": actual, "passed": passed})

        launch = time.monotonic()
        try:
            remaining = deadline - launch
            require(remaining > 0, "total output-contract deadline exhausted")
            row["timeout_seconds"] = min(12, remaining)
            with (case_dir / "stdout.log").open("wb") as stdout, (case_dir / "stderr.log").open("wb") as stderr:
                child = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout,
                                       stderr=stderr, timeout=row["timeout_seconds"], cwd=case_dir,
                                       env={**os.environ, "LC_ALL": "C"})
            row["returncode"] = child.returncode
            check("exit_status", 1 if expect_error else 0, child.returncode)
            root = ET.parse(xml).getroot()
            finished = root.find("runstats/finished")
            require(finished is not None, "XML did not contain final run statistics")
            check("xml_exit", "error" if expect_error else "success", finished.get("exit"))
            if expect_error:
                check("xml_output_error_diagnostic", True, bool(finished.get("errormsg")))
            xml_hosts = root.findall("host")
            xml_ips = [h.find("address[@addrtype='ipv4']").get("addr") for h in xml_hosts]
            check("known_xml_hosts", sorted(expected_ips), sorted(xml_ips))
            xml_total = int(root.find("runstats/hosts").get("total"))
            expected_total = 0 if "--exclude" in options else len(targets)
            check("xml_scanned_count", expected_total, xml_total)
            if timedout:
                check("timeout_path_reached", [True], [h.get("timedout") == "true" for h in xml_hosts])
            if not bad_json and full_device != "json":
                document = json.loads(js.read_text(encoding="utf-8"))
                json_hosts = document["hosts"]
                json_by_ip = {next(a["addr"] for a in h["addresses"] if a["addrtype"] == "ipv4"): h
                              for h in json_hosts}
                check("json_no_duplicate_hosts", len(json_hosts), len(json_by_ip))
                check("known_json_hosts", sorted(expected_ips), sorted(json_by_ip))
                check("json_scanned_count", expected_total, document["stats"]["hosts_total"])
                for metric in ("up", "down"):
                    check("json_xml_hosts_" + metric, int(root.find("runstats/hosts").get(metric)),
                          document["stats"]["hosts_" + metric])
                for host in xml_hosts:
                    ip = host.find("address[@addrtype='ipv4']").get("addr")
                    jhost = json_by_ip.get(ip)
                    if jhost is None:
                        continue
                    check(ip + "_status", host.find("status").get("state"), jhost["status"]["state"])
                    if "-sL" in options:
                        check(ip + "_listed_state", "unknown", jhost["status"]["state"])
                    if timedout:
                        check(ip + "_json_timeout", True, jhost.get("timedout", False))
                    if states and ip in states:
                        xp = {int(p.get("portid")): p.find("state").get("state") for p in host.findall("ports/port")}
                        jp = {p["portid"]: p["state"]["state"] for p in jhost["ports"]}
                        check(ip + "_xml_port_ground_truth", states[ip], xp)
                        check(ip + "_json_port_ground_truth", states[ip], jp)
            if not bad_report and full_device != "report":
                check("report_created", True, report.is_file())
                if report.is_file():
                    text = report.read_text(encoding="utf-8")
                    report_ips = re.findall(r"(?:TARGET: |## Target: )(127\.0\.0\.[123])", text)
                    check("known_report_hosts", sorted(expected_ips), sorted(report_ips))
                    markdown = suffix.lower() == ".md"
                    heading = r"^## Target: (127\.0\.0\.[123]).*$" if markdown else r"^  TARGET: (127\.0\.0\.[123]).*$"
                    headers = list(re.finditer(heading, text, re.M))
                    for index, header in enumerate(headers):
                        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
                        section = text[header.start():end]
                        ip = header.group(1)
                        if states and ip in states:
                            pattern = (r"^\|\s*(\d+)/tcp\s*\|\s*([a-z|]+)\s*\|" if markdown else
                                       r"^\s*(\d+)/tcp\s+([a-z|]+)\b")
                            report_ports = {int(port): state for port, state in re.findall(pattern, section, re.M)}
                            check(ip + "_report_port_ground_truth", states[ip], report_ports)
                        if "-sL" in options:
                            state = re.search(r"\*\*Status:\*\* (\w+)" if markdown else r"\[(\w+)\]", section)
                            check(ip + "_report_listed_state", "unknown", state.group(1) if state else None)
                    if timedout:
                        check("report_timeout", True, "[timeout]" in text or "**Status:** timeout" in text)
                    if "-sL" in options and expected_ips:
                        check("report_listed_state", True, "[unknown]" in text or "**Status:** unknown" in text)
            if bad_report or full_device == "report":
                text = (case_dir / "stdout.log").read_text(encoding="utf-8", errors="replace")
                check("no_false_report_success", False, "Report written to " in text)
            if expect_error:
                diagnostic = (case_dir / "stderr.log").read_text(encoding="utf-8", errors="replace")
                if bad_json or full_device == "json":
                    check("json_failure_explained", True, "JSON output" in diagnostic)
                if bad_report or full_device == "report":
                    check("report_failure_explained", True, "report file" in diagnostic)
            row["status"] = "passed" if all(c["passed"] for c in row["oracles"]) else "failed"
        except Exception:
            row.update(status="failed", error=traceback.format_exc())
        finally:
            row["elapsed_seconds"] = round(time.monotonic() - launch, 3)
            row["artifact_sha256"] = {p.name: digest(p) for p in case_dir.iterdir() if p.is_file()}
            for path in (xml, js, report):
                if path.parent == case_dir and path.is_file():
                    saved_outputs[str(path)] = digest(path)
            save()

    try:
        if args.only != "timeout":
            run("list-txt", ["-sL", "-v"])
            run("list-md-uppercase", ["-sL", "-v"], suffix=".MD")
            run("no-port-md", ["-Pn", "-sn"], suffix=".md")
            run("empty-txt", ["-sL", "-v"], targets=())
            run("excluded-md", ["-sL", "-v", "--exclude", ",".join(IPS)], emitted=(), suffix=".md")
            run("json-output-directory", ["-sL", "-v"], targets=IPS[:1], bad_json=True)
            run("report-output-directory", ["-sL", "-v"], targets=IPS[:1], bad_report=True)
            run("both-output-directories", ["-sL", "-v"], targets=IPS[:1], bad_json=True, bad_report=True)
            if os.name == "posix" and Path("/dev/full").exists() and stat.S_ISCHR(Path("/dev/full").stat().st_mode):
                run("json-buffered-write-failure", ["-sL", "-v"], targets=IPS[:1], full_device="json")
                run("report-buffered-write-failure", ["-sL", "-v"], targets=IPS[:1], full_device="report")
            else:
                results["unsupported_optional_checks"].append("POSIX /dev/full buffered-write failure checks")
        if args.only is None:
            with listeners() as (opened, closed):
                options = ["-Pn", "-sT", "--max-retries", "0", "--max-hostgroup", "1", "-p", f"{opened},{closed}"]
                states = {ip: {opened: "open", closed: "closed"} for ip in IPS}
                run("groups-txt", options, states=states)
                run("groups-md", options, suffix=".md", states=states)
                run("open-filter", [*options, "--open"], targets=(IPS[0], "127.0.0.3"),
                    emitted=(IPS[0],), suffix=".md", states={IPS[0]: {opened: "open"}})
        if args.only is None or args.include_timeout or args.only == "timeout":
            with timeout_ports() as ports:
                run("timeout", ["-Pn", "-sT", "-r", "--max-retries", "0",
                                "--scan-delay", "200ms", "--host-timeout", "250ms", "-p", ",".join(map(str, ports))],
                    targets=IPS[:1], timedout=True)
        results["persisted_outputs_unchanged"] = all(digest(Path(p)) == value for p, value in saved_outputs.items())
    except Exception:
        results["fixture_error"] = traceback.format_exc()
    finally:
        results["binary_sha256_end"] = digest(binary)
        results["driver_sha256_end"] = digest(Path(__file__))
        results["source_inputs_end"] = {p: digest(source / p) for p in results["source_inputs"]}
        results["status"] = "passed" if (results["cases"] and
            all(c["status"] == "passed" for c in results["cases"]) and
            results.get("persisted_outputs_unchanged", False) and not results.get("fixture_error") and
            results["binary_sha256_start"] == results["binary_sha256_end"] and
            results["driver_sha256_start"] == results["driver_sha256_end"]) else "failed"
        save()
    print(f"output contracts: {sum(c['status'] == 'passed' for c in results['cases'])}/{len(results['cases'])} passed; {out}")
    return 0 if results["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
