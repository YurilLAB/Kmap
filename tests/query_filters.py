#!/usr/bin/env python3
"""Offline actual-CLI contracts for stored CVE metadata and query arguments.

Only --net-query and --search are invoked; fixture addresses are inert SQLite
values. Every command has a 15-second timeout, and logs/fixtures/hashes survive
failures.
"""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import time
import traceback

from query_performance import digest, fixture, normalized_digest
from runtime_smoke import Runner, require


def definitions():
    high = {"id": "CVE-2000-0001", "cvss": 9.1, "epss": 0.9, "kev": 1, "ransomware": 1}
    compact = json.dumps([high], separators=(",", ":"))
    return [
        (compact, ["kev", "ransomware", "vuln"]),
        ('[{"id":"CVE-2000-0002","cvss":4.0,"epss":5e-05,"kev":0}]', ["vuln"]),
        (json.dumps([high], indent=2), ["kev", "ransomware", "vuln"]),
        (json.dumps([high], indent=2).replace(": ", ":\n "), ["kev", "ransomware", "vuln"]),
        ('[{"id":"CVE-2000-0002","desc":"CVE-2000-0001","cvss":4.0,"epss":0.1}]', ["vuln"]),
        (compact.replace('"CVE-', '"\\u0043ve-'), ["kev", "ransomware", "vuln"]),
        ('[{"id":"CVE-2000-0002","cvss":11,"epss":2,"kev":10,"ransomware":10}]', ["vuln"]),
        ('[{"id":"CVE-2000-0002","cvss":"9","epss":"0.9","kev":"1","ransomware":"1"}]', ["vuln"]),
        ('[{"id":"CVE-2000-0002","cvss":true,"epss":false,"kev":true,"ransomware":true}]', ["kev", "ransomware", "vuln"]),
        ('[{"id":"CVE-2000-0002","details":{"cvss":9,"epss":0.9,"kev":1,"ransomware":1}}]', ["vuln"]),
        ('[', []),
        (json.dumps(high), []),
        ('[42,null,true,"CVE-2000-0001"]', []),
        ('[{"cvss":9,"epss":0.9,"kev":1,"ransomware":1}]', []),
        ('[]', []),
        ('[{"id":"CVE-2000-0002","cvss":-9,"epss":-0.9,"kev":false,"ransomware":false}]', ["vuln"]),
        ('[{"id":"CVE-2000-0001","cvss":9.1e0,"epss":9e-1,"kev":true,"ransomware":true}]', ["kev", "ransomware", "vuln"]),
        ('[]', []),
        ('[{"id":"CVE-2000-0003","cvss":0,"epss":0,"kev":0,"ransomware":0}]', ["vuln"]),
        ('[]', ["cloud", "database", "self-signed"]),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    deadline = time.monotonic() + 300
    binary = args.binary.resolve()
    data = runner.artifacts / "fixture"
    rows, expected = [], []
    for number, (raw, tags) in enumerate(definitions(), 1):
        service = "postgresql" if number == 20 else "https"
        asn = {15: 4000000000, 18: 4294967295}.get(number, 64512)
        row = dict(ip=f"192.0.2.{number}", port=443, service=service, raw_cves=raw,
                   asn=asn, country="US")
        rows.append(row)
        result = dict(ip=row["ip"], port=443, proto="tcp", service=service, asn=asn,
                      country="US", device_class="db" if number == 20 else "web")
        if tags:
            result["tags"] = tags
        if raw != "[]":
            try:
                parsed = json.loads(raw)
                result["cves"] = parsed if isinstance(parsed, list) else raw
            except ValueError:
                result["cves"] = raw
        if number == 20:
            result["cloud"] = "aws"
        expected.append(result)
    fixture(data, rows)
    with closing(sqlite3.connect(data / "shard_024.db")) as db:
        db.executescript("ALTER TABLE hosts ADD COLUMN cloud_provider TEXT;"
                         "ALTER TABLE hosts ADD COLUMN tls_self_signed INTEGER;")
        db.execute("UPDATE hosts SET cloud_provider='aws',tls_self_signed=1 WHERE ip='192.0.2.20'")
        db.commit()
    source_hashes = {name: digest(Path(__file__).resolve().parents[1] / name)
                     for name in ("net_query.cc", "net_query.h", "net_scan.cc",
                                  "json_escape.h", "kmap.cc", "KmapOps.h")}
    metadata = dict(binary=str(binary), binary_sha256=digest(binary), driver_sha256=digest(__file__),
                    helper_hashes={name: digest(Path(__file__).parent / name)
                                   for name in ("query_performance.py", "runtime_smoke.py")},
                    working_source_hashes=source_hashes, fixture_initial_sha256=digest(data / "shard_024.db"))
    cases = []

    def query(name, options=(), error=False, text=False):
        command = [str(binary), "--net-query", "--data-dir", str(data)]
        if not text:
            command += ["--nq-format", "json"]
        remaining = deadline - time.monotonic()
        require(remaining > 0, "300-second suite budget exhausted")
        runner.run(name, [*command, *options], timeout=min(15, remaining),
                   expected_returncodes=(1,) if error else (0,))
        output = (runner.artifacts / (name + ".stdout.log")).read_text(encoding="utf-8")
        if error:
            diagnostic = output + (runner.artifacts / (name + ".stderr.log")).read_text(encoding="utf-8")
            require(any(word in diagnostic.lower() for word in ("error", "invalid", "range", "must", "valid")),
                    "controlled error lacked a diagnostic")
            return None
        return output if text else json.loads(output)

    def case(name, check):
        try:
            check()
            cases.append(dict(name=name, status="passed"))
        except Exception:
            cases.append(dict(name=name, status="failed", error=traceback.format_exc()))
        runner.save(**metadata, cases=cases)

    def subset(name, options, numbers):
        actual = query(name, options)
        oracle = [expected[i - 1] for i in numbers]
        require(actual == oracle, f"{name}: complete result differs; expected {oracle!r}; actual {actual!r}")

    case("all-fields-tags", lambda: subset("all", [], range(1, 21)))
    for name, options, numbers in [
        ("cvss", ["--nq-min-cvss", "8"], [1, 3, 4, 6, 17]),
        ("epss", ["--nq-min-epss", "0.5"], [1, 3, 4, 6, 17]),
        ("kev", ["--nq-kev"], [1, 3, 4, 6, 9, 17]),
        ("kev-tag", ["--nq-tag", "KeV"], [1, 3, 4, 6, 9, 17]),
        ("ransomware", ["--nq-tag", "ransomware"], [1, 3, 4, 6, 9, 17]),
        ("id", ["--nq-cve", "cVe-2000-0001"], [1, 3, 4, 6, 17]),
        ("id-fragment-prefix", ["--nq-cve", "CVE-2000-000"], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 17, 19]),
        ("id-fragment-interior", ["--nq-cve", "2000-0001"], [1, 3, 4, 6, 17]),
        ("id-no-like-wildcard", ["--nq-cve", "CVE-%"], []),
        ("id-no-like-underscore", ["--nq-cve", "CVE-2000-000_"], []),
        ("asn-large", ["--nq-asn", "4000000000"], [15]),
        ("asn-max", ["--nq-asn", "4294967295"], [18]),
        ("non-cve-tags", ["--nq-tag", "cloud"], [20]),
        ("country-case", ["--nq-country", "uS"], range(1, 21)),
    ]:
        case(name, lambda n=name, o=options, ids=numbers: subset(n, o, ids))
    # Substring filters are literal: '%' and '_' in the argument are not LIKE wildcards.
    literal = runner.artifacts / "literal-fixture"
    fixture(literal, [
        dict(ip="192.0.2.1", port=80, service="http", web_title="Admin Panel", web_server="srv_a"),
        dict(ip="192.0.2.2", port=80, service="http", web_title="Admin_Panel", web_server="srv%b"),
        dict(ip="192.0.2.3", port=80, service="http", web_title="100% uptime"),
        dict(ip="192.0.2.4", port=80, service="http", web_title="1000 servers")])

    def literal_ips(name, options):
        runner.run(name, [str(binary), "--net-query", "--data-dir", str(literal),
                          "--nq-format", "json", *options], timeout=15)
        return [r["ip"] for r in json.loads((runner.artifacts / (name + ".stdout.log")).read_text())]
    for name, options, ips in [
        ("title-underscore", ["--nq-web-title", "Admin_Panel"], ["192.0.2.2"]),
        ("title-percent", ["--nq-web-title", "100%"], ["192.0.2.3"]),
        ("server-percent", ["--nq-web-server", "srv%"], ["192.0.2.2"]),
        ("title-substring", ["--nq-web-title", "admin"], ["192.0.2.1", "192.0.2.2"]),
    ]:
        case(name, lambda n=name, o=options, e=ips: require(
            literal_ips(n, o) == e, f"{n}: rows differ from the literal-substring oracle"))
    case("filtered-count", lambda: require(query("filtered-count", ["--nq-cve", "CVE-2000-0001", "--nq-count"])
                                           == {"count": 5}, "filtered count differs"))
    for name, options, count in [
        ("count-ordinary", [], 20),
        ("count-device", ["--nq-device", "web"], 19),
        ("count-device-database", ["--nq-device", "db"], 1),
        ("count-device-no-match", ["--nq-device", "ftp"], 0),
        ("count-sql", ["--nq-asn", "4294967295", "--nq-country", "us"], 1),
        ("count-cidr-device", ["--nq-ip-range", "192.0.2.16/28", "--nq-device", "web"], 4),
        ("count-cve-fragment", ["--nq-cve", "2000-0001"], 5),
        ("count-score", ["--nq-min-cvss", "8"], 5),
        ("count-epss", ["--nq-min-epss", "0.5"], 5),
        ("count-kev", ["--nq-kev"], 6),
        ("count-tag", ["--nq-tag", "ransomware"], 6),
        ("count-combined", ["--nq-min-cvss", "8", "--nq-min-epss", "0.5", "--nq-kev", "--nq-tag", "ransomware"], 5),
        ("count-device-cve", ["--nq-device", "db", "--nq-cve", "2000-0001"], 0),
    ]:
        case(name, lambda n=name, o=options, c=count: require(
            query(n, [*o, "--nq-count"]) == {"count": c}, n + ": count differs from fixture oracle"))

    # Explicit JSON format; query(text=True) avoids trying to parse stdout diagnostics.
    def export_json():
        target = runner.artifacts / "export.json"
        query("export", ["--nq-format", "json", "--nq-output", str(target)], text=True)
        require(json.loads(target.read_text(encoding="utf-8")) == expected, "export differs from independent oracle")
    case("file-export", export_json)

    def text_summaries():
        output = query("text", ["--nq-format", "text", "--nq-cve", "CVE-2000-0001"], text=True)
        lines = [line for line in output.splitlines() if line.startswith("192.0.2.")]
        require(len(lines) == 5, "text query omitted equivalent JSON rows")
        require(all("(CVSS:9.1)" in line and "[kev, ransomware, vuln]" in line for line in lines),
                "text summary/tags differ across equivalent JSON formatting")
    case("text-summaries", text_summaries)
    for name, options in [
        ("epss-nan", ["--nq-min-epss", "nan"]), ("cvss-nan", ["--nq-min-cvss", "NaN"]),
        ("epss-infinity", ["--nq-min-epss", "inf"]), ("cvss-overflow", ["--nq-min-cvss", "1e999"]),
        ("asn-overflow", ["--nq-asn", "4294967296"]), ("asn-strtoull-overflow", ["--nq-asn", "18446744073709551616"]),
        ("asn-zero", ["--nq-asn", "0"]), ("asn-negative", ["--nq-asn", "-1"]),
        ("asn-trailing", ["--nq-asn", "64512junk"]), ("country-digits", ["--nq-country", "12"]),
        ("country-mixed", ["--nq-country", "U1"]), ("country-short", ["--nq-country", "U"]),
    ]:
        case("invalid-" + name, lambda n=name, o=options: query("invalid-" + n, o, error=True))

    # Search shares the collected store with --net-query, but has a separate
    # output path. Exercise it through the actual CLI, including legacy raw
    # banner bytes and errors that must never look like an empty successful
    # result. These fixtures are inert database values, not scan targets.
    search_data = runner.artifacts / "search-fixture"
    fixture(search_data, [dict(ip="192.0.2.1", port=80, service="http")])
    raw_title = 'Café 東京 "quoted"\n'.encode("utf-8") + b"\xff\xed\xa0\x80\xe2"
    with closing(sqlite3.connect(search_data / "shard_024.db")) as db:
        db.execute("UPDATE hosts SET web_title=CAST(? AS TEXT)", (raw_title,))
        db.commit()

    def search(name, directory=search_data, options=(), error=False):
        runner.run(name, [str(binary), "--search", "http", "--data-dir", str(directory),
                          "--search-format", "json", *options], timeout=15,
                   expected_returncodes=(1,) if error else (0,))
        output = (runner.artifacts / (name + ".stdout.log")).read_bytes()
        if error:
            diagnostic = (runner.artifacts / (name + ".stderr.log")).read_text(encoding="utf-8")
            require(any(word in diagnostic.lower() for word in ("error", "cannot", "failed")),
                    "search error lacked a diagnostic")
            return None
        if "--search-output" in options:
            return None
        return json.loads(output.decode("utf-8"))

    def search_json():
        actual = search("search-utf8")
        require(len(actual) == 1 and actual[0]["web_title"] ==
                'Café 東京 "quoted"\n' + "\ufffd" * 5,
                "search JSON did not repair malformed/truncated UTF-8")
        target = runner.artifacts / "search-export.json"
        search("search-export", options=["--search-output", str(target)])
        require(json.loads(target.read_text(encoding="utf-8")) == actual,
                "search file export differs from stdout JSON")

    case("search-json-utf8-export", search_json)
    case("search-missing-directory", lambda: search("search-missing", runner.artifacts / "missing", error=True))
    bad_search_data = runner.artifacts / "search-corrupt"
    bad_search_data.mkdir()
    (bad_search_data / "shard_025.db").write_bytes(b"invalid SQLite fixture")
    case("search-corrupt-shard", lambda: search("search-corrupt", bad_search_data, error=True))
    # Good matches in one shard must not mask another shard's failure.
    (search_data / "shard_025.db").write_bytes(b"invalid SQLite fixture")

    def partial_search():
        target = runner.artifacts / "search-preserved.json"
        original = b"previous complete search export\n"
        target.write_bytes(original)
        search("search-partial", options=["--search-output", str(target)], error=True)
        require(target.read_bytes() == original,
                "a failed search replaced an existing export with partial results")

    case("search-partial-store", partial_search)
    (search_data / "shard_025.db").unlink()
    if Path("/dev/full").exists():
        case("search-full-output", lambda: search("search-full-output",
             options=["--search-output", "/dev/full"], error=True))
    passed = all(c["status"] == "passed" for c in cases)
    runner.save(**metadata, status="passed" if passed else "failed", cases=cases,
                expected_normalized_sha256=normalized_digest(expected), fixture_final_sha256=digest(data / "shard_024.db"))
    print(f"query filters: {sum(c['status'] == 'passed' for c in cases)}/{len(cases)} passed; {runner.artifacts}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
