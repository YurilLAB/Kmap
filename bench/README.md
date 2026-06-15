# Kmap benchmarks

Reproducible micro-benchmarks that link the **real** Kmap code (no mock paths),
plus a recipe for the metrics that need a live binary and a network target.

Two kinds of numbers:

- **Component benchmarks** (`bench_db`, `bench_compute`) measure the subsystems
  that are pure CPU / disk — DB write throughput, on-disk growth, and the
  per-host enrichment primitives. They build and run anywhere a C++17 compiler
  and the bundled sqlite are present (including CI), so they give honest,
  reproducible numbers without a full link against libpcap/OpenSSL.
- **Live measurements** (`measure-live.sh`) cover the metrics that only a
  running `./kmap` against a network target can produce: network IPs/sec, peak
  RSS, and screenshot throughput. They are pinned to loopback / TEST-NET-1
  (RFC 5737, non-routable) so **no real host is ever touched.**

## Building & running the component benchmarks

From the repo root:

```bash
# one-time: compile the bundled sqlite amalgamation
cc -O1 -c sqlite/sqlite3.c -o /tmp/sqlite3.o

# DB write throughput + on-disk growth (writes N fully-enriched hosts)
g++ -O2 -std=gnu++17 -I. -Inbase bench/bench_db.cc net_db.cc /tmp/sqlite3.o \
    -lpthread -ldl -o /tmp/bench_db          # Linux
# Windows/MinGW: add -DWIN32 and -lws2_32 -lbcrypt instead of -lpthread -ldl
/tmp/bench_db 200000

# Enrichment CPU primitives + IP-generation rate
g++ -O2 -std=gnu++17 -I. bench/bench_compute.cc net_hash_helpers.cc cloud_map.cc \
    -o /tmp/bench_compute
/tmp/bench_compute
```

> On the dev box (MinGW), add `-static-libstdc++ -static-libgcc` to anything that
> touches `<fstream>` (`bench_compute` loads `kmap-cloud-ranges.csv`) — the
> system `libstdc++-6.dll` on `PATH` can be ABI-mismatched with the compiler.

## Reference results

Measured on **Windows 11 Pro (build 26200), AMD Ryzen 5 5600X (6C/12T) @ 4.27 GHz,
32 GB, MinGW g++ 16.1 `-O2`**, single-thread unless noted. (These component benches
link the real `.cc` via g++; the shipping `kmap.exe` is built with MSVC / VS 2026.)

| Benchmark | Result |
|---|---|
| `bench_db` write throughput | ~8,070 enriched hosts/sec (Stage-C, 1 shard; 56.5 K row-ops/sec) |
| `bench_db` size per host | ~1.86 KB / 1,862 B (1 port + 5 fingerprints + ASN/cloud/TLS) |
| `bench_db` DB growth / 1e9 IPs | ~8.7 GB @0.5% · ~17.3 GB @1% · ~34.7 GB @2% open-port hit |
| `bench_compute` IP generation | ~111 M IPs/sec (permute + exclude) |
| `bench_compute` cloud lookup | ~82 M/sec |
| `bench_compute` mmh3 | ~3.76 GB/sec |
| `bench_compute` sha256 (16 KB) | ~311 MB/sec (~19.9 K bodies/sec) |
| `bench_compute` favicon (4 KB) | ~86 K/sec |
| `bench_compute` derive_cpe | ~3.4 M/sec |

Live-binary metrics (MSVC `kmap.exe`, same box) — peak RSS via PowerShell
`WorkingSet64` polling, since GNU `time -v` is Linux-only:

| Live metric | Result |
|---|---|
| Peak RSS, enriching scan (`--cve-map --web-recon`) | ~22 MB |
| Peak RSS, default `/24` discovery | ~28 MB |
| Peak RSS, `--fast` `/24` discovery | ~42 MB |

Full pipeline on a **real random internet sample** (no synthetic targets;
`--net-scan --net-max-ips 5000 -p 80,443,22 --cve-map`, 400 workers / 1.2 s):

| Full-pipeline metric | Result |
|---|---|
| Discovery | 5,000 IPs in ~15 s (~333 IPs/sec) |
| Open ports / live hosts | 154 ports across 89 hosts |
| Enrichment (incl. CVE matching) | ~25 s (~3.6 hosts/sec, avg 3.7 s/host) |
| CVE-bearing ports persisted | 25 |
| End-to-end (discover→enrich→report) | ~40 s |

Your numbers will differ with CPU, disk, and compiler; re-run and quote your own
hardware. The component benches are deterministic and safe to wire into CI to
keep the README table honest over time.

## Live measurements

See [`measure-live.sh`](measure-live.sh). Needs a built `kmap` and a network
target. On Linux it uses GNU `/usr/bin/time -v` for peak RSS; on Windows, where
that isn't available, sample the process instead — poll `WorkingSet64` while the
scan runs (the lifetime peak is not retained after exit):

```powershell
$p = Start-Process .\kmap.exe -ArgumentList '--net-scan','192.0.2.0/24','-p','80','--no-builtin-excludes','--data-dir','d' -PassThru -NoNewWindow
$peak = 0; while (-not $p.HasExited) { $ws=(Get-Process -Id $p.Id).WorkingSet64; if ($ws -gt $peak){$peak=$ws}; Start-Sleep -Milliseconds 40 }
"peak RSS = {0} MB" -f [math]::Round($peak/1MB,1)
```

Each metric is reported with the exact env/flags it depends on
(`KMAP_NETSCAN_CONCURRENCY`, `KMAP_PROBE_TIMEOUT_MS`, `--fast`, `--rate`) —
every figure is a function of those knobs, so always quote them next to a result.

## Full-pipeline benchmark (real random internet sample)

The component benches isolate subsystems; this exercises the **whole pipeline**
— random-IP discovery → service/version detection → CVE matching against
`kmap-cve.db` → enrichment → sharded storage → report. It uses a bounded random
sample of the public IPv4 space (the multiplicative-inverse permutation, with
the built-in reserved/private excludes still applied), so it touches **real
hosts** — run it only where outbound connect-scanning of a random sample is
acceptable for your link.

```bash
# 5,000-IP random sample on the three most common ports, with CVE matching.
KMAP_NETSCAN_CONCURRENCY=400 KMAP_PROBE_TIMEOUT_MS=1200 \
  ./kmap --net-scan --net-max-ips 5000 -p 80,443,22 --cve-map --data-dir bench-pipe
# Read the per-phase wall times from the "discovery/enrichment phase complete"
# log lines; count results + CVE-bearing ports with:
./kmap --net-query --data-dir bench-pipe | grep -c ':.*tcp'     # open ports
./kmap --net-query --data-dir bench-pipe | grep -c 'CVE-'       # CVE matches
```

`hosts/sec = hosts_enriched / enrichment_seconds`; `IPs/sec = max_ips /
discovery_seconds`. Discovery tracks `workers / timeout` on dark space and
`workers / RTT` on responsive hosts; enrichment is internet-bound (banner +
HTTP + TLS + ASN + reverse-DNS round-trips per host), so raise
`KMAP_NETSCAN_ENRICH_CONCURRENCY` to overlap more hosts.
