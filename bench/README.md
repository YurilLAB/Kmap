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

Measured on an **AMD Ryzen 5 5600X (6C/12T), 32 GB, g++ 16.1 `-O2`**,
single-thread unless noted:

| Benchmark | Result |
|---|---|
| `bench_db` write throughput | ~7,900 enriched hosts/sec (Stage-C, 1 shard) |
| `bench_db` size per host | ~1.86 KB (1 port + 5 fingerprints + ASN/cloud/TLS) |
| `bench_db` DB growth / 1e9 IPs | ~8.7 GB @0.5% · ~17 GB @1% · ~35 GB @2% open-port hit |
| `bench_compute` IP generation | ~101 M IPs/sec (permute + exclude) |
| `bench_compute` cloud lookup | ~78 M/sec |
| `bench_compute` mmh3 | ~3.7 GB/sec |
| `bench_compute` sha256 (16 KB) | ~300 MB/sec (~19 K bodies/sec) |
| `bench_compute` favicon (4 KB) | ~80 K/sec |
| `bench_compute` derive_cpe | ~3 M/sec |

Your numbers will differ with CPU, disk, and compiler; re-run and quote your own
hardware. The component benches are deterministic and safe to wire into CI to
keep the README table honest over time.

## Live measurements

See [`measure-live.sh`](measure-live.sh). Needs a built `./kmap` on Linux. Each
metric is reported with the exact env/flags it depends on
(`KMAP_NETSCAN_CONCURRENCY`, `KMAP_PROBE_TIMEOUT_MS`, `--fast`, `--rate`) —
every figure is a function of those knobs, so always quote them next to a result.
