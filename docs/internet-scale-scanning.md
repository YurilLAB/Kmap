# Internet-scale scanning

Kmap's headline capability is sweeping large slices of the IPv4 internet from
an ordinary machine and turning open ports into a queryable, CVE-tagged attack
surface. This guide covers the end-to-end `--net-scan` pipeline: how discovery
works, how to run it safely, how to resume and sample, and how the data is laid
out on disk.

For tuning throughput on your hardware, see
[`docs/performance.md`](performance.md). For searching the results afterwards,
see [`docs/querying.md`](querying.md).

---

## The pipeline at a glance

`--net-scan` runs three phases in order:

| Phase | What it does | Output |
|-------|--------------|--------|
| **1. Discover** | Sweeps IPs in randomized order, probing each port; records open ports | shard databases in `kmap-data/` |
| **2. Enrich** | Re-visits open ports: banner/service/version detection, CVE matching, web fingerprint, TLS, ASN/geo | enrichment columns on each host row |
| **3. Report** | Renders human-readable findings | `Findings/findings_NNN.txt` |

```bash
# Full pipeline against a single port across a sample of the internet
kmap --net-scan -p 443 --net-max-ips 100000
```

Each phase can be run on its own (see [Running phases independently](#running-phases-independently)),
which is how you split a long sweep across sessions or machines.

---

## How discovery works

Discovery does **not** require root/administrator. It uses non-blocking
`connect()` probes rather than raw SYN packets, so it runs unprivileged on any
OS. A shared token-bucket rate limiter caps the global send rate; a pool of
worker threads keeps enough probes in flight to saturate network round-trip
time without straining the CPU (a probe wave typically sits at ≈1–2% CPU — the
bottleneck is the network, not your box).

Three properties make it internet-scale-safe:

- **Randomized IP order.** IPs are visited via a multiplicative-inverse
  permutation over the full 2³² space, so a sweep spreads load evenly across
  networks instead of hammering one /16 at a time. Every address is visited
  exactly once per full sweep.
- **Reserved/private ranges are skipped automatically.** The built-in exclude
  list covers RFC 1918 private space, loopback, link-local, CGNAT, multicast,
  documentation/benchmark ranges, and assorted reserved/DoD blocks. Add your
  own with `--exclude-file`.
- **Early-bail on dead hosts.** After 8 consecutive no-response probes on a
  host that has shown zero signs of life, the remaining ports for that host are
  skipped. A single `RST` (closed port) counts as "alive" and resets the bail,
  so a firewalled-but-up host still gets fully scanned.

### Choosing ports

The canonical internet-scale workload is a **single port across many IPs** —
for example, "find every HTTPS endpoint in this slice":

```bash
kmap --net-scan -p 443 --net-max-ips 1000000
```

A single-port sweep takes Kmap's fastest internal path (no per-host port
fan-out). If you don't pass `-p`, discovery falls back to a built-in **top-100
ports** list. Multi-port sweeps are best reserved for bounded samples or
watchlists, not full-internet runs — each extra port multiplies the probe
count by the number of hosts.

### Rate

`--rate <pps>` caps packets per second across all workers (default **25000**).
The default is a deliberate, neighbourly ceiling that respects residential
uplinks and avoids tripping upstream abuse detection. Raise it only when you
own or are authorized for the path and have the bandwidth:

```bash
kmap --net-scan -p 443 --rate 50000
```

The rate limiter starts gently (no opening burst) so the first second of a scan
doesn't spike your NIC or a downstream IDS.

---

## Sampling and resuming

A full IPv4 sweep is enormous. Two flags let you work in slices.

### `--net-max-ips <N>` — scan a bounded sample

Caps discovery at N IP indices and stops. Combined with the checkpoint, each
re-run **continues past** the previous slice rather than rescanning the same
first-N addresses:

```bash
kmap --net-scan -p 443 --net-max-ips 500000          # first 500k
kmap --net-scan -p 443 --net-max-ips 500000 --net-resume   # next 500k
```

### `--net-resume` — pick up an interrupted scan

Discovery writes a checkpoint to `<data-dir>/.net-scan-checkpoint` every 60
seconds and on a clean `Ctrl+C`. `--net-resume` restarts from that point using
the **same permutation seed** as the original run, so the IP order is preserved
and no address is skipped or double-scanned.

```bash
kmap --net-scan -p 443                # start a full sweep
# ... Ctrl+C after a while ...
kmap --net-scan -p 443 --net-resume   # continue where it stopped
```

> The seed lives in the checkpoint. A checkpoint that shows progress but has no
> seed (from a very old build) is refused rather than resumed incorrectly —
> delete it and restart if you hit that.

---

## Running phases independently

By default `--net-scan` runs all three phases. To split the work:

| Flag | Runs | Typical use |
|------|------|-------------|
| `--discover-only` | Phase 1 only | Collect open ports fast; enrich later/elsewhere |
| `--enrich-only` | Phase 2 only | Enrich a store you discovered earlier |
| `--report-only` | Phase 3 only | Regenerate findings without re-touching the network |

```bash
# Day 1: discover only, fast
kmap --net-scan -p 443 --discover-only --net-max-ips 2000000

# Day 2: enrich the collected hosts (banner/CVE/web/TLS)
kmap --net-scan --enrich-only

# Anytime: rebuild the findings report from enriched data
kmap --net-scan --report-only
```

The three are mutually exclusive — passing two at once is an error.

---

## On-disk layout

Everything a scan produces lives under two directories (both gitignored):

| Path | Default | Contents |
|------|---------|----------|
| Data dir | `kmap-data/` | 32 shard databases, checkpoint, event log |
| Findings dir | `Findings/` | `findings_NNN.txt` reports |

Override with `--data-dir <dir>` and `--findings-dir <dir>`.

### Sharding

Discovered hosts are spread across **32 SQLite shard databases**
(`shard_000.db` … `shard_031.db`), keyed by the top 5 bits of the IP. Sharding
keeps each database small enough to stay fast on a desktop SSD and lets the
enrichment phase work on shards in parallel. You don't manage shards directly —
`--net-query` reads across all of them transparently.

### The event log

Every run appends to `<data-dir>/kmap.log` with ISO timestamps. Always check it
after a scan, even one that looked fine on screen — warnings that scrolled past
(missing CVE database, per-host enrichment failures, malformed exclude lines)
stay here:

```bash
tail -20 kmap-data/kmap.log
grep -E "  (WARN|ERROR) " kmap-data/kmap.log | tail
```

A healthy run logs at minimum a scan-start line, a CVE-database line, and a
scan-complete line with per-phase wall times.

---

## Watchlist mode

For a fixed, known set of targets (not a random sweep), use `--watchlist`:

```bash
kmap --net-scan --watchlist targets.txt
```

The file holds one IP or CIDR per line (`#` comments allowed). CIDR blocks up
to **/16** (65,534 hosts) are expanded in full; anything larger is rejected
with a warning rather than silently collapsed — keep full-internet-scale work
on `--net-scan`, and use the watchlist for targeted asset lists. Watchlist mode
is **cumulative and non-destructive**: it never deletes prior results, so
re-running it tracks each host over time (`first_seen` / `last_seen` /
`scan_count`) and produces a diff report showing what newly opened, changed, or
went dark since the last run. This is the right tool for monitoring your own
assets on a schedule.

---

## After the scan

```bash
# What did we find?
kmap --net-query --nq-count
kmap --net-query --nq-port 443 --nq-min-cvss 9.0

# Sanity-check the store
sqlite3 kmap-data/shard_000.db "SELECT COUNT(*) FROM hosts;"
```

See [`docs/querying.md`](querying.md) for the full filter set (port, service,
CVE, CVSS, ASN, country, web title/server, device class) and output formats.

---

## Quick reference

```bash
# Single-port sample sweep, full pipeline
kmap --net-scan -p 443 --net-max-ips 100000

# Top-100-port bounded sample
kmap --net-scan --net-max-ips 50000

# Faster sweep (authorized paths only)
kmap --net-scan -p 80,443 --rate 50000 --net-max-ips 1000000

# Discover now, enrich later
kmap --net-scan -p 22 --discover-only --net-max-ips 1000000
kmap --net-scan --enrich-only

# Resume an interrupted sweep
kmap --net-scan -p 443 --net-resume

# Exclude extra ranges (one CIDR/IP per line, # comments)
kmap --net-scan -p 443 --exclude-file my-excludes.txt

# Monitor a fixed asset list over time
kmap --net-scan --watchlist assets.txt
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-p <spec>` | top-100 | Ports to probe (single port = fastest path) |
| `--rate <pps>` | 25000 | Global send-rate ceiling |
| `--net-max-ips <N>` | unlimited | Stop after N IPs (sample mode) |
| `--net-resume` | off | Continue from the last checkpoint |
| `--discover-only` / `--enrich-only` / `--report-only` | off | Run one phase |
| `--exclude-file <f>` | — | Extra ranges to skip |
| `--data-dir <d>` | `kmap-data` | Shard DBs + checkpoint + log |
| `--findings-dir <d>` | `Findings` | Report output |
| `--watchlist <f>` | — | Fixed-target monitoring with diff report |

---

*Scan only networks you own or are explicitly authorized to test.*
