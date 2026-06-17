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

Enrichment processes hosts in bounded batches (a deliberate memory cap so a
sweep that finds millions of open hosts never loads them all into RAM at once),
but it **drains the full backlog automatically** — it keeps running batches
until every discovered host has been enriched, so you don't need to re-run
`--enrich-only` by hand to mop up the overflow. Hosts whose enrichment errors
are parked on a one-hour cool-down and retried on a later run.

---

## How discovery works

Discovery runs one of two engines. When raw packets are available
(root/administrator **and** an Npcap/libpcap capture device) Kmap uses a
**stateless raw-SYN engine**: a TX thread blasts cookie-stamped SYNs while a
separate RX thread validates the returning SYN-ACKs against the cookie (the
state lives in the TCP sequence number, so there is zero per-probe bookkeeping —
masscan/zmap style). Where raw packets are unavailable it transparently falls
back to non-blocking `connect()` probes, which run **unprivileged on any OS**. A
shared token-bucket rate limiter can cap the global send rate (it is **unlimited
by default** — pass `--rate <pps>` to throttle), and on the connect() path a
pool of worker threads keeps enough probes in flight to saturate network
round-trip time without straining the CPU (a probe wave typically sits at ≈1–2%
CPU — the bottleneck is the network, not your box). Both engines write their
discovered open ports into the same 32-shard store, so enrichment is identical
regardless of which ran. Force a specific engine with `KMAP_RAWSYN=1` / `0`.

Three properties make it internet-scale-safe:

- **Randomized IP order.** IPs are visited via a multiplicative-inverse
  permutation over the full 2³² space, so a sweep spreads load evenly across
  networks instead of hammering one /16 at a time. Every address is visited
  exactly once per full sweep.
- **Reserved/private ranges are skipped automatically.** Add your own with
  `--exclude-file` (one CIDR or IP per line, `#` comments allowed). A malformed
  line is reported to stderr and skipped rather than silently misinterpreted,
  so a typo can't accidentally widen or void your exclusions. The built-in
  list is:

  | Category | Ranges |
  |----------|--------|
  | This-host / private (RFC 1918) | `0.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
  | Loopback / link-local / CGNAT | `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10` |
  | Protocol / documentation / benchmark | `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24` |
  | Deprecated / multicast / reserved | `192.88.99.0/24` (6to4, RFC 7526), `224.0.0.0/4`, `240.0.0.0/4` |
  | US DoD blocks (policy default, to avoid abuse reports) | `6/8`, `7/8`, `11/8`, `21/8`, `22/8`, `26/8`, `28/8`, `29/8`, `30/8`, `33/8`, `55/8`, `214/8`, `215/8` |

  The DoD `/8`s are excluded by policy (they're routable but scanning them
  invites abuse complaints). If you have authorization to scan one of these
  ranges (for example a block you own), `--no-builtin-excludes` opts out of the
  entire built-in list — it is off by default, prints a prominent warning when
  set, and still honors any `--exclude-file` you pass. Use it only against
  ranges you are permitted to scan.
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

`--rate <pps>` caps packets per second across all workers. It is **unlimited by
default** (`--rate 0` is the same as omitting it); the send loop then runs as
fast as the link/NIC/`send_tcp_raw` path allows. Because an unlimited rate can
saturate a shared or metered uplink and trip upstream abuse detection, pass an
explicit, neighbourly cap on anything but your own dedicated infrastructure:

```bash
kmap --net-scan -p 443 --rate 25000      # polite cap for a residential uplink
kmap --net-scan -p 443 --rate 50000      # faster, when you own/authorize the path
```

When a cap is set the token-bucket limiter starts gently (no opening burst) so
the first second of a scan doesn't spike your NIC or a downstream IDS.

---

## What enrichment captures

For every open port discovery finds, the enrichment phase re-connects and
gathers a fingerprint. Nothing here re-scans the network from scratch — it
only touches the hosts already in the store.

- **Service & version.** Banner grab + pattern match identifies
  `ssh`, `http`, `https`, `ftp`, `smtp`, `imap`, `pop3`, `mysql`,
  `postgresql`, `mongodb`, and `redis`, and extracts a version string where
  the banner carries one (e.g. `OpenSSH 8.2p1`, `nginx 1.18.0`). Anything
  that responds but matches no signature is recorded as `unknown` with the
  raw first line kept.
- **CVE matching.** Detected product + version are cross-referenced against
  `kmap-cve.db` with strict version-bound comparison, and each match is
  tagged `[REMOTE]` / needs-auth / unknown from its CVSS vector so you can
  tell network-exploitable findings from local/auth-required ones. (No DB on
  disk → a `WARN kmap-cve.db not found` line and empty CVE columns.)
- **Web recon** (HTTP/S ports): page title, `Server` / `X-Powered-By` /
  `X-Generator` headers, redirect target, and a probe of a few interesting
  paths.
- **TLS** (on TLS ports): subject CN, issuer, SAN list, not-after, the
  self-signed flag, negotiated protocol, and the cert SHA-256 fingerprint.
- **ASN / geo / reverse-DNS.** Origin ASN, AS name, BGP prefix, registry,
  and country (via Team Cymru), plus a batched reverse-DNS hostname.
  `KMAP_NO_DNS=1` skips the reverse-DNS traffic.

All of this is queryable afterward without re-scanning — `--net-query` also
buckets hosts into device classes (`web`, `ssh`, `ftp`, `telnet`, `mail`,
`dns`, `db`, `rdp`, `vnc`, `snmp`, `smb`, `router`, `iot`) derived from the
detected service. See [querying.md](querying.md).

### Why a live service can still show no CVEs

CVE matching is deliberately **conservative** — it would rather report nothing
than flood you with false positives across millions of hosts. A host can be
clearly up, with a detected service, and still carry an empty `cves` column for
sound reasons:

- **No version was detected.** Matching requires a dotted version (e.g. `2.4`,
  `1.18.0`) parsed from the banner. A bare `Server: Apache` or an SSH banner
  with no version yields no match, because most version-specific CVEs cannot be
  confirmed to apply without knowing the version — claiming them anyway would
  tag every "Apache" host with dozens of CVEs it may have patched.
- **The detected version is outside every CVE's range.** Each candidate CVE is
  filtered by its `version_min` / `version_max` bounds against the detected
  version, so a fully-patched current release legitimately matches nothing.
- **The implementation is SSH but not OpenSSH.** A `ssh` service whose banner
  names AWS Transfer Family, Dropbear, Bitvise, Tectia, libssh, Paramiko, or
  Erlang/OTP returns no product, because those don't share OpenSSH's CVE
  history. Only banners that explicitly say `OpenSSH` are matched against
  OpenSSH CVEs.
- **The product isn't a tracked CVE product.** Front-ends like `cloudflare`
  are recorded as services but have no CVE product name to look up.

When a CVE *does* apply, up to 100 of them (highest CVSS first) are stored per
host. If you expected findings and got none, see the *No CVEs show up* section
of [`troubleshooting.md`](troubleshooting.md) — the usual real cause is a
missing `kmap-cve.db` (look for the `WARN kmap-cve.db not found` log line), not
a matching gap.

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

### The diff report

Each run writes two dated files into `<findings-dir>/watchlist/` (default
`Findings/watchlist/`):

| File | Contents |
|------|----------|
| `diff_YYYY-MM-DD.txt` | What changed since the previous run |
| `full_YYYY-MM-DD.txt` | Full enriched snapshot of every tracked host |

The diff flags three kinds of change, keyed by `ip:port`:

```
[NEW PORT] 203.0.113.7:8443/tcp        open now, was not open last run
    Service: https  Version: nginx 1.27.1
[CHANGED] 203.0.113.7:443/tcp          open in both runs, service/version moved
    Service: nginx 1.25.3 -> nginx 1.27.1
    Version: 1.25.3 -> 1.27.1
[CLOSED] 203.0.113.7:21                open last run, did not respond now
    Was: ftp vsftpd 3.0.5
```

"Since the last run" is literal: the baseline is the **previous completed** run,
not the all-time history. A port that went dark is reported `[CLOSED]` once —
on the run it disappeared — and then drops out, rather than being re-flagged on
every subsequent run. An interrupted run does not move the baseline, so the next
full run still diffs against the last complete one. (A `[CHANGED]` entry is
suppressed when this run failed to re-detect the service/version, so a transient
enrichment miss is never misreported as a change.)

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
| `--rate <pps>` | unlimited | Global send-rate cap (`0` = unlimited; max 1e9) |
| `--net-max-ips <N>` | unlimited | Stop after N IPs (sample mode) |
| `--net-resume` | off | Continue from the last checkpoint |
| `--discover-only` / `--enrich-only` / `--report-only` | off | Run one phase |
| `--exclude-file <f>` | — | Extra ranges to skip |
| `--no-builtin-excludes` | off | Disable the built-in reserved/private/DoD excludes (authorized use only) |
| `--data-dir <d>` | `kmap-data` | Shard DBs + checkpoint + log |
| `--findings-dir <d>` | `Findings` | Report output |
| `--watchlist <f>` | — | Fixed-target monitoring with diff report |

The raw-SYN engine is masscan/zmap-class: it builds the SYN frame once as a
54-byte template and per probe patches only the dst IP, dst port and SYN-cookie
with an incremental checksum, transmits frames **batched** (Npcap `pcap_sendqueue`
on Windows), buffers discovered opens **in memory**, and **flushes them to the
shard DBs after the sweep** (bulk prepared-statement insert) so discovery never
blocks on SQLite. Measured **~90k pps** TX peak and **~28-38k IPs/sec** on a sparse
real internet sample (~9x the old per-packet loop; ~90k is that NIC's Npcap ceiling
-- the architecture goes higher on faster send paths). Environment variables that
tune it:

| Variable | Default | Effect |
|---|---|---|
| `KMAP_RAWSYN` | auto (on when raw packets available) | `1`/`0` forces the raw engine on/off |
| `KMAP_RAWSYN_TX_THREADS` | `1` | Send-handle shards (each its own pcap handle); raise to approach the adapter's aggregate packet rate. A few duplicate probes on `--net-resume` are harmless. |
| `KMAP_RAWSYN_BATCH` | `64` | Frames per transmit (1–1024). |
| `KMAP_RAWSYN_DRAIN_MS` | `2000` | Time the RX keeps reading after TX ends, measured as **silence since the last *new* open** (deduped retransmits do not extend it; a late first response does). Lower for tighter small-scan latency, raise to chase high-RTT stragglers. |
| `KMAP_RAWSYN_MAX_OPENS` | `1000000` | In-memory open buffer cap before a forced mid-scan spill to the DB (bounds RAM on a very dense sweep). |
| `KMAP_RAWSYN_MANUAL_RST` | off | Send an explicit RST per open (default off — the kernel RSTs the unbound source port). |

> On a **dense** responsive `/20`, the inbound SYN-ACK rate measured ~1.3k/s and
> was **identical for Cloudflare and Fastly** — which pins the limit on the
> residential inbound path (a router/ISP rate-limit on new flows), not on Kmap or
> the target: the RX captures every reply with zero drops and `pcap_dispatch` is
> not the bottleneck. `connect()` is faster on dense ranges because its replies
> belong to established handshakes, not rate-limited new flows; on an unrestricted
> uplink the raw engine is not so bounded. Sparse internet sweeps (the headline
> use case) are send-bound and unaffected.

---

*Scan only networks you own or are explicitly authorized to test.*
