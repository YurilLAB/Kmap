# Troubleshooting

Common issues running Kmap's internet-scale scanner, with the actual cause and
the fix. For the full workflow see
[internet-scale-scanning.md](internet-scale-scanning.md); for tuning see
[performance.md](performance.md).

---

## The scan runs far slower than my `--rate`

**Cause.** Discovery uses non-blocking `connect()` probes, not raw SYN. On
unresponsive (filtered / dark) IP space every probe runs to the full timeout
before its worker frees, so the pool's ceiling there is
`workers / (KMAP_PROBE_TIMEOUT_MS/1000)` — independent of `--rate`. With the
defaults (100 workers, 500 ms) a single-port sweep tops out near **200 pps** no
matter what `--rate` you pass; the rate limiter never even engages. Kmap prints
a one-line `NOTE:` at scan start when this gap exists.

**Fix.** Give it more concurrency or a shorter timeout:

```bash
KMAP_NETSCAN_CONCURRENCY=1000 kmap --net-scan -p 443           # ~2000 pps on dark space
KMAP_NETSCAN_CONCURRENCY=1000 KMAP_PROBE_TIMEOUT_MS=100 kmap --net-scan -p 443  # ~10000 pps
```

A shorter timeout trades coverage for speed (a host answering just after the
cutoff is recorded as filtered). 500 ms suits cross-continent paths; 100–200 ms
is fine for nearby ranges. See the throughput table in
[performance.md](performance.md#how-fast-can-a-sweep-actually-go).

---

## Scan warns about the open-file limit

You see a line like:

```
WARNING: open-file limit is 1024 but this scan needs ~1152 descriptors;
raise it (ulimit -Hn) or lower KMAP_NETSCAN_CONCURRENCY, otherwise some
probes will fail with EMFILE and those hosts get marked closed.
```

**Cause.** A connect()-based sweep holds one socket per in-flight probe.
Discovery keeps up to `KMAP_NETSCAN_CONCURRENCY` (or
`KMAP_WATCHLIST_CONCURRENCY`) sockets open at once; enrichment keeps up to
`KMAP_NETSCAN_ENRICH_CONCURRENCY × KMAP_HOST_PORT_PARALLELISM`. Add the shard
databases, the CVE database and the log and a high-concurrency run can want
several thousand file descriptors — well past the default POSIX soft limit of
**1024**. Kmap raises the soft limit toward the hard limit automatically before
each pool starts, but it cannot exceed the **hard** limit; if that is still too
low, it prints this warning. Left unaddressed, `socket()` starts failing with
`EMFILE` mid-scan and those probes are recorded as **closed** — silent
false negatives (a host that was actually up looks filtered).

**Fix (Linux/macOS).** Raise the hard limit, then re-run:

```bash
ulimit -Hn          # show the current hard cap
ulimit -n 65535     # raise the soft limit for this shell (must be <= hard cap)
# if the hard cap itself is low, raise it as root / via limits.conf, e.g.:
#   sudo prlimit --pid $$ --nofile=65535:65535
#   or add  "* hard nofile 65535"  to /etc/security/limits.conf and re-login
```

Or simply lower the concurrency so the pool fits the available descriptors
(`KMAP_NETSCAN_CONCURRENCY`, `KMAP_NETSCAN_ENRICH_CONCURRENCY`,
`KMAP_HOST_PORT_PARALLELISM`). On a typical gaming-PC scan the defaults stay
well under 1024 and you will never see this warning.

**Windows is unaffected** — its handle table is not governed by this limit, so
the auto-raise is a no-op there.

---

## No CVEs show up (`--nq-cve` / reports empty of CVEs)

**Cause 1 — no CVE database.** CVE matching needs `kmap-cve.db`. If it isn't
found, enrichment logs `WARNING: kmap-cve.db not found -- CVE enrichment
skipped.` and every `cves` column stays empty.

**Fix.** Put `kmap-cve.db` next to `kmap`/`kmap.exe`, in `--data-dir`, in
`$KMAPDIR`, or in the current directory.

**Cause 2 — detected services aren't CVE products.** Generic banners (e.g.
`cloudflare`) or services with no extracted version don't match — matching is
deliberately strict and needs a dotted version. Check what was detected:

```bash
sqlite3 kmap-data/shard_000.db "SELECT DISTINCT service, version FROM hosts WHERE service != ''"
```

If you see real products (nginx/openssh/apache) with versions and still no
CVEs, the DB lookup is suspect; if everything is generic banners, the service
detector needs a richer signature for that product.

---

## No ASN / country / AS-name data

**Cause.** ASN enrichment resolves `<reverse-ip>.origin.asn.cymru.com` over
**outbound UDP 53** (Team Cymru). If your network blocks outbound DNS or that
resolution fails, the ASN columns stay empty.

**Fix.** Confirm from the same host:

```bash
dig +short TXT 1.1.1.1.origin.asn.cymru.com
```

If that returns nothing, outbound UDP 53 is blocked or filtered. Set
`KMAP_NO_DNS=1` to skip reverse-DNS traffic entirely if you don't want it.

---

## `ERROR: --data-dir '…' is not writable`

**Cause.** Kmap write-tests the data directory before scanning and aborts if it
can't create files there.

**Fix.** Point `--data-dir` at a writable location, or fix the permissions:

```bash
kmap --net-scan -p 443 --data-dir ./my-scan-data
```

---

## Resume fails: `cannot resume safely`

**Cause.** `--net-resume` replays the **same** randomized IP permutation as the
original run using the seed stored in `<data-dir>/.net-scan-checkpoint`. A
checkpoint that shows progress but has no seed (written by a very old build)
can't be resumed without re-walking a different order and skipping/repeating
IPs, so Kmap refuses rather than producing incorrect coverage.

**Fix.** Delete the stale checkpoint and start fresh:

```bash
rm kmap-data/.net-scan-checkpoint
kmap --net-scan -p 443
```

> A clean interrupt or crash can leave a small number of in-flight IPs
> (up to the worker count) un-rescanned on resume — negligible against a
> full sweep, but worth knowing for exact-coverage work.

---

## `WARNING: Could not import all necessary Npcap functions` (Windows)

**Cause.** Kmap probes for Npcap at startup for nmap's raw-packet features.

**Fix.** **Ignore it for `--net-scan`.** Internet-scale discovery uses
`connect()` probes, not raw packets, so it runs fully without Npcap (and
without administrator). Npcap only matters for classic raw-SYN/OS-detection
nmap modes.

---

## The scan finished but found nothing

- **All probed ports filtered.** Most of the internet won't answer on any one
  port; that's expected. Confirm the pipeline works against a known-open host
  first (e.g. your own server).
- **A malformed `--exclude-file` line.** Kmap now prints
  `WARNING: ignoring malformed exclude line: …` and skips it (a bad line can no
  longer silently void or widen your exclusions) — check stderr for those.
- **Concurrency too low for the time you gave it.** See the slow-scan section
  above; at ~200 pps a large sample takes a long time to surface hits.
- **Hit the open-file limit (`EMFILE`).** A very high concurrency on a box with
  a low hard `nofile` cap makes `socket()` fail mid-scan, so probes get marked
  closed. Kmap warns when this is likely — see
  [Scan warns about the open-file limit](#scan-warns-about-the-open-file-limit).

---

## Where did my results go? (triage a finished or interrupted scan)

| What | Where |
|------|-------|
| Per-run event log (start, per-phase timing, completion, warnings) | `<data-dir>/kmap.log` |
| Open ports + enrichment | `<data-dir>/shard_*.db` (query with `--net-query`) |
| Human-readable findings | `<findings-dir>/findings_*.txt` |
| Resume position | `<data-dir>/.net-scan-checkpoint` |

```bash
tail -20 kmap-data/kmap.log                       # what happened
grep -E "  (WARN|ERROR) " kmap-data/kmap.log      # anything that went wrong
kmap --net-query --nq-count                       # how many hosts collected
```
