# Reading the findings report

The report phase (phase 3 of `--net-scan`, or `--report-only`) turns the
enriched scan store into plain-text findings files under `Findings/`. This page
explains the file layout and every section so you can read — or post-process —
the output without guessing.

These are the **net-scan** findings. The `--watchlist` diff report is a
different format and lives under `Findings/watchlist/` — see
[internet-scale-scanning.md](internet-scale-scanning.md#the-diff-report).

---

## File naming and ordering

Reports are written as:

```
Findings/findings_0000001-0072348.txt
Findings/findings_0072349-0144696.txt
...
```

The two zero-padded numbers are the 1-based host range the file covers. Each
file holds up to **72,348 hosts** (a fixed batch size that keeps any single
report openable in an editor); a full sweep rolls over into as many files as
needed. The trailing file may be short.

Hosts are emitted in **ascending IP order globally**. The store is sharded by
the top bits of the IP, so iterating shards in order already groups hosts by
prefix; within each shard the IPs are numerically sorted (so `2.x` sorts before
`10.x`, unlike a naive string sort). Generation streams one shard at a time, so
even a full-IPv4 report never loads every host into memory at once.

Each file opens with a header (generation time, the IP range it covers, host
count) and closes with a [file summary](#file-summary). In between is one
section per host.

---

## A host section

```
================================================================================
  TARGET: 203.0.113.10
================================================================================

  PORT TABLE
  --------------------------------------------------------------------
  PORT          STATE     SERVICE         VERSION
  22/tcp        open      ssh             OpenSSH 8.2p1
  443/tcp       open      https           nginx 1.18.0
```

A host with no open ports is rendered as `(no open ports found)`. Otherwise the
**PORT TABLE** lists every open port with its detected service and version
(`unknown` when no signature matched; version blank when the banner carried
none). The remaining sections appear only when there is something to show.

### CVE MAP

```
  CVE MAP
  --------------------------------------------------------------------
  443/tcp https (nginx 1.18.0):
    CVE-2021-23017   CVSS:7.7   HIGH      [REMOTE]
      One-byte memory overwrite in the resolver may allow worker-proc...
```

One block per port that has CVEs. Each CVE line is the ID, CVSS score
(`N/A` if the row has none), severity, and a **confidence tag** derived from the
CVE's CVSS vector:

| Tag | Meaning |
|-----|---------|
| `[REMOTE]` | Network-reachable, no authentication and no user interaction required |
| `[needs-auth/other]` | Requires authentication, local access, or user interaction |
| `[unknown]` | Legacy CVE row not yet backfilled with a CVSS v3 vector |

A one-line description follows (truncated to ~70 characters). For how CVEs are
matched — and why a live service can legitimately show none — see
[internet-scale-scanning.md](internet-scale-scanning.md#why-a-live-service-can-still-show-no-cves).

### PATCH STATUS

Shown only for hosts seen in **two or more scans** (the value of keeping the
`prev_*` history columns — see [data-model.md](data-model.md#rescan--history-semantics-the-non-obvious-part)).
Per port it reports the scan count, the previous enrichment date, any
service/version drift, and the CVE delta since the prior scan:

```
  PATCH STATUS
  --------------------------------------------------------------------
  443/tcp https [scans=3] (prev scan 2025-06-01)
    VERSION:   1.18.0 -> 1.27.0
    PATCHED:   CVE-2021-23017, CVE-2019-9511
    PERSISTING: CVE-2023-44487
    NEW:       CVE-2024-7347
```

- **PATCHED** — present last scan, gone now.
- **PERSISTING** — present in both scans.
- **NEW** — introduced since the last scan.

If every prior CVE is gone and none were introduced, the port is flagged
`STATUS: fully patched since last scan`. Long CVE lists wrap at six IDs per line.

### WEB RECON

```
  WEB RECON
  --------------------------------------------------------------------
  Port 443/https:
    Title:   Example Domain
    Server:  nginx
    [200] /  "Example Domain"
    [301] /admin -> https://example.com/login
```

For HTTP/HTTPS ports: the page title, `Server` header, and per-path probe
results as `[status] path` — with the page title quoted, or `-> target` when the
path redirected.

---

## File summary

Each file ends with a rollup of just that file's hosts:

```
================================================================================
  FILE SUMMARY
================================================================================
  Hosts in file:   72,348
  With open ports:  41,002
  Total ports:      98,517
  CVEs found:       12,904
  Rescanned hosts:  3,110
  Patched CVEs:     580
  Persisting CVEs:  1,422
  New CVEs:         96
  Scan period:      2025-06-01 to 2026-06-15
```

The four patch-status lines (`Rescanned hosts` … `New CVEs`) appear only when at
least one host in the file was rescanned; on a first-ever scan they are omitted
rather than shown as meaningless zeros.

---

## Post-processing tips

The reports are line-oriented and grep-friendly:

```bash
# Every network-exploitable CVE across all reports
grep -h "\[REMOTE\]" Findings/findings_*.txt

# Hosts that got fully patched between scans
grep -B40 "fully patched since last scan" Findings/findings_*.txt | grep TARGET
```

For structured queries (by port, service, CVE, CVSS, ASN, country, web
fingerprint, device class) without parsing text, use `--net-query` against the
store directly — see [querying.md](querying.md). `--net-query --nq-format json`
emits machine-readable output.
