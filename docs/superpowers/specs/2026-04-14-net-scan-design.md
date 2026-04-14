# Kmap Net Scan — Internet-Scale Scanner Design

**Date:** 2026-04-14
**Status:** Approved
**Scope:** New `--net-scan` and `--net-query` modes for Kmap

---

## Overview

A built-in internet-scale scanning pipeline for Kmap. Scans the entire public IPv4 address space (or a targeted watchlist), enriches discovered hosts with service detection, CVE cross-referencing, and HTTP/S reconnaissance, then outputs structured findings. Everything runs from a single binary with zero external dependencies beyond what Kmap already requires.

### Goals

- Scan all ~3.7 billion public IPv4 addresses for open ports
- Enrich discovered hosts using Kmap's existing feature modules
- Store results in sharded SQLite databases for efficient querying
- Generate human-readable findings reports (72,348 IPs per file)
- Support a watchlist mode for monitoring owned/client assets with change detection
- CLI query interface for searching collected data by port, service, CVE, etc.

### Non-Goals

- Web UI or API server (CLI only)
- IPv6 scanning (future work)
- Credential probing on unknown hosts (only on authorized watchlist targets)
- Real-time streaming output (batch processing)

---

## CLI Interface

### Net Scan Commands

```bash
# Full pipeline: discover → enrich → report
kmap --net-scan --rate 25000

# Scan specific ports (default: top 100)
kmap --net-scan --rate 25000 --ports 22,80,443,3306,5432,8080,8443

# Run phases independently
kmap --net-scan --discover-only --rate 25000
kmap --net-scan --enrich-only
kmap --net-scan --report-only

# Resume an interrupted scan
kmap --net-scan --resume

# Custom exclusion list
kmap --net-scan --rate 25000 --exclude-file my_excludes.txt

# Custom data/output directories
kmap --net-scan --data-dir /mnt/storage/kmap-data --findings-dir /mnt/storage/Findings
```

### Watchlist Commands

```bash
# Scan watchlist targets and generate diff
kmap --net-scan --watchlist clients.txt

# Watchlist targets file format (one per line, # for comments):
#   10.0.0.1
#   192.168.1.0/24
#   example.com
```

### Query Commands

```bash
# Search by port
kmap --net-query --port 22
kmap --net-query --port 80,443

# Search by service
kmap --net-query --service openssh
kmap --net-query --service nginx

# Search by CVE
kmap --net-query --cve CVE-2024-6387

# Search by CVSS score
kmap --net-query --min-cvss 9.0

# Search by web content
kmap --net-query --web-title "phpMyAdmin"
kmap --net-query --web-server "Apache/2.4.49"

# Combine filters
kmap --net-query --port 22 --service openssh --min-cvss 7.0

# Count results instead of listing
kmap --net-query --port 443 --count

# Export to file
kmap --net-query --port 3306 --output mysql_hosts.txt

# Search specific shard or IP range
kmap --net-query --ip-range 93.184.0.0/16
```

---

## Module Architecture

### New Source Files

| File | Purpose |
|------|---------|
| `net_scan.cc` / `net_scan.h` | Top-level orchestrator. Parses `--net-scan` options, coordinates phases, manages state. |
| `fast_syn.cc` / `fast_syn.h` | High-speed async SYN scanner. Raw packet TX/RX, rate limiter, IP randomization, exclusion filtering. |
| `net_db.cc` / `net_db.h` | Shard database manager. Creates/opens shards, inserts hosts, tracks enrichment progress, handles shard rotation. |
| `net_enrich.cc` / `net_enrich.h` | Enrichment pipeline. Pulls unenriched hosts from shards, invokes Kmap's service detection + CVE map + web recon, writes results back. |
| `net_report.cc` / `net_report.h` | Findings generator. Reads enriched shards, writes `Findings/*.txt` files with 72,348 IPs each. |
| `net_query.cc` / `net_query.h` | Query engine. Searches across all shards by port, service, CVE, CVSS, web content. |
| `exclude.conf` | Default IP exclusion ranges (RFC 1918, multicast, DoD, reserved). |

### Existing Modules Used (No Modification)

| Module | Used By |
|--------|---------|
| `service_scan` (nmap core) | `net_enrich.cc` — service/version detection |
| `cve_map.cc` | `net_enrich.cc` — CVE cross-referencing |
| `web_recon.cc` | `net_enrich.cc` — HTTP/S reconnaissance |
| `sqlite/sqlite3.c` | `net_db.cc` — database operations |
| `libpcap` | `fast_syn.cc` — raw packet capture |

### Integration with kmap.cc

New options added to `KmapOps.h`:

```cpp
/* --net-scan options */
bool net_scan;              /* Enable net-scan mode */
bool net_discover_only;     /* Only run discovery phase */
bool net_enrich_only;       /* Only run enrichment phase */
bool net_report_only;       /* Only run report generation */
bool net_resume;            /* Resume interrupted scan */
int  net_rate;              /* Packets per second (default 25000) */
char *net_exclude_file;     /* Custom exclusion list */
char *net_data_dir;         /* Shard database directory (default: kmap-data) */
char *net_findings_dir;     /* Findings output directory (default: Findings) */
char *net_watchlist;        /* Watchlist targets file */
/* --net-query options */
bool net_query;             /* Enable query mode */
int  nq_port;               /* Filter by port */
char *nq_service;           /* Filter by service name */
char *nq_cve;               /* Filter by CVE ID */
float nq_min_cvss;          /* Filter by minimum CVSS score */
char *nq_web_title;         /* Filter by web page title */
char *nq_web_server;        /* Filter by server header */
char *nq_ip_range;          /* Filter by IP range */
char *nq_output;            /* Export results to file */
bool nq_count;              /* Count mode (just print count) */
```

The `--net-scan` and `--net-query` modes run before the normal scan pipeline in `kmap.cc` and call `exit()` when done (they don't proceed to normal nmap scanning).

---

## Phase 1: DISCOVER (fast_syn)

### Design

A custom high-speed asynchronous SYN scanner using Kmap's existing `libpcap` linkage. Does NOT reuse nmap's scan engine (too much per-host overhead for internet scale). Instead, implements the well-known async SYN technique:

1. **TX path**: Iterates the IPv4 space in randomized order. For each IP+port pair, crafts and sends a raw TCP SYN packet. Rate-controlled by a token bucket.
2. **RX path**: Runs a pcap capture filter for incoming SYN-ACK and RST packets. Matches responses to sent probes and records results.
3. **Two threads**: TX and RX run concurrently. TX sends at the configured rate. RX captures continuously.

### IP Randomization

Sequential scanning (1.0.0.1, 1.0.0.2, 1.0.0.3...) is easily detected and blocked. Instead, use a multiplicative inverse permutation over the IPv4 space:

```
randomized_ip = (ip_index * PRIME_MULTIPLIER) mod IP_SPACE_SIZE
```

This visits every IP exactly once in a pseudorandom order with O(1) memory. Same technique masscan uses (based on the "Blackrock" cipher concept).

### Exclusion List

Hard-coded exclusions (always skipped, cannot be overridden):

| Range | Reason |
|-------|--------|
| `0.0.0.0/8` | "This" network |
| `10.0.0.0/8` | RFC 1918 private |
| `100.64.0.0/10` | Carrier-grade NAT |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `172.16.0.0/12` | RFC 1918 private |
| `192.0.0.0/24` | IETF protocol assignments |
| `192.0.2.0/24` | Documentation (TEST-NET-1) |
| `192.168.0.0/16` | RFC 1918 private |
| `198.18.0.0/15` | Benchmarking |
| `198.51.100.0/24` | Documentation (TEST-NET-2) |
| `203.0.113.0/24` | Documentation (TEST-NET-3) |
| `224.0.0.0/4` | Multicast |
| `240.0.0.0/4` | Reserved/broadcast |

User-supplied exclusions via `--exclude-file` are merged with the above.

### Rate Limiting

Token bucket algorithm:

- Default: 25,000 packets per second (safe for most home broadband)
- Configurable: `--rate 10000` to `--rate 1000000`
- Burst allowance: 1.5x the rate for short bursts

### Resume Support

Every 60 seconds, the scanner writes a checkpoint file:

```
kmap-data/.net-scan-checkpoint
```

Contains: last IP index processed, ports being scanned, timestamp, packets sent/received counts. `--resume` reads this and continues from the checkpoint.

### Port Selection

- Default: top 100 TCP ports (matches nmap's `--top-ports 100`)
- Custom: `--ports 22,80,443,3306,8080` or `--ports 1-1024`

### Output

Discovered (ip, port) pairs are written directly into shard SQLite databases during scanning. No intermediate file.

---

## Phase 2: ENRICH (net_enrich)

### Design

Processes shard databases one at a time. For each shard:

1. Query `SELECT DISTINCT ip FROM hosts WHERE enriched = 0 LIMIT batch_size`
2. For each IP, gather all its open ports from the shard
3. Run Kmap's service detection against each open port
4. Run CVE cross-reference on detected service versions
5. Run web recon on any HTTP/HTTPS ports
6. Write all results back to the shard database
7. Set `enriched = 1` for all processed rows

### Batch Processing

- Default batch: 1000 IPs at a time
- After each batch, commit to database and print progress
- Progress format: `Enriching shard_003.db: 45,231 / 2,000,000 hosts [2.3%]`
- Fully resumable — only processes rows where `enriched = 0`

### Connection Handling

Each enrichment probe opens fresh TCP connections to the target (same as running `kmap -sV --cve-map --web-recon` against that host). The enrichment engine uses Kmap's existing probe implementations:

- Service detection: existing `service_scan` module
- CVE lookup: existing `run_cve_map()` against `kmap-cve.db`
- Web recon: existing `run_web_recon()` for title/headers/paths

### Timeout and Error Handling

- Per-host timeout: 30 seconds (configurable via `--enrich-timeout`)
- Per-probe timeout: 5 seconds (matches existing Kmap defaults)
- If a host is unreachable during enrichment (port closed since discovery), mark as enriched with empty service data
- Network errors are logged but do not stop the pipeline

---

## Phase 3: REPORT (net_report)

### Output Structure

```
Findings/
├── findings_0000001-0072348.txt
├── findings_0072349-0144696.txt
├── findings_0144697-0217044.txt
└── ...
```

Each file contains exactly 72,348 IPs with their complete scan results.

### File Format

Same styled format as Kmap's `--report` text output:

```
================================================================================
                    KMAP NET SCAN FINDINGS
================================================================================
  Generated: 2026-04-14 15:30:22
  IP Range:  1.0.0.0 - 1.4.163.155
  Hosts:     72,348
================================================================================

================================================================================
  TARGET: 1.0.0.1
================================================================================

  PORT TABLE
  --------------------------------------------------------------------------
  PORT          STATE     SERVICE         VERSION
  53/tcp        open      dns             ISC BIND 9.18.1
  80/tcp        open      http            cloudflare
  443/tcp       open      https           cloudflare

  CVE MAP
  --------------------------------------------------------------------------
  53/tcp dns (ISC BIND 9.18.1):
    CVE-2023-3341  CVSS:7.5  HIGH
      ISC BIND named stack exhaustion via recursive query...

  WEB RECON
  --------------------------------------------------------------------------
  Port 443/https:
    Title:   APNIC - Whois Search
    Server:  cloudflare
    [200] /robots.txt
    [301] /api -> /api/v1

================================================================================
  TARGET: 1.0.0.2
================================================================================
  (no open ports found)

... (72,346 more hosts)

================================================================================
  FILE SUMMARY
================================================================================
  Hosts in file:   72,348
  With open ports:  31,442
  Total ports:      89,217
  CVEs found:       12,853
  Scan period:      2026-04-14 to 2026-04-14
================================================================================
```

### Ordering

Hosts are ordered by IP address within each file. Files are numbered sequentially.

---

## Phase 4: WATCHLIST

### Design

The watchlist is a separate scan mode that:

1. Reads target IPs/ranges/hostnames from a file
2. Runs the same discover → enrich pipeline on just those targets
3. Stores results in a dedicated `watchlist.db` (not the regular shards)
4. Compares against the previous scan stored in `watchlist.db`
5. Generates a diff report showing changes

### Diff Report

```
Findings/watchlist/
├── full_2026-04-14.txt       (complete current state)
└── diff_2026-04-14.txt       (changes since last scan)
```

Diff format:

```
================================================================================
                    WATCHLIST DIFF — 2026-04-14
================================================================================
  Targets scanned: 47
  Changes detected: 5
================================================================================

  [NEW PORT] 10.0.0.5:8080/tcp
    Service: http  Version: Apache Tomcat 9.0.65
    CVE-2023-42795  CVSS:7.5  HIGH

  [CLOSED] 10.0.0.12:21/tcp
    Was: ftp  vsftpd 3.0.3

  [NEW CVE] 10.0.0.1:22/tcp (OpenSSH 8.9p1)
    CVE-2026-1234  CVSS:9.8  CRITICAL
    (CVE added to kmap-cve.db since last scan)

  [VERSION CHANGED] 10.0.0.8:443/tcp
    Was: nginx 1.18.0
    Now: nginx 1.24.0
    (3 CVEs no longer applicable, 0 new)

  [TITLE CHANGED] 10.0.0.20:80/tcp
    Was: "Under Construction"
    Now: "Login — Admin Panel"

================================================================================
```

### Watchlist Frequency

The user runs `kmap --net-scan --watchlist clients.txt` manually whenever they want a re-scan. No built-in scheduler — that's the user's cron job or task scheduler.

---

## Database Design

### Shard Strategy

The public IPv4 space is split into shards by IP range. Each shard covers a `/5` prefix block (~134 million IPs, but only hosts with open ports are stored):

| Shard | IP Range | Approx IPs |
|-------|----------|------------|
| `shard_001.db` | `0.0.0.0/5` → `0.0.0.0 - 7.255.255.255` | 134M |
| `shard_002.db` | `8.0.0.0/5` → `8.0.0.0 - 15.255.255.255` | 134M |
| ... | ... | ... |
| `shard_025.db` | `192.0.0.0/5` → `192.0.0.0 - 199.255.255.255` | 134M |
| ... | ... | ... |

Only ~200-400M open port entries expected across the full space. Each shard stays well under SQLite's practical limit.

### Schema (per shard)

```sql
CREATE TABLE hosts (
    ip            TEXT NOT NULL,
    port          INTEGER NOT NULL,
    proto         TEXT DEFAULT 'tcp',
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    service       TEXT,
    version       TEXT,
    cves          TEXT,
    web_title     TEXT,
    web_server    TEXT,
    web_headers   TEXT,
    web_paths     TEXT,
    enriched      INTEGER DEFAULT 0,
    PRIMARY KEY (ip, port)
);

CREATE INDEX idx_hosts_port ON hosts(port);
CREATE INDEX idx_hosts_service ON hosts(service);
CREATE INDEX idx_hosts_enriched ON hosts(enriched);
CREATE INDEX idx_hosts_last_seen ON hosts(last_seen);
```

- `cves`: JSON array — `[{"id":"CVE-2024-6387","cvss":8.1,"severity":"HIGH","desc":"..."}]`
- `web_headers`: JSON object — `{"Server":"nginx/1.18","X-Powered-By":"PHP/7.4"}`
- `web_paths`: JSON array — `[{"path":"/admin","status":200,"title":"Login"}]`
- `first_seen` / `last_seen`: Unix epoch timestamps

### Watchlist Schema

`watchlist.db` uses the same schema as shards, plus a history table:

```sql
CREATE TABLE scan_history (
    scan_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_date     INTEGER NOT NULL,
    targets_file  TEXT,
    hosts_scanned INTEGER,
    changes       INTEGER
);
```

---

## Directory Layout

```
kmap-data/                          (--data-dir, default: kmap-data/)
├── shard_001.db
├── shard_002.db
├── ...
├── watchlist.db
├── .net-scan-checkpoint            (resume state)
└── .net-scan-meta.json             (scan metadata: start time, ports, rate)

Findings/                           (--findings-dir, default: Findings/)
├── findings_0000001-0072348.txt
├── findings_0072349-0144696.txt
├── ...
└── watchlist/
    ├── full_2026-04-14.txt
    └── diff_2026-04-14.txt
```

Both directories are added to `.gitignore`.

---

## Responsible Scanning

### Built-in Safeguards

- Hard-coded exclusion of all private, reserved, multicast, and documentation ranges
- Default rate of 25,000 pps — safe for home broadband without saturating the link
- Randomized IP ordering to avoid hammering individual network blocks
- Only SYN scanning (no exploitation, no credential probing on unknown hosts)
- All collected data is from public-facing services responding to standard TCP connections

### User Responsibilities

- Only scan from networks where outbound scanning is permitted
- Set up a reverse DNS PTR record on the scanning IP (e.g., `scanner.yourdomain.com`)
- Host a simple web page on the scanning IP explaining the research purpose
- Maintain an abuse contact email and honor opt-out requests
- Respect local laws regarding network scanning in your jurisdiction

---

## Build Sequence

Since this is a large feature, implementation should be phased:

1. **Phase A**: `net_db.cc` + `net_scan.cc` CLI skeleton + `exclude.conf` — database layer and command parsing
2. **Phase B**: `fast_syn.cc` — the SYN scanner (most complex piece)
3. **Phase C**: `net_enrich.cc` — enrichment pipeline connecting to existing Kmap modules
4. **Phase D**: `net_report.cc` — findings file generation
5. **Phase E**: `net_query.cc` — search/query interface
6. **Phase F**: Watchlist mode + diff logic
7. **Phase G**: Testing, MSVC project updates, documentation

Each phase produces a working increment that can be tested independently.
