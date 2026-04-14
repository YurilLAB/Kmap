<p align="center">
  <img src="kmap_logo.png" alt="Kmap Logo" width="600">
</p>

# Kmap

**Kmap** is a fork of [nmap](https://nmap.org/) extended with active pentesting and internet-scale reconnaissance capabilities. It keeps everything nmap does — port scanning, service detection, OS fingerprinting, NSE scripts — and adds offensive features designed for security assessments, vulnerability research, and asset monitoring.

> **License:** Kmap inherits the Nmap Public Source License (NPSL). See `LICENSE` for full terms.

---

## Background

In 2014, leaked NSA documents revealed programs like **TREASUREMAP** and **HACIENDA** — tools built to map every device on the internet, scan entire countries for open ports, and catalog vulnerable services at scale. Commercial platforms like [Shodan](https://www.shodan.io/), [Censys](https://censys.io/), and Rapid7's [Project Sonar](https://www.rapid7.com/research/project-sonar/) now do this openly, providing searchable databases of internet-wide scan data for security research.

Kmap brings that same capability to individual security researchers and teams. Its `--net-scan` pipeline can discover, fingerprint, and catalog services across the entire public IPv4 address space — or monitor a targeted watchlist of client assets for changes — all from a single binary with no external dependencies.

---

## What's New Over nmap

| Feature | Flag | What it does |
|---|---|---|
| Default credential probing | `--default-creds` | Tests open services against 280+ built-in credential pairs |
| HTTP/S recon | `--web-recon` | Grabs titles, headers, TLS info, probes 180+ high-value paths |
| CVE cross-reference | `--cve-map` | Queries bundled 10,000+ CVE database for detected service versions |
| Scan report | `--report <file>` | Generates a styled `.txt` or `.md` report with all findings |
| Web screenshots | `--screenshot` | Captures PNG screenshots of discovered web ports |
| Internet-scale scanning | `--net-scan` | Full pipeline: discover, enrich, and report across the entire IPv4 space |
| Watchlist monitoring | `--watchlist <file>` | Re-scan owned/client assets and detect changes |
| Data query | `--net-query` | Search collected scan data by port, service, CVE, CVSS score |

All per-host features auto-enable `-sV` (service/version detection) and print results inline alongside the normal port table.

---

## Quick Start

### Single-Target Scanning

```bash
# Standard scan — all nmap features work unchanged
kmap -sV -sC 192.168.1.0/24

# Probe open services for default credentials
kmap --default-creds 10.0.0.1

# HTTP/S recon: title, headers, TLS cert, interesting paths
kmap --web-recon 10.0.0.1

# Cross-reference detected service versions with CVE database
kmap --cve-map 10.0.0.1

# Run all features together
kmap --default-creds --web-recon --cve-map -p 22,80,443,3306,5432 10.0.0.1

# Generate a report
kmap --report results.txt -sV 10.0.0.1
kmap --report findings.md --default-creds --cve-map 10.0.0.1

# Capture web screenshots
kmap --screenshot 10.0.0.1

# JSON output
kmap -sV -oJ results.json 10.0.0.1

# Colored terminal output
kmap --color=always -sV 10.0.0.1
```

### Internet-Scale Scanning

```bash
# Scan the entire public IPv4 space (discover + enrich + report)
kmap --net-scan --rate 25000

# Scan specific ports only
kmap --net-scan --rate 25000 -p 22,80,443,3306,8080

# Run phases independently
kmap --net-scan --discover-only --rate 25000    # Fast SYN discovery only
kmap --net-scan --enrich-only                    # Enrich existing data
kmap --net-scan --report-only                    # Generate findings reports

# Resume an interrupted scan
kmap --net-scan --resume

# Monitor your own / client assets with change detection
kmap --net-scan --watchlist clients.txt

# Search collected data
kmap --net-query --nq-port 22 --nq-service openssh
kmap --net-query --nq-cve CVE-2024-6387
kmap --net-query --nq-min-cvss 9.0 --nq-count
```

---

## Building from Source

### Requirements

- GCC 7+ or Clang 5+ (C++17)
- libssh2 (SSH credential probing)
- OpenSSL (HTTPS recon)
- libpcap
- autoconf, automake

**Debian/Ubuntu:**
```bash
sudo apt install build-essential autoconf automake \
                 libssl-dev libpcap-dev libssh2-1-dev
```

**RHEL/CentOS:**
```bash
sudo yum install gcc-c++ autoconf automake \
                 openssl-devel libpcap-devel libssh2-devel
```

### Build

```bash
git clone https://github.com/YurilLAB/Kmap.git
cd Kmap
./configure
make -j$(nproc)
sudo make install
```

The `kmap-cve.db` SQLite database is installed alongside the binary and located automatically at runtime.

---

## Feature Reference

### `--default-creds` — Default Credential Probing

Tests every open port with a detected service against a built-in list of common/default credentials. Stops on the first hit per port.

**Supported protocols:** SSH (libssh2), FTP, Telnet, HTTP Basic Auth, MySQL (SHA1 native auth), PostgreSQL (MD5 auth), MSSQL (TDS Login7), MongoDB (wire protocol)

```bash
kmap --default-creds 10.0.0.1

# Use a custom credential file instead of the built-in list
kmap --default-creds --creds-file /path/to/creds.txt 10.0.0.1

# Set per-attempt timeout (default: 3 seconds)
kmap --default-creds --creds-timeout 5 10.0.0.1
```

**Custom credential file format** (whitespace-separated, `#` for comments):
```
# service  username  password
ssh        root      toor
ftp        admin     password
mysql      root
```

**Example output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1
  |  DEFAULT CREDS 22/tcp: root:root [FOUND]
3306/tcp open mysql  MySQL 5.7.38
  |  DEFAULT CREDS 3306/tcp: root:(empty) [FOUND]
```

---

### `--web-recon` — HTTP/HTTPS Reconnaissance

Performs passive HTTP/HTTPS reconnaissance on every detected web port. Does not attempt exploitation.

```bash
kmap --web-recon 10.0.0.1

# Probe additional paths from a file (one path per line, # for comments)
kmap --web-recon --web-paths /path/to/extra-paths.txt 10.0.0.1
```

**Collects:**
- Page title, `Server`, `X-Powered-By`, `X-Generator` response headers
- TLS certificate subject CN, issuer, expiry date, self-signed detection
- `robots.txt` disallowed paths (often reveals hidden structure)
- HTTP status codes for 180+ high-value paths: admin panels, config files, debug endpoints, backup files, API docs, framework-specific paths, Spring actuator endpoints, Docker/Kubernetes metadata, environment files

**Example output:**
```
PORT    STATE SERVICE VERSION
443/tcp open  https   Apache httpd 2.4.49
  |  Web Recon (443/https):
  |    Title:   Admin Dashboard — MyApp
  |    Server:  Apache/2.4.49 (Ubuntu)
  |    TLS CN:  example.com [self-signed]
  |    Expiry:  Dec 31 23:59:59 2024 GMT
  |    Robots:  /admin, /private, /backup
  |    [200] /admin — Login Required
  |    [200] /.env
  |    [301] /phpMyAdmin → /phpmyadmin/
  |    [200] /api/swagger.json
```

---

### `--cve-map` — CVE Cross-Reference

After service version detection, cross-references each identified product against the bundled `kmap-cve.db` database. Results are sorted by CVSS score descending and filtered by a minimum score threshold.

```bash
kmap --cve-map 10.0.0.1

# Only show CRITICAL (CVSS >= 9.0)
kmap --cve-map --cve-min-score 9.0 10.0.0.1

# Show all severities including MEDIUM
kmap --cve-map --cve-min-score 4.0 10.0.0.1
```

**Database:** `kmap-cve.db` — 10,000+ CVEs from 2021–2026, CVSS >= 7.0 (HIGH and CRITICAL). Covers: OpenSSH, nginx, Apache HTTP, MySQL, PostgreSQL, Redis, Elasticsearch, MSSQL, MongoDB, Samba, Jenkins, GitLab, Confluence, Jira, Exchange, vCenter, WebLogic, Struts, Log4j, OpenSSL, PHP, WordPress, Drupal, and more.

**Example output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
  |_ CVE Map:
  |  22/tcp ssh (OpenSSH 8.2p1):
  |    CVE-2024-6387  CVSS:8.1  HIGH
  |      regreSSHion: race condition in signal handler allows unauthenticated...
  |    CVE-2023-38408  CVSS:9.8  CRITICAL
  |      OpenSSH ssh-agent RCE via crafted PKCS#11 provider loading.
```

CRITICAL CVEs are highlighted **red**, HIGH are **yellow** when `--color` is active.

#### Updating the CVE Database

```bash
# Re-download from NVD (requires internet access)
python3 scripts/update_cves.py

# Insert additional curated CVEs
python3 scripts/add_cves.py

# Import CVEs from any supported file format
kmap --import-cves /path/to/cves.csv
kmap --import-cves /path/to/another.db
kmap --import-cves cves.txt --import-cves-db custom-cve.db
```

**`--import-cves`** accepts:
- **Text files** (`.txt`, `.csv`, `.md`, `.tsv`) — comma, tab, or pipe delimited. Format: `CVE-ID, product, vendor, ver_min, ver_max, cvss_score, severity, description`. Lines starting with `#` are comments.
- **SQLite databases** (`.db`, `.sqlite`) — any database with a `cves` table matching the kmap schema. All rows are imported; duplicates are skipped.

Severity is auto-derived from the CVSS score if not provided. Validation catches invalid CVE IDs, out-of-range CVSS scores, and empty products.

---

### `--report` — Scan Report Generator

Generates a styled report combining all scan results into a single file. The output format is determined by the file extension.

```bash
# Plain text report
kmap --report scan_results.txt -sV 10.0.0.1

# Markdown report (great for sharing or rendering in GitHub/GitLab)
kmap --report findings.md --default-creds --web-recon --cve-map 10.0.0.1
```

**Formats:**
- **`.txt`** — Styled plain text with aligned columns and box separators
- **`.md`** — Markdown with tables, headers, and links

**Report includes:**
- Scan date and target information (IP, hostname)
- Port table with service/version info
- Default credential findings (if `--default-creds` used)
- Web recon results (if `--web-recon` used)
- CVE map results (if `--cve-map` used)
- Summary statistics (hosts, ports, creds found, CVEs, scan time)

---

### `--screenshot` — Web Page Screenshots

Captures PNG screenshots of every discovered HTTP/HTTPS port using a headless browser. Auto-detects Chrome, Chromium, Edge, or Firefox.

```bash
# Capture to default directory (kmap-screenshots/)
kmap --screenshot 10.0.0.1

# Custom output directory
kmap --screenshot --screenshot-dir /path/to/output 10.0.0.1

# Combine with web recon for full picture
kmap --screenshot --web-recon --report findings.md 10.0.0.1
```

Screenshots are saved as `<ip>_<port>.png` (e.g., `10.0.0.1_443.png`). Requires one of: Google Chrome, Chromium, Microsoft Edge, or Firefox installed on the system.

---

## Internet-Scale Scanning (`--net-scan`)

Kmap includes a built-in internet-scale scanning pipeline inspired by the same techniques used by the NSA's HACIENDA program and commercial platforms like Shodan and Censys. It scans the entire public IPv4 address space (~3.7 billion addresses), enriches discovered hosts with service detection, CVE cross-referencing, and web reconnaissance, then outputs structured findings reports.

Everything runs from the same `kmap` binary with zero external dependencies. No masscan, no Python, no separate database server — just Kmap and its bundled SQLite.

### How It Works

The pipeline runs in three phases:

```
Phase 1: DISCOVER     Fast SYN scanner sweeps the IPv4 space
    ↓                 Records open ports in sharded SQLite databases
Phase 2: ENRICH       Connects to each discovered port
    ↓                 Banner grab → service detection → CVE lookup → web recon
Phase 3: REPORT       Reads enriched data
    ↓                 Generates Findings/*.txt files (72,348 IPs per file)
```

**Discovery** uses a custom high-speed scanner with:
- Randomized IP iteration (multiplicative-inverse permutation — avoids sequential sweeps that ISPs detect)
- Token bucket rate limiter (default 25,000 pps, configurable)
- Hard-coded exclusion of all private, reserved, multicast, and DoD ranges
- Checkpoint/resume support (Ctrl+C saves progress, `--resume` continues)

**Enrichment** connects to each discovered host and:
- Grabs service banners and matches against known patterns (SSH, HTTP, FTP, MySQL, PostgreSQL, etc.)
- Cross-references detected versions against the bundled CVE database
- Performs HTTP reconnaissance on web ports (title, server header, interesting paths)
- All probes have 5-second timeouts — blocked/rate-limited hosts are skipped, never stall the pipeline

**Results** are stored in sharded SQLite databases (32 shards, split by `/5` IP prefix) and written to styled text reports.

### Commands

```bash
# Full pipeline: discover → enrich → report
kmap --net-scan --rate 25000

# Scan only specific ports
kmap --net-scan --rate 25000 -p 22,80,443,3306,8080

# Run each phase independently
kmap --net-scan --discover-only --rate 25000
kmap --net-scan --enrich-only
kmap --net-scan --report-only

# Resume after interruption
kmap --net-scan --resume

# Use custom directories
kmap --net-scan --data-dir /mnt/storage/kmap-data --findings-dir /mnt/storage/Findings

# Add custom exclusion ranges
kmap --net-scan --exclude-file my_excludes.txt
```

### Findings Output

Reports are written to `Findings/` with exactly 72,348 IPs per file:

```
Findings/
├── findings_0000001-0072348.txt
├── findings_0072349-0144696.txt
└── ...
```

Each file contains the full scan results per host:

```
================================================================================
  TARGET: 93.184.216.34
================================================================================

  PORT TABLE
  --------------------------------------------------------------------------
  PORT          STATE     SERVICE         VERSION
  80/tcp        open      http            nginx 1.18.0
  443/tcp       open      https           nginx 1.18.0

  CVE MAP
  --------------------------------------------------------------------------
  80/tcp http (nginx 1.18.0):
    CVE-2021-23017  CVSS:7.7  HIGH
      1-byte memory overwrite in nginx resolver...

  WEB RECON
  --------------------------------------------------------------------------
  Port 443/https:
    Title:   Example Domain
    Server:  nginx/1.18.0
    [200] /robots.txt
```

---

## Watchlist Monitoring (`--watchlist`)

Monitor your own and client assets for changes. Kmap scans the targets, compares against the previous scan, and generates a diff report showing what changed.

```bash
# Create a targets file
echo "10.0.0.1" > clients.txt
echo "192.168.1.0/24" >> clients.txt

# Run watchlist scan
kmap --net-scan --watchlist clients.txt
```

Output:

```
Findings/watchlist/
├── full_2026-04-14.txt       Complete current state
└── diff_2026-04-14.txt       Changes since last scan
```

The diff report highlights:
- **New ports** opened since last scan
- **Closed ports** that were previously open
- **New CVEs** applicable to existing services
- **Version changes** in detected software
- **Title changes** on web pages

---

## Querying Scan Data (`--net-query`)

Search across all collected scan data using filters. Works on the sharded databases populated by `--net-scan`.

```bash
# Find all hosts with OpenSSH on port 22
kmap --net-query --nq-port 22 --nq-service openssh

# Find everything with critical CVEs
kmap --net-query --nq-min-cvss 9.0

# Find specific CVE across all scanned hosts
kmap --net-query --nq-cve CVE-2024-6387

# Find web servers with a specific title
kmap --net-query --nq-web-title "phpMyAdmin"

# Count results
kmap --net-query --nq-port 443 --nq-count

# Export to file
kmap --net-query --nq-port 3306 --nq-output mysql_hosts.txt

# Narrow search to IP range
kmap --net-query --nq-ip-range 93.184.0.0/16
```

---

## All Options Reference

### Scanning Features

| Option | Description |
|---|---|
| `--default-creds` | Test open services for default/common credentials |
| `--creds-file <file>` | Custom credential wordlist (overrides built-in) |
| `--creds-timeout <sec>` | Per-attempt timeout for credential checks (default: 3) |
| `--web-recon` | HTTP/S reconnaissance on detected web ports |
| `--web-paths <file>` | Additional paths to probe during web recon |
| `--cve-map` | Cross-reference service versions with CVE database |
| `--cve-min-score <score>` | Minimum CVSS score to report (default: 7.0) |
| `--screenshot` | Capture PNG screenshots of web ports |
| `--screenshot-dir <dir>` | Screenshot output directory (default: `kmap-screenshots`) |

### Output Options

| Option | Description |
|---|---|
| `-oJ <file>` | JSON output (complements `-oN`, `-oX`, `-oG`) |
| `--report <file>` | Generate scan report (`.txt` or `.md` format) |
| `--color=auto\|always\|never` | Terminal color (default: auto) |

### CVE Database Management

| Option | Description |
|---|---|
| `--import-cves <file>` | Import CVEs from text/CSV/SQLite file |
| `--import-cves-db <path>` | Custom target database (default: `kmap-cve.db`) |

### Internet-Scale Scanning

| Option | Description |
|---|---|
| `--net-scan` | Run the full scanning pipeline (discover + enrich + report) |
| `--discover-only` | Only run the SYN scan discovery phase |
| `--enrich-only` | Only enrich existing shard databases |
| `--report-only` | Only generate findings from enriched data |
| `--resume` | Resume an interrupted net-scan |
| `--rate <pps>` | Discovery rate in packets per second (default: 25,000) |
| `--exclude-file <file>` | Additional IP ranges to exclude from scanning |
| `--data-dir <dir>` | Shard database directory (default: `kmap-data`) |
| `--findings-dir <dir>` | Findings output directory (default: `Findings`) |
| `--watchlist <file>` | Scan targets from file with change detection |

### Data Query

| Option | Description |
|---|---|
| `--net-query` | Search collected scan data |
| `--nq-port <port>` | Filter by port number |
| `--nq-service <name>` | Filter by service name |
| `--nq-cve <id>` | Filter by CVE ID |
| `--nq-min-cvss <score>` | Filter by minimum CVSS score |
| `--nq-web-title <text>` | Filter by web page title |
| `--nq-web-server <text>` | Filter by server header |
| `--nq-ip-range <CIDR>` | Restrict search to IP range |
| `--nq-output <file>` | Export query results to file |
| `--nq-count` | Show count instead of listing results |

---

## Project Layout

```
Kmap/
├── kmap.cc               Main entry point and argument parsing
├── KmapOps.h/cc          Global options struct
├── output.cc             Text/machine/XML output
├── output_json.cc        JSON serializer + report generator
├── default_creds.cc      --default-creds probe engine
├── web_recon.cc          --web-recon HTTP/S recon + screenshot engine
├── cve_map.cc            --cve-map CVE lookup + import engine
├── net_scan.cc           --net-scan pipeline orchestrator
├── fast_syn.cc           High-speed SYN scanner for internet-scale discovery
├── net_db.cc             Sharded SQLite database manager
├── net_enrich.cc         Enrichment pipeline (service + CVE + web recon)
├── net_report.cc         Findings report generator (72,348 IPs per file)
├── net_query.cc          CLI query engine for searching collected data
├── exclude.conf          Default IP exclusion ranges
├── color.h               ANSI color helpers
├── sqlite/               SQLite 3.53.0 amalgamation
├── third-party/nlohmann/ nlohmann/json single-header library
├── kmap-cve.db           CVE database (10,000+ entries, ~5MB)
└── scripts/
    ├── update_cves.py    Download CVEs from NVD JSON 2.0 feeds
    └── add_cves.py       Insert additional CVE records
```

---

## Differences from nmap

- **CLI only** — Zenmap GUI removed
- **Renamed throughout** — binary `kmap`, data files `kmap-*`, config `~/.kmap/`
- **Offensive features** — `--default-creds`, `--web-recon`, `--cve-map`, `--screenshot`
- **Internet-scale scanning** — `--net-scan` with built-in SYN scanner, sharded database, enrichment pipeline
- **Watchlist monitoring** — `--watchlist` with change detection and diff reports
- **Data query** — `--net-query` for searching collected scan data
- **Report generation** — `--report` for styled `.txt` / `.md` output
- **JSON output** — `-oJ` via nlohmann/json
- **Terminal colors** — `--color` with `NO_COLOR` env var support
- **Full protocol authentication** — MySQL SHA1, PostgreSQL MD5, MSSQL TDS Login7 (when OpenSSL is available)
- **IPv6 support** in all custom probes
- **C++17** for modified source files
- **Bundled SQLite** — no external DB dependency for CVE lookups or scan data

All existing nmap scan types, NSE scripts, OS fingerprinting, timing profiles, decoys, and output formats work unchanged.

---

## Responsible Scanning

When using `--net-scan` for internet-wide scanning:

- **Rate limit appropriately** — the default 25,000 pps is safe for most broadband connections. Start lower if unsure.
- **Set up identification** — configure a reverse DNS PTR record on your scanning IP (e.g., `scanner.yourdomain.com`) and host a simple page explaining your research.
- **Honor opt-outs** — maintain an abuse contact email and respect requests to exclude IP ranges.
- **Know your jurisdiction** — network scanning laws vary by country. Ensure compliance with local regulations.
- **Excluded by default** — Kmap automatically skips all RFC 1918 private addresses, loopback, multicast, link-local, documentation ranges, and US DoD address space.

---

## Legal Notice

Kmap is intended for authorized security testing and research only. Only scan networks and systems you own or have explicit written permission to test. Internet-wide scanning of public-facing services is legal in most jurisdictions (Shodan, Censys, and similar services operate commercially), but unauthorized access or exploitation is not. The authors assume no liability for misuse.
