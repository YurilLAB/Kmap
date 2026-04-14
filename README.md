<p align="center">
  <img src="kmap_logo.png" alt="Kmap Logo" width="600">
</p>

# Kmap

**Kmap** is a fork of [nmap](https://nmap.org/) extended with active pentesting capabilities. It keeps everything nmap does — port scanning, service detection, OS fingerprinting, NSE scripts — and adds three new offensive features designed for security assessments.

> **License:** Kmap inherits the Nmap Public Source License (NPSL). See `LICENSE` for full terms.

---

## What's New Over nmap

| Feature | Flag | What it does |
|---|---|---|
| Default credential probing | `--default-creds` | Tests open services against 175+ built-in credential pairs |
| HTTP/S recon | `--web-recon` | Grabs titles, headers, TLS info, probes 95+ high-value paths |
| CVE cross-reference | `--cve-map` | Queries bundled 10,000+ CVE database for detected service versions |
| Scan report | `--report <file>` | Generates a styled .txt or .md report with all findings |
| Web screenshots | `--screenshot` | Captures PNG screenshots of discovered web ports |

All features auto-enable `-sV` (service/version detection) and print results inline alongside the normal port table.

---

## Quick Start

```bash
# Standard scan — all nmap features work unchanged
kmap -sV -sC 192.168.1.0/24

# Probe open services for default credentials
kmap --default-creds 10.0.0.1

# HTTP/S recon: title, headers, TLS cert, interesting paths
kmap --web-recon 10.0.0.1

# Cross-reference detected service versions with CVE database
kmap --cve-map 10.0.0.1

# Run all three features together
kmap --default-creds --web-recon --cve-map -p 22,80,443,3306,5432 10.0.0.1

# Generate a scan report (txt or md format)
kmap --report results.txt -sV 10.0.0.1
kmap --report findings.md --default-creds --cve-map 10.0.0.1

# Capture screenshots of web ports
kmap --screenshot 10.0.0.1
kmap --screenshot --screenshot-dir /tmp/screens 10.0.0.1

# JSON output
kmap -sV -oJ results.json 10.0.0.1

# Colored terminal output
kmap --color=always -sV 10.0.0.1
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
- HTTP status codes for 95+ high-value paths: admin panels, config files, debug endpoints, backup files, API docs, framework-specific paths, Spring actuator endpoints, Docker/Kubernetes metadata, environment files

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

**Database:** `kmap-cve.db` — 10,000+ CVEs from 2021–2026, CVSS ≥ 7.0 (HIGH and CRITICAL). Covers: OpenSSH, nginx, Apache HTTP, MySQL, PostgreSQL, Redis, Elasticsearch, MSSQL, MongoDB, Samba, Jenkins, GitLab, Confluence, Jira, Exchange, vCenter, WebLogic, Struts, Log4j, OpenSSL, PHP, WordPress, Drupal, and more.

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

## Additional Options

| Option | Description |
|---|---|
| `-oJ <file>` | JSON output (complements existing `-oN`, `-oX`, `-oG`) |
| `--color=auto\|always\|never` | Terminal color (default: auto via `isatty` + `NO_COLOR`) |
| `--import-cves <file>` | Import CVEs from text/CSV/SQLite file into the database |
| `--import-cves-db <path>` | Target database for import (default: `kmap-cve.db`) |
| `--report <file>` | Generate scan report (`.txt` or `.md` format based on extension) |
| `--screenshot` | Capture PNG screenshots of discovered web ports |
| `--screenshot-dir <dir>` | Output directory for screenshots (default: `kmap-screenshots`) |
| `--net-scan` | Internet-scale scanning pipeline (discover + enrich + report) |
| `--discover-only` | Only run the SYN scan discovery phase |
| `--enrich-only` | Only enrich existing shard databases |
| `--report-only` | Only generate findings from enriched data |
| `--resume` | Resume an interrupted net-scan |
| `--rate <pps>` | Discovery packets per second (default: 25000) |
| `--watchlist <file>` | Scan targets from file with change detection |
| `--net-query` | Search collected scan data |
| `--nq-port <port>` | Query filter: port number |
| `--nq-service <name>` | Query filter: service name |
| `--nq-cve <id>` | Query filter: CVE ID |
| `--nq-min-cvss <score>` | Query filter: minimum CVSS score |

---

## Project Layout

```
Kmap/
├── kmap.cc               Main entry point and argument parsing
├── KmapOps.h/cc          Global options struct
├── output.cc             Text/machine/XML output
├── output_json.cc        JSON serializer (nlohmann/json 3.12.0)
├── default_creds.cc      --default-creds probe engine
├── web_recon.cc          --web-recon HTTP/S recon engine
├── cve_map.cc            --cve-map CVE lookup engine
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
- **Three new features** — `--default-creds`, `--web-recon`, `--cve-map`
- **JSON output** — `-oJ` via nlohmann/json
- **Terminal colors** — `--color` with `NO_COLOR` env var support
- **Full protocol authentication** — MySQL SHA1, PostgreSQL MD5, MSSQL TDS Login7 (when OpenSSL is available)
- **IPv6 support** in all custom probes
- **C++17** for modified source files
- **Bundled SQLite** — no external DB dependency for CVE lookups

All existing nmap scan types, NSE scripts, OS fingerprinting, timing profiles, decoys, and output formats work unchanged.

---

## Legal Notice

Kmap is intended for authorized security testing only. Only scan networks and systems you own or have explicit written permission to test. Unauthorized use may violate computer crime laws. The authors assume no liability for misuse.
