#!/usr/bin/env python3
"""
update_cves.py - NVD CVE feed downloader and importer for kmap-cve.db

Downloads NVD JSON 2.0 annual feeds (2021-2026) and populates a local SQLite
database with CVEs relevant to pentesting-relevant network services.
Falls back to NVD 1.1 feeds if 2.0 are unavailable.

Usage:
    python scripts/update_cves.py [--db PATH] [--years 2021,2022,...]
"""

import sqlite3
import gzip
import json
import urllib.request
import urllib.error
import os
import sys
import time
import argparse
from datetime import date

# ── Configuration ────────────────────────────────────────────────────────────

DEFAULT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "kmap-cve.db")

# NVD feed URL templates (2.0 format is preferred; 1.1 is legacy/fallback)
NVD_2_0_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
NVD_1_1_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"

YEARS = [2021, 2022, 2023, 2024, 2025, 2026]
MIN_CVSS = 7.0          # Only import CVEs with CVSS >= this value
REQUEST_TIMEOUT = 120   # seconds per HTTP request

# ── Curated corrections ───────────────────────────────────────────────────────
# NVD's machine-readable data is sometimes imprecise in ways that produce
# scanner false positives: a CVE may carry an upper version bound but no lower
# bound (so it matches every older release, even ones predating the bug), or be
# CPE-tagged to a product whose name collides with an unrelated one. These are
# applied AFTER import (and via --apply-corrections-only) so the shipped DB and
# every regeneration stay accurate. Verified against the CVE's own advisory.
CORRECTIONS = [
    # Introduced in OpenSSH 9.0/9.1, fixed in 9.2p1 (double-free in
    # options.kex_algorithms). NVD omits the lower bound, so the row matched
    # every OpenSSH back to the 2000s (e.g. 6.6.1p1) -- a false positive.
    ("CVE-2023-25136", {"version_min": "9.0", "version_max": "9.1"}),
    # "IngressNightmare" is an unauth RCE in the Kubernetes ingress-nginx
    # Controller (< 1.11.5 / < 1.12.1), NOT the nginx web server. Re-tag the
    # product so it can never match a plain nginx banner.
    ("CVE-2025-1974", {"product": "ingress-nginx",
                       "version_min": "0", "version_max": "1.12.1"}),
]

# ── Target products (lower-cased keywords) ───────────────────────────────────
TARGET_VENDORS = {
    "apache", "nginx", "openssh", "vsftpd", "proftpd",
    "mysql", "postgresql", "mssql", "microsoft", "mongodb",
    "log4j", "log4shell", "spring", "struts", "jenkins", "confluence", "jira",
    "wordpress", "drupal", "joomla", "phpmyadmin",
    "openssl", "libssl",
    "exchange", "sharepoint", "iis",
    "cisco", "fortinet", "palo_alto", "paloalto", "fortios",
    "atlassian", "vmware", "weblogic", "oracle",
    "tomcat", "jetty", "glassfish",
    "samba", "smb", "rdp", "ssl", "tls",
}

TARGET_PRODUCTS = {
    "apache_http_server", "apache_tomcat", "apache_log4j", "apache_struts",
    "nginx", "openssh", "vsftpd", "proftpd",
    "mysql", "mysql_server", "mariadb", "postgresql", "sql_server", "mongodb",
    "log4j", "log4j2",
    "spring_framework", "spring_boot", "spring_cloud",
    "jenkins", "confluence_server", "confluence_data_center", "jira",
    "wordpress", "drupal", "joomla", "phpmyadmin",
    "openssl",
    "exchange_server", "sharepoint_server", "internet_information_services",
    "ios", "ios_xe", "ios_xr", "asa", "fortigate", "fortios",
    "pan-os", "globalprotect",
    "smb", "samba", "rdp", "remote_desktop",
    "weblogic_server",
}


# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
  cve_id      TEXT PRIMARY KEY,
  product     TEXT NOT NULL,
  vendor      TEXT,
  version_min TEXT,
  version_max TEXT,
  cvss_score  REAL,
  severity    TEXT,
  description TEXT
);
CREATE INDEX IF NOT EXISTS idx_product  ON cves(product);
CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity);
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);
"""


def init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_updated', ?)", (str(date.today()),))
    conn.execute("INSERT OR IGNORE INTO meta VALUES ('cve_count', '0')")
    conn.execute("INSERT OR REPLACE INTO meta VALUES ('years_covered', '2021-2026')")
    conn.commit()
    return conn


# ── Helpers ───────────────────────────────────────────────────────────────────

def fetch_gz(url, retries=2):
    """Download a gzip URL and return decompressed bytes. Returns None on failure."""
    headers = {"User-Agent": "kmap-cve-updater/1.0 (github.com/kmap-project)"}
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                compressed = resp.read()
            return gzip.decompress(compressed)
        except urllib.error.HTTPError as e:
            print(f"  HTTP {e.code} for {url}", flush=True)
            return None
        except Exception as e:
            if attempt < retries:
                wait = 5 * (attempt + 1)
                print(f"  Attempt {attempt+1} failed ({e}), retrying in {wait}s…", flush=True)
                time.sleep(wait)
            else:
                print(f"  Failed after {retries+1} attempts: {e}", flush=True)
                return None


def is_target(vendor_str, product_str):
    """Return True if this vendor/product is in our target list."""
    v = (vendor_str or "").lower().replace(" ", "_").replace("-", "_")
    p = (product_str or "").lower().replace(" ", "_").replace("-", "_")
    if any(t in v for t in TARGET_VENDORS):
        return True
    if any(t in p for t in TARGET_PRODUCTS):
        return True
    # Also match partial product tokens
    for token in TARGET_PRODUCTS:
        if token in p or token in v:
            return True
    return False


# ── NVD 2.0 parser ────────────────────────────────────────────────────────────

def parse_nvd_2_0(data_bytes):
    """Parse NVD CVE 2.0 feed JSON. Returns list of row dicts."""
    try:
        data = json.loads(data_bytes)
    except json.JSONDecodeError as e:
        print(f"  JSON parse error: {e}", flush=True)
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    rows = []

    for entry in vulnerabilities:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")

        # ── Description (English) ────────────────────────────────────────────
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # ── CVSS score ───────────────────────────────────────────────────────
        cvss_score = None
        severity = None
        metrics = cve.get("metrics", {})

        # Prefer CVSSv3.1 > CVSSv3.0 > CVSSv2
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                m = metric_list[0].get("cvssData", {})
                cvss_score = m.get("baseScore")
                severity = m.get("baseSeverity") or metric_list[0].get("baseSeverity")
                if cvss_score is not None:
                    break

        if cvss_score is None or cvss_score < MIN_CVSS:
            continue

        # ── CPE / vendor / product / versions ────────────────────────────────
        configurations = cve.get("configurations", [])
        extracted = extract_cpe_info_2_0(configurations)

        # No CPE applicability data => no version bounds. The previous code
        # keyword-matched the description to a target product and inserted a
        # row with version_min/version_max = None, which then matched EVERY
        # version of that product and collided across similarly-named products
        # (e.g. a Kubernetes "ingress-nginx" CVE tagged as plain "nginx"). The
        # matcher now rejects bound-less rows, so such inserts are unmatchable
        # noise and a false-positive hazard -- skip them. A CVE with no
        # machine-readable version applicability is not an actionable finding.
        for info in extracted:
            if not is_target(info["vendor"], info["product"]):
                continue
            rows.append({
                "cve_id": cve_id,
                "product": info["product"],
                "vendor": info["vendor"],
                "version_min": info["version_min"],
                "version_max": info["version_max"],
                "cvss_score": cvss_score,
                "severity": severity,
                "description": desc[:2000],
            })

    return rows


def extract_cpe_info_2_0(configurations):
    """Extract vendor/product/version info from NVD 2.0 configurations."""
    results = []
    seen = set()

    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for cpe_match in cpe_matches:
                if not cpe_match.get("vulnerable", True):
                    continue
                cpe_name = cpe_match.get("criteria", "")
                parts = cpe_name.split(":")
                # cpe:2.3:a:vendor:product:version:...
                if len(parts) < 5:
                    continue
                vendor = parts[3] if parts[3] != "*" else None
                product = parts[4] if parts[4] != "*" else None

                version_min = (cpe_match.get("versionStartIncluding") or
                               cpe_match.get("versionStartExcluding"))
                version_max = (cpe_match.get("versionEndIncluding") or
                               cpe_match.get("versionEndExcluding"))

                # Single-version CPE (no range): the affected version is pinned
                # in field 5 of the CPE string. Capture it as an exact bound so
                # the row is version-constrained instead of matching everything.
                if not version_min and not version_max and len(parts) > 5:
                    exact = parts[5]
                    if exact and exact not in ("*", "-"):
                        version_min = exact
                        version_max = exact

                key = (vendor, product, version_min, version_max)
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "vendor": vendor,
                    "product": product,
                    "version_min": version_min,
                    "version_max": version_max,
                })
    return results


# ── NVD 1.1 parser ────────────────────────────────────────────────────────────

def parse_nvd_1_1(data_bytes):
    """Parse NVD CVE 1.1 feed JSON. Returns list of row dicts."""
    try:
        data = json.loads(data_bytes)
    except json.JSONDecodeError as e:
        print(f"  JSON parse error: {e}", flush=True)
        return []

    cve_items = data.get("CVE_Items", [])
    rows = []

    for item in cve_items:
        cve_meta = item.get("cve", {})
        cve_id = cve_meta.get("CVE_data_meta", {}).get("ID", "")

        # ── Description ───────────────────────────────────────────────────────
        desc = ""
        desc_data = cve_meta.get("description", {}).get("description_data", [])
        for d in desc_data:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # ── CVSS ──────────────────────────────────────────────────────────────
        cvss_score = None
        severity = None
        impact = item.get("impact", {})
        bm_v3 = impact.get("baseMetricV3", {})
        bm_v2 = impact.get("baseMetricV2", {})

        if bm_v3:
            cvss_v3 = bm_v3.get("cvssV3", {})
            cvss_score = cvss_v3.get("baseScore")
            severity = cvss_v3.get("baseSeverity") or bm_v3.get("severity")
        elif bm_v2:
            cvss_score = bm_v2.get("cvssV2", {}).get("baseScore")
            severity = bm_v2.get("severity")

        if cvss_score is None or cvss_score < MIN_CVSS:
            continue

        # ── CPE ───────────────────────────────────────────────────────────────
        configurations = item.get("configurations", {})
        extracted = extract_cpe_info_1_1(configurations)

        # Same policy as the 2.0 parser: no CPE data => no version bounds =>
        # skip. Bound-less, description-keyword rows are unmatchable under the
        # corrected matcher and are a product-collision false-positive hazard.
        for info in extracted:
            if not is_target(info["vendor"], info["product"]):
                continue
            rows.append({
                "cve_id": cve_id,
                "product": info["product"],
                "vendor": info["vendor"],
                "version_min": info["version_min"],
                "version_max": info["version_max"],
                "cvss_score": cvss_score,
                "severity": severity,
                "description": desc[:2000],
            })

    return rows


def extract_cpe_info_1_1(configurations):
    """Extract vendor/product/version info from NVD 1.1 configurations."""
    results = []
    seen = set()

    nodes = configurations.get("nodes", [])
    for node in nodes:
        cpe_matches = node.get("cpe_match", [])
        # also check children
        children = node.get("children", [])
        for child in children:
            cpe_matches += child.get("cpe_match", [])

        for cpe_match in cpe_matches:
            if not cpe_match.get("vulnerable", True):
                continue
            cpe_str = cpe_match.get("cpe23Uri", "") or cpe_match.get("cpe22Uri", "")
            parts = cpe_str.split(":")
            if len(parts) < 5:
                continue
            vendor = parts[3] if parts[3] not in ("*", "-") else None
            product = parts[4] if parts[4] not in ("*", "-") else None

            version_min = (cpe_match.get("versionStartIncluding") or
                           cpe_match.get("versionStartExcluding"))
            version_max = (cpe_match.get("versionEndIncluding") or
                           cpe_match.get("versionEndExcluding"))

            # Single-version CPE (no range): capture the pinned version (field 5)
            # as an exact bound so the row is version-constrained.
            if not version_min and not version_max and len(parts) > 5:
                exact = parts[5]
                if exact and exact not in ("*", "-"):
                    version_min = exact
                    version_max = exact

            key = (vendor, product, version_min, version_max)
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "vendor": vendor,
                "product": product,
                "version_min": version_min,
                "version_max": version_max,
            })
    return results


# ── Insert rows ───────────────────────────────────────────────────────────────

def insert_rows(conn, rows):
    """Insert (or ignore duplicate) rows into the cves table."""
    inserted = 0
    for row in rows:
        try:
            conn.execute(
                """INSERT OR IGNORE INTO cves
                   (cve_id, product, vendor, version_min, version_max,
                    cvss_score, severity, description)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (row["cve_id"], row["product"], row["vendor"],
                 row["version_min"], row["version_max"],
                 row["cvss_score"], row["severity"], row["description"])
            )
            if conn.execute("SELECT changes()").fetchone()[0]:
                inserted += 1
        except sqlite3.Error as e:
            print(f"  DB error for {row['cve_id']}: {e}", flush=True)
    conn.commit()
    return inserted


def apply_corrections(conn):
    """Apply the curated CORRECTIONS to rows already in the DB. Idempotent."""
    applied = 0
    for cve_id, fields in CORRECTIONS:
        row = conn.execute("SELECT 1 FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
        if not row:
            continue
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [cve_id]
        conn.execute(f"UPDATE cves SET {sets} WHERE cve_id=?", vals)
        applied += 1
        print(f"  correction: {cve_id} -> {fields}", flush=True)
    conn.commit()
    return applied


# ── Main ──────────────────────────────────────────────────────────────────────

def process_year(conn, year):
    """Try to download and import CVE data for a single year. Returns inserted count."""
    print(f"\n[{year}] Downloading NVD 2.0 feed…", flush=True)
    url_2 = NVD_2_0_URL.format(year=year)
    data = fetch_gz(url_2)

    parser = None
    if data:
        print(f"  Downloaded {len(data):,} bytes (uncompressed)", flush=True)
        parser = parse_nvd_2_0
    else:
        # Fallback to 1.1
        print(f"  2.0 feed unavailable, trying 1.1 fallback…", flush=True)
        url_1 = NVD_1_1_URL.format(year=year)
        data = fetch_gz(url_1)
        if data:
            print(f"  Downloaded {len(data):,} bytes (uncompressed) [1.1 format]", flush=True)
            parser = parse_nvd_1_1
        else:
            print(f"  Both feeds unavailable for {year}, skipping.", flush=True)
            return 0

    rows = parser(data)
    print(f"  Parsed {len(rows)} relevant CVE entries", flush=True)
    inserted = insert_rows(conn, rows)
    print(f"  Inserted {inserted} new rows", flush=True)
    return inserted


def update_meta_count(conn):
    count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    conn.execute("UPDATE meta SET value=? WHERE key='cve_count'", (str(count),))
    conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_updated', ?)", (str(date.today()),))
    conn.commit()
    return count


def main():
    parser = argparse.ArgumentParser(description="Update kmap CVE database from NVD feeds")
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to SQLite database")
    parser.add_argument("--years", help="Comma-separated years to import (default: 2021-2026)")
    parser.add_argument("--apply-corrections-only", action="store_true",
                        help="Apply the curated CORRECTIONS to an existing DB and exit "
                             "(no network download)")
    args = parser.parse_args()

    if args.apply_corrections_only:
        conn = sqlite3.connect(args.db)
        n = apply_corrections(conn)
        update_meta_count(conn)
        conn.close()
        print(f"Applied {n} correction(s) to {args.db}")
        return

    years = YEARS
    if args.years:
        years = [int(y.strip()) for y in args.years.split(",")]

    db_path = args.db
    print(f"Database: {db_path}", flush=True)
    print(f"Years to import: {years}", flush=True)
    print(f"Min CVSS score: {MIN_CVSS}", flush=True)

    conn = init_db(db_path)
    total_inserted = 0
    succeeded = []
    failed = []

    for year in years:
        try:
            n = process_year(conn, year)
            if n >= 0:
                succeeded.append(year)
                total_inserted += n
        except Exception as e:
            print(f"  Unexpected error for {year}: {e}", flush=True)
            failed.append(year)

    print("\nApplying curated corrections…", flush=True)
    apply_corrections(conn)

    final_count = update_meta_count(conn)
    conn.close()

    print("\n" + "=" * 60)
    print(f"Import complete.")
    print(f"  Years succeeded : {succeeded}")
    print(f"  Years failed    : {failed}")
    print(f"  Rows inserted   : {total_inserted}")
    print(f"  Total in DB     : {final_count}")
    print("=" * 60)


if __name__ == "__main__":
    main()
