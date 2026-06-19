#!/usr/bin/env python3
"""
update_epss_kev.py -- enrich kmap-cve.db with EPSS scores and CISA KEV flags.

Two industry-standard exploit-triage signals, layered on top of the existing
CVSS data so --cve-map / --net-query can rank by "likely to be exploited" and
"known exploited in the wild" instead of severity alone:

  * EPSS (Exploit Prediction Scoring System, FIRST.org) -- a daily-updated
    probability (0..1) that a CVE will be exploited in the next 30 days, plus
    its percentile rank. Source: https://www.first.org/epss/

  * CISA KEV (Known Exploited Vulnerabilities catalog) -- the authoritative
    U.S. CISA list of CVEs with confirmed in-the-wild exploitation, including
    the date added and whether it is tied to a known ransomware campaign.
    Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Only rows already present in kmap-cve.db are touched -- this never adds new
CVEs (use update_cves.py / add_cves.py for that), it annotates the ones the
bundled DB already matches against.

Usage:
    python scripts/update_epss_kev.py [--db PATH]
                                      [--epss-file FILE] [--kev-file FILE]
                                      [--no-download]

With no file overrides the current EPSS CSV (gzip) and KEV JSON are downloaded.
--epss-file / --kev-file use a local copy instead (the file may be .gz or
plain); --no-download requires both files to be supplied locally.
"""

import argparse
import csv
import gzip
import io
import json
import os
import sqlite3
import sys
import urllib.request
from datetime import date

DEFAULT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "kmap-cve.db")

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
REQUEST_TIMEOUT = 120  # seconds


# ── Schema ────────────────────────────────────────────────────────────────────

# (column, type) pairs added to the cves table. ALTER TABLE ADD COLUMN is
# idempotent-guarded below (SQLite has no ADD COLUMN IF NOT EXISTS).
NEW_COLUMNS = [
    ("epss_score", "REAL"),       # 0..1 exploitation probability (next 30 days)
    ("epss_percentile", "REAL"),  # 0..1 percentile rank of epss_score
    ("kev", "INTEGER"),           # 1 = listed in the CISA KEV catalog, else 0
    ("kev_date_added", "TEXT"),   # ISO date the CVE entered the KEV catalog
    ("kev_ransomware", "INTEGER"),  # 1 = known ransomware-campaign use
]


def ensure_columns(conn):
    existing = {r[1] for r in conn.execute("PRAGMA table_info(cves)")}
    for col, typ in NEW_COLUMNS:
        if col not in existing:
            conn.execute(f"ALTER TABLE cves ADD COLUMN {col} {typ}")
    # KEV-only queries (--nq-kev) hit this; partial index keeps it tiny.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_kev "
                 "ON cves(kev) WHERE kev = 1")
    conn.commit()


# ── Fetch helpers ─────────────────────────────────────────────────────────────

def _read_maybe_gzip(raw, name):
    """Return text from bytes that may or may not be gzip-compressed."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return raw.decode("utf-8", "replace")


def load_epss(path, allow_download):
    if path:
        with open(path, "rb") as f:
            raw = f.read()
    elif allow_download:
        print(f"  downloading EPSS: {EPSS_URL}")
        with urllib.request.urlopen(EPSS_URL, timeout=REQUEST_TIMEOUT) as r:
            raw = r.read()
    else:
        return {}
    text = _read_maybe_gzip(raw, "EPSS")
    scores = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("cve,"):  # header
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        cve = parts[0].strip().upper()
        try:
            scores[cve] = (float(parts[1]), float(parts[2]))
        except ValueError:
            continue
    return scores


def load_kev(path, allow_download):
    if path:
        with open(path, "rb") as f:
            raw = f.read()
    elif allow_download:
        print(f"  downloading KEV:  {KEV_URL}")
        with urllib.request.urlopen(KEV_URL, timeout=REQUEST_TIMEOUT) as r:
            raw = r.read()
    else:
        return {}
    data = json.loads(_read_maybe_gzip(raw, "KEV"))
    kev = {}
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        ransom = 1 if (v.get("knownRansomwareCampaignUse", "")
                       .strip().lower() == "known") else 0
        kev[cve] = (v.get("dateAdded", ""), ransom)
    return kev


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Enrich kmap-cve.db with EPSS + CISA KEV")
    ap.add_argument("--db", default=DEFAULT_DB, help="path to kmap-cve.db")
    ap.add_argument("--epss-file", help="local EPSS CSV (.gz or plain)")
    ap.add_argument("--kev-file", help="local CISA KEV JSON")
    ap.add_argument("--no-download", action="store_true",
                    help="never fetch over the network; requires local files")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"ERROR: database not found: {args.db}", file=sys.stderr)
        return 1

    allow_download = not args.no_download
    if args.no_download and not (args.epss_file or args.kev_file):
        print("ERROR: --no-download requires --epss-file and/or --kev-file",
              file=sys.stderr)
        return 1

    conn = sqlite3.connect(args.db)
    try:
        ensure_columns(conn)
        total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        db_ids = {r[0].upper() for r in conn.execute("SELECT cve_id FROM cves")}

        print(f"kmap-cve.db: {total} CVEs")
        epss = load_epss(args.epss_file, allow_download)
        kev = load_kev(args.kev_file, allow_download)
        print(f"  EPSS dataset: {len(epss)} CVEs;  KEV catalog: {len(kev)} CVEs")

        # EPSS: only update rows we actually carry.
        epss_rows = [(s, p, cve) for cve, (s, p) in epss.items() if cve in db_ids]
        conn.executemany(
            "UPDATE cves SET epss_score=?, epss_percentile=? WHERE cve_id=?",
            epss_rows)

        # KEV: reset all flags first so a CVE removed from the catalog clears,
        # then mark the current set.
        conn.execute("UPDATE cves SET kev=0, kev_date_added=NULL, kev_ransomware=0")
        kev_rows = [(d, r, cve) for cve, (d, r) in kev.items() if cve in db_ids]
        conn.executemany(
            "UPDATE cves SET kev=1, kev_date_added=?, kev_ransomware=? WHERE cve_id=?",
            kev_rows)
        conn.commit()

        kev_ransom = sum(1 for _, r, _ in kev_rows if r)
        print(f"  updated: {len(epss_rows)} EPSS scores, "
              f"{len(kev_rows)} KEV flags ({kev_ransom} ransomware-linked)")
        print(f"  ({date.today().isoformat()})")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
