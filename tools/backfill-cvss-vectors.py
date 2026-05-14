#!/usr/bin/env python3
"""Backfill cvss_vector + remote_unauthed columns for kmap-cve.db rows.

Pulls the CVSS v3 vector from NVD's REST API for each cve_id whose
cvss_vector is NULL, derives a remote_unauthed flag (AV:N + PR:N + UI:N),
and commits in batches.

Rate-limited to NVD's anonymous quota (5 requests / 30 seconds = one
request every ~6 seconds with a small safety margin). Pass --limit to
cap how many rows the run will touch.
"""

import argparse
import json
import sqlite3
import sys
import time
import urllib.request
import urllib.error

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"


def fetch_vector(cve_id):
    """Return (vector_string, base_score) or (None, None) on miss/error."""
    req = urllib.request.Request(NVD_URL.format(cve_id),
                                 headers={"User-Agent": "kmap-cve-backfill/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.load(resp)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        print(f"  {cve_id}: fetch failed ({e})", file=sys.stderr)
        return None, None

    if not data.get("vulnerabilities"):
        return None, None
    metrics = data["vulnerabilities"][0]["cve"].get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            cvss = metrics[key][0]["cvssData"]
            return cvss.get("vectorString"), cvss.get("baseScore")
    return None, None


def is_remote_unauthed(vec):
    """Return 1 if vector is network + no auth + no user interaction, else 0."""
    if not vec:
        return None
    parts = dict(p.split(":", 1) for p in vec.split("/") if ":" in p)
    return int(parts.get("AV") == "N"
               and parts.get("PR") == "N"
               and parts.get("UI") == "N")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="kmap-cve.db")
    ap.add_argument("--limit", type=int, default=20,
                    help="cap on rows to fetch this run (default 20)")
    ap.add_argument("--products", nargs="*",
                    help="only backfill rows for these products")
    ap.add_argument("--cve-ids", nargs="*",
                    help="only backfill these specific cve_ids")
    ap.add_argument("--delay", type=float, default=6.5,
                    help="seconds between API calls (NVD anon limit: 5/30s)")
    args = ap.parse_args()

    db = sqlite3.connect(args.db)

    query = "SELECT cve_id FROM cves WHERE cvss_vector IS NULL"
    params = []
    if args.products:
        query += " AND product IN (" + ",".join("?" * len(args.products)) + ")"
        params += args.products
    if args.cve_ids:
        query += " AND cve_id IN (" + ",".join("?" * len(args.cve_ids)) + ")"
        params += args.cve_ids
    query += " ORDER BY cvss_score DESC LIMIT ?"
    params.append(args.limit)

    rows = [r[0] for r in db.execute(query, params)]
    print(f"Backfilling {len(rows)} rows ({args.delay}s between calls = "
          f"~{len(rows) * args.delay / 60:.1f} min)")

    updated = 0
    missing = 0
    for i, cve_id in enumerate(rows, 1):
        vec, score = fetch_vector(cve_id)
        if vec is None:
            print(f"  [{i}/{len(rows)}] {cve_id}: no v3 vector")
            missing += 1
        else:
            remote = is_remote_unauthed(vec)
            db.execute(
                "UPDATE cves SET cvss_vector=?, remote_unauthed=? WHERE cve_id=?",
                (vec, remote, cve_id))
            db.commit()
            tag = "REMOTE" if remote else "needs-auth/other"
            print(f"  [{i}/{len(rows)}] {cve_id}: {vec} [{tag}]")
            updated += 1
        if i < len(rows):
            time.sleep(args.delay)

    print(f"\nDone. Updated {updated}, missing v3 vector for {missing}.")


if __name__ == "__main__":
    main()
