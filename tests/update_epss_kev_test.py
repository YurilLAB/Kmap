#!/usr/bin/env python3
"""Exercise partial vulnerability-feed refreshes through the offline CLI."""
import gzip
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "update_epss_kev.py"
INITIAL = [
    ("CVE-2024-1001", 0.1, 0.2, 1, "2024-01-01", 1),
    ("CVE-2024-1002", 0.3, 0.4, 0, None, 0),
]


class PartialFeedRefreshTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="kmap-feed-refresh-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.db = self.root / "cves.db"
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE cves (cve_id TEXT PRIMARY KEY, "
                         "epss_score REAL, epss_percentile REAL, kev INTEGER, "
                         "kev_date_added TEXT, kev_ransomware INTEGER)")
            conn.executemany("INSERT INTO cves VALUES (?,?,?,?,?,?)", INITIAL)

    def rows(self):
        with sqlite3.connect(self.db) as conn:
            return conn.execute("SELECT * FROM cves ORDER BY cve_id").fetchall()

    def refresh(self, *args, success=True):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--db", str(self.db), "--no-download", *args],
            capture_output=True, text=True, timeout=10)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def write_kev(self, vulnerabilities):
        path = self.root / "kev.json"
        path.write_text(json.dumps({"vulnerabilities": vulnerabilities}), encoding="utf-8")
        return str(path)

    def test_epss_only_preserves_kev_annotations(self):
        path = self.root / "epss.csv.gz"
        with gzip.open(path, "wt", encoding="utf-8") as stream:
            stream.write("#model_version:v2024\ncve,epss,percentile\n"
                         "CVE-2024-1001,0.9,0.99\nCVE-2024-9999,0.8,0.9\n")
        result = self.refresh("--epss-file", str(path))
        self.assertEqual(self.rows(), [
            ("CVE-2024-1001", 0.9, 0.99, 1, "2024-01-01", 1), INITIAL[1]])
        self.assertIn("KEV catalog: not supplied (preserved)", result.stdout)

    def test_kev_only_preserves_epss_and_replaces_catalog(self):
        path = self.write_kev([
            {"cveID": "CVE-2024-1002", "dateAdded": "2024-02-01",
             "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2024-9999", "dateAdded": "2024-02-02"},
        ])
        result = self.refresh("--kev-file", path)
        self.assertEqual(self.rows(), [
            ("CVE-2024-1001", 0.1, 0.2, 0, None, 0),
            ("CVE-2024-1002", 0.3, 0.4, 1, "2024-02-01", 1)])
        self.assertIn("EPSS dataset: not supplied (preserved)", result.stdout)

    def test_explicit_empty_catalog_clears_kev(self):
        self.refresh("--kev-file", self.write_kev([]))
        self.assertEqual(self.rows(), [
            ("CVE-2024-1001", 0.1, 0.2, 0, None, 0), INITIAL[1]])

    def test_failed_feed_does_not_change_annotations(self):
        epss = self.root / "epss.csv"
        epss.write_text("cve,epss,percentile\nCVE-2024-1001,0.9,0.99\n", encoding="utf-8")
        kev = self.root / "broken.json"
        kev.write_text("{", encoding="utf-8")
        self.refresh("--epss-file", str(epss), "--kev-file", str(kev), success=False)
        self.assertEqual(self.rows(), INITIAL)

    def test_invalid_catalog_shape_does_not_clear_annotations(self):
        kev = self.root / "invalid-catalog.json"
        for payload in ({}, [], {"vulnerabilities": {}}, {"vulnerabilities": None}):
            with self.subTest(payload=payload):
                kev.write_text(json.dumps(payload), encoding="utf-8")
                result = self.refresh("--kev-file", str(kev), success=False)
                self.assertIn("KEV catalog must contain a vulnerabilities array", result.stderr)
                self.assertEqual(self.rows(), INITIAL)

    def test_missing_feeds_rejected(self):
        self.refresh(success=False)
        self.assertEqual(self.rows(), INITIAL)


if __name__ == "__main__":
    unittest.main()
