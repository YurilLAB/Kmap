#!/usr/bin/env python3
"""Offline checks for the NVD importer and the curated CVE insert script."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"

# Column layout of the shipped kmap-cve.db, including later migrations.
SHIPPED_SCHEMA = (
    "CREATE TABLE cves (cve_id TEXT PRIMARY KEY, product TEXT NOT NULL, "
    "vendor TEXT, version_min TEXT, version_max TEXT, cvss_score REAL, "
    "severity TEXT, description TEXT, cvss_vector TEXT, remote_unauthed INTEGER, "
    "version_min_exclusive INTEGER DEFAULT 0, version_max_exclusive INTEGER DEFAULT 0, "
    "epss_score REAL, epss_percentile REAL, kev INTEGER, kev_date_added TEXT, "
    "kev_ransomware INTEGER)")


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def feed(match):
    return json.dumps({"vulnerabilities": [{"cve": {
        "id": "CVE-2099-0001",
        "descriptions": [{"lang": "en", "value": "fixture"}],
        "metrics": {"cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [dict(
            vulnerable=True,
            criteria="cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", **match)]}]}],
    }}]}).encode()


class UpdateCvesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="kmap-update-cves-")
        self.addCleanup(self.directory.cleanup)
        self.db = str(Path(self.directory.name) / "cves.db")
        self.uc = load("update_cves")

    def import_feed(self, match):
        conn = self.uc.init_db(self.db)
        self.addCleanup(conn.close)
        self.uc.insert_rows(conn, self.uc.parse_nvd_2_0(feed(match)))
        return conn.execute(
            "SELECT version_min, version_max, version_min_exclusive, "
            "version_max_exclusive FROM cves").fetchall()

    def test_excluding_bounds_are_stored_exclusive(self):
        self.assertEqual(self.import_feed(
            {"versionStartExcluding": "8.0", "versionEndExcluding": "9.3"}),
            [("8.0", "9.3", 1, 1)])

    def test_including_bounds_are_stored_inclusive(self):
        self.assertEqual(self.import_feed(
            {"versionStartIncluding": "8.0", "versionEndIncluding": "9.3"}),
            [("8.0", "9.3", 0, 0)])

    def test_unavailable_year_is_reported_failed(self):
        out = io.StringIO()
        argv = ["update_cves.py", "--db", self.db, "--years", "2021"]
        with mock.patch.object(self.uc, "fetch_gz", return_value=None), \
                mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(out):
            self.uc.main()
        self.assertIn("Years succeeded : []", out.getvalue())
        self.assertIn("Years failed    : [2021]", out.getvalue())


class AddCvesTest(unittest.TestCase):
    def test_inserts_into_shipped_schema(self):
        with tempfile.TemporaryDirectory(prefix="kmap-add-cves-") as directory:
            db = str(Path(directory) / "cves.db")
            with sqlite3.connect(db) as conn:
                conn.execute(SHIPPED_SCHEMA)
            module = load("add_cves")
            module.DB = db
            with contextlib.redirect_stdout(io.StringIO()):
                module.main()
            conn = sqlite3.connect(db)
            try:
                count, excl = conn.execute(
                    "SELECT COUNT(*), SUM(version_max_exclusive) FROM cves").fetchone()
            finally:
                conn.close()
            self.assertEqual(count, len(module.NEW_CVES))
            self.assertEqual(excl, 0)


if __name__ == "__main__":
    unittest.main()
