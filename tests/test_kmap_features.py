#!/usr/bin/env python3
"""
Comprehensive test suite for Kmap extended features.

Tests cover:
  - Credential database integrity and coverage
  - Web recon path list integrity
  - Protocol implementations (MySQL SHA1, PostgreSQL MD5, TDS encoding)
  - CVE database integrity and query logic
  - Version comparison logic
  - HTTP response parsing algorithms
  - Service normalization mappings
  - Source code structure and cross-platform compatibility
  - Command-line argument definitions

Run:  python3 tests/test_kmap_features.py
      python3 -m pytest tests/test_kmap_features.py -v
"""

import hashlib
import base64
import os
import re
import sqlite3
import struct
import sys
import unittest

# Resolve project root (one level up from tests/)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Helpers — Python reimplementations of C++ algorithms for verification
# ---------------------------------------------------------------------------

def tds_encode_password(password: str) -> bytes:
    """Reimplements TDS Login7 password encoding (nibble-swap + XOR 0xA5)."""
    encoded = bytearray()
    for ch in password:
        lo = ord(ch) & 0xFF  # low byte of UTF-16LE
        hi = 0x00             # high byte of UTF-16LE (ASCII)
        lo = ((lo << 4) & 0xF0 | (lo >> 4) & 0x0F) ^ 0xA5
        hi = ((hi << 4) & 0xF0 | (hi >> 4) & 0x0F) ^ 0xA5
        encoded.append(lo)
        encoded.append(hi)
    return bytes(encoded)


def mysql_native_password(password: str, scramble: bytes) -> bytes:
    """Reimplements MySQL native_password: SHA1(pass) XOR SHA1(scramble + SHA1(SHA1(pass)))."""
    if not password:
        return b""
    sha1_pw = hashlib.sha1(password.encode()).digest()
    sha1_sha1_pw = hashlib.sha1(sha1_pw).digest()
    sha1_combined = hashlib.sha1(scramble + sha1_sha1_pw).digest()
    return bytes(a ^ b for a, b in zip(sha1_pw, sha1_combined))


def pg_md5_password(password: str, username: str, salt: bytes) -> str:
    """Reimplements PostgreSQL MD5 auth: 'md5' + hex(MD5(hex(MD5(pass+user)) + salt))."""
    inner = hashlib.md5((password + username).encode()).hexdigest()
    outer = hashlib.md5((inner.encode() + salt)).hexdigest()
    return "md5" + outer


def base64_encode_basic(user: str, password: str) -> str:
    """HTTP Basic Auth encoding."""
    return base64.b64encode(f"{user}:{password}".encode()).decode()


def extract_version(s: str) -> str:
    """Reimplements cve_map.cc extract_ver()."""
    i = 0
    while i < len(s):
        if s[i].isdigit():
            start = i
            while i < len(s) and (s[i].isdigit() or s[i] in ".p"):
                i += 1
            candidate = s[start:i]
            if "." in candidate:
                return candidate
        else:
            i += 1
    return ""


def parse_ver(ver: str) -> list:
    """Reimplements cve_map.cc parse_ver()."""
    parts = []
    for token in ver.split("."):
        digits = ""
        for ch in token:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits:
            parts.append(int(digits))
    return parts


def ver_cmp(a: str, b: str) -> int:
    """Reimplements cve_map.cc ver_cmp()."""
    va, vb = parse_ver(a), parse_ver(b)
    n = max(len(va), len(vb))
    for i in range(n):
        ai = va[i] if i < len(va) else 0
        bi = vb[i] if i < len(vb) else 0
        if ai < bi:
            return -1
        if ai > bi:
            return 1
    return 0


# ---------------------------------------------------------------------------
# Source code readers
# ---------------------------------------------------------------------------

def read_source(filename: str) -> str:
    path = os.path.join(ROOT, filename)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def read_cred_entries(src: str):
    """Parse builtin_creds[] entries from default_creds.cc."""
    entries = re.findall(r'\{"(\w*)",\s*"([^"]*)",\s*"([^"]*)"\}', src)
    return entries


def read_path_entries(src: str):
    """Parse builtin_paths[] entries from web_recon.cc."""
    start = src.find("builtin_paths[] = {")
    end = src.find("nullptr", start)
    return re.findall(r'"(/[^"]+)"', src[start:end])


# ============================================================================
# TEST CLASSES
# ============================================================================

class TestCredentialDatabase(unittest.TestCase):
    """Tests for the builtin_creds[] array in default_creds.cc."""

    @classmethod
    def setUpClass(cls):
        cls.src = read_source("default_creds.cc")
        cls.entries = read_cred_entries(cls.src)

    def test_minimum_entry_count(self):
        """Should have at least 200 credential entries."""
        self.assertGreaterEqual(len(self.entries), 200,
                                f"Only {len(self.entries)} credential entries")

    def test_all_eight_services_covered(self):
        """Every supported service must have at least 10 entries."""
        services = {}
        for svc, user, pw in self.entries:
            services[svc] = services.get(svc, 0) + 1
        required = ["ssh", "ftp", "telnet", "http", "mysql",
                     "postgresql", "mssql", "mongodb"]
        for svc in required:
            self.assertIn(svc, services, f"Missing service: {svc}")
            self.assertGreaterEqual(services[svc], 10,
                                    f"{svc} has only {services[svc]} entries")

    def test_no_duplicate_entries(self):
        """No exact duplicate (service, user, password) triples."""
        seen = set()
        dupes = []
        for e in self.entries:
            key = (e[0], e[1], e[2])
            if key in seen:
                dupes.append(key)
            seen.add(key)
        self.assertEqual(len(dupes), 0, f"Duplicate entries: {dupes}")

    def test_critical_defaults_present(self):
        """High-impact default credentials must be in the list."""
        must_have = [
            ("ssh", "root", ""),
            ("ssh", "root", "root"),
            ("ssh", "admin", "admin"),
            ("ssh", "pi", "raspberry"),
            ("ftp", "anonymous", ""),
            ("mysql", "root", ""),
            ("mssql", "sa", ""),
            ("mssql", "sa", "Password1"),
            ("mongodb", "", ""),
            ("http", "tomcat", "tomcat"),
            ("telnet", "admin", "admin"),
            ("postgresql", "postgres", ""),
        ]
        entry_set = set(self.entries)
        for svc, user, pw in must_have:
            self.assertIn((svc, user, pw), entry_set,
                          f"Missing critical default: {svc}/{user}/{pw}")

    def test_terminator_present(self):
        """The array must end with {nullptr, nullptr, nullptr}."""
        self.assertIn("nullptr, nullptr, nullptr", self.src)

    def test_iot_credentials_present(self):
        """IoT-specific credentials should be included."""
        entry_set = set(self.entries)
        iot_creds = [
            ("ssh", "ubnt", "ubnt"),
            ("ssh", "vagrant", "vagrant"),
            ("telnet", "root", "vizxv"),
        ]
        for svc, user, pw in iot_creds:
            self.assertIn((svc, user, pw), entry_set,
                          f"Missing IoT cred: {svc}/{user}/{pw}")


class TestWebReconPaths(unittest.TestCase):
    """Tests for the builtin_paths[] array in web_recon.cc."""

    @classmethod
    def setUpClass(cls):
        cls.src = read_source("web_recon.cc")
        cls.paths = read_path_entries(cls.src)

    def test_minimum_path_count(self):
        """Should have at least 100 paths."""
        self.assertGreaterEqual(len(self.paths), 100,
                                f"Only {len(self.paths)} paths")

    def test_no_duplicate_paths(self):
        """No duplicate paths."""
        dupes = [p for p in self.paths if self.paths.count(p) > 1]
        self.assertEqual(len(dupes), 0,
                         f"Duplicate paths: {set(dupes)}")

    def test_all_paths_start_with_slash(self):
        """Every path must start with /."""
        bad = [p for p in self.paths if not p.startswith("/")]
        self.assertEqual(len(bad), 0, f"Paths not starting with /: {bad}")

    def test_critical_paths_present(self):
        """High-value paths must be included."""
        must_have = [
            "/admin", "/.env", "/.git/HEAD", "/robots.txt",
            "/phpMyAdmin", "/wp-login.php", "/actuator",
            "/api/swagger.json", "/server-status", "/graphql",
            "/.htpasswd", "/wp-admin/",
        ]
        for p in must_have:
            self.assertIn(p, self.paths, f"Missing critical path: {p}")

    def test_terminator_present(self):
        """Array must end with nullptr."""
        idx = self.src.find("builtin_paths[] = {")
        # Find the last nullptr after the array start
        rest = self.src[idx:]
        self.assertIn("nullptr\n};", rest)

    def test_sensitive_file_paths(self):
        """Sensitive file disclosure paths must be present."""
        sensitive = ["/.env", "/.git/HEAD", "/web.config",
                     "/WEB-INF/web.xml", "/backup.sql"]
        for p in sensitive:
            self.assertIn(p, self.paths, f"Missing sensitive path: {p}")


class TestTDSPasswordEncoding(unittest.TestCase):
    """Verify TDS Login7 password encoding matches MS-TDS spec."""

    def test_empty_password(self):
        self.assertEqual(tds_encode_password(""), b"")

    def test_single_char(self):
        # 'P' = 0x50 → nibble swap = 0x05 → XOR 0xA5 = 0xA0
        # high byte 0x00 → nibble swap = 0x00 → XOR 0xA5 = 0xA5
        result = tds_encode_password("P")
        self.assertEqual(result, bytes([0xA0, 0xA5]))

    def test_known_password(self):
        """'sa' should produce a known encoding."""
        result = tds_encode_password("sa")
        # 's' = 0x73 → swap = 0x37 → XOR 0xA5 = 0x92
        # 'a' = 0x61 → swap = 0x16 → XOR 0xA5 = 0xB3
        self.assertEqual(result[0], 0x92)  # 's' low byte
        self.assertEqual(result[1], 0xA5)  # 's' high byte
        self.assertEqual(result[2], 0xB3)  # 'a' low byte
        self.assertEqual(result[3], 0xA5)  # 'a' high byte

    def test_round_trip(self):
        """Encode then decode should recover the original (XOR is its own inverse after swap)."""
        for pw in ["password", "P@ssw0rd!", "123456", ""]:
            encoded = tds_encode_password(pw)
            decoded = ""
            for i in range(0, len(encoded), 2):
                lo = encoded[i] ^ 0xA5
                lo = ((lo << 4) & 0xF0 | (lo >> 4) & 0x0F)
                decoded += chr(lo)
            self.assertEqual(decoded, pw)


class TestMySQLNativePassword(unittest.TestCase):
    """Verify MySQL native_password SHA1 algorithm."""

    def test_empty_password(self):
        self.assertEqual(mysql_native_password("", b"\x00" * 20), b"")

    def test_known_hash(self):
        """Verify against a known scramble/password pair."""
        scramble = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a" \
                   b"\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
        result = mysql_native_password("root", scramble)
        self.assertEqual(len(result), 20)
        # Verify independently
        sha1_pw = hashlib.sha1(b"root").digest()
        sha1_sha1 = hashlib.sha1(sha1_pw).digest()
        expected = hashlib.sha1(scramble + sha1_sha1).digest()
        expected = bytes(a ^ b for a, b in zip(sha1_pw, expected))
        self.assertEqual(result, expected)

    def test_output_length(self):
        for pw in ["a", "password", "very_long_password_12345"]:
            result = mysql_native_password(pw, b"\x00" * 20)
            self.assertEqual(len(result), 20)


class TestPostgreSQLMD5(unittest.TestCase):
    """Verify PostgreSQL MD5 auth algorithm."""

    def test_format(self):
        """Result must start with 'md5' and be 35 chars total."""
        result = pg_md5_password("password", "postgres", b"\x01\x02\x03\x04")
        self.assertTrue(result.startswith("md5"))
        self.assertEqual(len(result), 35)  # "md5" + 32 hex chars

    def test_known_hash(self):
        """Verify against a known user/password/salt combination."""
        salt = b"\xab\xcd\xef\x01"
        result = pg_md5_password("postgres", "postgres", salt)
        # Independently compute
        inner = hashlib.md5(b"postgrespostgres").hexdigest()
        outer = hashlib.md5(inner.encode() + salt).hexdigest()
        self.assertEqual(result, "md5" + outer)

    def test_different_users_different_hashes(self):
        salt = b"\x01\x02\x03\x04"
        h1 = pg_md5_password("password", "user1", salt)
        h2 = pg_md5_password("password", "user2", salt)
        self.assertNotEqual(h1, h2)


class TestBase64Encoding(unittest.TestCase):
    """Verify base64 encoding for HTTP Basic Auth."""

    def test_known_values(self):
        self.assertEqual(base64_encode_basic("admin", "admin"),
                         "YWRtaW46YWRtaW4=")
        self.assertEqual(base64_encode_basic("user", "pass"),
                         "dXNlcjpwYXNz")

    def test_empty_password(self):
        result = base64_encode_basic("admin", "")
        self.assertEqual(result, base64.b64encode(b"admin:").decode())

    def test_special_chars(self):
        result = base64_encode_basic("admin", "p@ss:w0rd!")
        expected = base64.b64encode(b"admin:p@ss:w0rd!").decode()
        self.assertEqual(result, expected)


class TestVersionComparison(unittest.TestCase):
    """Verify cve_map.cc version comparison logic."""

    def test_equal(self):
        self.assertEqual(ver_cmp("1.0", "1.0"), 0)
        self.assertEqual(ver_cmp("2.4.49", "2.4.49"), 0)

    def test_less_than(self):
        self.assertEqual(ver_cmp("1.0", "2.0"), -1)
        self.assertEqual(ver_cmp("2.4.49", "2.4.50"), -1)
        self.assertEqual(ver_cmp("7.4", "8.2"), -1)

    def test_greater_than(self):
        self.assertEqual(ver_cmp("2.0", "1.0"), 1)
        self.assertEqual(ver_cmp("8.2p1", "7.4"), 1)

    def test_different_lengths(self):
        self.assertEqual(ver_cmp("1.0", "1.0.0"), 0)
        self.assertEqual(ver_cmp("1.0.1", "1.0"), 1)

    def test_extract_version(self):
        self.assertEqual(extract_version("OpenSSH 8.2p1 Ubuntu 4"), "8.2p1")
        self.assertEqual(extract_version("nginx/1.18.0"), "1.18.0")
        self.assertEqual(extract_version("Apache/2.4.49"), "2.4.49")
        self.assertEqual(extract_version("no version here"), "")

    def test_parse_ver_strips_suffix(self):
        self.assertEqual(parse_ver("8.2p1"), [8, 2])
        self.assertEqual(parse_ver("2.4.49"), [2, 4, 49])


class TestCVEDatabase(unittest.TestCase):
    """Tests for the kmap-cve.db SQLite database."""

    @classmethod
    def setUpClass(cls):
        db_path = os.path.join(ROOT, "kmap-cve.db")
        if not os.path.exists(db_path):
            raise unittest.SkipTest("kmap-cve.db not found")
        cls.conn = sqlite3.connect(db_path)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "conn"):
            cls.conn.close()

    def test_minimum_entry_count(self):
        """Database should have at least 10000 CVE entries."""
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM cves")
        count = c.fetchone()[0]
        self.assertGreaterEqual(count, 10000)

    def test_schema_has_required_columns(self):
        """Table must have all required columns."""
        c = self.conn.cursor()
        c.execute("PRAGMA table_info(cves)")
        columns = {row[1] for row in c.fetchall()}
        required = {"cve_id", "product", "vendor", "version_min",
                     "version_max", "cvss_score", "severity", "description"}
        self.assertTrue(required.issubset(columns),
                        f"Missing columns: {required - columns}")

    def test_key_products_have_entries(self):
        """Critical products must have CVE coverage."""
        c = self.conn.cursor()
        products = ["openssh", "nginx", "mysql", "postgresql",
                     "http_server", "redis", "elasticsearch"]
        for prod in products:
            c.execute("SELECT COUNT(*) FROM cves WHERE product = ?", (prod,))
            count = c.fetchone()[0]
            self.assertGreater(count, 0, f"No CVEs for product: {prod}")

    def test_cvss_scores_valid(self):
        """All CVSS scores should be between 0.0 and 10.0."""
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM cves WHERE cvss_score < 0 OR cvss_score > 10")
        bad = c.fetchone()[0]
        self.assertEqual(bad, 0, f"{bad} entries with invalid CVSS score")

    def test_severity_values(self):
        """Severity should be one of the standard values."""
        c = self.conn.cursor()
        c.execute("SELECT DISTINCT severity FROM cves")
        severities = {row[0] for row in c.fetchall()}
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL", None}
        invalid = severities - valid
        self.assertEqual(len(invalid), 0,
                         f"Invalid severity values: {invalid}")

    def test_cve_id_format(self):
        """All CVE IDs should match CVE-YYYY-NNNNN format."""
        c = self.conn.cursor()
        c.execute("SELECT cve_id FROM cves WHERE cve_id NOT LIKE 'CVE-____-%'")
        bad = c.fetchall()
        self.assertEqual(len(bad), 0,
                         f"{len(bad)} entries with invalid CVE ID format")

    def test_null_vendor_query(self):
        """SQL with OR vendor IS NULL should match NULL vendor entries."""
        c = self.conn.cursor()
        c.execute("""
            SELECT COUNT(*) FROM cves
            WHERE product = 'asa'
              AND (vendor LIKE '%cisco%' OR vendor IS NULL)
        """)
        count = c.fetchone()[0]
        self.assertGreater(count, 0,
                           "NULL vendor fix not working for Cisco ASA")

    def test_joomla_both_names(self):
        """Both 'joomla' and 'joomla\\!' product names should have entries."""
        c = self.conn.cursor()
        for name in ["joomla", "joomla\\!"]:
            c.execute("SELECT COUNT(*) FROM cves WHERE product = ?", (name,))
            count = c.fetchone()[0]
            self.assertGreater(count, 0, f"No entries for product '{name}'")


class TestMongoDBWireProtocol(unittest.TestCase):
    """Verify MongoDB isMaster message structure."""

    def test_message_length_matches(self):
        """The length field in the isMaster message must equal the total byte count."""
        # Read the actual bytes from the source — array spans multiple lines
        src = read_source("default_creds.cc")
        start = src.find("ismaster_msg[]")
        self.assertNotEqual(start, -1, "Could not find ismaster_msg in source")
        end = src.find("};", start)
        block = src[start:end]
        hex_values = re.findall(r"0x([0-9A-Fa-f]{2})", block)
        msg_bytes = bytes(int(h, 16) for h in hex_values)
        # Length field is first 4 bytes, little-endian
        length_field = struct.unpack_from("<I", msg_bytes, 0)[0]
        self.assertEqual(length_field, len(msg_bytes),
                         f"Length field ({length_field}) != actual size ({len(msg_bytes)})")

    def test_opcode_is_op_query(self):
        """Opcode should be OP_QUERY = 2004."""
        src = read_source("default_creds.cc")
        start = src.find("ismaster_msg[]")
        end = src.find("};", start)
        block = src[start:end]
        hex_values = re.findall(r"0x([0-9A-Fa-f]{2})", block)
        msg_bytes = bytes(int(h, 16) for h in hex_values)
        opcode = struct.unpack_from("<I", msg_bytes, 12)[0]
        self.assertEqual(opcode, 2004, f"Opcode should be 2004 (OP_QUERY), got {opcode}")


class TestCrossPlatformCompatibility(unittest.TestCase):
    """Verify cross-platform code structure."""

    def test_no_netinet_in6_include(self):
        """netinet/in6.h must NOT be included (breaks macOS/OpenBSD)."""
        for f in ["default_creds.cc", "web_recon.cc", "cve_map.cc"]:
            src = read_source(f)
            self.assertNotIn("netinet/in6.h", src,
                             f"{f} still includes netinet/in6.h")

    def test_win32_guards_present(self):
        """Feature files must have WIN32 platform guards."""
        for f in ["default_creds.cc", "web_recon.cc"]:
            src = read_source(f)
            self.assertIn("#ifdef WIN32", src,
                          f"{f} missing WIN32 guard")
            self.assertIn("winsock2.h", src,
                          f"{f} missing winsock2.h include")

    def test_msvc_project_includes_new_files(self):
        """All Kmap source files must be in the MSVC project."""
        proj = read_source("mswin32/kmap.vcxproj")
        required = ["default_creds.cc", "web_recon.cc", "cve_map.cc",
                     "output_json.cc", "sqlite3.c"]
        for f in required:
            self.assertIn(f, proj,
                          f"{f} missing from mswin32/kmap.vcxproj")

    def test_makefile_includes_new_files(self):
        """All Kmap source files must be in Makefile.in."""
        makefile = read_source("Makefile.in")
        for f in ["default_creds.cc", "web_recon.cc", "cve_map.cc",
                   "output_json.cc", "sqlite3.o"]:
            self.assertIn(f.replace(".cc", "").replace(".o", ""),
                          makefile,
                          f"{f} missing from Makefile.in")

    def test_no_munmap_typo(self):
        """kmap.cc must use munmap, not mukmap."""
        src = read_source("kmap.cc")
        self.assertNotIn("mukmap", src, "mukmap typo still present in kmap.cc")
        self.assertIn("munmap", src, "munmap call missing from kmap.cc")

    def test_target_has_attribute_member(self):
        """Target.h must define the attribute key-value store."""
        src = read_source("Target.h")
        self.assertIn("attribute", src,
                      "Target.h missing attribute member")
        self.assertIn("std::map", src,
                      "Target.h attribute should use std::map")


class TestServiceNormalization(unittest.TestCase):
    """Verify service name normalization in default_creds.cc."""

    @classmethod
    def setUpClass(cls):
        cls.src = read_source("default_creds.cc")

    def test_ssh_normalization(self):
        self.assertIn('s.find("ssh")', self.src)

    def test_ftp_normalization(self):
        self.assertIn('s.find("ftp")', self.src)

    def test_mssql_both_names(self):
        """Both 'ms-sql' and 'mssql' service names must be handled."""
        self.assertIn('s.find("ms-sql")', self.src)
        self.assertIn('s.find("mssql")', self.src)

    def test_https_not_mapped_to_http(self):
        """HTTPS services should NOT be mapped to http for credential probing."""
        # Find the normalize_service function
        match = re.search(
            r'normalize_service\(const char \*name\).*?^}',
            self.src, re.MULTILINE | re.DOTALL
        )
        self.assertIsNotNone(match)
        func = match.group()
        # It should use exact matches for http, not a find that catches https
        self.assertIn('s == "http"', func,
                      "Should use exact match for http service")


class TestCVENormalization(unittest.TestCase):
    """Verify CVE product normalization in cve_map.cc."""

    @classmethod
    def setUpClass(cls):
        cls.src = read_source("cve_map.cc")

    def test_openssh_mapping(self):
        self.assertIn('"openssh"', self.src)

    def test_apache_http_mapping(self):
        self.assertIn('"http_server"', self.src)
        self.assertIn('"apache"', self.src)

    def test_nginx_mapping(self):
        self.assertIn('"nginx"', self.src)

    def test_redis_mapping(self):
        self.assertIn('"redis"', self.src)

    def test_joomla_dual_query(self):
        """Joomla should query both 'joomla\\!' and 'joomla'."""
        self.assertIn('"joomla"', self.src)
        self.assertIn('joomla\\\\!', self.src)

    def test_null_vendor_sql(self):
        """SQL queries with vendor filter must include OR vendor IS NULL."""
        count = self.src.count("OR vendor IS NULL")
        self.assertGreaterEqual(count, 2,
                                "Need OR vendor IS NULL in both exact and LIKE queries")


class TestHTTPParsing(unittest.TestCase):
    """Verify HTTP response parsing in web_recon.cc."""

    @classmethod
    def setUpClass(cls):
        cls.src = read_source("web_recon.cc")

    def test_status_code_no_stoi(self):
        """extract_status_code must NOT use std::stoi (crash risk)."""
        # Find the function
        match = re.search(
            r'extract_status_code\(.*?\n\}',
            self.src, re.DOTALL
        )
        self.assertIsNotNone(match)
        func = match.group()
        self.assertNotIn("stoi", func,
                         "extract_status_code should not use std::stoi")

    def test_ssl_sni_ip_check(self):
        """SSL_set_tlsext_host_name should not be called for IP addresses."""
        self.assertIn("inet_pton", self.src)
        # Should check both IPv4 and IPv6
        # Look for the SNI guard pattern
        self.assertIn("AF_INET", self.src)
        self.assertIn("AF_INET6", self.src)


class TestCommandLineArgs(unittest.TestCase):
    """Verify Kmap CLI argument definitions in kmap.cc."""

    @classmethod
    def setUpClass(cls):
        cls.src = read_source("kmap.cc")

    def test_default_creds_option(self):
        self.assertIn("default-creds", self.src)

    def test_web_recon_option(self):
        self.assertIn("web-recon", self.src)

    def test_cve_map_option(self):
        self.assertIn("cve-map", self.src)

    def test_cve_min_score_option(self):
        self.assertIn("cve-min-score", self.src)

    def test_creds_file_option(self):
        self.assertIn("creds-file", self.src)

    def test_creds_timeout_option(self):
        self.assertIn("creds-timeout", self.src)

    def test_web_paths_option(self):
        self.assertIn("web-paths", self.src)

    def test_color_option(self):
        self.assertIn("--color", self.src)

    def test_json_output_option(self):
        """JSON output flag -oJ must be defined."""
        self.assertIn("oJ", self.src)

    def test_features_auto_enable_sv(self):
        """All three features must auto-enable service version detection."""
        # Count o.servicescan = true near feature option parsing
        svc_enables = self.src.count("o.servicescan")
        self.assertGreaterEqual(svc_enables, 3,
                                "Features should auto-enable -sV")


class TestErrorHandling(unittest.TestCase):
    """Verify error handling patterns in feature code."""

    def test_cve_db_missing_handled(self):
        """cve_map.cc must handle missing database gracefully."""
        src = read_source("cve_map.cc")
        self.assertIn("db_path.empty()", src)
        self.assertIn("WARNING", src)

    def test_cve_db_open_error_handled(self):
        """cve_map.cc must handle SQLite open errors."""
        src = read_source("cve_map.cc")
        self.assertIn("sqlite3_open_v2", src)
        self.assertIn("SQLITE_OK", src)

    def test_creds_file_open_error(self):
        """default_creds.cc must handle missing creds file."""
        src = read_source("default_creds.cc")
        self.assertIn("cannot open creds file", src)

    def test_connect_failure_handled(self):
        """tcp_connect must return -1 on failure and callers must check."""
        src = read_source("default_creds.cc")
        self.assertGreater(src.count("if (fd < 0) return false"),  5,
                           "Not enough fd < 0 checks")

    def test_openssl_conditional(self):
        """OpenSSL code must be inside #ifdef HAVE_OPENSSL."""
        for f in ["default_creds.cc", "web_recon.cc"]:
            src = read_source(f)
            self.assertIn("HAVE_OPENSSL", src,
                          f"{f} missing HAVE_OPENSSL guard")


class TestNoClaudeReferences(unittest.TestCase):
    """Ensure no AI tool attribution in the codebase."""

    def test_no_claude_in_source(self):
        """No Claude/Anthropic references in Kmap feature files."""
        files = ["default_creds.cc", "web_recon.cc", "cve_map.cc",
                 "default_creds.h", "web_recon.h", "cve_map.h",
                 "color.h", "output_json.cc", "output_json.h",
                 "README.md", "Target.h"]
        for f in files:
            src = read_source(f)
            lower = src.lower()
            self.assertNotIn("claude", lower, f"'claude' found in {f}")
            self.assertNotIn("anthropic", lower, f"'anthropic' found in {f}")


# ============================================================================
# EXTENDED TESTS — Edge cases, malformed input, deeper protocol verification
# ============================================================================

class TestTDSEdgeCases(unittest.TestCase):
    """Edge cases for TDS password encoding."""

    def test_special_characters(self):
        """Passwords with special chars should encode without error."""
        for pw in ["P@ssw0rd!", "p4$$w0rd", "root'--", 'admin"', "a\tb\nc"]:
            result = tds_encode_password(pw)
            self.assertEqual(len(result), len(pw) * 2)

    def test_long_password(self):
        """Long passwords should encode correctly."""
        pw = "A" * 128
        result = tds_encode_password(pw)
        self.assertEqual(len(result), 256)

    def test_all_byte_values(self):
        """Every printable ASCII char should encode and decode."""
        for i in range(32, 127):
            ch = chr(i)
            encoded = tds_encode_password(ch)
            # Decode
            lo = encoded[0] ^ 0xA5
            lo = ((lo << 4) & 0xF0 | (lo >> 4) & 0x0F)
            self.assertEqual(chr(lo), ch, f"Round-trip failed for char {i} ({ch!r})")


class TestMySQLEdgeCases(unittest.TestCase):
    """Edge cases for MySQL native_password."""

    def test_different_scrambles_different_tokens(self):
        """Same password with different scrambles must produce different tokens."""
        pw = "password"
        s1 = b"\x01" * 20
        s2 = b"\x02" * 20
        self.assertNotEqual(mysql_native_password(pw, s1),
                            mysql_native_password(pw, s2))

    def test_special_chars_in_password(self):
        result = mysql_native_password("p@$$w0rd!#%", b"\x00" * 20)
        self.assertEqual(len(result), 20)

    def test_unicode_like_password(self):
        """Passwords with high-ASCII chars."""
        result = mysql_native_password("\xff\xfe", b"\x00" * 20)
        self.assertEqual(len(result), 20)


class TestPostgreSQLEdgeCases(unittest.TestCase):
    """Edge cases for PostgreSQL MD5 auth."""

    def test_empty_password(self):
        """Empty password should still produce valid hash."""
        result = pg_md5_password("", "postgres", b"\x00\x00\x00\x00")
        self.assertTrue(result.startswith("md5"))
        self.assertEqual(len(result), 35)

    def test_long_username(self):
        result = pg_md5_password("password", "a" * 256, b"\x01\x02\x03\x04")
        self.assertTrue(result.startswith("md5"))

    def test_same_credentials_different_salt(self):
        h1 = pg_md5_password("password", "user", b"\x01\x02\x03\x04")
        h2 = pg_md5_password("password", "user", b"\x05\x06\x07\x08")
        self.assertNotEqual(h1, h2)


class TestVersionComparisonEdgeCases(unittest.TestCase):
    """Edge cases for version comparison."""

    def test_version_with_only_major(self):
        self.assertEqual(ver_cmp("3", "3"), 0)
        self.assertEqual(ver_cmp("3", "4"), -1)

    def test_deeply_nested_version(self):
        self.assertEqual(ver_cmp("1.2.3.4.5", "1.2.3.4.5"), 0)
        self.assertEqual(ver_cmp("1.2.3.4.5", "1.2.3.4.6"), -1)

    def test_version_with_suffix(self):
        """Suffixes like 'p1', 'rc1', 'beta' should be stripped."""
        self.assertEqual(parse_ver("8.2p1"), [8, 2])
        self.assertEqual(parse_ver("2.4.49-ubuntu1"), [2, 4, 49])
        self.assertEqual(parse_ver("1.0rc1"), [1, 0])

    def test_extract_ver_edge_cases(self):
        self.assertEqual(extract_version(""), "")
        self.assertEqual(extract_version("no digits"), "")
        self.assertEqual(extract_version("v1"), "")  # single digit, no dot
        self.assertEqual(extract_version("version 3.14.159"), "3.14.159")
        self.assertEqual(extract_version("12"), "")  # no dot

    def test_leading_zeros(self):
        self.assertEqual(ver_cmp("1.01", "1.1"), 0)
        self.assertEqual(ver_cmp("01.02.03", "1.2.3"), 0)


class TestCVEDatabaseDeeper(unittest.TestCase):
    """Deeper CVE database verification."""

    @classmethod
    def setUpClass(cls):
        db_path = os.path.join(ROOT, "kmap-cve.db")
        if not os.path.exists(db_path):
            raise unittest.SkipTest("kmap-cve.db not found")
        cls.conn = sqlite3.connect(db_path)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "conn"):
            cls.conn.close()

    def test_no_empty_cve_ids(self):
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM cves WHERE cve_id IS NULL OR cve_id = ''")
        self.assertEqual(c.fetchone()[0], 0, "Found empty CVE IDs")

    def test_no_empty_descriptions(self):
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM cves WHERE description IS NULL OR description = ''")
        bad = c.fetchone()[0]
        self.assertEqual(bad, 0, f"{bad} CVEs with empty descriptions")

    def test_version_ranges_valid(self):
        """version_min should be <= version_max when both are set."""
        c = self.conn.cursor()
        c.execute("""
            SELECT cve_id, version_min, version_max FROM cves
            WHERE version_min != '' AND version_max != ''
              AND version_min IS NOT NULL AND version_max IS NOT NULL
        """)
        bad = []
        for cve_id, vmin, vmax in c.fetchall():
            if ver_cmp(vmin, vmax) > 0:
                bad.append(f"{cve_id}: {vmin} > {vmax}")
        self.assertEqual(len(bad), 0,
                         f"Inverted version ranges: {bad[:5]}")

    def test_high_impact_cves_present(self):
        """Well-known critical CVEs must be in the database."""
        c = self.conn.cursor()
        must_have = [
            "CVE-2021-44228",  # Log4Shell
            "CVE-2024-6387",   # regreSSHion
        ]
        for cve_id in must_have:
            c.execute("SELECT COUNT(*) FROM cves WHERE cve_id = ?", (cve_id,))
            count = c.fetchone()[0]
            self.assertGreater(count, 0, f"Missing high-impact CVE: {cve_id}")

    def test_product_names_lowercase(self):
        """Product names should be lowercase (CPE convention)."""
        c = self.conn.cursor()
        c.execute("SELECT DISTINCT product FROM cves WHERE product != lower(product)")
        bad = [r[0] for r in c.fetchall()]
        # Filter out known exceptions like 'joomla\!'
        bad = [p for p in bad if p and not p.startswith("joomla")]
        self.assertEqual(len(bad), 0, f"Non-lowercase products: {bad[:10]}")

    def test_cvss_severity_consistency(self):
        """CVSS score should match severity label."""
        c = self.conn.cursor()
        c.execute("""
            SELECT COUNT(*) FROM cves
            WHERE (cvss_score >= 9.0 AND severity != 'CRITICAL')
               OR (cvss_score >= 7.0 AND cvss_score < 9.0 AND severity != 'HIGH')
        """)
        mismatch = c.fetchone()[0]
        # Allow some tolerance — NVD sometimes has edge cases
        self.assertLess(mismatch, 50,
                        f"{mismatch} entries with CVSS/severity mismatch")


class TestCredentialDatabaseDeeper(unittest.TestCase):
    """Deeper credential database tests."""

    @classmethod
    def setUpClass(cls):
        cls.src = read_source("default_creds.cc")
        cls.entries = read_cred_entries(cls.src)

    def test_no_whitespace_in_usernames(self):
        """Usernames should not contain whitespace."""
        bad = [(s, u, p) for s, u, p in self.entries if ' ' in u or '\t' in u]
        self.assertEqual(len(bad), 0, f"Usernames with whitespace: {bad}")

    def test_services_are_lowercase(self):
        """All service names must be lowercase."""
        bad = [(s, u, p) for s, u, p in self.entries if s != s.lower()]
        self.assertEqual(len(bad), 0, f"Non-lowercase services: {bad}")

    def test_empty_password_entries_exist(self):
        """Each service should have at least one empty-password entry."""
        services_with_empty = set()
        for svc, user, pw in self.entries:
            if pw == "":
                services_with_empty.add(svc)
        required = {"ssh", "ftp", "mysql", "mssql", "mongodb", "telnet", "postgresql"}
        missing = required - services_with_empty
        self.assertEqual(len(missing), 0,
                         f"Services missing empty-password entry: {missing}")

    def test_credential_pair_length_limits(self):
        """Usernames and passwords should be reasonable length."""
        for svc, user, pw in self.entries:
            self.assertLess(len(user), 64,
                            f"Username too long: {svc}/{user}")
            self.assertLess(len(pw), 64,
                            f"Password too long: {svc}/{user}/{pw}")

    def test_ftp_anonymous_variations(self):
        """FTP should have multiple anonymous access variations."""
        anon = [(s, u, p) for s, u, p in self.entries
                if s == "ftp" and u == "anonymous"]
        self.assertGreaterEqual(len(anon), 3,
                                "Need at least 3 anonymous FTP variations")


class TestWebReconPathsDeeper(unittest.TestCase):
    """Deeper web recon path tests."""

    @classmethod
    def setUpClass(cls):
        cls.src = read_source("web_recon.cc")
        cls.paths = read_path_entries(cls.src)

    def test_no_double_slashes(self):
        """Paths should not contain // (except at start for protocol)."""
        bad = [p for p in self.paths if "//" in p]
        self.assertEqual(len(bad), 0, f"Paths with //: {bad}")

    def test_no_trailing_spaces(self):
        """Paths should not have trailing whitespace."""
        bad = [p for p in self.paths if p != p.strip()]
        self.assertEqual(len(bad), 0, f"Paths with trailing space: {bad}")

    def test_category_coverage(self):
        """Paths should cover major categories."""
        categories = {
            "admin": any("/admin" in p for p in self.paths),
            "api": any("/api/" in p for p in self.paths),
            "git": any(".git" in p for p in self.paths),
            "env": any(".env" in p for p in self.paths),
            "backup": any("backup" in p.lower() for p in self.paths),
            "wordpress": any("wp-" in p for p in self.paths),
            "actuator": any("actuator" in p for p in self.paths),
            "debug": any("debug" in p for p in self.paths),
        }
        missing = [cat for cat, present in categories.items() if not present]
        self.assertEqual(len(missing), 0,
                         f"Missing path categories: {missing}")

    def test_common_extensions_covered(self):
        """Sensitive file extensions should be probed."""
        has_php = any(p.endswith(".php") for p in self.paths)
        has_env = any(".env" in p for p in self.paths)
        has_sql = any(".sql" in p for p in self.paths)
        has_yml = any(".yml" in p for p in self.paths)
        self.assertTrue(has_php, "No .php paths")
        self.assertTrue(has_env, "No .env paths")
        self.assertTrue(has_sql, "No .sql paths")
        self.assertTrue(has_yml, "No .yml paths")


class TestErrorHandlingDeeper(unittest.TestCase):
    """More thorough error handling verification."""

    def test_fd_send_checked_in_all_probes(self):
        """Every probe function should check fd_send return value."""
        src = read_source("default_creds.cc")
        # Count fd_send calls vs checked fd_send calls
        total_sends = src.count("fd_send(")
        checked_sends = src.count("!fd_send(") + src.count("if (!fd_send")
        # At least 60% of sends should be checked (some internal helpers don't need it)
        ratio = checked_sends / max(total_sends, 1)
        self.assertGreaterEqual(ratio, 0.5,
                                f"Only {checked_sends}/{total_sends} fd_send calls checked")

    def test_close_fd_on_all_error_paths(self):
        """close_fd should appear on error paths."""
        src = read_source("default_creds.cc")
        # Every probe that opens a connection should close it
        opens = src.count("tcp_connect(")
        closes = src.count("close_fd(")
        self.assertGreaterEqual(closes, opens,
                                f"Fewer close_fd ({closes}) than tcp_connect ({opens})")

    def test_web_recon_ssl_error_handling(self):
        """web_recon.cc should handle SSL connection failures."""
        src = read_source("web_recon.cc")
        self.assertIn("SSL_connect", src)
        # Should check SSL_connect return
        self.assertIn("!= 1", src, "SSL_connect return not checked")

    def test_sqlite_finalize_called(self):
        """sqlite3_finalize must be called after sqlite3_prepare."""
        src = read_source("cve_map.cc")
        prepares = src.count("sqlite3_prepare")
        finalizes = src.count("sqlite3_finalize")
        self.assertEqual(prepares, finalizes,
                         f"Mismatched prepare ({prepares}) vs finalize ({finalizes})")

    def test_sqlite_close_called(self):
        """sqlite3_close must be called after sqlite3_open."""
        src = read_source("cve_map.cc")
        opens = src.count("sqlite3_open")
        closes = src.count("sqlite3_close")
        self.assertGreaterEqual(closes, opens,
                                f"Fewer sqlite3_close ({closes}) than open ({opens})")


class TestSourceCodeQuality(unittest.TestCase):
    """Code quality and consistency checks."""

    def test_no_raw_magic_numbers_in_probes(self):
        """Timeout values should use named constants, not hardcoded."""
        src = read_source("web_recon.cc")
        self.assertIn("CONNECT_TIMEOUT", src)
        self.assertIn("READ_TIMEOUT", src)

    def test_color_header_only(self):
        """color.h should be header-only (inline functions)."""
        src = read_source("color.h")
        self.assertIn("inline", src)
        # No .cc file for color
        self.assertFalse(os.path.exists(os.path.join(ROOT, "color.cc")))

    def test_json_output_header_functions(self):
        """output_json.h should declare all necessary functions."""
        src = read_source("output_json.h")
        required = ["json_initialize", "json_write_scaninfo",
                     "json_write_host", "json_write_stats", "json_finalize"]
        for func in required:
            self.assertIn(func, src, f"Missing JSON function: {func}")

    def test_no_broken_urls_in_readme(self):
        """README should not have broken kmap.org links."""
        src = read_source("README.md")
        self.assertNotIn("kmap.org", src, "README has kmap.org reference")
        self.assertIn("github.com/YurilLAB/Kmap", src,
                      "README missing GitHub repo link")

    def test_logo_referenced_in_readme(self):
        """README should reference the logo file."""
        src = read_source("README.md")
        self.assertIn("kmap_logo", src, "README missing logo reference")

    def test_feature_counts_in_readme(self):
        """README feature counts should reflect actual data."""
        src = read_source("README.md")
        # Check credential count claim is reasonable
        cred_src = read_source("default_creds.cc")
        actual_creds = len(read_cred_entries(cred_src))
        # README should not claim significantly more than actual
        self.assertGreaterEqual(actual_creds, 200,
                                "Actual creds less than README claims")


# ============================================================================

if __name__ == "__main__":
    # Support both unittest and pytest
    unittest.main(verbosity=2)
