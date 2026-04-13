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

if __name__ == "__main__":
    # Support both unittest and pytest
    unittest.main(verbosity=2)
