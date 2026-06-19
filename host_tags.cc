/*
 * host_tags.cc -- implementation of derive_host_tags (see header).
 *
 * Pure string/version math over already-collected fields.  Every tag is a
 * deterministic function of stored data, so the result is stable across runs
 * and fully unit-testable (fuzz/test_host_tags.cc).
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "host_tags.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

/* ---------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------- */

static std::string ht_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}

/* Numeric component-wise version compare: returns true if a < b.  Missing
 * trailing components count as 0 ("2.4" == "2.4.0").  Non-numeric segments
 * stop the parse (so "2.4.49 (Ubuntu)" reads as 2.4.49). */
static std::vector<int> ht_ver_parts(const std::string &v) {
  std::vector<int> out;
  size_t i = 0, n = v.size();
  while (i < n) {
    if (!isdigit(static_cast<unsigned char>(v[i]))) break;
    int val = 0;
    while (i < n && isdigit(static_cast<unsigned char>(v[i]))) {
      val = val * 10 + (v[i] - '0');
      i++;
    }
    out.push_back(val);
    if (i < n && v[i] == '.') { i++; continue; }
    break;  /* stop at the first non-dot, non-digit (e.g. "p1", " (Ubuntu)") */
  }
  return out;
}

static bool ht_ver_lt(const std::string &a, const std::string &b) {
  std::vector<int> pa = ht_ver_parts(a), pb = ht_ver_parts(b);
  if (pa.empty()) return false;  /* unparseable version -> cannot assert EOL */
  size_t m = std::max(pa.size(), pb.size());
  for (size_t i = 0; i < m; i++) {
    int x = i < pa.size() ? pa[i] : 0;
    int y = i < pb.size() ? pb[i] : 0;
    if (x != y) return x < y;
  }
  return false;
}

/* Pull the (product, version) out of a CPE 2.3 formatted string:
 *   cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
 * fields are colon-separated; [4]=product, [5]=version.  Returns false when
 * the string is not a parseable CPE or the version is ANY ("*"). */
static bool ht_cpe_product_version(const std::string &cpe,
                                   std::string &product, std::string &version) {
  if (cpe.compare(0, 8, "cpe:2.3:") != 0) return false;
  std::vector<std::string> f;
  size_t start = 0;
  for (size_t i = 0; i <= cpe.size(); i++) {
    if (i == cpe.size() || cpe[i] == ':') {
      f.push_back(cpe.substr(start, i - start));
      start = i + 1;
    }
  }
  if (f.size() < 6) return false;
  product = ht_lower(f[4]);
  version = f[5];
  if (version.empty() || version == "*" || version == "-") return false;
  return true;
}

/* ---------------------------------------------------------------------------
 * End-of-life ruleset
 *
 * Keyed by CPE product token (the same tokens net_hash_helpers.cc::derive_cpe
 * emits).  A detected version strictly below `eol_below` is past end-of-life.
 * Conservative on purpose: only products whose EOL boundary is a single clean
 * "everything below major.minor X is dead" cutoff are listed, so a tag is
 * never a guess.  Products with interleaved LTS/short-term branches (e.g.
 * MariaDB, where 10.6 LTS outlives the higher-numbered 10.7/10.8) cannot be
 * expressed this way and are deliberately omitted.  Cutoffs verified against
 * endoflife.date as of 2026-06; the comment on each rule cites the boundary
 * release's EOL date.  Update alongside the CVE refresh.
 * ------------------------------------------------------------------------- */
struct EolRule {
  const char *cpe_product;  /* CPE product field */
  const char *eol_below;    /* versions < this are EOL */
};
static const EolRule EOL_RULES[] = {
  {"http_server",   "2.4"},  /* Apache 2.2.x EOL 2017-07-11 */
  {"mysql",         "8.0"},  /* MySQL 5.7 EOL 2023-10-31 */
  {"postgresql",    "14"},   /* PostgreSQL 13 EOL 2025-11-13 (whole majors) */
  {"php",           "8.1"},  /* PHP 8.0 EOL 2023-11-26 */
  {"tomcat",        "9.0"},  /* Tomcat 8.5 EOL 2024-03-31 */
  {"mongodb",       "7.0"},  /* MongoDB 6.0 and earlier EOL (lowest LTS 7.0) */
  {"elasticsearch", "8.0"},  /* Elasticsearch 7.x EOL 2026-01-15; 6.x EOL 2022 */
};

static bool ht_is_eol(const std::string &cpe) {
  std::string product, version;
  if (!ht_cpe_product_version(cpe, product, version)) return false;
  for (const EolRule &r : EOL_RULES) {
    if (product == r.cpe_product)
      return ht_ver_lt(version, r.eol_below);
  }
  return false;
}

/* ---------------------------------------------------------------------------
 * Tag derivation
 * ------------------------------------------------------------------------- */

static bool ht_is_database(const std::string &service) {
  std::string s = ht_lower(service);
  if (s == "mysql" || s == "mariadb" || s == "postgresql" || s == "mongodb" ||
      s == "redis" || s == "elasticsearch" || s == "memcached" ||
      s == "couchdb" || s == "ms-sql-s" || s == "mssql" || s == "oracle")
    return true;
  return s.find("sql") != std::string::npos;
}

/* Known CDN providers (subset of cloud_map's provider tokens). Shodan splits
   `cdn` from `cloud`; a CDN-fronted host gets both here. */
static bool ht_is_cdn(const std::string &provider) {
  std::string p = ht_lower(provider);
  return p == "cloudflare" || p == "akamai" || p == "fastly" ||
         p == "cloudfront" || p == "incapsula" || p == "imperva" ||
         p == "stackpath" || p == "sucuri" || p == "edgecast" ||
         p == "bunnycdn" || p == "keycdn";
}

/* Canonical ICS/SCADA service ports (Shodan's `ics` category). Kept to
   strongly protocol-specific ports to avoid false positives:
     502 Modbus | 102 Siemens S7 (ISO-TSAP) | 20000 DNP3 | 44818 EtherNet/IP |
     47808 BACnet | 1911,4911 Niagara Fox | 2404 IEC 60870-5-104 |
     1962 PCWorx | 789 Red Lion/Crimson | 18245,18246 GE-SRTP | 5094 HART-IP */
static bool ht_is_ics_port(int port) {
  switch (port) {
    case 502: case 102: case 20000: case 44818: case 47808:
    case 1911: case 4911: case 2404: case 1962: case 789:
    case 18245: case 18246: case 5094:
      return true;
    default:
      return false;
  }
}

std::vector<std::string> derive_host_tags(const HostTagInput &in) {
  std::vector<std::string> tags;

  if (in.tls_self_signed == 1)        tags.push_back("self-signed");
  if (!in.cloud_provider.empty())     tags.push_back("cloud");
  if (ht_is_cdn(in.cloud_provider))   tags.push_back("cdn");
  if (ht_is_database(in.service))     tags.push_back("database");
  if (ht_is_ics_port(in.port))        tags.push_back("ics");

  /* CVE-derived tags. The cves column is a JSON array; "" or "[]" means none.
     kev/ransomware are substring-tested against the exact keys cves_to_json
     emits ("kev":1 / "ransomware":1). */
  const std::string &c = in.cves_json;
  bool has_cves = !c.empty() && c != "[]";
  if (has_cves)                                   tags.push_back("vuln");
  if (c.find("\"kev\":1") != std::string::npos)        tags.push_back("kev");
  if (c.find("\"ransomware\":1") != std::string::npos) tags.push_back("ransomware");

  if (ht_is_eol(in.cpe))              tags.push_back("eol-product");

  /* Deterministic, de-duplicated output. */
  std::sort(tags.begin(), tags.end());
  tags.erase(std::unique(tags.begin(), tags.end()), tags.end());
  return tags;
}
