/*
 * cve_map.cc -- CVE cross-reference engine for Kmap (--cve-map).
 *
 * Opens the bundled kmap-cve.db SQLite database, queries it for each
 * open port whose service was identified by version detection (-sV),
 * and reports matching CVEs ordered by CVSS score descending.
 *
 * Product normalization maps nmap/kmap service names and product strings
 * (e.g. "OpenSSH 8.2p1", service "http") to the CPE-style product names
 * stored in the database (e.g. "openssh", "http_server").
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "cve_map.h"
#include "KmapOps.h"
#include "kmap.h"          /* kmap_fetchfile */
#include "output.h"
#include "portlist.h"
#include "color.h"

#include "sqlite/sqlite3.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>
#include <map>

extern KmapOps o;

/* Attribute key used to attach TargetCveData to a Target */
static const char CVE_ATTR_KEY[] = "kmap_cve_map";

/* -----------------------------------------------------------------------
 * String helpers
 * ----------------------------------------------------------------------- */

static std::string str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}

/* Split on a single character delimiter */
static std::vector<std::string> str_split(const std::string &s, char delim) {
  std::vector<std::string> parts;
  std::istringstream ss(s);
  std::string part;
  while (std::getline(ss, part, delim))
    if (!part.empty()) parts.push_back(part);
  return parts;
}

/* -----------------------------------------------------------------------
 * Version comparison helpers
 * ----------------------------------------------------------------------- */

/* Parse "2.4.49p1" → {2, 4, 49} (stops at first non-digit/non-dot) */
static std::vector<int> parse_ver(const std::string &ver) {
  std::vector<int> parts;
  auto tokens = str_split(ver, '.');
  for (auto &t : tokens) {
    std::string digits;
    for (char c : t) {
      if (isdigit((unsigned char)c)) digits += c;
      else break;
    }
    if (!digits.empty()) {
      try { parts.push_back(std::stoi(digits)); }
      catch (...) {}
    }
  }
  return parts;
}

/* Returns -1/0/1 for a<b, a==b, a>b */
static int ver_cmp(const std::string &a, const std::string &b) {
  auto va = parse_ver(a);
  auto vb = parse_ver(b);
  size_t n = std::max(va.size(), vb.size());
  for (size_t i = 0; i < n; i++) {
    int ai = (i < va.size()) ? va[i] : 0;
    int bi = (i < vb.size()) ? vb[i] : 0;
    if (ai < bi) return -1;
    if (ai > bi) return  1;
  }
  return 0;
}

/* Extract the first dotted version number from a product string
   e.g. "OpenSSH 8.2p1 Ubuntu 4" → "8.2" */
static std::string extract_ver(const std::string &s) {
  size_t i = 0;
  while (i < s.size()) {
    if (isdigit((unsigned char)s[i])) {
      size_t start = i;
      while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '.' || s[i] == 'p'))
        i++;
      std::string candidate = s.substr(start, i - start);
      if (candidate.find('.') != std::string::npos)
        return candidate;
    } else {
      i++;
    }
  }
  return "";
}

/* -----------------------------------------------------------------------
 * Product normalization
 *
 * Maps (service_name, product_str) → list of DB query specs.
 * product_pattern = exact DB product name (exact=true) or a LIKE substring.
 * vendor_pattern  = substring to match vendor column, or "" to skip.
 * ----------------------------------------------------------------------- */

struct ProductQuery {
  std::string product_pattern; /* DB product name or LIKE fragment */
  std::string vendor_pattern;  /* DB vendor LIKE fragment, or "" */
  bool        exact;           /* true → exact match; false → LIKE '%pattern%' */
};

static std::vector<ProductQuery> normalize_service(
    const std::string &service_name,
    const std::string &product_str)
{
  std::string svc  = str_lower(service_name);
  std::string prod = str_lower(product_str);

  /* OpenSSH */
  if (prod.find("openssh") != std::string::npos || svc == "ssh")
    return {{"openssh", "", true}};

  /* Apache HTTP Server */
  if ((prod.find("apache") != std::string::npos) &&
      (prod.find("http") != std::string::npos || prod.find("httpd") != std::string::npos))
    return {{"http_server", "apache", true}};

  /* Apache Tomcat */
  if (prod.find("tomcat") != std::string::npos)
    return {{"tomcat", "apache", true}};

  /* Apache Struts */
  if (prod.find("struts") != std::string::npos)
    return {{"struts", "apache", true}};

  /* Apache Log4j */
  if (prod.find("log4j") != std::string::npos)
    return {{"log4j", "apache", true}};

  /* nginx */
  if (prod.find("nginx") != std::string::npos)
    return {{"nginx", "", true}};

  /* lighttpd */
  if (prod.find("lighttpd") != std::string::npos)
    return {{"lighttpd", "", true}};

  /* Microsoft IIS */
  if (prod.find("iis") != std::string::npos ||
      (prod.find("microsoft") != std::string::npos && (svc == "http" || svc == "https")))
    return {{"iis", "microsoft", true}};

  /* MySQL */
  if (prod.find("mysql") != std::string::npos || svc == "mysql")
    return {{"mysql", "", true}};

  /* MariaDB */
  if (prod.find("mariadb") != std::string::npos || svc == "mariadb")
    return {{"mariadb", "", true}};

  /* PostgreSQL */
  if (prod.find("postgresql") != std::string::npos ||
      svc == "postgresql" || svc == "postgres")
    return {{"postgresql", "", true}};

  /* Microsoft SQL Server */
  if (prod.find("sql server") != std::string::npos ||
      prod.find("mssql") != std::string::npos ||
      svc == "ms-sql-s" || svc == "ms-sql-m")
    return {{"sql_server", "microsoft", true}};

  /* MongoDB */
  if (prod.find("mongodb") != std::string::npos || svc == "mongodb")
    return {{"mongodb", "", true}};

  /* Redis */
  if (prod.find("redis") != std::string::npos || svc == "redis")
    return {{"redis", "", true}};

  /* Elasticsearch */
  if (prod.find("elasticsearch") != std::string::npos || svc == "elasticsearch")
    return {{"elasticsearch", "", true}};

  /* Jenkins */
  if (prod.find("jenkins") != std::string::npos || svc == "jenkins")
    return {{"jenkins", "jenkins", true}};

  /* GitLab */
  if (prod.find("gitlab") != std::string::npos)
    return {{"gitlab", "gitlab", true}};

  /* Atlassian Jira */
  if (prod.find("jira") != std::string::npos)
    return {{"jira", "atlassian", true}};

  /* Atlassian Confluence */
  if (prod.find("confluence") != std::string::npos)
    return {{"confluence", "atlassian", true}};

  /* vsftpd */
  if (prod.find("vsftpd") != std::string::npos)
    return {{"vsftpd", "", true}};

  /* ProFTPd */
  if (prod.find("proftpd") != std::string::npos)
    return {{"proftpd", "", true}};

  /* FileZilla Server */
  if (prod.find("filezilla") != std::string::npos)
    return {{"filezilla_server", "", true}};

  /* Samba / SMB */
  if (prod.find("samba") != std::string::npos ||
      svc == "netbios-ssn" || svc == "microsoft-ds")
    return {{"samba", "", true}};

  /* Spring Framework / Spring Boot — no vendor filter (DB has mixed vendors) */
  if (prod.find("spring") != std::string::npos)
    return {{"spring_framework", "", true}};

  /* OpenSSL (embedded in many service banners) */
  if (prod.find("openssl") != std::string::npos)
    return {{"openssl", "", true}};

  /* PHP */
  if (prod.find("php") != std::string::npos)
    return {{"php", "", true}};

  /* WordPress */
  if (prod.find("wordpress") != std::string::npos)
    return {{"wordpress", "", true}};

  /* Drupal */
  if (prod.find("drupal") != std::string::npos)
    return {{"drupal", "", true}};

  /* Joomla — DB has entries under both "joomla!" and "joomla" */
  if (prod.find("joomla") != std::string::npos)
    return {{"joomla!", "", true}, {"joomla", "", true}};

  /* Microsoft Exchange */
  if (prod.find("exchange") != std::string::npos)
    return {{"exchange_server", "microsoft", true}};

  /* VMware vCenter */
  if (prod.find("vcenter") != std::string::npos || prod.find("vsphere") != std::string::npos)
    return {{"vcenter_server", "vmware", true}};

  /* Oracle WebLogic */
  if (prod.find("weblogic") != std::string::npos)
    return {{"weblogic_server", "oracle", true}};

  /* Nagios */
  if (prod.find("nagios") != std::string::npos)
    return {{"nagios_xi", "nagios", true}};

  /* Cisco IOS XE */
  if (prod.find("ios xe") != std::string::npos || prod.find("iosxe") != std::string::npos)
    return {{"ios_xe", "cisco", true}};

  /* Cisco ASA */
  if (prod.find("adaptive security appliance") != std::string::npos ||
      (prod.find("cisco") != std::string::npos && prod.find("asa") != std::string::npos))
    return {{"asa", "cisco", true}};

  /* Generic HTTP/HTTPS — no product info to match, skip to avoid noise */
  if (svc == "http" || svc == "https" ||
      svc == "http-alt" || svc == "https-alt" ||
      svc == "http-proxy")
    return {};

  /* Generic FTP — service name alone is not specific enough */
  if (svc == "ftp")
    return {};

  /* Unknown / unsupported service */
  return {};
}

/* -----------------------------------------------------------------------
 * SQLite query
 * ----------------------------------------------------------------------- */

static std::vector<CveEntry> query_cves(
    sqlite3 *db,
    const ProductQuery &pq,
    const std::string &detected_ver,
    float min_score)
{
  std::vector<CveEntry> results;

  const char *sql_exact_vendor =
    "SELECT cve_id, product, vendor, version_min, version_max, "
    "cvss_score, severity, description "
    "FROM cves WHERE product = ? AND vendor LIKE ? AND cvss_score >= ? "
    "ORDER BY cvss_score DESC LIMIT 15";

  const char *sql_exact =
    "SELECT cve_id, product, vendor, version_min, version_max, "
    "cvss_score, severity, description "
    "FROM cves WHERE product = ? AND cvss_score >= ? "
    "ORDER BY cvss_score DESC LIMIT 15";

  const char *sql_like_vendor =
    "SELECT cve_id, product, vendor, version_min, version_max, "
    "cvss_score, severity, description "
    "FROM cves WHERE product LIKE ? AND vendor LIKE ? AND cvss_score >= ? "
    "ORDER BY cvss_score DESC LIMIT 15";

  const char *sql_like =
    "SELECT cve_id, product, vendor, version_min, version_max, "
    "cvss_score, severity, description "
    "FROM cves WHERE product LIKE ? AND cvss_score >= ? "
    "ORDER BY cvss_score DESC LIMIT 15";

  const char *sql;
  bool has_vendor = !pq.vendor_pattern.empty();

  if (pq.exact)
    sql = has_vendor ? sql_exact_vendor : sql_exact;
  else
    sql = has_vendor ? sql_like_vendor  : sql_like;

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return results;

  std::string prod_bind = pq.exact ? pq.product_pattern
                                   : ("%" + pq.product_pattern + "%");
  std::string vend_bind = "%" + pq.vendor_pattern + "%";

  int idx = 1;
  sqlite3_bind_text(stmt, idx++, prod_bind.c_str(), -1, SQLITE_TRANSIENT);
  if (has_vendor)
    sqlite3_bind_text(stmt, idx++, vend_bind.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_double(stmt, idx++, (double)min_score);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    CveEntry e;
    auto col_str = [&](int c) -> std::string {
      const unsigned char *p = sqlite3_column_text(stmt, c);
      return p ? reinterpret_cast<const char *>(p) : "";
    };

    e.cve_id      = col_str(0);
    e.product     = col_str(1);
    e.vendor      = col_str(2);
    std::string vmin = col_str(3);
    std::string vmax = col_str(4);
    e.cvss_score  = (float)sqlite3_column_double(stmt, 5);
    e.severity    = col_str(6);
    e.description = col_str(7);

    /* Version range filter — only applied when we have a detected version
       and the DB row has at least one bound */
    if (!detected_ver.empty() && (!vmin.empty() || !vmax.empty())) {
      std::string dver = extract_ver(detected_ver);
      if (!dver.empty()) {
        if (!vmin.empty() && !vmax.empty()) {
          if (ver_cmp(dver, vmin) < 0 || ver_cmp(dver, vmax) > 0)
            continue;
        } else if (!vmin.empty()) {
          if (ver_cmp(dver, vmin) < 0)
            continue;
        } else {
          if (ver_cmp(dver, vmax) > 0)
            continue;
        }
      }
    }

    results.push_back(e);
  }

  sqlite3_finalize(stmt);
  return results;
}

/* -----------------------------------------------------------------------
 * Database location
 * ----------------------------------------------------------------------- */

static std::string find_db() {
  char buf[1024];

  /* Use kmap_fetchfile to search all standard data directories */
  if (kmap_fetchfile(buf, sizeof(buf), "kmap-cve.db") > 0)
    return buf;

  return "";
}

/* -----------------------------------------------------------------------
 * Target attribute helpers
 * ----------------------------------------------------------------------- */

static TargetCveData *get_or_create(Target *t) {
  void *raw = t->attribute.get(CVE_ATTR_KEY);
  if (raw) return static_cast<TargetCveData *>(raw);
  auto *data = new TargetCveData();
  t->attribute.set(CVE_ATTR_KEY, data);
  return data;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

void run_cve_map(std::vector<Target*>& Targets, float min_score) {
  std::string db_path = find_db();
  if (db_path.empty()) {
    log_write(LOG_STDOUT,
      "WARNING: --cve-map: kmap-cve.db not found.\n"
      "  Place kmap-cve.db in the current directory or Kmap data directory.\n"
      "  Use scripts/update_cves.py to (re)download the CVE database.\n");
    return;
  }

  sqlite3 *db = nullptr;
  if (sqlite3_open_v2(db_path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
    log_write(LOG_STDOUT, "WARNING: --cve-map: Cannot open %s: %s\n",
              db_path.c_str(), db ? sqlite3_errmsg(db) : "unknown error");
    if (db) sqlite3_close(db);
    return;
  }

  for (Target *t : Targets) {
    Port *port = nullptr;
    Port portstore{};

    while ((port = t->ports.nextPort(port, &portstore,
                                      TCPANDUDPANDSCTP, PORT_OPEN)) != nullptr) {
      struct serviceDeductions sd{};
      t->ports.getServiceDeductions(port->portno, port->proto, &sd);
      if (!sd.name) continue;

      std::string svc  = sd.name;
      std::string prod = sd.product  ? sd.product : "";
      std::string ver  = sd.version  ? sd.version : "";

      /* Build combined product+version string for display */
      std::string ver_display = prod;
      if (!ver.empty()) {
        if (!ver_display.empty()) ver_display += " ";
        ver_display += ver;
      }

      auto queries = normalize_service(svc, prod);
      if (queries.empty()) continue;

      PortCveResults pr;
      pr.portno  = port->portno;
      pr.proto   = (port->proto == IPPROTO_TCP) ? "tcp" : "udp";
      pr.service = svc;
      pr.version = ver_display;

      for (auto &pq : queries) {
        auto cves = query_cves(db, pq, ver, min_score);
        for (auto &c : cves)
          pr.cves.push_back(std::move(c));
      }

      if (!pr.cves.empty()) {
        /* Deduplicate by CVE ID and re-sort */
        std::map<std::string, CveEntry> seen;
        for (auto &c : pr.cves)
          if (seen.find(c.cve_id) == seen.end())
            seen[c.cve_id] = c;
        pr.cves.clear();
        for (auto &kv : seen)
          pr.cves.push_back(kv.second);
        std::sort(pr.cves.begin(), pr.cves.end(),
                  [](const CveEntry &a, const CveEntry &b){
                    return a.cvss_score > b.cvss_score;
                  });

        get_or_create(t)->port_results.push_back(std::move(pr));
      }
    }
  }

  sqlite3_close(db);
}

void print_cve_map_output(const Target *t) {
  void *raw = t->attribute.get(CVE_ATTR_KEY);
  if (!raw) return;
  const auto *data = static_cast<const TargetCveData *>(raw);
  if (data->port_results.empty()) return;

  log_write(LOG_PLAIN, "  |_ CVE Map:\n");

  for (const auto &pr : data->port_results) {
    std::string port_line = std::to_string(pr.portno) + "/" + pr.proto
                          + " " + pr.service;
    if (!pr.version.empty())
      port_line += " (" + pr.version + ")";

    log_write(LOG_PLAIN, "  |  %s:\n", port_line.c_str());

    for (const auto &cve : pr.cves) {
      /* Format CVSS score as "X.Y" */
      char score_buf[8];
      snprintf(score_buf, sizeof(score_buf), "%.1f", cve.cvss_score);

      std::string entry = "  |    " + cve.cve_id
                        + "  CVSS:" + score_buf
                        + "  " + cve.severity;

      if (Color::enabled()) {
        if (cve.severity == "CRITICAL")
          entry = Color::red(entry);
        else if (cve.severity == "HIGH")
          entry = Color::yellow(entry);
      }

      log_write(LOG_PLAIN, "%s\n", entry.c_str());

      /* Description — truncate to 76 chars */
      std::string desc = cve.description;
      if (desc.size() > 76) desc = desc.substr(0, 73) + "...";
      log_write(LOG_PLAIN, "  |      %s\n", desc.c_str());
    }
  }
}
