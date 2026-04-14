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

  /* Joomla — DB has entries under "joomla" and "joomla\!" (escaped) */
  if (prod.find("joomla") != std::string::npos)
    return {{"joomla", "", true}, {"joomla\\!", "", true}};

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
    "FROM cves WHERE product = ? AND (vendor LIKE ? OR vendor IS NULL) AND cvss_score >= ? "
    "ORDER BY cvss_score DESC LIMIT 15";

  const char *sql_exact =
    "SELECT cve_id, product, vendor, version_min, version_max, "
    "cvss_score, severity, description "
    "FROM cves WHERE product = ? AND cvss_score >= ? "
    "ORDER BY cvss_score DESC LIMIT 15";

  const char *sql_like_vendor =
    "SELECT cve_id, product, vendor, version_min, version_max, "
    "cvss_score, severity, description "
    "FROM cves WHERE product LIKE ? AND (vendor LIKE ? OR vendor IS NULL) AND cvss_score >= ? "
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

      std::vector<ProductQuery> queries;
      try {
        queries = normalize_service(svc, prod);
      } catch (...) {
        /* String operation failure in normalization -- skip this port */
        continue;
      }
      if (queries.empty()) continue;

      PortCveResults pr;
      pr.portno  = port->portno;
      pr.proto   = (port->proto == IPPROTO_TCP) ? "tcp"
                 : (port->proto == IPPROTO_UDP) ? "udp" : "sctp";
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

/* =======================================================================
 * --import-cves: Import CVEs from external files into kmap-cve.db
 *
 * Supported input formats:
 *   .txt / .csv / .md — delimited text (comma, tab, or pipe)
 *     Line format: CVE-ID, product, vendor, ver_min, ver_max, cvss, severity, desc
 *     Lines starting with # are comments.  Empty lines are skipped.
 *
 *   .db / .sqlite — SQLite database with a 'cves' table matching our schema
 *     All rows are copied.  Duplicates (by cve_id PK) are skipped.
 * ======================================================================= */

#include <fstream>

/* -----------------------------------------------------------------------
 * Validation helpers
 * ----------------------------------------------------------------------- */

static bool is_valid_cve_id(const std::string &id) {
  /* Must match CVE-YYYY-NNNNN (at least 4 digits after second dash) */
  if (id.size() < 13 || id.substr(0, 4) != "CVE-") return false;
  if (id[8] != '-') return false;
  for (int i = 4; i < 8; i++)
    if (!isdigit((unsigned char)id[i])) return false;
  for (size_t i = 9; i < id.size(); i++)
    if (!isdigit((unsigned char)id[i])) return false;
  return true;
}

static bool is_valid_severity(const std::string &sev) {
  return sev.empty() || sev == "LOW" || sev == "MEDIUM" ||
         sev == "HIGH" || sev == "CRITICAL";
}

static bool is_valid_cvss(float score) {
  return score >= 0.0f && score <= 10.0f;
}

/* -----------------------------------------------------------------------
 * Trim whitespace and optional surrounding quotes from a field
 * ----------------------------------------------------------------------- */
static std::string trim_field(const std::string &s) {
  size_t a = s.find_first_not_of(" \t\r\n\"'");
  if (a == std::string::npos) return "";
  size_t b = s.find_last_not_of(" \t\r\n\"'");
  return s.substr(a, b - a + 1);
}

/* -----------------------------------------------------------------------
 * Split a line by the first delimiter found (comma, tab, or pipe)
 * ----------------------------------------------------------------------- */
static std::vector<std::string> split_line(const std::string &line) {
  /* Detect delimiter: use the first of comma, tab, pipe that appears */
  char delim = ',';
  if (line.find('\t') != std::string::npos &&
      (line.find(',') == std::string::npos || line.find('\t') < line.find(',')))
    delim = '\t';
  else if (line.find('|') != std::string::npos && line.find(',') == std::string::npos)
    delim = '|';

  std::vector<std::string> fields;
  std::istringstream ss(line);
  std::string field;
  while (std::getline(ss, field, delim))
    fields.push_back(trim_field(field));
  return fields;
}

/* -----------------------------------------------------------------------
 * Detect file type by extension
 * ----------------------------------------------------------------------- */
enum ImportFileType { IMPORT_TEXT, IMPORT_SQLITE, IMPORT_UNKNOWN };

static ImportFileType detect_file_type(const std::string &path) {
  size_t dot = path.rfind('.');
  if (dot == std::string::npos) return IMPORT_UNKNOWN;
  std::string ext = path.substr(dot);
  std::transform(ext.begin(), ext.end(), ext.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  if (ext == ".db" || ext == ".sqlite" || ext == ".sqlite3")
    return IMPORT_SQLITE;
  if (ext == ".txt" || ext == ".csv" || ext == ".md" || ext == ".tsv" || ext == ".json")
    return IMPORT_TEXT;
  return IMPORT_UNKNOWN;
}

/* -----------------------------------------------------------------------
 * Ensure the target database exists and has the correct schema
 * ----------------------------------------------------------------------- */
static bool ensure_schema(sqlite3 *db) {
  const char *create_sql =
    "CREATE TABLE IF NOT EXISTS cves ("
    "  cve_id      TEXT PRIMARY KEY,"
    "  product     TEXT NOT NULL,"
    "  vendor      TEXT,"
    "  version_min TEXT,"
    "  version_max TEXT,"
    "  cvss_score  REAL,"
    "  severity    TEXT,"
    "  description TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_product  ON cves(product);"
    "CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity);";

  char *errmsg = nullptr;
  if (sqlite3_exec(db, create_sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
    fprintf(stderr, "ERROR: Failed to create schema: %s\n",
            errmsg ? errmsg : "unknown error");
    sqlite3_free(errmsg);
    return false;
  }
  return true;
}

/* -----------------------------------------------------------------------
 * Insert a single validated CVE entry.  Returns 1 if inserted, 0 if dup.
 * ----------------------------------------------------------------------- */
static int insert_cve(sqlite3_stmt *stmt, const std::string &cve_id,
                      const std::string &product, const std::string &vendor,
                      const std::string &vmin, const std::string &vmax,
                      float cvss, const std::string &severity,
                      const std::string &desc) {
  sqlite3_reset(stmt);
  sqlite3_bind_text(stmt, 1, cve_id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, product.c_str(), -1, SQLITE_TRANSIENT);
  if (vendor.empty())
    sqlite3_bind_null(stmt, 3);
  else
    sqlite3_bind_text(stmt, 3, vendor.c_str(), -1, SQLITE_TRANSIENT);
  if (vmin.empty())
    sqlite3_bind_null(stmt, 4);
  else
    sqlite3_bind_text(stmt, 4, vmin.c_str(), -1, SQLITE_TRANSIENT);
  if (vmax.empty())
    sqlite3_bind_null(stmt, 5);
  else
    sqlite3_bind_text(stmt, 5, vmax.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_double(stmt, 6, static_cast<double>(cvss));
  sqlite3_bind_text(stmt, 7, severity.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 8, desc.c_str(), -1, SQLITE_TRANSIENT);

  int rc = sqlite3_step(stmt);
  return (rc == SQLITE_DONE) ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * Import from delimited text file (.txt, .csv, .md, .tsv)
 * ----------------------------------------------------------------------- */
static int import_from_text(const char *path, sqlite3 *db) {
  std::ifstream f(path);
  if (!f.is_open()) {
    fprintf(stderr, "ERROR: Cannot open file: %s\n", path);
    return 1;
  }

  const char *ins_sql =
    "INSERT OR IGNORE INTO cves "
    "(cve_id, product, vendor, version_min, version_max, cvss_score, severity, description) "
    "VALUES (?,?,?,?,?,?,?,?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, ins_sql, -1, &stmt, nullptr) != SQLITE_OK) {
    fprintf(stderr, "ERROR: Failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
    return 1;
  }

  sqlite3_exec(db, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);

  int line_num = 0, inserted = 0, skipped = 0, errors = 0;
  std::string line;

  while (std::getline(f, line)) {
    line_num++;

    /* Skip empty lines and comments */
    size_t first = line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos || line[first] == '#' || line[first] == '/')
      continue;

    /* Skip markdown headers and horizontal rules */
    if (line[first] == '-' || line[first] == '=' || line[first] == '|')
      continue;

    auto fields = split_line(line);

    /* Need at least CVE-ID and product (2 fields minimum) */
    if (fields.size() < 2) {
      /* Could be a bare CVE-ID line — skip silently */
      continue;
    }

    std::string cve_id = fields[0];
    std::string product = fields.size() > 1 ? str_lower(fields[1]) : "";
    std::string vendor  = fields.size() > 2 ? str_lower(fields[2]) : "";
    std::string vmin    = fields.size() > 3 ? fields[3] : "";
    std::string vmax    = fields.size() > 4 ? fields[4] : "";
    float cvss          = 0.0f;
    std::string severity = fields.size() > 6 ? fields[6] : "";
    std::string desc    = fields.size() > 7 ? fields[7] : "";

    /* Parse CVSS score */
    if (fields.size() > 5 && !fields[5].empty()) {
      try { cvss = std::stof(fields[5]); }
      catch (...) { cvss = 0.0f; }
    }

    /* Severity: auto-derive from CVSS if not provided */
    if (severity.empty() && cvss > 0.0f) {
      if (cvss >= 9.0f)      severity = "CRITICAL";
      else if (cvss >= 7.0f) severity = "HIGH";
      else if (cvss >= 4.0f) severity = "MEDIUM";
      else                    severity = "LOW";
    } else {
      /* Normalize to uppercase */
      std::transform(severity.begin(), severity.end(), severity.begin(),
                     [](unsigned char c){ return static_cast<char>(toupper(c)); });
    }

    /* Validate */
    if (!is_valid_cve_id(cve_id)) {
      fprintf(stderr, "  WARN line %d: invalid CVE ID '%s' — skipped\n",
              line_num, cve_id.c_str());
      errors++;
      continue;
    }
    if (product.empty()) {
      fprintf(stderr, "  WARN line %d: empty product for %s — skipped\n",
              line_num, cve_id.c_str());
      errors++;
      continue;
    }
    if (!is_valid_cvss(cvss)) {
      fprintf(stderr, "  WARN line %d: invalid CVSS %.1f for %s — clamped\n",
              line_num, cvss, cve_id.c_str());
      if (cvss < 0.0f) cvss = 0.0f;
      if (cvss > 10.0f) cvss = 10.0f;
    }
    if (!is_valid_severity(severity)) {
      fprintf(stderr, "  WARN line %d: invalid severity '%s' for %s — cleared\n",
              line_num, severity.c_str(), cve_id.c_str());
      severity = "";
    }

    if (insert_cve(stmt, cve_id, product, vendor, vmin, vmax, cvss, severity, desc))
      inserted++;
    else
      skipped++;
  }

  sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
  sqlite3_finalize(stmt);

  printf("Text import complete: %d inserted, %d duplicates skipped, %d errors\n",
         inserted, skipped, errors);
  return 0;
}

/* -----------------------------------------------------------------------
 * Import from another SQLite database
 * ----------------------------------------------------------------------- */
static int import_from_sqlite(const char *path, sqlite3 *db) {
  sqlite3 *src = nullptr;
  if (sqlite3_open_v2(path, &src, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
    fprintf(stderr, "ERROR: Cannot open source database: %s\n",
            src ? sqlite3_errmsg(src) : "unknown error");
    if (src) sqlite3_close(src);
    return 1;
  }

  /* Verify source has a 'cves' table */
  sqlite3_stmt *check = nullptr;
  sqlite3_prepare_v2(src, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cves'", -1, &check, nullptr);
  int has_table = 0;
  if (sqlite3_step(check) == SQLITE_ROW)
    has_table = sqlite3_column_int(check, 0);
  sqlite3_finalize(check);

  if (!has_table) {
    fprintf(stderr, "ERROR: Source database has no 'cves' table\n");
    sqlite3_close(src);
    return 1;
  }

  /* Read all rows from source */
  sqlite3_stmt *read_stmt = nullptr;
  if (sqlite3_prepare_v2(src,
        "SELECT cve_id, product, vendor, version_min, version_max, "
        "cvss_score, severity, description FROM cves", -1, &read_stmt, nullptr) != SQLITE_OK) {
    fprintf(stderr, "ERROR: Failed to query source database: %s\n", sqlite3_errmsg(src));
    sqlite3_close(src);
    return 1;
  }

  /* Prepare insert into destination */
  const char *ins_sql =
    "INSERT OR IGNORE INTO cves "
    "(cve_id, product, vendor, version_min, version_max, cvss_score, severity, description) "
    "VALUES (?,?,?,?,?,?,?,?)";
  sqlite3_stmt *ins_stmt = nullptr;
  if (sqlite3_prepare_v2(db, ins_sql, -1, &ins_stmt, nullptr) != SQLITE_OK) {
    fprintf(stderr, "ERROR: Failed to prepare insert: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(read_stmt);
    sqlite3_close(src);
    return 1;
  }

  sqlite3_exec(db, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);

  int inserted = 0, skipped = 0, errors = 0;
  auto col_str = [&](int c) -> std::string {
    const unsigned char *p = sqlite3_column_text(read_stmt, c);
    return p ? reinterpret_cast<const char *>(p) : "";
  };

  while (sqlite3_step(read_stmt) == SQLITE_ROW) {
    std::string cve_id = col_str(0);
    std::string product = col_str(1);
    std::string vendor  = col_str(2);
    std::string vmin    = col_str(3);
    std::string vmax    = col_str(4);
    float cvss = static_cast<float>(sqlite3_column_double(read_stmt, 5));
    std::string severity = col_str(6);
    std::string desc    = col_str(7);

    if (!is_valid_cve_id(cve_id) || product.empty()) {
      errors++;
      continue;
    }

    if (insert_cve(ins_stmt, cve_id, product, vendor, vmin, vmax, cvss, severity, desc))
      inserted++;
    else
      skipped++;
  }

  sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
  sqlite3_finalize(ins_stmt);
  sqlite3_finalize(read_stmt);
  sqlite3_close(src);

  printf("SQLite import complete: %d inserted, %d duplicates skipped, %d invalid\n",
         inserted, skipped, errors);
  return 0;
}

/* -----------------------------------------------------------------------
 * Public API: import_cves()
 * ----------------------------------------------------------------------- */
int import_cves(const char *import_file, const char *db_path) {
  if (!import_file || !import_file[0]) {
    fprintf(stderr, "ERROR: --import-cves requires a file path\n");
    return 1;
  }

  /* Determine the target database path */
  std::string target_db;
  if (db_path && db_path[0]) {
    target_db = db_path;
  } else {
    target_db = find_db();
    if (target_db.empty()) {
      /* No existing DB — create one in the current directory */
      target_db = "kmap-cve.db";
      printf("No existing kmap-cve.db found; creating new database: %s\n",
             target_db.c_str());
    }
  }

  /* Detect input file type */
  ImportFileType ftype = detect_file_type(import_file);
  if (ftype == IMPORT_UNKNOWN) {
    /* Default to text for unrecognized extensions */
    fprintf(stderr, "WARNING: Unrecognized file extension, treating as text format\n");
    ftype = IMPORT_TEXT;
  }

  /* Open (or create) the target database */
  sqlite3 *db = nullptr;
  if (sqlite3_open(target_db.c_str(), &db) != SQLITE_OK) {
    fprintf(stderr, "ERROR: Cannot open database %s: %s\n",
            target_db.c_str(), db ? sqlite3_errmsg(db) : "unknown");
    if (db) sqlite3_close(db);
    return 1;
  }

  /* Ensure schema exists (creates table + indexes if missing) */
  if (!ensure_schema(db)) {
    sqlite3_close(db);
    return 1;
  }

  /* Count existing entries before import */
  sqlite3_stmt *cnt = nullptr;
  int before = 0;
  if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM cves", -1, &cnt, nullptr) == SQLITE_OK) {
    if (sqlite3_step(cnt) == SQLITE_ROW)
      before = sqlite3_column_int(cnt, 0);
    sqlite3_finalize(cnt);
  }

  printf("Importing CVEs from: %s\n", import_file);
  printf("Target database:     %s (%d existing entries)\n", target_db.c_str(), before);
  printf("Format:              %s\n", ftype == IMPORT_SQLITE ? "SQLite" : "Text/CSV");
  printf("\n");

  int rc;
  if (ftype == IMPORT_SQLITE)
    rc = import_from_sqlite(import_file, db);
  else
    rc = import_from_text(import_file, db);

  /* Report final count */
  int after = 0;
  if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM cves", -1, &cnt, nullptr) == SQLITE_OK) {
    if (sqlite3_step(cnt) == SQLITE_ROW)
      after = sqlite3_column_int(cnt, 0);
    sqlite3_finalize(cnt);
  }

  printf("\nDatabase now contains %d CVE entries (was %d)\n", after, before);
  sqlite3_close(db);
  return rc;
}
