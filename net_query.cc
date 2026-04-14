/*
 * net_query.cc -- Query engine for Kmap net-scan data.
 *
 * Searches across all (or targeted) shard databases using SQL WHERE
 * clauses built from the provided filters.  Supports filtering by port,
 * service, CVE ID, CVSS score, web title, web server header, and IP
 * range.  Outputs results to stdout or a file, with an optional
 * count-only mode.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_query.h"
#include "net_db.h"
#include "KmapOps.h"
#include "kmap.h"
#include "output.h"

#include "sqlite/sqlite3.h"

#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <sstream>

extern KmapOps o;

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static std::string str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}

/* Format a number with thousand separators */
static std::string format_count(int64_t n) {
  if (n < 0) return "-" + format_count(-n);
  std::string raw = std::to_string(n);
  std::string out;
  int len = static_cast<int>(raw.size());
  for (int i = 0; i < len; i++) {
    if (i > 0 && (len - i) % 3 == 0) out += ',';
    out += raw[i];
  }
  return out;
}

/* -----------------------------------------------------------------------
 * CIDR range parsing
 *
 * Parses "93.184.0.0/16" into a base IP and mask, then determines
 * which shards need to be searched.
 * ----------------------------------------------------------------------- */

struct CidrRange {
  uint32_t network;  /* host byte order */
  uint32_t mask;     /* host byte order, e.g. 0xFFFF0000 for /16 */
  bool     valid;
};

static CidrRange parse_cidr(const char *cidr) {
  CidrRange r{};
  r.valid = false;

  if (!cidr || !cidr[0]) return r;

  char buf[64];
  size_t slen = strlen(cidr);
  if (slen >= sizeof(buf)) return r;
  memcpy(buf, cidr, slen + 1);

  char *slash = strchr(buf, '/');
  int prefix_len = 32;
  if (slash) {
    *slash = '\0';
    prefix_len = atoi(slash + 1);
    if (prefix_len < 0 || prefix_len > 32) return r;
  }

  uint32_t ip = ip_to_u32(buf);
  if (ip == 0 && strcmp(buf, "0.0.0.0") != 0) return r;

  if (prefix_len == 0)
    r.mask = 0;
  else
    r.mask = 0xFFFFFFFFU << (32 - prefix_len);

  r.network = ip & r.mask;
  r.valid = true;
  return r;
}

/* Check if an IP (host byte order) falls within a CIDR range */
static bool ip_in_cidr(uint32_t ip, const CidrRange &cidr) {
  return (ip & cidr.mask) == cidr.network;
}

/* Determine which shard indices overlap with a CIDR range.
 * Each shard covers a /5 block (top 5 bits). */
static std::vector<int> shards_for_cidr(const CidrRange &cidr) {
  std::vector<int> shards;
  for (int i = 0; i < NET_SHARD_COUNT; i++) {
    uint32_t shard_start = static_cast<uint32_t>(i) << 27;
    uint32_t shard_end   = shard_start | 0x07FFFFFFU;

    /* The CIDR range spans [cidr.network, cidr.network | ~cidr.mask] */
    uint32_t cidr_end = cidr.network | ~cidr.mask;

    /* Two ranges [a,b] and [c,d] overlap iff a <= d && c <= b */
    if (cidr.network <= shard_end && shard_start <= cidr_end)
      shards.push_back(i);
  }
  return shards;
}

/* -----------------------------------------------------------------------
 * Minimal JSON helpers for CVSS extraction from the cves column
 *
 * The cves column contains a JSON array like:
 *   [{"id":"CVE-2024-6387","cvss":8.1,"severity":"HIGH","desc":"..."}]
 * ----------------------------------------------------------------------- */

/* Extract the maximum CVSS score from a cves JSON string.
 * Returns -1.0f if no valid score found. */
static float max_cvss_from_json(const std::string &cves_json) {
  float max_score = -1.0f;
  size_t pos = 0;
  while (true) {
    pos = cves_json.find("\"cvss\":", pos);
    if (pos == std::string::npos) break;
    pos += 7;
    while (pos < cves_json.size() && cves_json[pos] == ' ') pos++;
    size_t end = pos;
    while (end < cves_json.size() &&
           (isdigit(static_cast<unsigned char>(cves_json[end])) ||
            cves_json[end] == '.' || cves_json[end] == '-'))
      end++;
    if (end > pos) {
      float score = static_cast<float>(
          atof(cves_json.substr(pos, end - pos).c_str()));
      if (score > max_score) max_score = score;
    }
    pos = end;
  }
  return max_score;
}

/* Extract the first CVE summary for compact display.
 * Returns something like "CVE-2024-6387 (CVSS:8.1)". */
static std::string first_cve_summary(const std::string &cves_json) {
  size_t id_pos = cves_json.find("\"id\":\"");
  if (id_pos == std::string::npos) return "";
  id_pos += 6;
  size_t id_end = cves_json.find('"', id_pos);
  if (id_end == std::string::npos) return "";
  std::string cve_id = cves_json.substr(id_pos, id_end - id_pos);

  /* Find the CVSS score near this entry */
  size_t cvss_pos = cves_json.find("\"cvss\":", id_pos);
  std::string cvss_str;
  if (cvss_pos != std::string::npos && cvss_pos < id_pos + 200) {
    cvss_pos += 7;
    while (cvss_pos < cves_json.size() && cves_json[cvss_pos] == ' ')
      cvss_pos++;
    size_t cvss_end = cvss_pos;
    while (cvss_end < cves_json.size() &&
           (isdigit(static_cast<unsigned char>(cves_json[cvss_end])) ||
            cves_json[cvss_end] == '.'))
      cvss_end++;
    if (cvss_end > cvss_pos)
      cvss_str = cves_json.substr(cvss_pos, cvss_end - cvss_pos);
  }

  if (!cvss_str.empty())
    return cve_id + " (CVSS:" + cvss_str + ")";
  return cve_id;
}

/* -----------------------------------------------------------------------
 * Build SQL WHERE clause and bind helpers
 *
 * Uses parameterized queries (sqlite3_bind_*) for all user-supplied
 * values to prevent SQL injection.
 * ----------------------------------------------------------------------- */

struct QueryFilter {
  std::string where_clause;
  /* Ordered list of bind values and their types */
  enum BindType { BTEXT, BINT };
  struct BindVal {
    BindType type;
    std::string text_val;
    int int_val;
  };
  std::vector<BindVal> binds;
};

static QueryFilter build_filter(int port, const char *service,
                                const char *cve, float min_cvss,
                                const char *web_title,
                                const char *web_server) {
  QueryFilter f;
  std::vector<std::string> conditions;

  if (port > 0) {
    conditions.push_back("port = ?");
    f.binds.push_back({QueryFilter::BINT, "", port});
  }

  if (service && service[0]) {
    conditions.push_back("LOWER(service) LIKE ?");
    f.binds.push_back({QueryFilter::BTEXT,
                       "%" + str_lower(service) + "%", 0});
  }

  if (cve && cve[0]) {
    conditions.push_back("cves LIKE ?");
    f.binds.push_back({QueryFilter::BTEXT,
                       "%" + std::string(cve) + "%", 0});
  }

  /* CVSS filtering is done in post-processing since the score is
   * embedded in the JSON cves column.  Pre-filter to rows with CVE data. */
  if (min_cvss > 0.0f) {
    conditions.push_back(
        "cves IS NOT NULL AND cves != '' AND cves != '[]'");
  }

  if (web_title && web_title[0]) {
    conditions.push_back("LOWER(web_title) LIKE ?");
    f.binds.push_back({QueryFilter::BTEXT,
                       "%" + str_lower(web_title) + "%", 0});
  }

  if (web_server && web_server[0]) {
    conditions.push_back("LOWER(web_server) LIKE ?");
    f.binds.push_back({QueryFilter::BTEXT,
                       "%" + str_lower(web_server) + "%", 0});
  }

  if (conditions.empty()) {
    f.where_clause = "1=1";
  } else {
    std::ostringstream oss;
    for (size_t i = 0; i < conditions.size(); i++) {
      if (i > 0) oss << " AND ";
      oss << conditions[i];
    }
    f.where_clause = oss.str();
  }

  return f;
}

/* Bind all filter values to a prepared statement */
static void bind_filter(sqlite3_stmt *stmt, const QueryFilter &f) {
  int idx = 1;
  for (const auto &b : f.binds) {
    switch (b.type) {
      case QueryFilter::BTEXT:
        sqlite3_bind_text(stmt, idx, b.text_val.c_str(), -1,
                          SQLITE_TRANSIENT);
        break;
      case QueryFilter::BINT:
        sqlite3_bind_int(stmt, idx, b.int_val);
        break;
    }
    idx++;
  }
}

/* -----------------------------------------------------------------------
 * Format one result line
 *
 * Format: 93.184.216.34:443/tcp  https  nginx 1.18.0  CVE-2021-23017 (CVSS:7.7)
 * ----------------------------------------------------------------------- */

static std::string format_result(const std::string &ip, int port,
                                 const std::string &proto,
                                 const std::string &service,
                                 const std::string &version,
                                 const std::string &cves_json) {
  std::ostringstream oss;

  /* IP:port/proto */
  oss << ip << ":" << port << "/" << proto;

  /* Pad to at least 24 chars for alignment */
  std::string addr = oss.str();
  oss.str("");
  oss << addr;
  if (addr.size() < 24)
    oss << std::string(24 - addr.size(), ' ');
  else
    oss << "  ";

  /* Service */
  if (!service.empty())
    oss << service;
  else
    oss << "unknown";

  /* Version */
  if (!version.empty())
    oss << "  " << version;

  /* First CVE summary */
  if (!cves_json.empty() && cves_json != "[]") {
    std::string cve_summary = first_cve_summary(cves_json);
    if (!cve_summary.empty())
      oss << "  " << cve_summary;
  }

  return oss.str();
}

/* -----------------------------------------------------------------------
 * run_net_query -- main entry point
 * ----------------------------------------------------------------------- */

int run_net_query(const char *data_dir,
                  int port,
                  const char *service,
                  const char *cve,
                  float min_cvss,
                  const char *web_title,
                  const char *web_server,
                  const char *ip_range,
                  const char *output_file,
                  bool count_only) {
  if (!data_dir) return 1;

  /* Parse IP range if provided */
  CidrRange cidr{};
  bool has_cidr = false;
  if (ip_range && ip_range[0]) {
    cidr = parse_cidr(ip_range);
    if (!cidr.valid) {
      log_write(LOG_STDOUT,
        "net-query: ERROR: invalid IP range '%s' "
        "(expected CIDR like 93.184.0.0/16)\n", ip_range);
      return 1;
    }
    has_cidr = true;
  }

  /* Determine which shards to search */
  std::vector<int> shard_indices;
  if (has_cidr) {
    shard_indices = shards_for_cidr(cidr);
  } else {
    for (int i = 0; i < NET_SHARD_COUNT; i++)
      shard_indices.push_back(i);
  }

  /* Build the query filter */
  QueryFilter filter = build_filter(port, service, cve, min_cvss,
                                    web_title, web_server);

  /* Open output file if specified */
  FILE *out_fp = nullptr;
  bool own_fp = false;
  if (output_file && output_file[0]) {
    out_fp = fopen(output_file, "w");
    if (!out_fp) {
      log_write(LOG_STDOUT,
        "net-query: ERROR: cannot open output file '%s'\n",
        output_file);
      return 1;
    }
    own_fp = true;
  }

  /* Build the SQL query */
  std::string sql =
    "SELECT ip, port, proto, service, version, cves "
    "FROM hosts WHERE " + filter.where_clause
    + " ORDER BY ip, port";

  int64_t total_count = 0;
  int shards_searched = 0;

  for (int shard_idx : shard_indices) {
    std::string db_path = net_shard_path(data_dir, shard_idx);

    /* Check if shard file exists before trying to open */
    FILE *test = fopen(db_path.c_str(), "r");
    if (!test) continue;
    fclose(test);

    sqlite3 *db = net_db_open(db_path);
    if (!db) {
      log_write(LOG_STDOUT,
        "net-query: WARNING: cannot open %s -- skipping.\n",
        db_path.c_str());
      continue;
    }
    shards_searched++;

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr)
        != SQLITE_OK) {
      log_write(LOG_STDOUT,
        "net-query: WARNING: query failed on %s: %s\n",
        db_path.c_str(), sqlite3_errmsg(db));
      net_db_close(db);
      continue;
    }

    bind_filter(stmt, filter);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      auto col_str = [&](int c) -> std::string {
        const unsigned char *p = sqlite3_column_text(stmt, c);
        return p ? reinterpret_cast<const char *>(p) : "";
      };

      std::string row_ip    = col_str(0);
      int         row_port  = sqlite3_column_int(stmt, 1);
      std::string row_proto = col_str(2);
      std::string row_svc   = col_str(3);
      std::string row_ver   = col_str(4);
      std::string row_cves  = col_str(5);

      /* Post-process: IP range filtering (exact CIDR check) */
      if (has_cidr) {
        uint32_t ip_num = ip_to_u32(row_ip.c_str());
        if (!ip_in_cidr(ip_num, cidr)) continue;
      }

      /* Post-process: CVSS score filtering */
      if (min_cvss > 0.0f) {
        float max_score = max_cvss_from_json(row_cves);
        if (max_score < min_cvss) continue;
      }

      total_count++;

      if (!count_only) {
        std::string line = format_result(row_ip, row_port, row_proto,
                                         row_svc, row_ver, row_cves);
        if (out_fp)
          fprintf(out_fp, "%s\n", line.c_str());
        else
          log_write(LOG_PLAIN, "%s\n", line.c_str());
      }
    }

    sqlite3_finalize(stmt);
    net_db_close(db);
  }

  /* Output final results */
  if (count_only) {
    if (out_fp)
      fprintf(out_fp, "%s\n", format_count(total_count).c_str());
    else
      log_write(LOG_PLAIN, "%s\n", format_count(total_count).c_str());
  } else if (total_count == 0) {
    const char *no_results = "No matching results found.\n";
    if (out_fp)
      fprintf(out_fp, "%s", no_results);
    else
      log_write(LOG_PLAIN, "%s", no_results);
  }

  /* Summary to log */
  log_write(LOG_STDOUT,
    "net-query: %s result(s) from %d shard(s)\n",
    format_count(total_count).c_str(), shards_searched);

  if (own_fp && out_fp) fclose(out_fp);
  return 0;
}
