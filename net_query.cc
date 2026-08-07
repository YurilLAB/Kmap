/*
 * net_query.cc -- Query engine for Kmap net-scan data.
 *
 * Searches across all (or targeted) shard databases using SQL WHERE
 * clauses built from the provided filters.  Supports filtering by port,
 * service, CVE ID, CVSS score, web title, web server header, IP range,
 * ASN, country code, and a derived device-class tag (web/ssh/router/iot/...).
 * Output is either human-readable text or a JSON array; both modes also
 * support count-only and writing to a file.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_query.h"
#include "net_db.h"
#include "json_escape.h"
#include "KmapOps.h"
#include "host_tags.h"
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
    /* Strict prefix parse. atoi() silently returns 0 for a non-numeric or
     * empty prefix ("10.0.0.0/abc", "10.0.0.0/"), which would set mask=0 and
     * make ip_in_cidr() match EVERY IP -- so the --nq-ip-range filter would
     * silently return the entire dataset instead of the requested range. Be
     * strict and leave r.valid=false so the caller reports a clean error. */
    const char *pp = slash + 1;
    if (*pp == '\0') return r;
    char *endp = nullptr;
    long pv = strtol(pp, &endp, 10);
    if (endp == pp || *endp != '\0') return r;
    if (pv < 0 || pv > 32) return r;
    prefix_len = static_cast<int>(pv);
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

/* Extract the maximum EPSS probability (0..1) from a cves JSON string.
 * EPSS values render as `"epss":0.9951`. Returns -1.0f if none present. */
static float max_epss_from_json(const std::string &cves_json) {
  float max_epss = -1.0f;
  size_t pos = 0;
  while (true) {
    pos = cves_json.find("\"epss\":", pos);
    if (pos == std::string::npos) break;
    pos += 7;
    while (pos < cves_json.size() && cves_json[pos] == ' ') pos++;
    size_t end = pos;
    while (end < cves_json.size() &&
           (isdigit(static_cast<unsigned char>(cves_json[end])) ||
            cves_json[end] == '.'))
      end++;
    if (end > pos) {
      float v = static_cast<float>(atof(cves_json.substr(pos, end - pos).c_str()));
      if (v > max_epss) max_epss = v;
    }
    pos = end;
  }
  return max_epss;
}

/* True if any CVE in the array is flagged as CISA-KEV (`"kev":1`). */
static bool json_has_kev(const std::string &cves_json) {
  return cves_json.find("\"kev\":1") != std::string::npos;
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
                                const char *web_server,
                                int asn,
                                const char *country,
                                bool kev_only, float min_epss) {
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
    /* Anchor the match to the full quoted id.  cves is a JSON array of
       [{"id":"CVE-...",...}] (no space after the colon), so binding the id
       wrapped in quotes makes the whole id match: "CVE-2024-1" no longer
       prefix-collides with "CVE-2024-100"/"CVE-2024-1234", and it matches the
       id field rather than CVE-description prose.  Still a substring LIKE (no
       cves index), but now correct. */
    conditions.push_back("cves LIKE ?");
    f.binds.push_back({QueryFilter::BTEXT,
                       "%\"" + std::string(cve) + "\"%", 0});
  }

  /* CVSS filtering is done in post-processing since the score is
   * embedded in the JSON cves column.  Pre-filter to rows with CVE data. */
  if (min_cvss > 0.0f) {
    conditions.push_back(
        "cves IS NOT NULL AND cves != '' AND cves != '[]'");
  }

  /* KEV / EPSS live in the same JSON cves column, so they too pre-filter to
     rows that carry CVE data and post-filter precisely below. */
  if (kev_only) {
    conditions.push_back("cves LIKE '%\"kev\":1%'");
  }
  if (min_epss > 0.0f) {
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

  if (asn > 0) {
    conditions.push_back("asn = ?");
    f.binds.push_back({QueryFilter::BINT, "", asn});
  }

  if (country && country[0]) {
    /* Country codes are stored as 2-letter uppercase. Compare uppercased
     * to be forgiving of "us" / "Us" / "US" on the command line. */
    std::string cc = country;
    std::transform(cc.begin(), cc.end(), cc.begin(),
                   [](unsigned char c){ return static_cast<char>(toupper(c)); });
    /* Compare the bare column (which is stored uppercase) against the
       uppercased argument rather than UPPER(country): wrapping the column in a
       function defeats idx_hosts_country and forces a full table scan (verified
       via EXPLAIN QUERY PLAN). With the raw column the index is used. */
    conditions.push_back("country = ?");
    f.binds.push_back({QueryFilter::BTEXT, cc, 0});
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

/* -----------------------------------------------------------------------
 * Device classifier
 *
 * Derives a coarse device-class tag from (service, port).  We avoid a
 * schema migration by classifying at query time.  Returns one of:
 *   "web", "ssh", "ftp", "telnet", "smtp", "mail", "dns", "db", "rdp",
 *   "vnc", "snmp", "smb", "router", "iot", "" (unclassified)
 *
 * Comparison against the user's --nq-device value is done case-insensitively
 * by str_lower-ing both sides at the call site.
 * ----------------------------------------------------------------------- */
static std::string classify_device(const std::string &service, int port) {
  std::string s = str_lower(service);

  /* Service-name hits win when present and unambiguous. */
  if (s.find("http") != std::string::npos) return "web";
  if (s == "ssh" || s.find("ssh") != std::string::npos) return "ssh";
  if (s == "telnet") return "telnet";
  if (s == "ftp" || s.rfind("ftp", 0) == 0) return "ftp";
  if (s.find("smtp") != std::string::npos) return "smtp";
  if (s.find("pop3") != std::string::npos ||
      s.find("imap") != std::string::npos) return "mail";
  if (s == "domain" || s == "dns") return "dns";
  if (s == "snmp") return "snmp";
  if (s == "microsoft-ds" || s == "netbios-ssn" || s == "smb") return "smb";
  if (s == "ms-wbt-server" || s == "rdp") return "rdp";
  if (s.rfind("vnc", 0) == 0) return "vnc";
  if (s == "mysql" || s == "postgresql" || s == "redis" ||
      s == "mongodb" || s == "ms-sql-s" || s == "memcached" ||
      s == "couchdb" || s.find("sql") != std::string::npos) return "db";
  if (s.find("rtsp") != std::string::npos ||
      s.find("mqtt") != std::string::npos ||
      s.find("coap") != std::string::npos) return "iot";
  if (s.find("routeros") != std::string::npos ||
      s.find("mikrotik") != std::string::npos) return "router";

  /* Port-only fallbacks for rows without an enriched service field. */
  switch (port) {
    case 80: case 443: case 8000: case 8080: case 8081: case 8082:
    case 8443: case 8888:                                return "web";
    case 22:                                             return "ssh";
    case 23:                                             return "telnet";
    case 21:                                             return "ftp";
    case 25: case 465: case 587: case 2525:              return "smtp";
    case 110: case 143: case 993: case 995:              return "mail";
    case 53:                                             return "dns";
    case 161: case 162:                                  return "snmp";
    case 139: case 445:                                  return "smb";
    case 3389:                                           return "rdp";
    case 3306: case 5432: case 6379: case 27017:
    case 1433: case 11211: case 5984:                    return "db";
    case 554: case 1883: case 5683: case 8554: case 8883: return "iot";
    case 8291:                                           return "router";
    default:
      if (port >= 5900 && port <= 5910) return "vnc";
      return "";
  }
}

/* -----------------------------------------------------------------------
 * JSON escaping + per-row JSON formatter
 *
 * The cves column is stored as a JSON array string; we emit it raw when it
 * looks well-formed (starts with '['), and as an escaped string otherwise.
 * ----------------------------------------------------------------------- */

/* Escape a string for a JSON value AND guarantee the result is valid UTF-8.
   Scan targets routinely return banners / web titles / versions that are not
   valid UTF-8 (raw Latin-1 bytes, or a multi-byte sequence the capture truncated
   mid-codepoint). RFC 8259 requires JSON text to be UTF-8, so any malformed or
   truncated sequence is replaced with U+FFFD; otherwise jq / Python json / the
   ingester reject the whole document. This mirrors the error_handler_t::replace
   that yuril_export.cc and output_json.cc already use via nlohmann. */
static std::string json_escape(const std::string &in) {
  return kmap_json_escape(in);   /* single source of truth: json_escape.h */
}

static void json_kv_str(std::ostringstream &oss, const char *key,
                        const std::string &val, bool &first) {
  if (val.empty()) return;
  if (!first) oss << ',';
  first = false;
  oss << '"' << key << "\":\"" << json_escape(val) << '"';
}

static void json_kv_int(std::ostringstream &oss, const char *key,
                        int64_t val, bool &first) {
  if (!first) oss << ',';
  first = false;
  oss << '"' << key << "\":" << val;
}

static std::string format_result_json(const std::string &ip, int port,
                                      const std::string &proto,
                                      const std::string &service,
                                      const std::string &version,
                                      const std::string &cves_json,
                                      int64_t asn, const std::string &as_name,
                                      const std::string &country,
                                      const std::string &hostname,
                                      const std::string &web_title,
                                      const std::string &web_server,
                                      const std::string &cpe,
                                      const std::string &cloud_provider,
                                      const std::string &device_class,
                                      const std::vector<std::string> &tags) {
  std::ostringstream oss;
  bool first = true;
  oss << '{';
  json_kv_str(oss, "ip",         ip,         first);
  json_kv_int(oss, "port",       port,       first);
  json_kv_str(oss, "proto",      proto,      first);
  json_kv_str(oss, "service",    service,    first);
  json_kv_str(oss, "version",    version,    first);
  if (asn > 0)             json_kv_int(oss, "asn",       asn,       first);
  json_kv_str(oss, "as_name",    as_name,    first);
  json_kv_str(oss, "country",    country,    first);
  json_kv_str(oss, "hostname",   hostname,   first);
  json_kv_str(oss, "web_title",  web_title,  first);
  json_kv_str(oss, "web_server", web_server, first);
  if (!cpe.empty()) json_kv_str(oss, "cpe", cpe, first);
  if (!cloud_provider.empty()) json_kv_str(oss, "cloud", cloud_provider, first);
  json_kv_str(oss, "device_class", device_class, first);
  if (!tags.empty()) {
    if (!first) oss << ',';
    first = false;
    oss << "\"tags\":[";
    for (size_t i = 0; i < tags.size(); i++) {
      if (i) oss << ',';
      oss << '"' << json_escape(tags[i]) << '"';
    }
    oss << ']';
  }
  /* cves is already JSON in the column.  Emit raw only if it looks like
   * a JSON array; otherwise fall back to an escaped string to keep the
   * output parseable. */
  if (!cves_json.empty() && cves_json != "[]") {
    if (!first) oss << ',';
    /* cves is the last emitted field, so `first` is intentionally not updated
       here (a trailing `first = false` would be a dead store). Keep this block
       last, or restore the assignment if another field is appended after it. */
    if (cves_json[0] == '[')
      /* Emitted verbatim as a nested array, but still run through a UTF-8
         repair so one CVE description with a truncated multi-byte sequence
         (or a column written by an older tool that predates the escaper's
         UTF-8 validation) cannot make the whole --nq-format json document
         unparseable. Structure is preserved -- only invalid high bytes become
         U+FFFD -- so a well-formed column is byte-identical to before. */
      oss << "\"cves\":" << kmap_json_repair_utf8(cves_json);
    else
      oss << "\"cves\":\"" << json_escape(cves_json) << '"';
  }
  oss << '}';
  return oss.str();
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
                                 const std::string &cves_json,
                                 const std::vector<std::string> &tags) {
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

  /* Tags, bracketed: [self-signed, cloud, kev] */
  if (!tags.empty()) {
    oss << "  [";
    for (size_t i = 0; i < tags.size(); i++) {
      if (i) oss << ", ";
      oss << tags[i];
    }
    oss << "]";
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
                  int asn,
                  const char *country,
                  const char *device_class,
                  const char *output_file,
                  const char *format,
                  bool count_only,
                  bool kev_only,
                  float min_epss,
                  const char *tag) {
  if (!data_dir) return 1;

  /* Pre-lowercase the tag filter for case-insensitive compare. */
  std::string tag_filter;
  if (tag && tag[0]) tag_filter = str_lower(tag);

  /* Validate port range if specified */
  if (port != -1 && (port < 1 || port > 65535)) {
    log_write(LOG_STDOUT,
      "net-query: ERROR: --nq-port %d is out of range (must be 1-65535)\n",
      port);
    return 1;
  }

  /* Validate format. NULL or empty means "text". */
  bool emit_json = false;
  if (format && format[0]) {
    if (strcmp(format, "json") == 0) {
      emit_json = true;
    } else if (strcmp(format, "text") != 0) {
      log_write(LOG_STDOUT,
        "net-query: ERROR: --nq-format must be one of: text, json\n");
      return 1;
    }
  }

  /* Validate country code is 2 letters if provided. */
  if (country && country[0]) {
    if (strlen(country) != 2) {
      log_write(LOG_STDOUT,
        "net-query: ERROR: --nq-country must be a 2-letter ISO code "
        "(e.g. US, GB, JP)\n");
      return 1;
    }
  }

  /* Pre-lowercase the device-class filter for case-insensitive compare. */
  std::string device_filter;
  if (device_class && device_class[0]) {
    device_filter = str_lower(device_class);
  }

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
                                    web_title, web_server,
                                    asn, country, kev_only, min_epss);

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

  /* Build the SQL query. We always SELECT the enrichment columns so that
   * JSON output is complete; text mode just ignores the extra fields. */
  std::string sql =
    "SELECT ip, port, proto, service, version, cves, "
    "       asn, as_name, country, hostname, web_title, web_server, cpe, "
    "       cloud_provider, tls_self_signed "
    "FROM hosts WHERE " + filter.where_clause;
  /* Deliberately no SQL "ORDER BY ip": hosts.ip is dotted-quad TEXT, so it would
     sort lexicographically ("10.0.0.1" < "2.2.2.2" < "9.9.9.9"). Each shard's
     surviving rows are collected and sorted by numeric ip_to_u32 below, the same
     fix net_report.cc already applies. */

  int64_t total_count = 0;
  int shards_searched = 0;

  /* JSON array open. In count_only + JSON we skip the array entirely and
   * emit {"count":N} at the bottom. */
  auto emit_line = [&](const std::string &s) {
    if (out_fp)
      fprintf(out_fp, "%s\n", s.c_str());
    else
      log_write(LOG_PLAIN, "%s\n", s.c_str());
  };
  auto emit_raw = [&](const char *s) {
    if (out_fp)
      fputs(s, out_fp);
    else
      log_write(LOG_PLAIN, "%s", s);
  };

  /* When the JSON document is on stdout (json format, no --nq-output), every
     diagnostic must avoid stdout or it corrupts the document.  Route warnings
     and the summary to stderr in that case; otherwise stdout is fine. */
  const bool json_on_stdout = emit_json && !out_fp;
  const int diag_dest = json_on_stdout ? LOG_STDERR : LOG_STDOUT;

  if (emit_json && !count_only) emit_raw("[");
  bool json_first = true;

  for (int shard_idx : shard_indices) {
    std::string db_path = net_shard_path(data_dir, shard_idx);

    /* Check if shard file exists before trying to open */
    FILE *test = fopen(db_path.c_str(), "r");
    if (!test) continue;
    fclose(test);

    sqlite3 *db = net_db_open(db_path);
    if (!db) {
      log_write(diag_dest,
        "net-query: WARNING: cannot open %s -- skipping.\n",
        db_path.c_str());
      continue;
    }
    shards_searched++;

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr)
        != SQLITE_OK) {
      log_write(diag_dest,
        "net-query: WARNING: query failed on %s: %s\n",
        db_path.c_str(), sqlite3_errmsg(db));
      net_db_close(db);
      continue;
    }

    bind_filter(stmt, filter);

    /* Buffer this shard's surviving rows, then emit in NUMERIC ip order (the DB
       cannot, since ip is TEXT). Per-shard bound, same as net_report.cc;
       count_only never buffers. Shards are walked in ascending index order and
       the index is the top 5 IP bits, so cross-shard order is already numeric --
       only within-shard order needed fixing. */
    struct EmitRow { uint32_t ipnum; int port; std::string payload; };
    std::vector<EmitRow> shard_rows;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      auto col_str = [&](int c) -> std::string {
        const unsigned char *p = sqlite3_column_text(stmt, c);
        return p ? reinterpret_cast<const char *>(p) : "";
      };

      std::string row_ip      = col_str(0);
      int         row_port    = sqlite3_column_int(stmt, 1);
      std::string row_proto   = col_str(2);
      std::string row_svc     = col_str(3);
      std::string row_ver     = col_str(4);
      std::string row_cves    = col_str(5);
      /* asn is stored as int64 (net_db.cc binds sqlite3_bind_int64 and the
         sibling reader net_db_get_host uses sqlite3_column_int64) so 4-byte
         ASNs in the top half of the 32-bit space (>= 2^31) round-trip intact.
         sqlite3_column_int would truncate those to a negative int32, which the
         `asn > 0` emit guard then drops from the JSON output entirely. */
      int64_t     row_asn     = sqlite3_column_int64(stmt, 6);
      std::string row_as_name = col_str(7);
      std::string row_country = col_str(8);
      std::string row_host    = col_str(9);
      std::string row_wtitle  = col_str(10);
      std::string row_wsrv    = col_str(11);
      std::string row_cpe     = col_str(12);
      std::string row_cloud   = col_str(13);
      int row_tls_self_signed = (sqlite3_column_type(stmt, 14) == SQLITE_NULL)
                                  ? -1 : sqlite3_column_int(stmt, 14);

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

      /* Post-process: CISA-KEV and EPSS filtering (both embedded in cves). */
      if (kev_only && !json_has_kev(row_cves)) continue;
      if (min_epss > 0.0f) {
        if (max_epss_from_json(row_cves) < min_epss) continue;
      }

      /* Post-process: device-class filtering (no schema column, classify
       * on the fly from service+port). */
      std::string dev_class = classify_device(row_svc, row_port);
      if (!device_filter.empty()) {
        if (dev_class != device_filter) continue;
      }

      /* Post-process: Shodan-style tags, derived from this row's already-
         collected columns (see host_tags.cc). --nq-tag filters on membership. */
      HostTagInput ti;
      ti.service = row_svc;
      ti.port = row_port;
      ti.version = row_ver;
      ti.cpe = row_cpe;
      ti.tls_self_signed = row_tls_self_signed;
      ti.cloud_provider = row_cloud;
      ti.cves_json = row_cves;
      std::vector<std::string> tags = derive_host_tags(ti);
      if (!tag_filter.empty() &&
          std::find(tags.begin(), tags.end(), tag_filter) == tags.end())
        continue;

      total_count++;

      if (!count_only) {
        std::string payload = emit_json
          ? format_result_json(row_ip, row_port, row_proto, row_svc, row_ver,
                               row_cves, row_asn, row_as_name, row_country,
                               row_host, row_wtitle, row_wsrv, row_cpe, row_cloud,
                               dev_class, tags)
          : format_result(row_ip, row_port, row_proto, row_svc, row_ver, row_cves,
                          tags);
        shard_rows.push_back({ ip_to_u32(row_ip.c_str()), row_port, payload });
      }
    }

    sqlite3_finalize(stmt);
    net_db_close(db);

    if (!count_only && !shard_rows.empty()) {
      std::sort(shard_rows.begin(), shard_rows.end(),
                [](const EmitRow &a, const EmitRow &b) {
                  return a.ipnum != b.ipnum ? a.ipnum < b.ipnum : a.port < b.port;
                });
      for (const auto &r : shard_rows) {
        if (emit_json) {
          if (!json_first) emit_raw(",");
          json_first = false;
          emit_raw(r.payload.c_str());
        } else {
          emit_line(r.payload);
        }
      }
    }
  }

  /* Output final results */
  if (count_only) {
    if (emit_json) {
      char buf[64];
      snprintf(buf, sizeof(buf), "{\"count\":%lld}",
               static_cast<long long>(total_count));
      emit_line(buf);
    } else {
      emit_line(format_count(total_count));
    }
  } else if (emit_json) {
    emit_raw("]\n");
  } else if (total_count == 0) {
    emit_raw("No matching results found.\n");
  }

  /* Human-readable summary. When the JSON document itself is going to stdout
     (--nq-format json with no --nq-output), this diagnostic line MUST go to
     stderr or it is appended after the closing ']' and corrupts the document
     for any consumer that pipes it into a JSON parser. LOG_STDOUT is stdout
     (not stderr, despite a prior comment here that claimed otherwise), so the
     stdout-JSON case is routed to LOG_STDERR. In every other case -- text
     output, or JSON written to a file via out_fp -- stdout is not carrying the
     data and the summary belongs there as before. */
  log_write(diag_dest,
    "net-query: %s result(s) from %d shard(s)\n",
    format_count(total_count).c_str(), shards_searched);

  if (own_fp && out_fp) fclose(out_fp);
  return 0;
}
