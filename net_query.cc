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
#include "store_output.h"
#include "json_escape.h"
#include "third-party/nlohmann/json.hpp"
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
#include <sys/stat.h>
#include <cerrno>
#include <cmath>

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
 * Parsed CVE metadata, shared by filters, tags, and output for each row
 *
 * The cves column contains a JSON array like:
 *   [{"id":"CVE-2024-6387","cvss":8.1,"severity":"HIGH","desc":"..."}]
 * ----------------------------------------------------------------------- */

struct CveMetadata {
  nlohmann::json parsed;
  std::vector<std::string> ids;
  float max_cvss = -1.0f;
  float max_epss = -1.0f;
  bool kev = false;
  bool ransomware = false;
  std::string first_summary;
};

/* JSON numeric values only: strings, booleans, out-of-range values, and
 * non-finite numbers must not qualify a host for a score filter. */
static float cve_score(const nlohmann::json &entry, const char *key, double hi) {
  const auto value = entry.find(key);
  if (value == entry.end() || !value->is_number()) return -1.0f;
  const double score = value->get<double>();
  return std::isfinite(score) && score >= 0.0 && score <= hi
           ? static_cast<float>(score) : -1.0f;
}

static bool cve_flag(const nlohmann::json &entry, const char *key) {
  const auto value = entry.find(key);
  if (value == entry.end()) return false;
  if (value->is_boolean()) return value->get<bool>();
  return value->is_number() && value->get<double>() == 1.0;
}

static CveMetadata parse_cves(const std::string &raw) {
  CveMetadata result;
  if (raw.empty() || raw == "[]") return result;
  /* Serializing a value back out is recursive, so nesting far beyond any CVE
     list (a corrupt row) is treated as malformed rather than overflowing the
     stack; it is then emitted as an escaped string like other bad values. */
  bool too_deep = false;
  const nlohmann::json::parser_callback_t limit =
      [&](int depth, nlohmann::json::parse_event_t, nlohmann::json &) {
        if (depth > 64) too_deep = true;
        return !too_deep;
      };
  result.parsed = nlohmann::json::parse(kmap_json_repair_utf8(raw), limit, false);
  if (too_deep) result.parsed = nlohmann::json();
  if (!result.parsed.is_array()) return result;
  for (const auto &entry : result.parsed) {
    if (!entry.is_object()) continue;
    const auto id = entry.find("id");
    if (id == entry.end() || !id->is_string()) continue;
    const std::string &name = id->get_ref<const std::string &>();
    if (name.empty()) continue;
    result.ids.push_back(str_lower(name));
    const float cvss = cve_score(entry, "cvss", 10.0);
    result.max_cvss = (std::max)(result.max_cvss, cvss);
    result.max_epss = (std::max)(result.max_epss, cve_score(entry, "epss", 1.0));
    result.kev = result.kev || cve_flag(entry, "kev");
    result.ransomware = result.ransomware || cve_flag(entry, "ransomware");
    if (result.first_summary.empty()) {
      result.first_summary = name;
      if (cvss >= 0.0f)
        result.first_summary += " (CVSS:" + entry["cvss"].dump() + ")";
    }
  }
  return result;
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
    int64_t int_val;
  };
  std::vector<BindVal> binds;
};

/* LIKE pattern for a case-insensitive literal substring: the documented
   filters are substrings, so '%' and '_' in the argument must not act as
   wildcards ("Admin_Panel" matched "Admin Panel"). */
static std::string like_substring(const char *text) {
  std::string out = "%";
  for (char c : str_lower(text)) {
    if (c == '%' || c == '_' || c == '\\') out += '\\';
    out += c;
  }
  return out + "%";
}

static QueryFilter build_filter(int port, const char *service,
                                const char *cve, float min_cvss,
                                const char *web_title,
                                const char *web_server,
                                int64_t asn,
                                const char *country,
                                bool kev_only, float min_epss) {
  QueryFilter f;
  std::vector<std::string> conditions;

  if (port > 0) {
    conditions.push_back("port = ?");
    f.binds.push_back({QueryFilter::BINT, "", port});
  }

  if (service && service[0]) {
    conditions.push_back("LOWER(service) LIKE ? ESCAPE '\\'");
    f.binds.push_back({QueryFilter::BTEXT, like_substring(service), 0});
  }

  /* Only discard empty CVE columns here. Matching JSON text with LIKE loses
   * valid whitespace/escapes and can match a description instead of an ID. */
  if ((cve && cve[0]) || min_cvss > 0.0f || kev_only || min_epss > 0.0f) {
    conditions.push_back(
        "cves IS NOT NULL AND cves != '' AND cves != '[]'");
  }

  if (web_title && web_title[0]) {
    conditions.push_back("LOWER(web_title) LIKE ? ESCAPE '\\'");
    f.binds.push_back({QueryFilter::BTEXT, like_substring(web_title), 0});
  }

  if (web_server && web_server[0]) {
    conditions.push_back("LOWER(web_server) LIKE ? ESCAPE '\\'");
    f.binds.push_back({QueryFilter::BTEXT, like_substring(web_server), 0});
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
 * The cves column is emitted as a parsed array, or as an escaped string when
 * malformed. Filters and output share the same parsed metadata.
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
                                      const CveMetadata &cves,
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
  /* Preserve legacy malformed values as escaped strings. Valid arrays are
   * serialized from the same parse used by filters and derived tags. */
  if (!cves_json.empty() && cves_json != "[]") {
    if (!first) oss << ',';
    /* cves is the last emitted field, so `first` is intentionally not updated
       here (a trailing `first = false` would be a dead store). Keep this block
       last, or restore the assignment if another field is appended after it. */
    if (cves.parsed.is_array())
      // Re-serialize: an accepted leading BOM is legal at a document start,
      // but cannot be embedded verbatim in the middle of this document.
      oss << "\"cves\":" << cves.parsed.dump();
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
        sqlite3_bind_int64(stmt, idx, b.int_val);
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
                                 const CveMetadata &cves,
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
  if (!cves.first_summary.empty())
    oss << "  " << cves.first_summary;

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
                  int64_t asn,
                  const char *country,
                  const char *device_class,
                  const char *output_file,
                  const char *format,
                  bool count_only,
                  bool kev_only,
                  float min_epss,
                  const char *tag) {
  if (!data_dir) return 1;
  std::string path_error;
  if (!net_db_validate_path(net_shard_path(data_dir, 0), &path_error)) {
    log_write(LOG_STDERR, "net-query: ERROR: invalid data directory '%s': %s\n",
              data_dir, path_error.c_str());
    return 1;
  }
#ifdef WIN32
  struct _stat directory_info;
  bool directory_ok = _stat(data_dir, &directory_info) == 0 &&
                       (directory_info.st_mode & _S_IFDIR) != 0;
#else
  struct stat directory_info;
  bool directory_ok = stat(data_dir, &directory_info) == 0 &&
                       S_ISDIR(directory_info.st_mode);
#endif
  if (!directory_ok) {
    log_write(LOG_STDERR, "net-query: ERROR: cannot read data directory '%s'\n", data_dir);
    return 1;
  }

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
    const auto ascii_letter = [](unsigned char c) {
      return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    };
    if (strlen(country) != 2 || !ascii_letter(country[0]) || !ascii_letter(country[1])) {
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
  const std::string cve_filter = cve ? str_lower(cve) : "";
  const bool count_without_metadata = count_only && cve_filter.empty() &&
      !(min_cvss > 0.0f) && !(min_epss > 0.0f) && !kev_only && tag_filter.empty();

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
    std::string output_error;
    out_fp = open_store_output(output_file, data_dir, output_error);
    if (!out_fp) {
      log_write(LOG_STDERR,
        "net-query: ERROR: cannot open output file '%s': %s\n",
        output_file, output_error.c_str());
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
  bool failed = false;

  /* JSON array open. In count_only + JSON we skip the array entirely and
   * emit {"count":N} at the bottom. */
  auto emit_line = [&](const std::string &s) {
    if (out_fp) {
      if (fprintf(out_fp, "%s\n", s.c_str()) < 0) failed = true;
    }
    else
      log_write(LOG_PLAIN, "%s\n", s.c_str());
  };
  auto emit_raw = [&](const char *s) {
    if (out_fp) {
      if (fputs(s, out_fp) == EOF) failed = true;
    }
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
    if (!test) {
      if (errno != ENOENT) {
        log_write(diag_dest, "net-query: ERROR: cannot read %s: %s\n",
                  db_path.c_str(), strerror(errno));
        failed = true;
      }
      continue;
    }
    fclose(test);

    sqlite3 *db = net_db_open(db_path);
    if (!db) {
      log_write(diag_dest,
        "net-query: WARNING: cannot open %s -- skipping.\n",
        db_path.c_str());
      failed = true;
      continue;
    }
    shards_searched++;

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr)
        != SQLITE_OK) {
      log_write(diag_dest,
        "net-query: WARNING: query failed on %s: %s\n",
        db_path.c_str(), sqlite3_errmsg(db));
      failed = true;
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

    int step_result;
    while ((step_result = sqlite3_step(stmt)) == SQLITE_ROW) {
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

      /* SQL and CIDR predicates already ran. Plain counts only need the
       * optional device classifier, never CVE parsing, tags or row output. */
      if (count_without_metadata) {
        if (device_filter.empty() || classify_device(row_svc, row_port) == device_filter)
          total_count++;
        continue;
      }

      /* Parse once for CVE membership, bounded scores, tags and output. */
      const CveMetadata cves = parse_cves(row_cves);
      /* The CLI accepts a literal ID fragment. Match decoded ID fields only;
       * descriptions, JSON formatting and SQL wildcard syntax are irrelevant. */
      if (!cve_filter.empty() && std::none_of(cves.ids.begin(), cves.ids.end(),
          [&](const std::string &id) { return id.find(cve_filter) != std::string::npos; }))
        continue;
      if (min_cvss > 0.0f && cves.max_cvss < min_cvss) continue;
      if (kev_only && !cves.kev) continue;
      if (min_epss > 0.0f && cves.max_epss < min_epss) continue;

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
      /* The shared helper still supplies non-CVE tags. Supply CVE tags from
       * structured metadata so JSON whitespace never changes membership. */
      ti.cves_json = "[]";
      std::vector<std::string> tags = derive_host_tags(ti);
      if (!cves.ids.empty()) tags.push_back("vuln");
      if (cves.kev) tags.push_back("kev");
      if (cves.ransomware) tags.push_back("ransomware");
      std::sort(tags.begin(), tags.end());
      if (!tag_filter.empty() &&
          std::find(tags.begin(), tags.end(), tag_filter) == tags.end())
        continue;

      total_count++;

      if (!count_only) {
        std::string payload = emit_json
          ? format_result_json(row_ip, row_port, row_proto, row_svc, row_ver,
                               row_cves, cves, row_asn, row_as_name, row_country,
                               row_host, row_wtitle, row_wsrv, row_cpe, row_cloud,
                               dev_class, tags)
          : format_result(row_ip, row_port, row_proto, row_svc, row_ver, cves,
                          tags);
        shard_rows.push_back({ ip_to_u32(row_ip.c_str()), row_port, payload });
      }
    }

    if (step_result != SQLITE_DONE) {
      log_write(diag_dest, "net-query: ERROR: reading %s failed: %s\n",
                db_path.c_str(), sqlite3_errmsg(db));
      failed = true;
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

  if (own_fp && out_fp && fclose(out_fp) != 0) {
    log_write(diag_dest, "net-query: ERROR: output file could not be flushed\n");
    failed = true;
  }
  if (!out_fp && (fflush(stdout) != 0 || ferror(stdout))) {
    log_write(LOG_STDERR, "net-query: ERROR: stdout write failed\n");
    failed = true;
  }
  if (failed) log_write(diag_dest, "net-query: ERROR: results may be incomplete\n");
  return failed ? 1 : 0;
}
