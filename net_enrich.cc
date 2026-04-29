/*
 * net_enrich.cc -- Enrichment pipeline for Kmap net-scan.
 *
 * Processes shard databases one at a time.  For each shard, fetches
 * unenriched IPs in batches, connects to each port for banner grabbing
 * and service pattern matching, runs CVE lookups against kmap-cve.db,
 * and performs lightweight HTTP recon on web ports.  Results are written
 * back via net_db_update_enrichment().
 *
 * Uses simplified probe logic (not the full service_scan/Target pipeline)
 * since we work directly with IP strings and shard database rows.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_enrich.h"
#include "net_db.h"
#include "asn_lookup.h"
#include "KmapOps.h"
#include "kmap.h"
#include "output.h"
#include "os_profile.h"

#include "sqlite/sqlite3.h"

#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <sstream>

#ifndef WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

extern KmapOps o;

/* -----------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------- */

#define ENRICH_CONNECT_TIMEOUT  5000  /* ms */
#define ENRICH_READ_TIMEOUT     5000  /* ms */
#define ENRICH_BANNER_MAX       1024  /* bytes */

/* -----------------------------------------------------------------------
 * Low-level TCP helpers — same pattern as default_creds.cc
 * ----------------------------------------------------------------------- */

/* Use intptr_t for socket handles to avoid SOCKET-to-int truncation
   on 64-bit Windows (SOCKET is UINT_PTR = 64 bits on Win64). */
typedef intptr_t kmap_fd_t;
#define KMAP_INVALID_FD ((kmap_fd_t)-1)

static kmap_fd_t enrich_tcp_connect(const char *ip, uint16_t port, int timeout_ms) {
  struct sockaddr_storage ss{};
  int af;
  socklen_t slen;

  struct sockaddr_in  *sa4 = reinterpret_cast<struct sockaddr_in  *>(&ss);
  struct sockaddr_in6 *sa6 = reinterpret_cast<struct sockaddr_in6 *>(&ss);

  if (inet_pton(AF_INET, ip, &sa4->sin_addr) == 1) {
    af = AF_INET;
    sa4->sin_family = AF_INET;
    sa4->sin_port   = htons(port);
    slen = sizeof(struct sockaddr_in);
  } else if (inet_pton(AF_INET6, ip, &sa6->sin6_addr) == 1) {
    af = AF_INET6;
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port   = htons(port);
    slen = sizeof(struct sockaddr_in6);
  } else {
    return KMAP_INVALID_FD;
  }

#ifdef WIN32
  SOCKET fd = socket(af, SOCK_STREAM, 0);
  if (fd == INVALID_SOCKET) return KMAP_INVALID_FD;
  u_long nb = 1;
  ioctlsocket(fd, FIONBIO, &nb);
#else
  int fd = socket(af, SOCK_STREAM, 0);
  if (fd < 0) return KMAP_INVALID_FD;
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif

  /* OS spoofing profile (--spoof-os). No-op when not set. */
  os_profile_apply_socket(static_cast<intptr_t>(fd), af,
                          os_profile_get(o.spoof_os));

  connect(fd, reinterpret_cast<struct sockaddr *>(&ss), slen);

  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(fd, &wset);
  struct timeval tv;
  tv.tv_sec  = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

  if (select(static_cast<int>(fd) + 1, nullptr, &wset, nullptr, &tv) <= 0) {
#ifdef WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return KMAP_INVALID_FD;
  }

  int sockerr = 0;
  socklen_t errlen = sizeof(sockerr);
  getsockopt(fd, SOL_SOCKET, SO_ERROR,
             reinterpret_cast<char *>(&sockerr), &errlen);
  if (sockerr != 0) {
#ifdef WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return KMAP_INVALID_FD;
  }

#ifdef WIN32
  nb = 0;
  ioctlsocket(fd, FIONBIO, &nb);
#else
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
#endif
  return static_cast<kmap_fd_t>(fd);
}

static void enrich_close_fd(kmap_fd_t fd) {
#ifdef WIN32
  closesocket(static_cast<SOCKET>(fd));
#else
  close(static_cast<int>(fd));
#endif
}

static bool enrich_fd_send(kmap_fd_t fd, const char *buf, size_t len) {
  size_t sent = 0;
  while (sent < len) {
#ifdef WIN32
    int n = send(static_cast<SOCKET>(fd), buf + sent, static_cast<int>(len - sent), 0);
#else
    int n = send(static_cast<int>(fd), buf + sent, static_cast<int>(len - sent), 0);
#endif
    if (n <= 0) return false;
    sent += static_cast<size_t>(n);
  }
  return true;
}

static int enrich_fd_recv(kmap_fd_t fd, char *buf, size_t len, int timeout_ms) {
  fd_set rset;
  FD_ZERO(&rset);
#ifdef WIN32
  FD_SET(static_cast<SOCKET>(fd), &rset);
#else
  FD_SET(static_cast<int>(fd), &rset);
#endif
  struct timeval tv;
  tv.tv_sec  = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  if (select(static_cast<int>(fd) + 1, &rset, nullptr, nullptr, &tv) <= 0)
    return -1;
#ifdef WIN32
  return static_cast<int>(recv(static_cast<SOCKET>(fd), buf, static_cast<int>(len), 0));
#else
  return static_cast<int>(recv(static_cast<int>(fd), buf, static_cast<int>(len), 0));
#endif
}

/* -----------------------------------------------------------------------
 * String helpers
 * ----------------------------------------------------------------------- */

static std::string str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}

/* Numeric version comparison — returns -1/0/1 for a<b, a==b, a>b.
   Parses "2.4.49p1" → {2, 4, 49} and compares component-by-component. */
static int ver_cmp_enrich(const std::string &a, const std::string &b) {
  auto parse = [](const std::string &s) -> std::vector<int> {
    std::vector<int> parts;
    std::istringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, '.')) {
      std::string digits;
      for (char c : tok) {
        if (isdigit(static_cast<unsigned char>(c))) digits += c;
        else break;
      }
      if (!digits.empty()) {
        try { parts.push_back(std::stoi(digits)); }
        catch (...) {}
      }
    }
    return parts;
  };
  auto va = parse(a), vb = parse(b);
  size_t n = std::max(va.size(), vb.size());
  for (size_t i = 0; i < n; i++) {
    int ai = (i < va.size()) ? va[i] : 0;
    int bi = (i < vb.size()) ? vb[i] : 0;
    if (ai < bi) return -1;
    if (ai > bi) return  1;
  }
  return 0;
}

/* Escape a string for JSON embedding (minimal: backslash and double-quote) */
static std::string json_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    if (c == '"') out += "\\\"";
    else if (c == '\\') out += "\\\\";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else if (c == '\t') out += "\\t";
    else out += c;
  }
  return out;
}

/* -----------------------------------------------------------------------
 * Service banner grabbing + pattern matching
 *
 * Connects to each port, reads whatever the server sends (or sends a
 * minimal probe and reads the response), then matches against known
 * banner patterns to identify the service name and version.
 * ----------------------------------------------------------------------- */

struct BannerResult {
  std::string service;       /* e.g. "ssh", "http", "ftp", "smtp", "mysql" */
  std::string version;       /* e.g. "OpenSSH 8.2p1", "nginx 1.18.0" */
  std::string http_response; /* raw HTTP response if banner grab did an HTTP probe */
};

/* Try to grab a banner by just reading what the server sends after connect */
static BannerResult grab_banner(const char *ip, int port, int timeout_ms) {
  BannerResult result;

  kmap_fd_t fd = enrich_tcp_connect(ip, static_cast<uint16_t>(port), timeout_ms);
  if (fd == KMAP_INVALID_FD)
    return result;

  char buf[ENRICH_BANNER_MAX]{};
  int n = enrich_fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);

  /* If no immediate banner, try sending a minimal HTTP request to elicit
     a response (many HTTP servers wait for the client to speak first).
     Use the os_profile-built request so the banner-grab leg also carries
     the spoofed User-Agent. ip is passed as the Host so the request looks
     plausible end-to-end. */
  if (n <= 0) {
    std::string http_probe =
        os_profile_http_request("/", ip, os_profile_get(o.spoof_os));
    if (enrich_fd_send(fd, http_probe.c_str(), http_probe.size())) {
      n = enrich_fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);
    }
  }

  enrich_close_fd(fd);

  if (n <= 0)
    return result;

  buf[n] = '\0';
  std::string banner(buf, static_cast<size_t>(n));
  std::string banner_lower = str_lower(banner);

  /* Extract first line for version parsing */
  std::string first_line = banner;
  size_t nl = first_line.find('\n');
  if (nl != std::string::npos) first_line = first_line.substr(0, nl);
  /* Strip trailing CR */
  while (!first_line.empty() &&
         (first_line.back() == '\r' || first_line.back() == '\n'))
    first_line.pop_back();

  /* Check for HTTP response */
  if (banner.size() >= 8 && banner.substr(0, 4) == "HTTP") {
    result.service = "http";
    result.http_response = banner; /* carry forward to avoid re-connecting */

    /* Parse Server header for version */
    size_t spos = banner_lower.find("\nserver:");
    if (spos != std::string::npos) {
      spos += 8; /* skip "\nserver:" */
      while (spos < banner.size() && banner[spos] == ' ') spos++;
      size_t epos = banner.find('\r', spos);
      if (epos == std::string::npos) epos = banner.find('\n', spos);
      if (epos == std::string::npos) epos = banner.size();
      result.version = banner.substr(spos, epos - spos);
    }

    /* Detect HTTPS ports by common port numbers (enrichment connects
       plain TCP — we cannot do TLS here without OpenSSL overhead) */
    if (port == 443 || port == 8443 || port == 4443)
      result.service = "https";

    return result;
  }

  /* Match against known banner patterns */
  if (banner.size() >= 4 && banner.substr(0, 4) == "SSH-") {
    result.service = "ssh";
    /* "SSH-2.0-OpenSSH_8.2p1" → version = "OpenSSH 8.2p1" */
    size_t dash3 = banner.find('-', 4);
    if (dash3 != std::string::npos && dash3 + 1 < first_line.size()) {
      result.version = first_line.substr(dash3 + 1);
      /* Replace underscores with spaces for readability */
      std::replace(result.version.begin(), result.version.end(), '_', ' ');
    }
    return result;
  }

  if (banner.size() >= 4 &&
      (banner.substr(0, 4) == "220 " || banner.substr(0, 4) == "220-")) {
    /* Could be FTP or SMTP.  Check for FTP-specific keywords. */
    if (banner_lower.find("ftp") != std::string::npos) {
      result.service = "ftp";
    } else if (banner_lower.find("smtp") != std::string::npos ||
               banner_lower.find("mail") != std::string::npos ||
               banner_lower.find("esmtp") != std::string::npos) {
      result.service = "smtp";
    } else {
      /* Ambiguous 220 — guess based on port */
      if (port == 21) result.service = "ftp";
      else if (port == 25 || port == 587 || port == 465) result.service = "smtp";
      else result.service = "ftp";  /* default */
    }
    result.version = first_line.substr(4);
    return result;
  }

  if (banner.size() >= 4 && banner.substr(0, 4) == "* OK") {
    result.service = "imap";
    result.version = first_line.size() > 5 ? first_line.substr(5) : "";
    return result;
  }

  if (banner.size() >= 3 && banner.substr(0, 3) == "+OK") {
    result.service = "pop3";
    result.version = first_line.size() > 4 ? first_line.substr(4) : "";
    return result;
  }

  /* MySQL greeting: starts with a packet length + protocol version 0x0a */
  if (n >= 5 && static_cast<unsigned char>(buf[4]) == 0x0a) {
    result.service = "mysql";
    /* Version string follows after byte 5 until null terminator */
    const char *verp = buf + 5;
    size_t vlen = strnlen(verp,
                          static_cast<size_t>(n) > 5 ? static_cast<size_t>(n) - 5 : 0);
    if (vlen > 0) result.version = std::string(verp, vlen);
    return result;
  }

  /* Redis: responds with -ERR, +PONG, or $-1 etc. */
  if (banner_lower.find("-err") == 0 || banner_lower.find("+pong") == 0 ||
      banner_lower.find("$") == 0) {
    result.service = "redis";
    return result;
  }

  /* MongoDB: binary wire protocol — check for valid OP_REPLY header */
  if (n >= 16 && static_cast<unsigned char>(buf[12]) == 0x01) {
    result.service = "mongodb";
    return result;
  }

  /* PostgreSQL: 'R' authentication response */
  if (n >= 9 && buf[0] == 'R') {
    result.service = "postgresql";
    return result;
  }

  /* Fallback: unknown service, store raw banner snippet as version */
  if (!first_line.empty()) {
    result.service = "unknown";
    if (first_line.size() > 64)
      result.version = first_line.substr(0, 64);
    else
      result.version = first_line;
  }

  return result;
}

/* -----------------------------------------------------------------------
 * CVE lookup against kmap-cve.db
 *
 * Simplified version of cve_map.cc's query_cves() — works with plain
 * strings instead of Target objects.
 * ----------------------------------------------------------------------- */

struct EnrichCve {
  std::string id;
  float       cvss;
  std::string severity;
  std::string description;
};

/* Normalize a service/version pair to a product name for DB lookup.
 * Returns the DB product name or empty string if unmappable. */
static std::string normalize_product(const std::string &service,
                                     const std::string &version) {
  std::string svc  = str_lower(service);
  std::string ver  = str_lower(version);

  if (ver.find("openssh") != std::string::npos || svc == "ssh")
    return "openssh";
  if (ver.find("apache") != std::string::npos &&
      (ver.find("http") != std::string::npos || svc == "http"))
    return "http_server";
  if (ver.find("nginx") != std::string::npos) return "nginx";
  if (ver.find("lighttpd") != std::string::npos) return "lighttpd";
  if (ver.find("iis") != std::string::npos) return "iis";
  if (ver.find("tomcat") != std::string::npos) return "tomcat";
  if (ver.find("mysql") != std::string::npos || svc == "mysql")
    return "mysql";
  if (ver.find("mariadb") != std::string::npos) return "mariadb";
  if (ver.find("postgresql") != std::string::npos || svc == "postgresql")
    return "postgresql";
  if (ver.find("redis") != std::string::npos || svc == "redis")
    return "redis";
  if (ver.find("mongodb") != std::string::npos || svc == "mongodb")
    return "mongodb";
  if (ver.find("vsftpd") != std::string::npos) return "vsftpd";
  if (ver.find("proftpd") != std::string::npos) return "proftpd";
  if (ver.find("samba") != std::string::npos) return "samba";
  if (ver.find("elasticsearch") != std::string::npos) return "elasticsearch";
  if (ver.find("jenkins") != std::string::npos) return "jenkins";
  if (ver.find("php") != std::string::npos) return "php";
  if (ver.find("wordpress") != std::string::npos) return "wordpress";

  return "";
}

/* Extract a dotted version number from a string.
 * "OpenSSH 8.2p1" → "8.2", "nginx/1.18.0" → "1.18.0" */
static std::string extract_version_number(const std::string &s) {
  size_t i = 0;
  while (i < s.size()) {
    if (isdigit(static_cast<unsigned char>(s[i]))) {
      size_t start = i;
      while (i < s.size() &&
             (isdigit(static_cast<unsigned char>(s[i])) ||
              s[i] == '.' || s[i] == 'p'))
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

static std::vector<EnrichCve> lookup_cves(sqlite3 *cve_db,
                                          const std::string &service,
                                          const std::string &version) {
  std::vector<EnrichCve> results;
  if (!cve_db) return results;

  std::string product = normalize_product(service, version);
  if (product.empty()) return results;

  const char *sql =
    "SELECT cve_id, cvss_score, severity, description, "
    "version_min, version_max "
    "FROM cves WHERE product = ? AND cvss_score >= 0.0 "
    "ORDER BY cvss_score DESC LIMIT 15";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(cve_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return results;

  sqlite3_bind_text(stmt, 1, product.c_str(), -1, SQLITE_TRANSIENT);

  std::string det_ver = extract_version_number(version);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    auto col_str = [&](int c) -> std::string {
      const unsigned char *p = sqlite3_column_text(stmt, c);
      return p ? reinterpret_cast<const char *>(p) : "";
    };

    std::string vmin = col_str(4);
    std::string vmax = col_str(5);

    /* Version range filtering — uses numeric version comparison,
       same algorithm as cve_map.cc's ver_cmp(). */
    if (!det_ver.empty() && (!vmin.empty() || !vmax.empty())) {
      if (!vmin.empty() && ver_cmp_enrich(det_ver, vmin) < 0) continue;
      if (!vmax.empty() && ver_cmp_enrich(det_ver, vmax) > 0) continue;
    }

    EnrichCve e;
    e.id          = col_str(0);
    e.cvss        = static_cast<float>(sqlite3_column_double(stmt, 1));
    e.severity    = col_str(2);
    e.description = col_str(3);
    results.push_back(std::move(e));
  }

  sqlite3_finalize(stmt);
  return results;
}

/* Build a JSON array string from a list of CVE entries.
 * Format: [{"id":"CVE-...","cvss":8.1,"severity":"HIGH","desc":"..."},...] */
static std::string cves_to_json(const std::vector<EnrichCve> &cves) {
  if (cves.empty()) return "";

  std::ostringstream oss;
  oss << "[";
  for (size_t i = 0; i < cves.size(); i++) {
    if (i > 0) oss << ",";
    char cvss_buf[16];
    snprintf(cvss_buf, sizeof(cvss_buf), "%.1f", cves[i].cvss);

    std::string desc = cves[i].description;
    if (desc.size() > 200) desc = desc.substr(0, 197) + "...";

    oss << "{\"id\":\"" << json_escape(cves[i].id)
        << "\",\"cvss\":" << cvss_buf
        << ",\"severity\":\"" << json_escape(cves[i].severity)
        << "\",\"desc\":\"" << json_escape(desc) << "\"}";
  }
  oss << "]";
  return oss.str();
}

/* -----------------------------------------------------------------------
 * Lightweight HTTP recon
 *
 * For HTTP ports, performs a GET / to extract title, server header, and
 * collects response headers as JSON.  No path probing (that's too slow
 * for internet-scale enrichment).
 * ----------------------------------------------------------------------- */

struct WebResult {
  std::string title;
  std::string server;
  std::string headers_json;  /* JSON object of selected headers */
  std::string paths_json;    /* JSON array of probed paths (just /) */
};

static std::string extract_header_val(const std::string &resp,
                                      const char *name) {
  std::string lower_resp = str_lower(resp);
  std::string lower_name = str_lower(std::string(name));
  /* Anchor to start of header line: require '\n' before the header name so a
   * search for "Server" does not match "X-Server:" or "Last-Modified-Server:". */
  std::string needle = "\n" + lower_name + ":";
  size_t pos = lower_resp.find(needle);
  if (pos == std::string::npos) return "";
  size_t start = pos + needle.size();
  while (start < resp.size() && resp[start] == ' ') start++;
  size_t end = resp.find('\r', start);
  if (end == std::string::npos) end = resp.find('\n', start);
  if (end == std::string::npos) end = resp.size();
  return resp.substr(start, end - start);
}

static std::string extract_html_title(const std::string &body) {
  std::string lower = str_lower(body);
  size_t ts = lower.find("<title>");
  if (ts == std::string::npos) return "";
  ts += 7;
  size_t te = lower.find("</title>", ts);
  if (te == std::string::npos) te = std::min(ts + 200, body.size());
  std::string t = body.substr(ts, te - ts);
  size_t a = t.find_first_not_of(" \t\r\n");
  size_t b = t.find_last_not_of(" \t\r\n");
  return (a == std::string::npos) ? "" : t.substr(a, b - a + 1);
}

static int extract_status(const std::string &resp) {
  if (resp.size() < 12) return 0;
  if (resp.substr(0, 4) != "HTTP") return 0;
  size_t sp = resp.find(' ');
  if (sp == std::string::npos || sp + 3 >= resp.size()) return 0;
  char c1 = resp[sp + 1], c2 = resp[sp + 2], c3 = resp[sp + 3];
  if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9' || c3 < '0' || c3 > '9')
    return 0;
  return (c1 - '0') * 100 + (c2 - '0') * 10 + (c3 - '0');
}

/* probe_http — if cached_response is non-empty, reuse it instead of
   making a new TCP connection (avoids the double-connect from grab_banner). */
static WebResult probe_http(const char *ip, int port, int timeout_ms,
                            const std::string &cached_response = "") {
  WebResult wr;

  std::string response;
  if (!cached_response.empty()) {
    response = cached_response;
  } else {
    kmap_fd_t fd = enrich_tcp_connect(ip, static_cast<uint16_t>(port), timeout_ms);
    if (fd == KMAP_INVALID_FD) return wr;

    /* Profile-driven request (User-Agent + Accept-* headers) — preserves
       the existing Host-with-port form by passing ip as the host and
       letting os_profile_http_request handle IPv6 bracketing. The :port
       suffix is not strictly required (HTTP/1.0 ignores port mismatch)
       and dropping it gives a more browser-faithful header. */
    std::string req =
        os_profile_http_request("/", ip, os_profile_get(o.spoof_os));

    if (!enrich_fd_send(fd, req.c_str(), req.size())) {
      enrich_close_fd(fd);
      return wr;
    }

    /* Read response (up to 64K) */
    response.reserve(4096);
    char chunk[4096];
    while (response.size() < 65536) {
      fd_set rset;
      FD_ZERO(&rset);
#ifdef WIN32
      FD_SET(static_cast<SOCKET>(fd), &rset);
#else
      FD_SET(static_cast<int>(fd), &rset);
#endif
      struct timeval tv;
      tv.tv_sec  = timeout_ms / 1000;
      tv.tv_usec = (timeout_ms % 1000) * 1000;
      if (select(static_cast<int>(fd) + 1, &rset, nullptr, nullptr, &tv) <= 0)
        break;
#ifdef WIN32
      int n = static_cast<int>(recv(static_cast<SOCKET>(fd), chunk, sizeof(chunk), 0));
#else
      int n = static_cast<int>(recv(static_cast<int>(fd), chunk, sizeof(chunk), 0));
#endif
      if (n <= 0) break;
      response.append(chunk, static_cast<size_t>(n));
    }

    enrich_close_fd(fd);
  }

  if (response.empty()) return wr;

  /* Parse response */
  size_t body_start = response.find("\r\n\r\n");
  std::string body = (body_start != std::string::npos)
                     ? response.substr(body_start + 4) : "";

  wr.title  = extract_html_title(body);
  wr.server = extract_header_val(response, "Server");

  /* Build headers JSON object with selected interesting headers */
  std::ostringstream hdr_json;
  hdr_json << "{";
  bool first = true;
  const char *interesting[] = {
    "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
    "X-Frame-Options", "Content-Type", "Set-Cookie", nullptr
  };
  for (const char **hp = interesting; *hp; hp++) {
    std::string val = extract_header_val(response, *hp);
    if (!val.empty()) {
      if (!first) hdr_json << ",";
      hdr_json << "\"" << json_escape(*hp) << "\":\""
               << json_escape(val) << "\"";
      first = false;
    }
  }
  hdr_json << "}";
  if (!first) wr.headers_json = hdr_json.str();

  /* Build paths JSON — just the root path result */
  int status = extract_status(response);
  if (status > 0) {
    std::ostringstream paths_json;
    paths_json << "[{\"path\":\"/\",\"status\":" << status;
    if (!wr.title.empty())
      paths_json << ",\"title\":\"" << json_escape(wr.title) << "\"";
    paths_json << "}]";
    wr.paths_json = paths_json.str();
  }

  return wr;
}

/* Check whether a port is likely HTTP/HTTPS */
static bool is_http_port(int port, const std::string &service) {
  std::string svc = str_lower(service);
  if (svc.find("http") != std::string::npos) return true;
  if (port == 80 || port == 443 || port == 8080 || port == 8443 ||
      port == 8000 || port == 8888 || port == 3000 || port == 4443 ||
      port == 9090 || port == 9443)
    return true;
  return false;
}

/* -----------------------------------------------------------------------
 * enrich_single_host — public API
 * ----------------------------------------------------------------------- */

int enrich_single_host(const char *ip,
                       const std::vector<int> &ports,
                       const std::vector<std::string> &protos,
                       const char *cve_db_path,
                       int timeout_ms,
                       std::vector<std::string> &out_services,
                       std::vector<std::string> &out_versions,
                       std::vector<std::string> &out_cves,
                       std::vector<std::string> &out_web_titles,
                       std::vector<std::string> &out_web_servers,
                       std::vector<std::string> &out_web_headers,
                       std::vector<std::string> &out_web_paths) {
  size_t nports = ports.size();
  out_services.resize(nports);
  out_versions.resize(nports);
  out_cves.resize(nports);
  out_web_titles.resize(nports);
  out_web_servers.resize(nports);
  out_web_headers.resize(nports);
  out_web_paths.resize(nports);

  /* Open CVE database (read-only) if path provided */
  sqlite3 *cve_db = nullptr;
  if (cve_db_path && cve_db_path[0]) {
    if (sqlite3_open_v2(cve_db_path, &cve_db,
                        SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
      if (cve_db) { sqlite3_close(cve_db); cve_db = nullptr; }
      /* Non-fatal: continue without CVE lookups */
    }
  }

  for (size_t i = 0; i < nports; i++) {
    /* Step 1: Banner grab / service detection */
    BannerResult br = grab_banner(ip, ports[i], timeout_ms);
    out_services[i] = br.service;
    out_versions[i] = br.version;

    /* Step 2: CVE lookup */
    if (cve_db && !br.service.empty()) {
      std::vector<EnrichCve> cves = lookup_cves(cve_db, br.service, br.version);
      out_cves[i] = cves_to_json(cves);
    }

    /* Step 3: HTTP recon on web ports — reuse response from banner grab
       if it already did an HTTP probe (avoids double TCP connection) */
    if (is_http_port(ports[i], br.service)) {
      WebResult wr = probe_http(ip, ports[i], timeout_ms, br.http_response);
      out_web_titles[i]  = wr.title;
      out_web_servers[i] = wr.server;
      out_web_headers[i] = wr.headers_json;
      out_web_paths[i]   = wr.paths_json;
    }
  }

  if (cve_db) sqlite3_close(cve_db);
  return 0;
}

/* -----------------------------------------------------------------------
 * Format a number with thousand separators: 1234567 → "1,234,567"
 * ----------------------------------------------------------------------- */
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
 * run_enrichment — full pipeline across all shards
 * ----------------------------------------------------------------------- */

int run_enrichment(const char *data_dir, int batch_size) {
  if (batch_size <= 0) batch_size = 1000;

  /* Locate kmap-cve.db for CVE lookups */
  std::string cve_path;
  {
    char buf[1024];
    if (kmap_fetchfile(buf, sizeof(buf), "kmap-cve.db") > 0)
      cve_path = buf;
  }
  if (cve_path.empty()) {
    log_write(LOG_STDOUT,
      "net-scan: WARNING: kmap-cve.db not found — CVE enrichment skipped.\n");
  }

  int errors = 0;

  for (int shard = 0; shard < NET_SHARD_COUNT; shard++) {
    std::string db_path = net_shard_path(data_dir, shard);

    /* Check if shard file exists before trying to open */
    FILE *test = fopen(db_path.c_str(), "r");
    if (!test) continue;  /* shard doesn't exist — skip */
    fclose(test);

    sqlite3 *db = net_db_open(db_path);
    if (!db) {
      log_write(LOG_STDOUT, "net-scan: WARNING: cannot open %s — skipping.\n",
                db_path.c_str());
      errors++;
      continue;
    }

    /* Get total and unenriched counts for progress display */
    int64_t total_hosts = net_db_count(db);
    int64_t unenriched_total = net_db_count_unenriched(db);

    if (unenriched_total <= 0) {
      net_db_close(db);
      continue;
    }

    /* Extract shard filename for display */
    std::string shard_name = db_path;
    size_t slash = shard_name.find_last_of("/\\");
    if (slash != std::string::npos)
      shard_name = shard_name.substr(slash + 1);

    int64_t processed = 0;
    int64_t enriched_start = total_hosts - unenriched_total;
    time_t enrich_start_time = time(nullptr);

    /* Process in batches */
    while (true) {
      std::vector<std::string> batch_ips =
          net_db_get_unenriched(db, batch_size);
      if (batch_ips.empty()) break;

      net_db_begin(db);

      for (const std::string &ip : batch_ips) {
        /* Get all ports for this IP */
        std::vector<NetHost> host_ports = net_db_get_host(db, ip.c_str());
        if (host_ports.empty()) continue;

        std::vector<int> ports;
        std::vector<std::string> protos;
        for (const auto &h : host_ports) {
          ports.push_back(h.port);
          protos.push_back(h.proto);
        }

        /* Run enrichment — isolated per-host so one failure
           does not abort the entire shard */
        std::vector<std::string> services, versions, cves_json;
        std::vector<std::string> web_titles, web_servers, web_headers, web_paths;

        int rc = enrich_single_host(ip.c_str(), ports, protos,
                                    cve_path.empty() ? nullptr : cve_path.c_str(),
                                    ENRICH_CONNECT_TIMEOUT,
                                    services, versions, cves_json,
                                    web_titles, web_servers,
                                    web_headers, web_paths);
        if (rc != 0) {
          /* Record the failure with a timestamp so the row becomes
             eligible to retry after NET_DB_ENRICH_RETRY_SECONDS. */
          if (o.verbose)
            log_write(LOG_STDOUT, "  WARNING: enrichment failed for %s, will retry later\n",
                      ip.c_str());
          char err_buf[64];
          snprintf(err_buf, sizeof(err_buf), "enrich_single_host rc=%d", rc);
          for (size_t j = 0; j < ports.size(); j++) {
            net_db_record_enrichment_error(db, ip.c_str(), ports[j], err_buf);
          }
          continue;
        }

        /* Write enrichment results back to DB — check bounds to avoid
           out-of-range access if output vectors are somehow short */
        for (size_t j = 0; j < ports.size(); j++) {
          net_db_update_enrichment(
            db, ip.c_str(), ports[j],
            j < services.size()    ? services[j].c_str()    : "",
            j < versions.size()    ? versions[j].c_str()    : "",
            j < cves_json.size()   ? cves_json[j].c_str()   : "",
            j < web_titles.size()  ? web_titles[j].c_str()  : "",
            j < web_servers.size() ? web_servers[j].c_str()  : "",
            j < web_headers.size() ? web_headers[j].c_str()  : "",
            j < web_paths.size()   ? web_paths[j].c_str()   : "");
        }

        /* ASN/GeoIP lookup — one per IP, applied to all ports */
        AsnInfo asn_info = lookup_asn(ip.c_str(), 2000);
        if (asn_info.asn > 0) {
          net_db_update_asn(db, ip.c_str(), asn_info.asn,
                            asn_info.as_name.c_str(),
                            asn_info.country.c_str(),
                            asn_info.bgp_prefix.c_str());
        }

        processed++;
      }

      net_db_commit(db);

      /* Progress output with ETA */
      int64_t done = enriched_start + processed;
      double pct = (total_hosts > 0)
                   ? (100.0 * static_cast<double>(done) /
                      static_cast<double>(total_hosts))
                   : 100.0;

      /* ETA calculation */
      time_t elapsed = time(nullptr) - enrich_start_time + 1;
      double hosts_per_sec = (elapsed > 0 && processed > 0)
                             ? (double)processed / (double)elapsed : 0;
      int64_t hosts_left = unenriched_total - processed;
      char eta_buf[32] = "...";
      if (hosts_per_sec > 0 && hosts_left > 0) {
        int64_t eta = static_cast<int64_t>((double)hosts_left / hosts_per_sec);
        int hrs  = static_cast<int>(eta / 3600);
        int mins = static_cast<int>((eta % 3600) / 60);
        int secs = static_cast<int>(eta % 60);
        snprintf(eta_buf, sizeof(eta_buf), "%02d:%02d:%02d", hrs, mins, secs);
      }

      log_write(LOG_STDOUT,
        "Enriching %s: %s / %s [%.1f%%] ETA: %s\n",
        shard_name.c_str(),
        format_count(done).c_str(),
        format_count(total_hosts).c_str(),
        pct, eta_buf);
    }

    net_db_close(db);
  }

  if (errors > 0)
    log_write(LOG_STDOUT,
      "net-scan: enrichment complete with %d shard error(s).\n", errors);
  else
    log_write(LOG_STDOUT, "net-scan: enrichment complete.\n");

  return (errors > 0) ? 1 : 0;
}
