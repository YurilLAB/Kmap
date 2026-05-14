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
#include "net_fp_helpers.h"
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
#include <thread>
#include <atomic>
#include <mutex>

#ifndef WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>          /* getnameinfo, NI_MAXHOST, NI_NAMEREQD */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>       /* getnameinfo on Win32 lives here */
#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

extern KmapOps o;

/* -----------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------- */

#define ENRICH_CONNECT_TIMEOUT  5000  /* ms */
#define ENRICH_READ_TIMEOUT     5000  /* ms */
#define ENRICH_BANNER_MAX       1024  /* bytes */

/* -----------------------------------------------------------------------
 * Low-level TCP helpers -- same pattern as default_creds.cc
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

  /* TCP_NODELAY: enrichment HTTP probes are typically <200 bytes
   * (just a GET / + headers); Nagle's algorithm holds them in the
   * send buffer waiting for an ACK that this exchange will never
   * benefit from coalescing.  Without TCP_NODELAY the kernel can
   * delay the send by up to 200ms per probe.  Per-host enrichment
   * sends one probe per port; 5 ports x 200ms = 1s of avoidable
   * stall per host.  Set before connect so even the SYN goes out
   * unbuffered. */
  int nodelay = 1;
  setsockopt(static_cast<int>(fd), IPPROTO_TCP, TCP_NODELAY,
             reinterpret_cast<const char *>(&nodelay), sizeof(nodelay));

  /* OS spoofing profile (--spoof-os). No-op when not set. Stable per
     target IP so the multiple enrichment probes against one host present
     a single coherent OS personality. */
  os_profile_apply_socket(static_cast<intptr_t>(fd), af,
                          os_profile_get_for_target(
                              o.spoof_os,
                              os_profile_seed_from_text(ip)));

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
 * Reverse-DNS (PTR) lookup
 *
 * Uses POSIX getnameinfo() with NI_NAMEREQD so an unresolvable IP yields
 * an empty string rather than the dotted-quad fallback.  Synchronous per
 * IP — fine because the enrichment loop is already serialized one host
 * at a time; mass async resolution belongs on the discover side.
 * ----------------------------------------------------------------------- */
static std::string reverse_dns_lookup(const char *ip) {
  struct sockaddr_storage ss{};
  socklen_t slen;

  struct sockaddr_in  *sa4 = reinterpret_cast<struct sockaddr_in  *>(&ss);
  struct sockaddr_in6 *sa6 = reinterpret_cast<struct sockaddr_in6 *>(&ss);

  if (inet_pton(AF_INET, ip, &sa4->sin_addr) == 1) {
    sa4->sin_family = AF_INET;
    slen = sizeof(struct sockaddr_in);
  } else if (inet_pton(AF_INET6, ip, &sa6->sin6_addr) == 1) {
    sa6->sin6_family = AF_INET6;
    slen = sizeof(struct sockaddr_in6);
  } else {
    return "";
  }

  char host[NI_MAXHOST]{};
  int rc = getnameinfo(reinterpret_cast<struct sockaddr *>(&ss), slen,
                       host, sizeof(host), nullptr, 0, NI_NAMEREQD);
  if (rc != 0) return "";
  return std::string(host);
}

/* -----------------------------------------------------------------------
 * Fingerprint derivation helpers live in net_fp_helpers.cc so the test
 * harness can link them without pulling in OpenSSL and the rest of the
 * enrichment pipeline.  Declarations come in via net_fp_helpers.h above.
 * ----------------------------------------------------------------------- */

/* -----------------------------------------------------------------------
 * String helpers
 * ----------------------------------------------------------------------- */

static std::string str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}

/* Numeric version comparison -- returns -1/0/1 for a<b, a==b, a>b.
   Parses "2.4.49p1" -> {2, 4, 49} and compares component-by-component. */
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
     plausible end-to-end.

     IMPORTANT: do NOT send the HTTP probe on known-TLS ports.  A TLS
     server waits for a ClientHello, so n<=0 always; sending plaintext
     GET / down the TCP stream gets a TLS Alert back, the response
     fails every pattern match, and the function returns empty anyway.
     Doing it wastes a second recv timeout AND pollutes any IDS that
     watches for plaintext-on-TLS-port traffic.  TLS ports get their
     real probing via tls_capture_cert; this guard only skips the
     wasteful plaintext step.  A server that does speak first (SSH on
     443 is a real pattern -- corporate-firewall bypass) is still
     captured by the initial recv above. */
  bool is_tls_port = (port == 443 || port == 4443 || port == 8443 ||
                      port == 9443);
  if (n <= 0 && !is_tls_port) {
    std::string http_probe = os_profile_http_request(
        "/", ip,
        os_profile_get_for_target(o.spoof_os,
                                  os_profile_seed_from_text(ip)));
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
       plain TCP -- we cannot do TLS here without OpenSSL overhead) */
    if (port == 443 || port == 8443 || port == 4443)
      result.service = "https";

    return result;
  }

  /* Match against known banner patterns */
  if (banner.size() >= 4 && banner.substr(0, 4) == "SSH-") {
    result.service = "ssh";
    /* "SSH-2.0-OpenSSH_8.2p1" -> version = "OpenSSH 8.2p1" */
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
      /* Ambiguous 220 -- guess based on port */
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

  /* MongoDB: binary wire protocol -- check for valid OP_REPLY header */
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
 * Simplified version of cve_map.cc's query_cves() -- works with plain
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
 * "OpenSSH 8.2p1" -> "8.2", "nginx/1.18.0" -> "1.18.0" */
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

  /* LIMIT raised from 15 to 100.  The previous ceiling silently evicted
   * lower-CVSS CVEs from the hosts.cves column on each rescan: a product
   * with 16+ applicable CVEs would lose every CVE past rank 15, and a
   * fresh top-15 CVE published since the previous scan would push an
   * older still-applicable CVE out of the stored list.  100 covers every
   * mainstream product's real-world CVE count (Apache 2.2, OpenSSH 7.x,
   * legacy nginx) without bloating the row: 100 rows of CVE JSON is
   * ~8 KB per port, negligible at shard scale. */
  const char *sql =
    "SELECT cve_id, cvss_score, severity, description, "
    "version_min, version_max "
    "FROM cves WHERE product = ? AND cvss_score >= 0.0 "
    "ORDER BY cvss_score DESC LIMIT 100";

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

    /* Version range filtering -- uses numeric version comparison,
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
  std::string headers_json;     /* JSON object of selected headers */
  std::string paths_json;       /* JSON array of probed paths (just /) */
  std::string powered_by;       /* X-Powered-By header */
  std::string x_generator;      /* X-Generator header */
  std::string redirect_target;  /* Location: header (3xx responses) */
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

/* probe_http -- if cached_response is non-empty, reuse it instead of
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

    /* Profile-driven request (User-Agent + Accept-* headers) -- preserves
       the existing Host-with-port form by passing ip as the host and
       letting os_profile_http_request handle IPv6 bracketing. The :port
       suffix is not strictly required (HTTP/1.0 ignores port mismatch)
       and dropping it gives a more browser-faithful header. */
    std::string req = os_profile_http_request(
        "/", ip,
        os_profile_get_for_target(o.spoof_os,
                                  os_profile_seed_from_text(ip)));

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

  wr.title           = extract_html_title(body);
  wr.server          = extract_header_val(response, "Server");
  wr.powered_by      = extract_header_val(response, "X-Powered-By");
  wr.x_generator     = extract_header_val(response, "X-Generator");
  wr.redirect_target = extract_header_val(response, "Location");

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

  /* Build paths JSON -- just the root path result */
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

/* HTTPS-only port heuristic — kept narrow so we do not waste a TLS handshake
   attempt on every HTTP port.  Non-standard TLS ports are still reachable
   via the per-target web_recon pipeline. */
static bool is_https_port(int port, const std::string &service) {
  std::string svc = str_lower(service);
  if (svc == "https" || svc.find("ssl") != std::string::npos) return true;
  return port == 443 || port == 4443 || port == 8443 || port == 9443;
}

/* -----------------------------------------------------------------------
 * TLS handshake + cert capture (HAVE_OPENSSL only)
 *
 * Captures the public TLS material we want to persist on every HTTPS host:
 * subject CN, issuer CN, SAN list (DNS names only), notAfter, self-signed
 * flag, negotiated protocol, and the server cert's SHA-256 fingerprint.
 *
 * The fingerprint is the (B)-step pivot key for relationship matching:
 * any two IPs that serve the same DER cert hash to the same hex string,
 * which clusters shared-deployment fleets even without DNS evidence.
 * ----------------------------------------------------------------------- */

/* TlsCapture struct is declared in net_enrich.h so the run_enrichment loop
   can plumb results to net_db_update_tls without leaking implementation
   details. */

#ifdef HAVE_OPENSSL
/* Shared SSL_CTX -- created once per process.  Mirrors web_recon.cc's
   pattern; VERIFY_NONE because we want the cert details even when the
   chain doesn't validate (self-signed certs are the whole point of one of
   the fields we capture).

   std::call_once + once_flag because the parallel enrichment workers
   added in the parallel-run_enrichment / parallel-watchlist commits
   can all race past `if (!ctx)` simultaneously and double-construct
   the SSL_CTX, leaking one and racing on which pointer the static
   ends up holding.  call_once guarantees the lambda body runs exactly
   once across all threads, and any thread that arrives later blocks
   until the first invocation completes.  OpenSSL 1.1+ auto-initializes
   on first use of any libssl/libcrypto function; SSL_library_init and
   SSL_load_error_strings are no-ops since 1.1 and deprecated in 3.0,
   so they are not called here. */
static SSL_CTX *enrich_ssl_ctx_inst = nullptr;
static std::once_flag enrich_ssl_ctx_once;

static SSL_CTX *enrich_get_ssl_ctx() {
  std::call_once(enrich_ssl_ctx_once, [](){
    enrich_ssl_ctx_inst = SSL_CTX_new(TLS_client_method());
    if (enrich_ssl_ctx_inst)
      SSL_CTX_set_verify(enrich_ssl_ctx_inst, SSL_VERIFY_NONE, nullptr);
  });
  return enrich_ssl_ctx_inst;
}

static int tls_capture_cert(const char *ip, int port, int timeout_ms,
                            TlsCapture &out) {
  SSL_CTX *ctx = enrich_get_ssl_ctx();
  if (!ctx) return -1;

  kmap_fd_t fd = enrich_tcp_connect(ip, static_cast<uint16_t>(port), timeout_ms);
  if (fd == KMAP_INVALID_FD) return -1;

  SSL *ssl = SSL_new(ctx);
  if (!ssl) { enrich_close_fd(fd); return -1; }

  SSL_set_fd(ssl, static_cast<int>(fd));
  /* No SNI: net_enrich works exclusively with IP literals, and RFC 6066
     forbids SNI on IP-form hosts.  Some pedantic servers will close
     instead of returning a default vhost; that's a wash given the volume. */

  if (SSL_connect(ssl) != 1) {
    SSL_free(ssl);
    enrich_close_fd(fd);
    return -1;
  }

  out.protocol = SSL_get_version(ssl);

  X509 *cert = SSL_get_peer_certificate(ssl);
  if (cert) {
    char buf[256]{};
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
                              NID_commonName, buf, sizeof(buf));
    out.subject_cn = buf;

    std::memset(buf, 0, sizeof(buf));
    X509_NAME_get_text_by_NID(X509_get_issuer_name(cert),
                              NID_commonName, buf, sizeof(buf));
    out.issuer = buf;

    ASN1_TIME *exp = X509_get_notAfter(cert);
    if (exp) {
      BIO *b = BIO_new(BIO_s_mem());
      if (b) {
        ASN1_TIME_print(b, exp);
        char tbuf[64]{};
        BIO_read(b, tbuf, sizeof(tbuf) - 1);
        BIO_free(b);
        out.not_after = tbuf;
      }
    }

    out.self_signed =
      (X509_NAME_cmp(X509_get_subject_name(cert),
                     X509_get_issuer_name(cert)) == 0) ? 1 : 0;

    /* SAN DNS names — emit only GEN_DNS entries.  GEN_IPADD entries are
       skipped: IP-form SANs are uncommon and harder to pivot than DNS
       names (an IP-form SAN typically just duplicates the cert's host). */
    GENERAL_NAMES *sans = static_cast<GENERAL_NAMES *>(
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (sans) {
      std::ostringstream oss;
      oss << "[";
      bool first = true;
      int n = sk_GENERAL_NAME_num(sans);
      for (int i = 0; i < n; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
        if (gn && gn->type == GEN_DNS) {
          const ASN1_IA5STRING *s = gn->d.dNSName;
          const char *val = reinterpret_cast<const char *>(
            ASN1_STRING_get0_data(s));
          int len = ASN1_STRING_length(s);
          if (val && len > 0) {
            if (!first) oss << ",";
            oss << "\"" << json_escape(std::string(val, static_cast<size_t>(len)))
                << "\"";
            first = false;
          }
        }
      }
      oss << "]";
      if (!first) out.san_json = oss.str();
      GENERAL_NAMES_free(sans);
    }

    /* DER-encoded cert SHA-256 — the pivot key for B-step relationship
       matching.  X509_digest hashes the canonical DER form, so two ports
       serving the same cert produce identical fingerprints regardless of
       handshake-level differences. */
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (X509_digest(cert, EVP_sha256(), digest, &digest_len) == 1 &&
        digest_len == 32) {
      static const char hex[] = "0123456789abcdef";
      char hexbuf[65];
      for (unsigned int i = 0; i < digest_len; i++) {
        hexbuf[i * 2]     = hex[digest[i] >> 4];
        hexbuf[i * 2 + 1] = hex[digest[i] & 0xF];
      }
      hexbuf[digest_len * 2] = '\0';
      out.sha256 = hexbuf;
    }

    X509_free(cert);
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  enrich_close_fd(fd);
  return 0;
}
#else
/* Build without OpenSSL: TLS capture is a no-op, leaves TlsCapture::self_signed
   at its -1 ("unknown") default so the DB layer writes NULL. */
static int tls_capture_cert(const char * /*ip*/, int /*port*/,
                            int /*timeout_ms*/, TlsCapture & /*out*/) {
  return -1;
}
#endif /* HAVE_OPENSSL */

/* -----------------------------------------------------------------------
 * enrich_single_host -- public API
 * ----------------------------------------------------------------------- */

int enrich_single_host(const char *ip,
                       const std::vector<int> &ports,
                       const std::vector<std::string> &protos,
                       sqlite3 *cve_db,
                       int timeout_ms,
                       std::vector<std::string> &out_services,
                       std::vector<std::string> &out_versions,
                       std::vector<std::string> &out_cves,
                       std::vector<std::string> &out_web_titles,
                       std::vector<std::string> &out_web_servers,
                       std::vector<std::string> &out_web_headers,
                       std::vector<std::string> &out_web_paths,
                       std::vector<std::string> &out_powered_by,
                       std::vector<std::string> &out_x_generator,
                       std::vector<std::string> &out_redirects,
                       std::vector<TlsCapture> *out_tls) {
  size_t nports = ports.size();
  out_services.resize(nports);
  out_versions.resize(nports);
  out_cves.resize(nports);
  out_web_titles.resize(nports);
  out_web_servers.resize(nports);
  out_web_headers.resize(nports);
  out_web_paths.resize(nports);
  out_powered_by.resize(nports);
  out_x_generator.resize(nports);
  out_redirects.resize(nports);
  if (out_tls) out_tls->assign(nports, TlsCapture{});

  /* CVE DB is now passed in already-open by the caller (run_watchlist
   * or run_enrichment).  Opening it once per call -- and 5x-10x per
   * batch with the parallel enrichment workers -- was both wasteful
   * (sqlite3_open_v2 does stat + open + page-cache warm-up every time)
   * and silently expensive at scale: a 100k-IP scan with 5 ports each
   * issued hundreds of thousands of redundant file opens before the
   * caller cleanup.  cve_db == nullptr is still valid: it just means
   * the caller could not find kmap-cve.db, and CVE lookups are
   * skipped (the `if (cve_db && !out_services[i].empty())` gate
   * below handles that case). */

  for (size_t i = 0; i < nports; i++) {
    /* Step 1: Banner grab / service detection.  Only overwrite
     * out_services / out_versions when the banner grab actually
     * produced something -- callers that pre-populate these vectors
     * with a prior scan's values (e.g. run_watchlist after
     * net_db_get_host) want the prior values preserved when this
     * scan's banner grab is flaky (port open but no recognizable
     * response).  Without this guard, a transient empty banner wipes
     * the CVE-lookup input and the cves column stays unpopulated
     * forever once a single re-scan misses. */
    BannerResult br = grab_banner(ip, ports[i], timeout_ms);
    if (!br.service.empty()) out_services[i] = br.service;
    if (!br.version.empty()) out_versions[i] = br.version;

    /* Step 2: CVE lookup -- uses out_services[i]/out_versions[i],
     * which now reflects either this scan's banner or the caller's
     * prior-scan hint when the banner came back empty. */
    if (cve_db && !out_services[i].empty()) {
      std::vector<EnrichCve> cves = lookup_cves(cve_db, out_services[i], out_versions[i]);
      out_cves[i] = cves_to_json(cves);
    }

    /* Step 3: HTTP recon on web ports -- reuse response from banner grab
       if it already did an HTTP probe (avoids double TCP connection).
       Skip on TLS ports: probe_http only speaks plaintext, so sending
       GET / into a TLS stream gets a TLS Alert back, every field comes
       out empty, and we wasted one more connection on top of the one
       grab_banner already short-circuited.  --web-recon mode has full
       TLS-aware HTTP probing via web_recon.cc for users who want
       title / server-header / paths on HTTPS. */
    if (is_http_port(ports[i], br.service) &&
        !is_https_port(ports[i], br.service)) {
      WebResult wr = probe_http(ip, ports[i], timeout_ms, br.http_response);
      out_web_titles[i]   = wr.title;
      out_web_servers[i]  = wr.server;
      out_web_headers[i]  = wr.headers_json;
      out_web_paths[i]    = wr.paths_json;
      out_powered_by[i]   = wr.powered_by;
      out_x_generator[i]  = wr.x_generator;
      out_redirects[i]    = wr.redirect_target;
    }

    /* Step 4: TLS handshake on HTTPS ports — captures cert details and
       fingerprint.  Best-effort: handshake failures (cert expired,
       protocol mismatch, IP-form pedantic server) leave the slot empty
       so net_db_update_tls writes NULLs and the row stays eligible for
       re-probing later. */
    if (out_tls && is_https_port(ports[i], br.service)) {
      tls_capture_cert(ip, ports[i], timeout_ms, (*out_tls)[i]);
    }
  }

  /* Don't close cve_db -- it's owned by the caller. */
  return 0;
}

/* -----------------------------------------------------------------------
 * Format a number with thousand separators: 1234567 -> "1,234,567"
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
 * run_enrichment -- full pipeline across all shards
 * ----------------------------------------------------------------------- */

int run_enrichment(const char *data_dir, int batch_size) {
  if (batch_size <= 0) batch_size = 1000;

  /* Locate kmap-cve.db for CVE lookups.  Mirrors run_watchlist's
   * lookup: try kmap_fetchfile first (which searches --datadir,
   * $KMAPDIR, %APPDATA%/kmap, exe-dir, ...) then fall back to
   * ./kmap-cve.db so users running kmap from the source tree get
   * CVE matches without having to install or copy the DB into
   * exe-dir.  Previously the WARN fired in net-scan mode even when
   * a perfectly good DB sat in the CWD, silently disabling CVE
   * enrichment for the whole scan. */
  std::string cve_path;
  {
    char buf[1024];
    if (kmap_fetchfile(buf, sizeof(buf), "kmap-cve.db") > 0) {
      cve_path = buf;
    } else {
      FILE *cwd_db = fopen("kmap-cve.db", "rb");
      if (cwd_db) {
        fclose(cwd_db);
        cve_path = "kmap-cve.db";
      }
    }
  }
  if (cve_path.empty()) {
    log_write(LOG_STDOUT,
      "net-scan: WARNING: kmap-cve.db not found -- CVE enrichment skipped.\n");
  } else {
    log_write(LOG_STDOUT,
      "net-scan: CVE database: %s\n", cve_path.c_str());
  }

  /* Open the CVE DB ONCE for the entire enrichment phase, shared
   * read-only across all shards' worker pools.  sqlite is in default
   * serialized threading mode so this handle is safe to share.
   * Previously enrich_single_host opened+closed the DB on every host
   * call -- 5x or more per batch with the parallel workers spinning
   * through hundreds of thousands of stat+open+page-cache-warm cycles
   * on a full sweep. */
  sqlite3 *cve_db = nullptr;
  if (!cve_path.empty()) {
    if (sqlite3_open_v2(cve_path.c_str(), &cve_db,
                        SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
      if (cve_db) { sqlite3_close(cve_db); cve_db = nullptr; }
      log_write(LOG_STDOUT,
        "net-scan: WARNING: could not open CVE database %s -- continuing.\n",
        cve_path.c_str());
    }
  }

  int errors = 0;

  /* Cross-shard pooled enrichment.
   *
   * The previous implementation iterated shards serially with a per-
   * shard worker pool.  On a small bounded scan (--net-max-ips 150)
   * with hosts spread across 25-30 shards, each shard had ~5 hosts
   * and 35 of 40 workers per shard sat idle while the next shard
   * waited its turn.  Cross-shard pooling collects every unenriched
   * host from every shard into one global queue, runs ONE worker
   * pool against the whole queue, then groups DB writes by shard at
   * the end so each shard's transaction still bundles cleanly.
   *
   * Measured net effect on a 150-IP / 25-shard scan: enrichment
   * wall time drops by roughly the number of effectively-empty
   * shards we no longer wait through.
   *
   * Single global pool means workers can chew through the global
   * queue with no idle gaps between shards.  Stage A (per-host
   * net_db_get_host) and Stage C (per-host UPDATEs) still touch
   * the right shard handle via the shard_idx tracked on every
   * result entry. */
  struct EnrichResult {
    int shard_idx = -1;
    std::string ip;
    std::vector<int> ports;
    std::vector<std::string> protos;
    std::vector<std::string> services, versions, cves_json;
    std::vector<std::string> web_titles, web_servers, web_headers, web_paths;
    std::vector<std::string> powered_by, x_generator, redirects;
    std::vector<TlsCapture> tls_caps;
    std::string hostname;
    AsnInfo asn_info{};
    int rc = 0;
    bool empty_host = false;
  };

  /* Worker / retry counts read once, applied globally. */
  int enrich_worker_count = 40;
  if (const char *env = getenv("KMAP_NETSCAN_ENRICH_CONCURRENCY")) {
    int v = atoi(env);
    if (v > 0 && v <= 256) enrich_worker_count = v;
  }
  int enrich_retries = 0;
  if (const char *env = getenv("KMAP_ENRICH_RETRIES")) {
    int v = atoi(env);
    if (v >= 0 && v <= 10) enrich_retries = v;
  }

  /* Open every shard upfront.  Skip shard files that don't exist
   * on disk (sparse: a freshly-discovered scan only writes the
   * shards whose IP space had open ports). */
  std::vector<sqlite3 *> shard_dbs(NET_SHARD_COUNT, nullptr);
  int64_t total_hosts_all = 0;
  int64_t unenriched_total = 0;
  for (int shard = 0; shard < NET_SHARD_COUNT; shard++) {
    std::string p = net_shard_path(data_dir, shard);
    FILE *test = fopen(p.c_str(), "r");
    if (!test) continue;
    fclose(test);
    shard_dbs[shard] = net_db_open(p);
    if (!shard_dbs[shard]) {
      log_write(LOG_STDOUT,
        "net-scan: WARNING: cannot open %s -- skipping.\n", p.c_str());
      errors++;
      continue;
    }
    total_hosts_all  += net_db_count(shard_dbs[shard]);
    unenriched_total += net_db_count_unenriched(shard_dbs[shard]);
  }

  if (unenriched_total <= 0) {
    log_write(LOG_STDOUT,
      "net-scan: no unenriched hosts in any shard -- skipping enrichment.\n");
    for (auto *db : shard_dbs) if (db) net_db_close(db);
    if (cve_db) sqlite3_close(cve_db);
    return errors > 0 ? 1 : 0;
  }

  log_write(LOG_STDOUT,
    "net-scan: enriching %s host(s) across %d shards with %d workers...\n",
    format_count(unenriched_total).c_str(), NET_SHARD_COUNT,
    enrich_worker_count);

  /* Stage A: pull unenriched IPs from every shard and pre-fetch each
   * host's port list serially.  net_db_get_unenriched + net_db_get_host
   * use the shared per-shard sqlite handles which we don't share
   * across worker threads, so this stage stays serial.  Cheap: one
   * SELECT per host, indexed lookup. */
  std::vector<EnrichResult> results;
  results.reserve(unenriched_total);
  time_t enrich_start_time = time(nullptr);
  for (int shard = 0; shard < NET_SHARD_COUNT; shard++) {
    if (!shard_dbs[shard]) continue;
    std::vector<std::string> batch_ips =
        net_db_get_unenriched(shard_dbs[shard], batch_size);
    for (const std::string &ip : batch_ips) {
      EnrichResult r;
      r.shard_idx = shard;
      r.ip = ip;
      std::vector<NetHost> host_ports =
          net_db_get_host(shard_dbs[shard], ip.c_str());
      if (host_ports.empty()) {
        r.empty_host = true;
        results.push_back(std::move(r));
        continue;
      }
      for (const auto &h : host_ports) {
        r.ports.push_back(h.port);
        r.protos.push_back(h.proto);
      }
      r.services.resize(r.ports.size());
      r.versions.resize(r.ports.size());
      for (size_t j = 0; j < host_ports.size() && j < r.ports.size(); j++) {
        r.services[j] = host_ports[j].service;
        r.versions[j] = host_ports[j].version;
      }
      results.push_back(std::move(r));
    }
  }

  /* Stage B: ONE global parallel worker pool over the entire results
   * vector.  No mutex on results because each worker writes only its
   * own slot. */
  int actual_workers = enrich_worker_count;
  if (static_cast<size_t>(actual_workers) > results.size())
    actual_workers = static_cast<int>(results.size());
  if (actual_workers < 1) actual_workers = 1;

  std::atomic<size_t> next_idx{0};
  std::atomic<int64_t> processed_atomic{0};
  auto worker = [&]() {
    while (true) {
      size_t i = next_idx.fetch_add(1, std::memory_order_relaxed);
      if (i >= results.size()) return;
      EnrichResult &r = results[i];
      if (r.empty_host) continue;

      int attempt = 0;
      while (true) {
        r.rc = enrich_single_host(r.ip.c_str(), r.ports, r.protos,
                   cve_db,
                   ENRICH_CONNECT_TIMEOUT,
                   r.services, r.versions, r.cves_json,
                   r.web_titles, r.web_servers,
                   r.web_headers, r.web_paths,
                   r.powered_by, r.x_generator, r.redirects,
                   &r.tls_caps);
        if (r.rc == 0) break;
        if (attempt >= enrich_retries) break;
        attempt++;
      }

      if (r.rc == 0) {
        r.hostname  = reverse_dns_lookup(r.ip.c_str());
        r.asn_info  = lookup_asn(r.ip.c_str(), 2000);
      }
      processed_atomic.fetch_add(1, std::memory_order_relaxed);
    }
  };

  /* Lightweight progress printer thread -- emits one line every 10 s
   * with global progress so an operator running a long enrichment
   * can tell something is happening. */
  std::atomic<bool> printer_stop{false};
  std::thread printer([&]() {
    int last_done = 0;
    while (!printer_stop.load(std::memory_order_relaxed)) {
      std::this_thread::sleep_for(std::chrono::seconds(10));
      if (printer_stop.load()) break;
      int64_t done = processed_atomic.load();
      if (done == last_done) continue;
      last_done = (int)done;
      double pct = (results.size() > 0)
                   ? 100.0 * (double)done / (double)results.size() : 100.0;
      time_t elapsed = time(nullptr) - enrich_start_time + 1;
      double hps = (elapsed > 0 && done > 0)
                   ? (double)done / (double)elapsed : 0;
      int64_t left = (int64_t)results.size() - done;
      char eta_buf[32] = "...";
      if (hps > 0 && left > 0) {
        int64_t eta = (int64_t)((double)left / hps);
        snprintf(eta_buf, sizeof(eta_buf), "%02d:%02d:%02d",
                 (int)(eta / 3600), (int)((eta % 3600) / 60), (int)(eta % 60));
      }
      log_write(LOG_STDOUT,
        "  Enriching: %s / %s hosts [%.1f%%]  rate=%.1f hps  ETA: %s\n",
        format_count(done).c_str(),
        format_count((int64_t)results.size()).c_str(),
        pct, hps, eta_buf);
    }
  });

  std::vector<std::thread> pool;
  pool.reserve(actual_workers);
  for (int i = 0; i < actual_workers; i++) pool.emplace_back(worker);
  for (auto &th : pool) th.join();
  printer_stop.store(true);
  printer.join();

  /* Stage C: serial DB writes, grouped by shard so each shard's
   * UPDATEs land inside one transaction.  Iterate shards outer-most;
   * for each shard, iterate results that belong to it. */
  int64_t processed = 0;
  for (int shard = 0; shard < NET_SHARD_COUNT; shard++) {
    sqlite3 *db = shard_dbs[shard];
    if (!db) continue;
    /* Skip the transaction-begin entirely when this shard has no
     * results, to avoid pointless write-locks. */
    bool any_for_this_shard = false;
    for (const auto &r : results) {
      if (r.shard_idx == shard) { any_for_this_shard = true; break; }
    }
    if (!any_for_this_shard) continue;

    net_db_begin(db);
    for (auto &r : results) {
      if (r.shard_idx != shard) continue;
      if (r.empty_host) continue;
      if (r.rc != 0) {
        if (o.verbose) {
          log_write(LOG_STDOUT,
            "  WARNING: enrichment failed for %s after retries, "
            "will retry later\n", r.ip.c_str());
        }
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf),
                 "enrich_single_host rc=%d", r.rc);
        for (size_t j = 0; j < r.ports.size(); j++) {
          net_db_record_enrichment_error(db, r.ip.c_str(),
                                         r.ports[j], err_buf);
        }
        continue;
      }

      if (!r.hostname.empty())
        net_db_set_hostname(db, r.ip.c_str(), r.hostname.c_str());

      for (size_t j = 0; j < r.ports.size(); j++) {
        net_db_update_enrichment(
          db, r.ip.c_str(), r.ports[j],
          j < r.services.size()    ? r.services[j].c_str()    : "",
          j < r.versions.size()    ? r.versions[j].c_str()    : "",
          j < r.cves_json.size()   ? r.cves_json[j].c_str()   : "",
          j < r.web_titles.size()  ? r.web_titles[j].c_str()  : "",
          j < r.web_servers.size() ? r.web_servers[j].c_str() : "",
          j < r.web_headers.size() ? r.web_headers[j].c_str() : "",
          j < r.web_paths.size()   ? r.web_paths[j].c_str()   : "",
          j < r.powered_by.size()  ? r.powered_by[j].c_str()  : nullptr,
          j < r.x_generator.size() ? r.x_generator[j].c_str() : nullptr,
          j < r.redirects.size()   ? r.redirects[j].c_str()   : nullptr,
          nullptr);

        if (j < r.tls_caps.size()) {
          const TlsCapture &tc = r.tls_caps[j];
          bool have_tls = !tc.subject_cn.empty() || !tc.issuer.empty() ||
                          !tc.sha256.empty()     || !tc.protocol.empty();
          if (have_tls) {
            net_db_update_tls(
              db, r.ip.c_str(), r.ports[j],
              tc.subject_cn.empty() ? nullptr : tc.subject_cn.c_str(),
              tc.issuer.empty()     ? nullptr : tc.issuer.c_str(),
              tc.san_json.empty()   ? nullptr : tc.san_json.c_str(),
              tc.not_after.empty()  ? nullptr : tc.not_after.c_str(),
              tc.self_signed,
              tc.protocol.empty()   ? nullptr : tc.protocol.c_str(),
              tc.sha256.empty()     ? nullptr : tc.sha256.c_str());
          }
        }
      }

      if (r.asn_info.asn > 0) {
        net_db_update_asn(db, r.ip.c_str(), r.asn_info.asn,
                          r.asn_info.as_name.c_str(),
                          r.asn_info.country.c_str(),
                          r.asn_info.bgp_prefix.c_str(),
                          r.asn_info.registry.c_str(),
                          r.asn_info.region.c_str());
      }

      uint32_t ip_u32 = ip_to_u32(r.ip.c_str());
      if (ip_u32 != 0) {
        int64_t fp_ts = static_cast<int64_t>(time(nullptr));
        if (!r.hostname.empty()) {
          net_db_insert_fingerprint(db, ip_u32, 0, "hostname",
                                    r.hostname.c_str(), fp_ts);
        }
        for (size_t j = 0; j < r.ports.size(); j++) {
          if (j < r.tls_caps.size()) {
            const TlsCapture &tc = r.tls_caps[j];
            if (!tc.sha256.empty()) {
              net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                        "tls_sha256",
                                        tc.sha256.c_str(), fp_ts);
            }
            if (!tc.subject_cn.empty() && !fp_looks_like_ip(tc.subject_cn)) {
              net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                        "tls_subject_cn",
                                        tc.subject_cn.c_str(), fp_ts);
            }
            if (!tc.san_json.empty()) {
              std::vector<std::string> sans =
                  fp_parse_san_json(tc.san_json);
              for (const std::string &san : sans) {
                if (san.empty() || fp_looks_like_ip(san)) continue;
                net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                          "tls_san",
                                          san.c_str(), fp_ts);
              }
            }
          }
          if (j < r.redirects.size() && !r.redirects[j].empty()) {
            std::string rh = fp_extract_redirect_host(r.redirects[j]);
            if (!rh.empty()) {
              net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                        "redirect_host",
                                        rh.c_str(), fp_ts);
            }
          }
        }
      }
      processed++;
    }
    net_db_commit(db);
  }

  /* Close every shard handle. */
  for (auto *db : shard_dbs) if (db) net_db_close(db);

  log_write(LOG_STDOUT,
    "net-scan: enrichment complete: %s host(s) written.\n",
    format_count(processed).c_str());
  if (errors > 0) {
    log_write(LOG_STDOUT,
      "net-scan: %d shard open error(s) during enrichment.\n", errors);
  }

  /* Release the shared CVE DB handle now that every shard's worker
   * pool has joined.  This handle was opened once at the top of the
   * function and shared across the entire global pool. */
  if (cve_db) { sqlite3_close(cve_db); cve_db = nullptr; }

  return (errors > 0) ? 1 : 0;
}
