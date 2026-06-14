/*
 * net_enrich_async.cc -- Async (nsock-driven) enrichment for Kmap net-scan.
 *
 * Phases 1a, 1b, 1c of the async-I/O migration.  Implements
 * async_enrich_batch: banner-grab + CVE lookup + HTTP probe + TLS
 * handshake/cert capture for many hosts in parallel inside ONE worker
 * thread, by issuing concurrent TCP-connect / SSL-connect / write / read
 * events on a single nsock_pool and letting the event loop multiplex them.
 *
 * Why this exists
 * ---------------
 * The synchronous enrich_single_host (net_enrich.cc) processes one host
 * per worker thread.  Even with KMAP_HOST_PORT_PARALLELISM=8 threads
 * inside a host, every port's TCP connect/recv is a blocking syscall
 * (timeout via select()), so each worker stalls for connect+read time
 * per port.  On a 1000-IP sweep we top out at ~6 hosts/sec, which is
 * unworkable at IPv4 scale.
 *
 * With nsock, one worker thread can hold hundreds of file descriptors
 * in flight simultaneously: the connect/read syscalls are non-blocking,
 * results arrive as callbacks, and the per-thread blocking ceiling
 * disappears.
 *
 * Scope (after Phase 1c)
 * ----------------------
 *   - Banner grab + service/version classification         (Phase 1a)
 *   - CVE lookup against shared read-only SQLite handle    (Phase 1a)
 *   - HTTP probe (GET /) on HTTP-ish ports                 (Phase 1b)
 *   - TLS handshake + X509 cert capture on HTTPS ports     (Phase 1c)
 *
 * What remains synchronous (the caller still does these in Stage B):
 *   - Reverse-DNS (PTR) lookup                             (Phase 1d)
 *   - ASN / whois lookup                                   (Phase 3)
 *
 * State machine, per port-item
 * ----------------------------
 *   STAGE_BANNER_CONNECT
 *       Issue nsock_connect_tcp on a fresh nsock_iod.
 *       Callback: on_banner_connect.
 *       success -> STAGE_BANNER_RECV
 *       failure -> port_done
 *
 *   STAGE_BANNER_RECV
 *       Callback: on_banner_recv.
 *       success: classify banner; if banner is HTTP response, save it as
 *                cached_http_response so the HTTP stage can reuse it.
 *                Dispatch based on (port, service) to HTTP / TLS / DONE.
 *       timeout/EOF: if port is HTTP-eligible and NOT TLS, fall through
 *                    to inline HTTP probe on the SAME socket
 *                    (STAGE_BANNER_HTTP_SEND) -- matches the synchronous
 *                    grab_banner() optimization.
 *
 *   STAGE_BANNER_HTTP_SEND  (only reached when initial recv was silent)
 *       Send the os_profile-built GET / request on the still-open banner
 *       socket.  Callback: on_banner_http_sent -> STAGE_BANNER_HTTP_RECV.
 *
 *   STAGE_BANNER_HTTP_RECV  (only reached after the above SEND)
 *       Accumulate response (multi-shot nsock_read up to BANNER_MAX).
 *       Callback: on_banner_http_recv.
 *       On terminal status (EOF/timeout/error) classify the accumulated
 *       buffer, save it as cached_http_response, then dispatch normally.
 *
 *   STAGE_HTTP_CONNECT
 *       (Skipped when cached_http_response is non-empty: parse it inline
 *       and go straight to port_done.)
 *       Fresh nsock_iod + nsock_connect_tcp.
 *       Callback: on_http_connect.
 *       success -> STAGE_HTTP_SEND
 *
 *   STAGE_HTTP_SEND
 *       nsock_write with the os_profile-built GET request.
 *       Callback: on_http_sent.  success -> STAGE_HTTP_RECV
 *
 *   STAGE_HTTP_RECV
 *       Accumulate response (multi-shot reads up to 64KB).
 *       Callback: on_http_recv.
 *       On terminal status, parse what we have and write out_web_*[port_idx],
 *       then port_done.  Empty/partial responses still write whatever the
 *       parsers can extract (a Server header with no body is still useful).
 *
 *   STAGE_TLS_CONNECT
 *       Fresh nsock_iod + nsock_connect_ssl (uses pool's shared SSL_CTX).
 *       Callback: on_tls_connect.
 *       success: synchronously extract X509 details (CPU only, microseconds),
 *                write (*out_tls)[port_idx], port_done.
 *       failure: port_done with TlsCapture left at default-init.
 *
 * Budget enforcement
 * ------------------
 * Each host has a steady_clock deadline = host_start +
 * KMAP_HOST_ENRICH_BUDGET_MS (default 15s, same env var the sync path
 * reads).  Every nsock event uses timeout = min(per_step_timeout,
 * budget_remaining), so the last step in a host's life cannot overshoot
 * its budget.  When budget expires mid-host, the next port_done finalizes
 * immediately.
 *
 * Concurrency model
 * -----------------
 * One nsock_pool, one calling thread.  nsock callbacks run on this
 * thread between nsock_loop() iterations -- never concurrently with the
 * code that submits new events -- so no mutex protects the per-host
 * state.  The SQLite handle is also touched from one thread only,
 * which is why integration callers should give each parallel worker its
 * own read-only cve_db handle (eliminating SQLite's serialization mutex
 * contention).
 *
 * Code shape
 * ----------
 * The classify_banner() / normalize_product() / lookup_cves_local() /
 * cves_to_json_local() helpers, plus the HTTP/TLS parsing helpers, are
 * deliberately copies of their synchronous counterparts in net_enrich.cc
 * (which are static there).  Duplication is preferred to invasive
 * refactors during this incremental migration; if you change the
 * classification or parsing logic in net_enrich.cc, update it here too --
 * they are meant to stay byte-for-byte identical.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_enrich_async.h"
#include "net_enrich.h"   /* TlsCapture + EnrichMetrics decls */
#include "os_profile.h"
#include "KmapOps.h"

#include "nsock.h"
#include "sqlite/sqlite3.h"

#include <string>
#include <vector>
#include <deque>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <chrono>
#include <atomic>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
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
 * Tunables
 * ----------------------------------------------------------------------- */

/* Maximum hosts the state machine will keep in flight at once.  The
   nsock event loop scales fine into the low thousands, but each in-flight
   host costs one FD per active port, one nsock_iod per active port, and
   one AsyncHostState heap entry.  64 keeps the per-worker memory
   footprint trivial and amortizes the nsock_loop kernel cost.  Override
   via KMAP_ASYNC_ENRICH_INFLIGHT. */
#define ASYNC_ENRICH_DEFAULT_INFLIGHT  64

/* Per-host wall-clock budget, in milliseconds.  Read from the same env
   var the sync path uses (KMAP_HOST_ENRICH_BUDGET_MS) so operators don't
   have to maintain two knobs.  Default 15000 ms = 15s, generous enough
   for a host with 5-10 slow-responding ports while bounding the worst
   case so one stuck host can't starve the pool. */
#define ASYNC_ENRICH_DEFAULT_BUDGET_MS  15000

/* Maximum bytes we'll read per banner.  Mirrors ENRICH_BANNER_MAX in
   net_enrich.cc.  Banners worth classifying are <200 bytes; the ceiling
   exists only to keep us from holding onto chargen-style data streams. */
#define ASYNC_ENRICH_BANNER_MAX  1024

/* Maximum bytes we'll accumulate per HTTP response.  Matches the sync
   probe_http (`while (response.size() < 65536)`).  Plenty for the
   <title>, Server header, and the headers JSON; anything bigger is
   either a large body we don't parse or a streaming response. */
#define ASYNC_ENRICH_HTTP_MAX    65536

/* -----------------------------------------------------------------------
 * Banner classification helpers (verbatim copies of net_enrich.cc shapes)
 * ----------------------------------------------------------------------- */

struct AsyncBannerResult {
  std::string service;
  std::string version;
  std::string http_response;  /* full raw response when banner was HTTP,
                                  used by the HTTP stage to skip a fresh
                                  TCP connect (mirrors sync grab_banner). */
};

static std::string a_str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}

/* classify_banner -- pattern-match a raw banner buffer to a service/version.
 *
 * MUST stay in sync with grab_banner() in net_enrich.cc lines 387-499.
 * The only difference is that this function does NOT do any I/O and does
 * NOT fall back to sending an HTTP probe on silent ports -- the calling
 * state machine handles that by chaining STAGE_BANNER_HTTP_SEND/RECV.
 *
 * If `n <= 0` returns an empty result (caller already handled).
 * port is used for ambiguous-220 disambiguation and HTTPS-port tagging.
 */
static AsyncBannerResult classify_banner(const char *buf, int n, int port) {
  AsyncBannerResult result;
  if (n <= 0 || !buf) return result;

  std::string banner(buf, static_cast<size_t>(n));
  std::string banner_lower = a_str_lower(banner);

  /* Extract first line for version parsing */
  std::string first_line = banner;
  size_t nl = first_line.find('\n');
  if (nl != std::string::npos) first_line = first_line.substr(0, nl);
  while (!first_line.empty() &&
         (first_line.back() == '\r' || first_line.back() == '\n'))
    first_line.pop_back();

  /* HTTP response */
  if (banner.size() >= 8 && banner.substr(0, 4) == "HTTP") {
    result.service = "http";
    result.http_response = banner;
    size_t spos = banner_lower.find("\nserver:");
    if (spos != std::string::npos) {
      spos += 8;
      while (spos < banner.size() && banner[spos] == ' ') spos++;
      size_t epos = banner.find('\r', spos);
      if (epos == std::string::npos) epos = banner.find('\n', spos);
      if (epos == std::string::npos) epos = banner.size();
      result.version = banner.substr(spos, epos - spos);
    }
    if (port == 443 || port == 8443 || port == 4443)
      result.service = "https";
    return result;
  }

  /* SSH */
  if (banner.size() >= 4 && banner.substr(0, 4) == "SSH-") {
    result.service = "ssh";
    size_t dash3 = banner.find('-', 4);
    if (dash3 != std::string::npos && dash3 + 1 < first_line.size()) {
      result.version = first_line.substr(dash3 + 1);
      std::replace(result.version.begin(), result.version.end(), '_', ' ');
    }
    return result;
  }

  /* FTP / SMTP 220 greeting */
  if (banner.size() >= 4 &&
      (banner.substr(0, 4) == "220 " || banner.substr(0, 4) == "220-")) {
    if (banner_lower.find("ftp") != std::string::npos) {
      result.service = "ftp";
    } else if (banner_lower.find("smtp") != std::string::npos ||
               banner_lower.find("mail") != std::string::npos ||
               banner_lower.find("esmtp") != std::string::npos) {
      result.service = "smtp";
    } else {
      if (port == 21) result.service = "ftp";
      else if (port == 25 || port == 587 || port == 465) result.service = "smtp";
      else result.service = "ftp";
    }
    result.version = first_line.substr(4);
    return result;
  }

  /* IMAP */
  if (banner.size() >= 4 && banner.substr(0, 4) == "* OK") {
    result.service = "imap";
    result.version = first_line.size() > 5 ? first_line.substr(5) : "";
    return result;
  }

  /* POP3 */
  if (banner.size() >= 3 && banner.substr(0, 3) == "+OK") {
    result.service = "pop3";
    result.version = first_line.size() > 4 ? first_line.substr(4) : "";
    return result;
  }

  /* MySQL handshake: pkt-len + protocol version 0x0a at offset 4 */
  if (n >= 5 && static_cast<unsigned char>(buf[4]) == 0x0a) {
    result.service = "mysql";
    const char *verp = buf + 5;
    size_t vlen = strnlen(verp,
                          static_cast<size_t>(n) > 5 ? static_cast<size_t>(n) - 5 : 0);
    if (vlen > 0) result.version = std::string(verp, vlen);
    return result;
  }

  /* Redis */
  if (banner_lower.find("-err") == 0 || banner_lower.find("+pong") == 0 ||
      banner_lower.find("$") == 0) {
    result.service = "redis";
    return result;
  }

  /* MongoDB wire protocol OP_REPLY */
  if (n >= 16 && static_cast<unsigned char>(buf[12]) == 0x01) {
    result.service = "mongodb";
    return result;
  }

  /* PostgreSQL 'R' authentication response */
  if (n >= 9 && buf[0] == 'R') {
    result.service = "postgresql";
    return result;
  }

  /* Unknown fallback */
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
 * CVE lookup helpers (copies of static helpers in net_enrich.cc).
 * Keep in sync with lookup_cves / normalize_product / extract_version_number /
 * ver_cmp_enrich / cves_to_json in net_enrich.cc.  Same Tier-1 precision
 * rules: empty product -> no match; bounded rows do real numeric compare;
 * empty det_ver -> no match.
 * ----------------------------------------------------------------------- */

struct AsyncEnrichCve {
  std::string id;
  float       cvss;
  std::string severity;
  std::string description;
  std::string cvss_vector;
  int         remote_unauthed = -1;
};

static int a_ver_cmp(const std::string &a, const std::string &b) {
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

/* RFC 8259 JSON string escaping. Escapes structural chars plus ALL control
   characters U+0000..U+001F (network banners/headers/TLS fields contain raw
   control bytes; emitting them unescaped produced invalid JSON). unsigned
   char iteration so UTF-8 high bytes are passed through, not mis-escaped. */
static std::string a_json_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b";  break;
      case '\f': out += "\\f";  break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

static std::string a_normalize_product(const std::string &service,
                                       const std::string &version) {
  std::string svc = a_str_lower(service);
  std::string ver = a_str_lower(version);

  if (svc == "ssh" || ver.find("ssh") != std::string::npos) {
    /* Non-OpenSSH variants: refuse match. */
    if (ver.find("aws_sftp")  != std::string::npos ||
        ver.find("aws sftp")  != std::string::npos ||
        ver.find("aws-sftp")  != std::string::npos) return "";
    if (ver.find("dropbear")  != std::string::npos) return "";
    if (ver.find("bitvise")   != std::string::npos ||
        ver.find("wsshd")     != std::string::npos) return "";
    if (ver.find("tectia")    != std::string::npos ||
        ver.find("sshcom")    != std::string::npos) return "";
    if (ver.find("erlangshell") != std::string::npos ||
        ver.find("erlang")    != std::string::npos) return "";
    if (ver.find("paramiko")  != std::string::npos) return "";
    if (ver.find("libssh")    != std::string::npos &&
        ver.find("openssh")   == std::string::npos) return "";
    if (ver.find("openssh")   != std::string::npos) return "openssh";
    return "";
  }
  if (ver.find("apache") != std::string::npos &&
      (ver.find("http") != std::string::npos || svc == "http"))
    return "http_server";
  if (ver.find("nginx")        != std::string::npos) return "nginx";
  if (ver.find("lighttpd")     != std::string::npos) return "lighttpd";
  if (ver.find("iis")          != std::string::npos) return "iis";
  if (ver.find("tomcat")       != std::string::npos) return "tomcat";
  if (ver.find("mysql")        != std::string::npos || svc == "mysql")
    return "mysql";
  if (ver.find("mariadb")      != std::string::npos) return "mariadb";
  if (ver.find("postgresql")   != std::string::npos || svc == "postgresql")
    return "postgresql";
  if (ver.find("redis")        != std::string::npos || svc == "redis")
    return "redis";
  if (ver.find("mongodb")      != std::string::npos || svc == "mongodb")
    return "mongodb";
  if (ver.find("vsftpd")       != std::string::npos) return "vsftpd";
  if (ver.find("proftpd")      != std::string::npos) return "proftpd";
  if (ver.find("samba")        != std::string::npos) return "samba";
  if (ver.find("elasticsearch")!= std::string::npos) return "elasticsearch";
  if (ver.find("jenkins")      != std::string::npos) return "jenkins";
  if (ver.find("php")          != std::string::npos) return "php";
  if (ver.find("wordpress")    != std::string::npos) return "wordpress";

  return "";
}

static std::string a_extract_version_number(const std::string &s) {
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

static std::vector<AsyncEnrichCve> a_lookup_cves(sqlite3 *cve_db,
                                                 const std::string &service,
                                                 const std::string &version) {
  std::vector<AsyncEnrichCve> results;
  if (!cve_db) return results;

  std::string product = a_normalize_product(service, version);
  if (product.empty()) return results;

  std::string det_ver = a_extract_version_number(version);
  if (det_ver.empty()) return results;

  const char *sql =
    "SELECT cve_id, cvss_score, severity, description, "
    "version_min, version_max, cvss_vector, remote_unauthed "
    "FROM cves WHERE product = ? AND cvss_score >= 0.0 "
    "ORDER BY cvss_score DESC LIMIT 100";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(cve_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return results;
  sqlite3_bind_text(stmt, 1, product.c_str(), -1, SQLITE_TRANSIENT);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    auto col_str = [&](int c) -> std::string {
      const unsigned char *p = sqlite3_column_text(stmt, c);
      return p ? reinterpret_cast<const char *>(p) : "";
    };
    std::string vmin = col_str(4);
    std::string vmax = col_str(5);
    if (!vmin.empty() && a_ver_cmp(det_ver, vmin) < 0) continue;
    if (!vmax.empty() && a_ver_cmp(det_ver, vmax) > 0) continue;

    AsyncEnrichCve e;
    e.id          = col_str(0);
    e.cvss        = static_cast<float>(sqlite3_column_double(stmt, 1));
    e.severity    = col_str(2);
    e.description = col_str(3);
    e.cvss_vector = col_str(6);
    e.remote_unauthed = (sqlite3_column_type(stmt, 7) == SQLITE_NULL)
                          ? -1
                          : sqlite3_column_int(stmt, 7);
    results.push_back(std::move(e));
  }
  sqlite3_finalize(stmt);
  return results;
}

static std::string a_cves_to_json(const std::vector<AsyncEnrichCve> &cves) {
  if (cves.empty()) return "";
  std::ostringstream oss;
  oss << "[";
  for (size_t i = 0; i < cves.size(); i++) {
    if (i > 0) oss << ",";
    char cvss_buf[16];
    snprintf(cvss_buf, sizeof(cvss_buf), "%.1f", cves[i].cvss);
    std::string desc = cves[i].description;
    if (desc.size() > 200) desc = desc.substr(0, 197) + "...";
    oss << "{\"id\":\"" << a_json_escape(cves[i].id)
        << "\",\"cvss\":" << cvss_buf
        << ",\"severity\":\"" << a_json_escape(cves[i].severity)
        << "\",\"desc\":\"" << a_json_escape(desc) << "\"";
    if (!cves[i].cvss_vector.empty())
      oss << ",\"vec\":\"" << a_json_escape(cves[i].cvss_vector) << "\"";
    if (cves[i].remote_unauthed >= 0)
      oss << ",\"remote\":" << cves[i].remote_unauthed;
    oss << "}";
  }
  oss << "]";
  return oss.str();
}

/* -----------------------------------------------------------------------
 * HTTP/HTTPS port classification (copies of net_enrich.cc helpers).
 * ----------------------------------------------------------------------- */

static bool a_is_http_port(int port, const std::string &service) {
  std::string svc = a_str_lower(service);
  if (svc.find("http") != std::string::npos) return true;
  if (port == 80 || port == 443 || port == 8080 || port == 8443 ||
      port == 8000 || port == 8888 || port == 3000 || port == 4443 ||
      port == 9090 || port == 9443)
    return true;
  return false;
}

static bool a_is_https_port(int port, const std::string &service) {
  std::string svc = a_str_lower(service);
  if (svc == "https" || svc.find("ssl") != std::string::npos) return true;
  return port == 443 || port == 4443 || port == 8443 || port == 9443;
}

/* TLS-port heuristic for the inline-HTTP-on-silent-banner fallback.
   Matches net_enrich.cc::grab_banner: we DO NOT send plaintext GET / on
   known-TLS ports because a TLS server waits for a ClientHello, so the
   probe just elicits a TLS Alert and wastes a recv timeout. */
static bool a_banner_is_tls_port(int port) {
  return port == 443 || port == 4443 || port == 8443 || port == 9443;
}

/* -----------------------------------------------------------------------
 * HTTP response parsing helpers (copies of static helpers in
 * net_enrich.cc -- extract_header_val / extract_html_title / extract_status).
 * Replicated rather than linked to keep the migration self-contained.
 * ----------------------------------------------------------------------- */

static std::string a_extract_header_val(const std::string &resp,
                                        const char *name) {
  std::string lower_resp = a_str_lower(resp);
  std::string lower_name = a_str_lower(std::string(name));
  /* Anchor to start of header line so a search for "Server" does not
     match "X-Server:" or "Last-Modified-Server:". */
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

static std::string a_extract_html_title(const std::string &body) {
  std::string lower = a_str_lower(body);
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

static int a_extract_status(const std::string &resp) {
  if (resp.size() < 12) return 0;
  if (resp.substr(0, 4) != "HTTP") return 0;
  size_t sp = resp.find(' ');
  if (sp == std::string::npos || sp + 3 >= resp.size()) return 0;
  char c1 = resp[sp + 1], c2 = resp[sp + 2], c3 = resp[sp + 3];
  if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9' || c3 < '0' || c3 > '9')
    return 0;
  return (c1 - '0') * 100 + (c2 - '0') * 10 + (c3 - '0');
}

/* WebResult mirrors the synchronous probe_http output. */
struct AsyncWebResult {
  std::string title;
  std::string server;
  std::string headers_json;
  std::string paths_json;
  std::string powered_by;
  std::string x_generator;
  std::string redirect_target;
};

/* Parse an accumulated HTTP response into structured fields.  Same
   shape as net_enrich.cc::probe_http -- only the I/O changes. */
static AsyncWebResult a_parse_http_response(const std::string &response) {
  AsyncWebResult wr;
  if (response.empty()) return wr;

  size_t body_start = response.find("\r\n\r\n");
  std::string body = (body_start != std::string::npos)
                     ? response.substr(body_start + 4) : "";

  wr.title           = a_extract_html_title(body);
  wr.server          = a_extract_header_val(response, "Server");
  wr.powered_by      = a_extract_header_val(response, "X-Powered-By");
  wr.x_generator     = a_extract_header_val(response, "X-Generator");
  wr.redirect_target = a_extract_header_val(response, "Location");

  std::ostringstream hdr_json;
  hdr_json << "{";
  bool first = true;
  const char *interesting[] = {
    "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
    "X-Frame-Options", "Content-Type", "Set-Cookie", nullptr
  };
  for (const char **hp = interesting; *hp; hp++) {
    std::string val = a_extract_header_val(response, *hp);
    if (!val.empty()) {
      if (!first) hdr_json << ",";
      hdr_json << "\"" << a_json_escape(*hp) << "\":\""
               << a_json_escape(val) << "\"";
      first = false;
    }
  }
  hdr_json << "}";
  if (!first) wr.headers_json = hdr_json.str();

  int status = a_extract_status(response);
  if (status > 0) {
    std::ostringstream paths_json;
    paths_json << "[{\"path\":\"/\",\"status\":" << status;
    if (!wr.title.empty())
      paths_json << ",\"title\":\"" << a_json_escape(wr.title) << "\"";
    paths_json << "}]";
    wr.paths_json = paths_json.str();
  }

  return wr;
}

/* -----------------------------------------------------------------------
 * Per-host / per-port state
 * ----------------------------------------------------------------------- */

/* Stage in a single port's pipeline.  All ports of a host run their own
   pipelines concurrently; stages live per-port. */
enum AsyncStage {
  STAGE_BANNER_CONNECT,
  STAGE_BANNER_RECV,
  STAGE_BANNER_HTTP_SEND,   /* inline GET / on silent banner socket */
  STAGE_BANNER_HTTP_RECV,
  STAGE_HTTP_CONNECT,
  STAGE_HTTP_SEND,
  STAGE_HTTP_RECV,
  STAGE_TLS_CONNECT,
  STAGE_DONE
};

struct AsyncHostState;  /* fwd */

/* Per-port work item.  Each port runs its full pipeline (banner -> CVE
   -> HTTP or TLS) independently of its sibling ports on the same host. */
struct AsyncPortItem {
  AsyncHostState *host;
  size_t          port_idx;
  int             port_num;
  AsyncStage      stage;
  nsock_iod       iod;

  /* Banner buffer carried across the optional STAGE_BANNER_HTTP_RECV
     loop.  When the initial recv produced nothing and we fired an
     inline GET /, we accumulate the response here until EOF/timeout. */
  std::string     banner_buf;

  /* Classified banner result, populated once at end of banner stage and
     consulted by the dispatcher to pick HTTP vs TLS vs DONE. */
  AsyncBannerResult banner_class;

  /* Request bytes for HTTP probe stages.  Stored on the item so the
     buffer outlives the nsock_write call (nsock copies but we still
     want a stable owner across the SEND -> RECV transition). */
  std::string     http_request;

  /* Accumulated HTTP response (across multi-shot reads). */
  std::string     http_response;

  AsyncPortItem()
    : host(nullptr), port_idx(0), port_num(0),
      stage(STAGE_BANNER_CONNECT), iod(NULL) {}
};

struct AsyncHostState {
  /* Input view */
  size_t       batch_idx;
  std::string  ip;
  const std::vector<int> *ports;

  /* Output sinks (pointers into the per-host inner vectors that
     async_enrich_batch has pre-sized).  When out_tls_per_host is NULL
     the caller didn't want TLS captures, so out_tls is NULL too. */
  std::vector<std::string> *out_services;
  std::vector<std::string> *out_versions;
  std::vector<std::string> *out_cves;
  std::vector<std::string> *out_web_titles;
  std::vector<std::string> *out_web_servers;
  std::vector<std::string> *out_web_headers;
  std::vector<std::string> *out_web_paths;
  std::vector<std::string> *out_powered_by;
  std::vector<std::string> *out_x_generator;
  std::vector<std::string> *out_redirects;
  std::vector<TlsCapture>  *out_tls;       /* may be NULL */

  std::vector<AsyncPortItem> port_items;
  std::atomic<int> ports_remaining{0};

  struct sockaddr_storage ss;
  socklen_t    sslen;
  bool         addr_ok;

  std::chrono::steady_clock::time_point deadline;
};

/* -----------------------------------------------------------------------
 * Batch driver -- owns pool, queue, active set
 * ----------------------------------------------------------------------- */

struct AsyncEnrichBatch {
  nsock_pool   pool;
#ifdef HAVE_OPENSSL
  /* Shared SSL_CTX initialized once on the pool.  nsock owns this; we
     just need to know it was successfully created before issuing any
     nsock_connect_ssl calls. */
  bool         ssl_ctx_ready;
#endif
  sqlite3     *cve_db;
  int          per_step_timeout_ms;
  int          budget_ms;
  size_t       max_in_flight;

  std::deque<AsyncHostState> hosts;
  std::deque<size_t>    pending_idx;
  size_t                active_count;

  std::atomic<uint64_t> hosts_completed;
  std::atomic<uint64_t> ports_attempted;
  std::atomic<uint64_t> banners_classified;
  std::atomic<uint64_t> http_ok;
  std::atomic<uint64_t> tls_ok;
  std::atomic<uint64_t> budget_bails;
};

/* Forward declarations for the callback web. */
static void on_banner_connect    (nsock_pool, nsock_event, void *);
static void on_banner_recv       (nsock_pool, nsock_event, void *);
static void on_banner_http_sent  (nsock_pool, nsock_event, void *);
static void on_banner_http_recv  (nsock_pool, nsock_event, void *);
static void on_http_connect      (nsock_pool, nsock_event, void *);
static void on_http_sent         (nsock_pool, nsock_event, void *);
static void on_http_recv         (nsock_pool, nsock_event, void *);
static void on_tls_connect       (nsock_pool, nsock_event, void *);

static void submit_port_connect  (AsyncEnrichBatch *b, AsyncPortItem *p);
static void dispatch_after_banner(AsyncEnrichBatch *b, AsyncPortItem *p);
static void submit_http_connect  (AsyncEnrichBatch *b, AsyncPortItem *p);
static void submit_http_send     (AsyncEnrichBatch *b, AsyncPortItem *p);
static void submit_tls_connect   (AsyncEnrichBatch *b, AsyncPortItem *p);
static void parse_and_store_http (AsyncEnrichBatch *b, AsyncPortItem *p,
                                  const std::string &response);
static void port_done            (AsyncEnrichBatch *b, AsyncPortItem *p);
static void finalize_host        (AsyncEnrichBatch *b, AsyncHostState *h);
static void try_admit            (AsyncEnrichBatch *b);

/* Compute remaining ms until host deadline, clamped to [0, INT_MAX]. */
static int remaining_ms(const AsyncHostState *h) {
  auto now = std::chrono::steady_clock::now();
  if (now >= h->deadline) return 0;
  auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
                h->deadline - now).count();
  if (rem > 2000000000) rem = 2000000000;
  return static_cast<int>(rem);
}

/* Step timeout: the smaller of (operator-configured per-step) and
   (remaining budget). */
static int step_timeout(const AsyncEnrichBatch *b, const AsyncHostState *h) {
  int rem = remaining_ms(h);
  return b->per_step_timeout_ms < rem ? b->per_step_timeout_ms : rem;
}

/* Parse a textual IP into a sockaddr_storage. */
static bool resolve_ip(const std::string &ip, struct sockaddr_storage *ss,
                       socklen_t *sslen) {
  std::memset(ss, 0, sizeof(*ss));
  struct sockaddr_in  *sa4 = reinterpret_cast<struct sockaddr_in  *>(ss);
  struct sockaddr_in6 *sa6 = reinterpret_cast<struct sockaddr_in6 *>(ss);
  if (inet_pton(AF_INET, ip.c_str(), &sa4->sin_addr) == 1) {
    sa4->sin_family = AF_INET;
    *sslen = sizeof(struct sockaddr_in);
    return true;
  }
  if (inet_pton(AF_INET6, ip.c_str(), &sa6->sin6_addr) == 1) {
    sa6->sin6_family = AF_INET6;
    *sslen = sizeof(struct sockaddr_in6);
    return true;
  }
  return false;
}

/* Close the port's iod if open. */
static void close_iod(AsyncPortItem *p) {
  if (p->iod) {
    nsock_iod_delete(p->iod, NSOCK_PENDING_SILENT);
    p->iod = NULL;
  }
}

/* -----------------------------------------------------------------------
 * Stage: BANNER_CONNECT / BANNER_RECV
 * ----------------------------------------------------------------------- */

static void submit_port_connect(AsyncEnrichBatch *b, AsyncPortItem *p) {
  AsyncHostState *h = p->host;
  int to = step_timeout(b, h);
  if (to <= 0) { port_done(b, p); return; }

  p->iod = nsock_iod_new(b->pool, p);
  if (p->iod == NULL) { port_done(b, p); return; }

  p->stage = STAGE_BANNER_CONNECT;
  b->ports_attempted.fetch_add(1, std::memory_order_relaxed);

  nsock_connect_tcp(b->pool, p->iod, on_banner_connect, to, p,
                    reinterpret_cast<struct sockaddr *>(&h->ss),
                    h->sslen, static_cast<unsigned short>(p->port_num));
}

static void on_banner_connect(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncPortItem *p = static_cast<AsyncPortItem *>(udata);
  enum nse_status st = nse_status(nse);

  if (st == NSE_STATUS_KILL) { p->iod = NULL; return; }

  if (st == NSE_STATUS_SUCCESS) {
    int to = step_timeout(b, p->host);
    if (to <= 0) { close_iod(p); port_done(b, p); return; }
    p->stage = STAGE_BANNER_RECV;
    nsock_read(b->pool, p->iod, on_banner_recv, to, p);
    return;
  }

  close_iod(p);
  port_done(b, p);
}

static void on_banner_recv(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncPortItem *p = static_cast<AsyncPortItem *>(udata);
  AsyncHostState *h = p->host;
  enum nse_status st = nse_status(nse);

  if (st == NSE_STATUS_KILL) { p->iod = NULL; return; }

  if (st == NSE_STATUS_SUCCESS) {
    int nbytes = 0;
    char *rb = nse_readbuf(nse, &nbytes);
    if (nbytes > ASYNC_ENRICH_BANNER_MAX) nbytes = ASYNC_ENRICH_BANNER_MAX;

    p->banner_class = classify_banner(rb, nbytes, p->port_num);
    dispatch_after_banner(b, p);
    return;
  }

  /* No banner data.  Mirror sync grab_banner(): on non-TLS ports, send an
     inline GET / on the still-open socket and try again.  Skip on TLS
     ports (plaintext on TLS is wasted) and when the port is not
     HTTP-eligible (sending GET / to mysqld pollutes nothing useful). */
  if (!a_banner_is_tls_port(p->port_num) &&
      a_is_http_port(p->port_num, "")) {
    int to = step_timeout(b, h);
    if (to > 0) {
      /* Build the HTTP probe once and stash on the item so the buffer
         lives across the async send. */
      p->http_request = os_profile_http_request(
          "/", h->ip.c_str(),
          os_profile_get_for_target(o.spoof_os,
                                    os_profile_seed_from_text(h->ip.c_str())));
      p->stage = STAGE_BANNER_HTTP_SEND;
      nsock_write(b->pool, p->iod, on_banner_http_sent, to, p,
                  p->http_request.data(),
                  static_cast<int>(p->http_request.size()));
      return;
    }
  }

  /* No fallback applicable -- finish banner stage with empty result and
     dispatch (will end up at STAGE_DONE for non-HTTP/TLS ports). */
  close_iod(p);
  dispatch_after_banner(b, p);
}

static void on_banner_http_sent(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncPortItem *p = static_cast<AsyncPortItem *>(udata);
  enum nse_status st = nse_status(nse);

  if (st == NSE_STATUS_KILL) { p->iod = NULL; return; }

  if (st != NSE_STATUS_SUCCESS) {
    close_iod(p);
    dispatch_after_banner(b, p);
    return;
  }

  int to = step_timeout(b, p->host);
  if (to <= 0) { close_iod(p); dispatch_after_banner(b, p); return; }
  p->stage = STAGE_BANNER_HTTP_RECV;
  p->banner_buf.clear();
  nsock_read(b->pool, p->iod, on_banner_http_recv, to, p);
}

static void on_banner_http_recv(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncPortItem *p = static_cast<AsyncPortItem *>(udata);
  enum nse_status st = nse_status(nse);

  if (st == NSE_STATUS_KILL) { p->iod = NULL; return; }

  if (st == NSE_STATUS_SUCCESS) {
    int nbytes = 0;
    char *rb = nse_readbuf(nse, &nbytes);
    if (nbytes > 0 && rb) {
      size_t cap = ASYNC_ENRICH_BANNER_MAX - p->banner_buf.size();
      size_t take = (static_cast<size_t>(nbytes) < cap)
                      ? static_cast<size_t>(nbytes) : cap;
      if (take > 0) p->banner_buf.append(rb, take);
    }

    /* Keep accumulating up to BANNER_MAX. */
    if (p->banner_buf.size() < ASYNC_ENRICH_BANNER_MAX) {
      int to = step_timeout(b, p->host);
      if (to > 0) {
        nsock_read(b->pool, p->iod, on_banner_http_recv, to, p);
        return;
      }
    }
  }

  /* Terminal: classify whatever we collected. */
  p->banner_class = classify_banner(p->banner_buf.data(),
                                    static_cast<int>(p->banner_buf.size()),
                                    p->port_num);
  close_iod(p);
  dispatch_after_banner(b, p);
}

/* After the banner stage completes (with or without data), write the
   service/version/cves outputs and pick the next stage. */
static void dispatch_after_banner(AsyncEnrichBatch *b, AsyncPortItem *p) {
  AsyncHostState *h = p->host;
  const AsyncBannerResult &br = p->banner_class;

  if (!br.service.empty()) {
    (*h->out_services)[p->port_idx] = br.service;
    b->banners_classified.fetch_add(1, std::memory_order_relaxed);
  }
  if (!br.version.empty()) {
    (*h->out_versions)[p->port_idx] = br.version;
  }
  if (b->cve_db && !br.service.empty()) {
    std::vector<AsyncEnrichCve> cves =
      a_lookup_cves(b->cve_db, br.service, br.version);
    (*h->out_cves)[p->port_idx] = a_cves_to_json(cves);
  }

  /* Branch.  Same logic as enrich_single_host's per-port worker. */
  bool is_https = a_is_https_port(p->port_num, br.service);
  bool is_http  = a_is_http_port (p->port_num, br.service) && !is_https;

  if (is_http) {
    /* Cached-response optimization: if banner already captured an HTTP
       response, parse it and skip the second connect. */
    if (!br.http_response.empty()) {
      parse_and_store_http(b, p, br.http_response);
      port_done(b, p);
      return;
    }
    submit_http_connect(b, p);
    return;
  }

  if (is_https && h->out_tls) {
    submit_tls_connect(b, p);
    return;
  }

  /* Nothing more to do for this port. */
  port_done(b, p);
}

/* -----------------------------------------------------------------------
 * Stage: HTTP_CONNECT / HTTP_SEND / HTTP_RECV
 * ----------------------------------------------------------------------- */

static void submit_http_connect(AsyncEnrichBatch *b, AsyncPortItem *p) {
  AsyncHostState *h = p->host;
  int to = step_timeout(b, h);
  if (to <= 0) { port_done(b, p); return; }

  p->iod = nsock_iod_new(b->pool, p);
  if (p->iod == NULL) { port_done(b, p); return; }

  p->stage = STAGE_HTTP_CONNECT;
  p->http_response.clear();

  nsock_connect_tcp(b->pool, p->iod, on_http_connect, to, p,
                    reinterpret_cast<struct sockaddr *>(&h->ss),
                    h->sslen, static_cast<unsigned short>(p->port_num));
}

static void on_http_connect(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncPortItem *p = static_cast<AsyncPortItem *>(udata);
  enum nse_status st = nse_status(nse);

  if (st == NSE_STATUS_KILL) { p->iod = NULL; return; }

  if (st != NSE_STATUS_SUCCESS) {
    close_iod(p);
    port_done(b, p);
    return;
  }

  submit_http_send(b, p);
}

static void submit_http_send(AsyncEnrichBatch *b, AsyncPortItem *p) {
  AsyncHostState *h = p->host;
  int to = step_timeout(b, h);
  if (to <= 0) { close_iod(p); port_done(b, p); return; }

  p->http_request = os_profile_http_request(
      "/", h->ip.c_str(),
      os_profile_get_for_target(o.spoof_os,
                                os_profile_seed_from_text(h->ip.c_str())));

  p->stage = STAGE_HTTP_SEND;
  nsock_write(b->pool, p->iod, on_http_sent, to, p,
              p->http_request.data(),
              static_cast<int>(p->http_request.size()));
}

static void on_http_sent(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncPortItem *p = static_cast<AsyncPortItem *>(udata);
  enum nse_status st = nse_status(nse);

  if (st == NSE_STATUS_KILL) { p->iod = NULL; return; }

  if (st != NSE_STATUS_SUCCESS) {
    close_iod(p);
    /* Send failed: nothing to parse, finalize with empty web fields. */
    port_done(b, p);
    return;
  }

  int to = step_timeout(b, p->host);
  if (to <= 0) { close_iod(p); port_done(b, p); return; }
  p->stage = STAGE_HTTP_RECV;
  p->http_response.clear();
  p->http_response.reserve(4096);
  nsock_read(b->pool, p->iod, on_http_recv, to, p);
}

static void on_http_recv(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncPortItem *p = static_cast<AsyncPortItem *>(udata);
  enum nse_status st = nse_status(nse);

  if (st == NSE_STATUS_KILL) { p->iod = NULL; return; }

  if (st == NSE_STATUS_SUCCESS) {
    int nbytes = 0;
    char *rb = nse_readbuf(nse, &nbytes);
    if (nbytes > 0 && rb) {
      size_t cap = ASYNC_ENRICH_HTTP_MAX - p->http_response.size();
      size_t take = (static_cast<size_t>(nbytes) < cap)
                      ? static_cast<size_t>(nbytes) : cap;
      if (take > 0) p->http_response.append(rb, take);
    }

    /* Keep reading until we hit cap, EOF, or timeout.  Matches the sync
       probe_http loop which reads up to 64K. */
    if (p->http_response.size() < ASYNC_ENRICH_HTTP_MAX) {
      int to = step_timeout(b, p->host);
      if (to > 0) {
        nsock_read(b->pool, p->iod, on_http_recv, to, p);
        return;
      }
    }
  }

  /* Terminal: parse whatever we accumulated and write outputs. */
  if (!p->http_response.empty()) {
    parse_and_store_http(b, p, p->http_response);
  }
  close_iod(p);
  port_done(b, p);
}

static void parse_and_store_http(AsyncEnrichBatch *b, AsyncPortItem *p,
                                 const std::string &response) {
  AsyncWebResult wr = a_parse_http_response(response);
  AsyncHostState *h = p->host;
  (*h->out_web_titles)  [p->port_idx] = wr.title;
  (*h->out_web_servers) [p->port_idx] = wr.server;
  (*h->out_web_headers) [p->port_idx] = wr.headers_json;
  (*h->out_web_paths)   [p->port_idx] = wr.paths_json;
  (*h->out_powered_by)  [p->port_idx] = wr.powered_by;
  (*h->out_x_generator) [p->port_idx] = wr.x_generator;
  (*h->out_redirects)   [p->port_idx] = wr.redirect_target;
  if (!wr.server.empty() || !wr.title.empty() || !wr.headers_json.empty())
    b->http_ok.fetch_add(1, std::memory_order_relaxed);
}

/* -----------------------------------------------------------------------
 * Stage: TLS_CONNECT  (HAVE_OPENSSL only; no-op otherwise)
 * ----------------------------------------------------------------------- */

#ifdef HAVE_OPENSSL
/* Extract X509 details from an SSL session into a TlsCapture.  Same
   walk as net_enrich.cc::tls_capture_cert -- only the I/O lead-in
   differs (the connect is async, the extraction is sync because it's
   pure CPU work in the microseconds range). */
static void extract_cert_into(SSL *ssl, TlsCapture &out) {
  const char *proto = SSL_get_version(ssl);
  if (proto) out.protocol = proto;

  X509 *cert = SSL_get_peer_certificate(ssl);
  if (!cert) return;

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
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio) {
      ASN1_TIME_print(bio, exp);
      char tbuf[64]{};
      BIO_read(bio, tbuf, sizeof(tbuf) - 1);
      BIO_free(bio);
      out.not_after = tbuf;
    }
  }

  out.self_signed =
    (X509_NAME_cmp(X509_get_subject_name(cert),
                   X509_get_issuer_name(cert)) == 0) ? 1 : 0;

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
          oss << "\"" << a_json_escape(std::string(val, static_cast<size_t>(len)))
              << "\"";
          first = false;
        }
      }
    }
    oss << "]";
    if (!first) out.san_json = oss.str();
    GENERAL_NAMES_free(sans);
  }

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
#endif /* HAVE_OPENSSL */

static void submit_tls_connect(AsyncEnrichBatch *b, AsyncPortItem *p) {
  AsyncHostState *h = p->host;

#ifdef HAVE_OPENSSL
  if (!b->ssl_ctx_ready) { port_done(b, p); return; }

  int to = step_timeout(b, h);
  if (to <= 0) { port_done(b, p); return; }

  p->iod = nsock_iod_new(b->pool, p);
  if (p->iod == NULL) { port_done(b, p); return; }

  p->stage = STAGE_TLS_CONNECT;
  nsock_connect_ssl(b->pool, p->iod, on_tls_connect, to, p,
                    reinterpret_cast<struct sockaddr *>(&h->ss),
                    h->sslen, IPPROTO_TCP,
                    static_cast<unsigned short>(p->port_num),
                    NULL /* no resumed session */);
#else
  (void)h;
  port_done(b, p);
#endif
}

static void on_tls_connect(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncPortItem *p = static_cast<AsyncPortItem *>(udata);
  enum nse_status st = nse_status(nse);

  if (st == NSE_STATUS_KILL) { p->iod = NULL; return; }

#ifdef HAVE_OPENSSL
  if (st == NSE_STATUS_SUCCESS && p->iod && p->host->out_tls) {
    SSL *ssl = static_cast<SSL *>(nsock_iod_get_ssl(p->iod));
    if (ssl) {
      extract_cert_into(ssl, (*p->host->out_tls)[p->port_idx]);
      b->tls_ok.fetch_add(1, std::memory_order_relaxed);
    }
  }
#else
  (void)st;
#endif

  close_iod(p);
  port_done(b, p);
}

/* -----------------------------------------------------------------------
 * Port / host finalization
 * ----------------------------------------------------------------------- */

static void port_done(AsyncEnrichBatch *b, AsyncPortItem *p) {
  p->stage = STAGE_DONE;
  AsyncHostState *h = p->host;
  int remaining = h->ports_remaining.fetch_sub(1, std::memory_order_acq_rel) - 1;
  if (remaining > 0) return;

  if (remaining_ms(h) == 0) {
    b->budget_bails.fetch_add(1, std::memory_order_relaxed);
  }
  finalize_host(b, h);
}

static void finalize_host(AsyncEnrichBatch *b, AsyncHostState *h) {
  (void)h;
  b->active_count--;
  b->hosts_completed.fetch_add(1, std::memory_order_relaxed);
  try_admit(b);
}

static void try_admit(AsyncEnrichBatch *b) {
  while (b->active_count < b->max_in_flight && !b->pending_idx.empty()) {
    size_t idx = b->pending_idx.front();
    b->pending_idx.pop_front();
    AsyncHostState *h = &b->hosts[idx];

    if (h->ports->empty()) {
      b->hosts_completed.fetch_add(1, std::memory_order_relaxed);
      continue;
    }

    if (!resolve_ip(h->ip, &h->ss, &h->sslen)) {
      b->hosts_completed.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    h->addr_ok = true;
    h->deadline = std::chrono::steady_clock::now() +
                  std::chrono::milliseconds(b->budget_ms);

    size_t nports = h->ports->size();
    h->port_items.clear();
    h->port_items.reserve(nports);
    h->ports_remaining.store(static_cast<int>(nports),
                             std::memory_order_relaxed);
    b->active_count++;

    for (size_t pi = 0; pi < nports; pi++) {
      AsyncPortItem item;
      item.host     = h;
      item.port_idx = pi;
      item.port_num = (*h->ports)[pi];
      item.stage    = STAGE_BANNER_CONNECT;
      item.iod      = NULL;
      h->port_items.push_back(item);
    }
    for (size_t pi = 0; pi < nports; pi++) {
      submit_port_connect(b, &h->port_items[pi]);
    }
  }
}

/* -----------------------------------------------------------------------
 * Public entry point
 * ----------------------------------------------------------------------- */

int async_enrich_batch(
    const std::vector<std::string> &ips,
    const std::vector<std::vector<int>> &ports_per_host,
    int timeout_ms,
    sqlite3 *cve_db,
    std::vector<std::vector<std::string>> &out_services_per_host,
    std::vector<std::vector<std::string>> &out_versions_per_host,
    std::vector<std::vector<std::string>> &out_cves_per_host,
    std::vector<std::vector<std::string>> &out_web_titles_per_host,
    std::vector<std::vector<std::string>> &out_web_servers_per_host,
    std::vector<std::vector<std::string>> &out_web_headers_per_host,
    std::vector<std::vector<std::string>> &out_web_paths_per_host,
    std::vector<std::vector<std::string>> &out_powered_by_per_host,
    std::vector<std::vector<std::string>> &out_x_generator_per_host,
    std::vector<std::vector<std::string>> &out_redirects_per_host,
    std::vector<std::vector<TlsCapture>> *out_tls_per_host)
{
  size_t N = ips.size();
  if (ports_per_host.size() != N) {
    return 0;
  }

  /* Pre-size outer vectors. */
  out_services_per_host.assign  (N, std::vector<std::string>{});
  out_versions_per_host.assign  (N, std::vector<std::string>{});
  out_cves_per_host    .assign  (N, std::vector<std::string>{});
  out_web_titles_per_host.assign(N, std::vector<std::string>{});
  out_web_servers_per_host.assign(N, std::vector<std::string>{});
  out_web_headers_per_host.assign(N, std::vector<std::string>{});
  out_web_paths_per_host.assign (N, std::vector<std::string>{});
  out_powered_by_per_host.assign(N, std::vector<std::string>{});
  out_x_generator_per_host.assign(N, std::vector<std::string>{});
  out_redirects_per_host.assign (N, std::vector<std::string>{});
  if (out_tls_per_host)
    out_tls_per_host->assign(N, std::vector<TlsCapture>{});

  /* Pre-size inner vectors so callbacks can write
     (*h->out_*)[port_idx] = ... without resizing under our feet. */
  for (size_t i = 0; i < N; i++) {
    size_t p = ports_per_host[i].size();
    out_services_per_host  [i].assign(p, std::string{});
    out_versions_per_host  [i].assign(p, std::string{});
    out_cves_per_host      [i].assign(p, std::string{});
    out_web_titles_per_host[i].assign(p, std::string{});
    out_web_servers_per_host[i].assign(p, std::string{});
    out_web_headers_per_host[i].assign(p, std::string{});
    out_web_paths_per_host [i].assign(p, std::string{});
    out_powered_by_per_host[i].assign(p, std::string{});
    out_x_generator_per_host[i].assign(p, std::string{});
    out_redirects_per_host [i].assign(p, std::string{});
    if (out_tls_per_host)
      (*out_tls_per_host)[i].assign(p, TlsCapture{});
  }

  if (N == 0) return 0;

  AsyncEnrichBatch batch;
  batch.cve_db              = cve_db;
  batch.per_step_timeout_ms = (timeout_ms > 0) ? timeout_ms : 3000;
  batch.budget_ms           = ASYNC_ENRICH_DEFAULT_BUDGET_MS;
  if (const char *env = getenv("KMAP_HOST_ENRICH_BUDGET_MS")) {
    int v = atoi(env);
    if (v > 0) batch.budget_ms = v;
  }
  batch.max_in_flight = ASYNC_ENRICH_DEFAULT_INFLIGHT;
  if (const char *env = getenv("KMAP_ASYNC_ENRICH_INFLIGHT")) {
    int v = atoi(env);
    if (v > 0 && v < 100000) batch.max_in_flight = static_cast<size_t>(v);
  }
  batch.active_count = 0;
  batch.hosts_completed.store(0, std::memory_order_relaxed);
  batch.ports_attempted.store(0, std::memory_order_relaxed);
  batch.banners_classified.store(0, std::memory_order_relaxed);
  batch.http_ok.store(0, std::memory_order_relaxed);
  batch.tls_ok.store(0, std::memory_order_relaxed);
  batch.budget_bails.store(0, std::memory_order_relaxed);

  for (size_t i = 0; i < N; i++) {
    batch.hosts.emplace_back();
    AsyncHostState &h = batch.hosts.back();
    h.batch_idx      = i;
    h.ip             = ips[i];
    h.ports          = &ports_per_host[i];
    h.out_services   = &out_services_per_host[i];
    h.out_versions   = &out_versions_per_host[i];
    h.out_cves       = &out_cves_per_host[i];
    h.out_web_titles = &out_web_titles_per_host[i];
    h.out_web_servers= &out_web_servers_per_host[i];
    h.out_web_headers= &out_web_headers_per_host[i];
    h.out_web_paths  = &out_web_paths_per_host[i];
    h.out_powered_by = &out_powered_by_per_host[i];
    h.out_x_generator= &out_x_generator_per_host[i];
    h.out_redirects  = &out_redirects_per_host[i];
    h.out_tls        = out_tls_per_host ? &(*out_tls_per_host)[i] : nullptr;
    h.sslen          = 0;
    h.addr_ok        = false;
    std::memset(&h.ss, 0, sizeof(h.ss));
    batch.pending_idx.push_back(i);
  }

  batch.pool = nsock_pool_new(&batch);
  if (!batch.pool) return 0;

#ifdef HAVE_OPENSSL
  /* Initialize the pool's shared SSL_CTX once -- nsock_connect_ssl will
     use this for every TLS handshake we drive.  NSOCK_SSL_MAX_SPEED
     biases for speed over strict cert verification (which we don't do
     anyway: we want the cert details even when the chain is broken). */
  batch.ssl_ctx_ready = (nsock_pool_ssl_init(batch.pool,
                                             NSOCK_SSL_MAX_SPEED) != NULL);
#endif

  try_admit(&batch);

  while (batch.active_count > 0 || !batch.pending_idx.empty()) {
    enum nsock_loopstatus rc = nsock_loop(batch.pool, -1);
    if (rc == NSOCK_LOOP_NOEVENTS) {
      if (!batch.pending_idx.empty()) {
        try_admit(&batch);
        if (batch.active_count == 0) break;
        continue;
      }
      break;
    }
    if (rc == NSOCK_LOOP_ERROR) break;
    if (rc == NSOCK_LOOP_QUIT)  break;
  }

  nsock_pool_delete(batch.pool);
  return 0;
}
