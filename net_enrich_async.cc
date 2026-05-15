/*
 * net_enrich_async.cc -- Async (nsock-driven) enrichment for Kmap net-scan.
 *
 * Phase 1a of the async-I/O migration.  Implements async_enrich_batch:
 * banner-grab + CVE lookup for many hosts in parallel inside ONE worker
 * thread, by issuing concurrent TCP connect + read events on a single
 * nsock_pool and letting the event loop multiplex them.
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
 * Scope
 * -----
 * Phase 1a covers banner-grab + CVE lookup ONLY.  HTTP probe
 * (probe_http) and TLS handshake (tls_capture_cert) remain on the
 * synchronous path in net_enrich.cc and will be migrated to this state
 * machine in Phase 1b/1c.  This file is the reference for those
 * extensions: the state machine below has hooks where future stages
 * will plug in.
 *
 * State machine, per host
 * -----------------------
 *   STAGE_BANNER_CONNECT
 *       Issue nsock_connect_tcp on a fresh nsock_iod for ports[port_idx].
 *       Callback: on_banner_connect.
 *
 *   on_banner_connect:
 *       NSE_STATUS_SUCCESS -> issue nsock_read with banner timeout.
 *                             Move to STAGE_BANNER_RECV.
 *       anything else      -> close iod, advance_to_next_port().
 *
 *   STAGE_BANNER_RECV
 *       Callback: on_banner_recv.
 *
 *   on_banner_recv:
 *       NSE_STATUS_SUCCESS -> grab buf via nse_readbuf, run
 *                             classify_banner(), write
 *                             out_services/versions/cves for this port,
 *                             then advance_to_next_port().
 *       NSE_STATUS_TIMEOUT -> no banner data: still advance.
 *       anything else      -> advance.
 *
 *   advance_to_next_port:
 *       port_idx++.  If port_idx >= ports.size() OR budget expired:
 *           finalize_host() -- drop from active set, attempt to admit
 *           a new host from the pending queue.
 *       Else:
 *           submit STAGE_BANNER_CONNECT for the new port (re-uses host
 *           state object; allocates a fresh iod).
 *
 * Budget enforcement
 * ------------------
 * Each host has a steady_clock deadline = host_start +
 * KMAP_HOST_ENRICH_BUDGET_MS (default 15s, same env var the sync path
 * reads).  Every nsock event uses timeout = min(per_step_timeout,
 * budget_remaining), so the last step in a host's life cannot overshoot
 * its budget.  When budget expires mid-host, the next advance_to_next_port
 * finalizes immediately.
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
 * cves_to_json_local() helpers are deliberately copies of their
 * synchronous counterparts in net_enrich.cc (which are static there).
 * Duplication is preferred to invasive refactors during this incremental
 * migration; after Phase 1c lands we can promote a shared helper.
 * If you change classification logic in net_enrich.cc, update it here
 * too -- they are meant to stay byte-for-byte identical.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_enrich_async.h"
#include "net_enrich.h"   /* EnrichMetrics decls; not relied on here */

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

/* -----------------------------------------------------------------------
 * Tunables
 * ----------------------------------------------------------------------- */

/* Maximum hosts the state machine will keep in flight at once.  The
   nsock event loop scales fine into the low thousands, but each in-flight
   host costs one FD (peak), one nsock_iod, and one AsyncHostState heap entry.
   64 keeps the per-worker memory footprint trivial and amortizes the
   nsock_loop kernel cost.  Override via KMAP_ASYNC_ENRICH_INFLIGHT. */
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

/* -----------------------------------------------------------------------
 * Banner classification helpers (verbatim copies of net_enrich.cc shapes)
 * ----------------------------------------------------------------------- */

struct AsyncBannerResult {
  std::string service;
  std::string version;
  /* http_response is captured by the sync path so the subsequent HTTP
     probe can reuse it; Phase 1a does not run HTTP, so we omit the
     field here.  When HTTP comes online in Phase 1b, restore it. */
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
 * NOT fall back to sending an HTTP probe on silent ports -- that's the
 * job of Phase 1b's HTTP stage.
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

static std::string a_json_escape(const std::string &s) {
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
 * Per-host state
 * ----------------------------------------------------------------------- */

/* Stage in the host's pipeline.  Phase 1a stops at BANNER_RECV; Phase 1b
   will append HTTP_CONNECT / HTTP_SEND / HTTP_RECV; Phase 1c TLS_*. */
enum AsyncStage {
  STAGE_BANNER_CONNECT,
  STAGE_BANNER_RECV,
  STAGE_DONE
};

struct AsyncHostState {
  /* Input view */
  size_t       batch_idx;        /* index into ips/ports_per_host */
  std::string  ip;
  const std::vector<int> *ports; /* owned by caller */

  /* Output sinks (pointers into the per-host inner vectors that
     async_enrich_batch has pre-sized) */
  std::vector<std::string> *out_services;
  std::vector<std::string> *out_versions;
  std::vector<std::string> *out_cves;

  /* Walk pointer */
  size_t       port_idx;
  AsyncStage   stage;

  /* Live nsock resources for the in-flight event on this host.  iod is
     re-created per port (one connect+read per fd) so a closed/half-open
     fd from port N doesn't bleed into port N+1. */
  nsock_iod    iod;

  /* Pre-resolved socket address for this host, computed once on admit. */
  struct sockaddr_storage ss;
  socklen_t    sslen;
  bool         addr_ok;

  /* Deadline for the whole host. */
  std::chrono::steady_clock::time_point deadline;
};

/* -----------------------------------------------------------------------
 * Batch driver -- owns pool, queue, active set
 * ----------------------------------------------------------------------- */

struct AsyncEnrichBatch {
  nsock_pool   pool;
  sqlite3     *cve_db;
  int          per_step_timeout_ms;
  int          budget_ms;
  size_t       max_in_flight;

  /* All AsyncHostState objects live here.  Pending entries are referenced by
     index from `pending_idx`; active entries are referenced by raw
     pointer from nsock callbacks.  We never move AsyncHostState after it's
     allocated (deque preserves pointer stability across push_back). */
  std::deque<AsyncHostState> hosts;
  std::deque<size_t>    pending_idx;
  size_t                active_count;

  /* Internal counters for debugging / future metrics tie-in. */
  std::atomic<uint64_t> hosts_completed;
  std::atomic<uint64_t> ports_attempted;
  std::atomic<uint64_t> banners_classified;
  std::atomic<uint64_t> budget_bails;
};

/* Forward declarations for the callback web. */
static void on_banner_connect(nsock_pool nsp, nsock_event nse, void *udata);
static void on_banner_recv  (nsock_pool nsp, nsock_event nse, void *udata);
static void submit_connect  (AsyncEnrichBatch *b, AsyncHostState *h);
static void advance_port    (AsyncEnrichBatch *b, AsyncHostState *h);
static void finalize_host   (AsyncEnrichBatch *b, AsyncHostState *h);
static void try_admit       (AsyncEnrichBatch *b);

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
   (remaining budget).  Ensures the last event in a host's life cannot
   overshoot the host budget. */
static int step_timeout(const AsyncEnrichBatch *b, const AsyncHostState *h) {
  int rem = remaining_ms(h);
  return b->per_step_timeout_ms < rem ? b->per_step_timeout_ms : rem;
}

/* Parse a textual IP into a sockaddr_storage.  Sets sslen and returns
   true on success.  Same parser shape as net_enrich.cc::enrich_tcp_connect. */
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

/* -----------------------------------------------------------------------
 * State machine
 * ----------------------------------------------------------------------- */

/* Allocate a fresh nsock_iod for this host and issue the connect for
   the current port_idx.  Caller must guarantee port_idx < ports.size()
   and budget not yet expired. */
static void submit_connect(AsyncEnrichBatch *b, AsyncHostState *h) {
  int port = (*h->ports)[h->port_idx];
  int to = step_timeout(b, h);
  if (to <= 0) {
    /* Budget exhausted right at the entry; bail through advance_port,
       which will see remaining_ms()==0 and finalize. */
    advance_port(b, h);
    return;
  }

  h->iod = nsock_iod_new(b->pool, h);
  if (h->iod == NULL) {
    /* No fd available, skip port. */
    advance_port(b, h);
    return;
  }

  h->stage = STAGE_BANNER_CONNECT;
  b->ports_attempted.fetch_add(1, std::memory_order_relaxed);

  nsock_connect_tcp(b->pool, h->iod, on_banner_connect, to, h,
                    reinterpret_cast<struct sockaddr *>(&h->ss),
                    h->sslen, static_cast<unsigned short>(port));
}

/* nsock callback: TCP connect attempt completed (or timed out / errored). */
static void on_banner_connect(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncHostState *h = static_cast<AsyncHostState *>(udata);
  enum nse_status st = nse_status(nse);

  /* KILL means the pool is being torn down -- bow out without touching
     anything else; the pool_delete path is releasing resources for us. */
  if (st == NSE_STATUS_KILL) {
    h->iod = NULL;
    return;
  }

  if (st == NSE_STATUS_SUCCESS) {
    /* Connect ok -- issue the banner read.  Use remaining step_timeout
       (budget-clamped) so a host that already ate most of its budget
       on connect can't then sit on a 5-second read. */
    int to = step_timeout(b, h);
    if (to <= 0) {
      /* Budget out: close iod, advance (which will finalize). */
      if (h->iod) { nsock_iod_delete(h->iod, NSOCK_PENDING_SILENT); h->iod = NULL; }
      advance_port(b, h);
      return;
    }
    h->stage = STAGE_BANNER_RECV;
    nsock_read(b->pool, h->iod, on_banner_recv, to, h);
    return;
  }

  /* Connect failed -- closed/filtered port, timeout, or proxy error.
     Close the iod and try the next port. */
  if (h->iod) { nsock_iod_delete(h->iod, NSOCK_PENDING_SILENT); h->iod = NULL; }
  advance_port(b, h);
}

/* nsock callback: banner read completed. */
static void on_banner_recv(nsock_pool nsp, nsock_event nse, void *udata) {
  AsyncEnrichBatch *b = static_cast<AsyncEnrichBatch *>(nsock_pool_get_udata(nsp));
  AsyncHostState *h = static_cast<AsyncHostState *>(udata);
  enum nse_status st = nse_status(nse);

  if (st == NSE_STATUS_KILL) {
    h->iod = NULL;
    return;
  }

  if (st == NSE_STATUS_SUCCESS) {
    /* We have at least one byte.  nse_readbuf returns a borrowed pointer
       owned by the event (freed when the callback returns), so we must
       consume / copy here. */
    int nbytes = 0;
    char *rb = nse_readbuf(nse, &nbytes);
    if (nbytes > ASYNC_ENRICH_BANNER_MAX) nbytes = ASYNC_ENRICH_BANNER_MAX;

    int port = (*h->ports)[h->port_idx];
    AsyncBannerResult br = classify_banner(rb, nbytes, port);

    if (!br.service.empty()) {
      (*h->out_services)[h->port_idx] = br.service;
      b->banners_classified.fetch_add(1, std::memory_order_relaxed);
    }
    if (!br.version.empty()) {
      (*h->out_versions)[h->port_idx] = br.version;
    }

    /* CVE lookup (sync, microseconds).  Phase 1a does not retry / soften
       on null cve_db -- a_lookup_cves handles that internally. */
    if (b->cve_db && !br.service.empty()) {
      std::vector<AsyncEnrichCve> cves =
        a_lookup_cves(b->cve_db, br.service, br.version);
      (*h->out_cves)[h->port_idx] = a_cves_to_json(cves);
    }
  }
  /* NSE_STATUS_TIMEOUT / EOF / ERROR / CANCELLED: nothing to record.
     The synchronous path leaves the slot empty in the same way (and
     also does an HTTP probe on silent ports -- Phase 1b territory). */

  if (h->iod) { nsock_iod_delete(h->iod, NSOCK_PENDING_SILENT); h->iod = NULL; }
  advance_port(b, h);
}

/* Step the host's port walker forward; either schedule the next port or
   finalize. */
static void advance_port(AsyncEnrichBatch *b, AsyncHostState *h) {
  h->port_idx++;
  if (h->port_idx >= h->ports->size() || remaining_ms(h) <= 0) {
    if (h->port_idx < h->ports->size())
      b->budget_bails.fetch_add(1, std::memory_order_relaxed);
    finalize_host(b, h);
    return;
  }
  submit_connect(b, h);
}

/* Finalize the host: mark stage DONE, drop from the active count, and
   try to admit a replacement from the pending queue. */
static void finalize_host(AsyncEnrichBatch *b, AsyncHostState *h) {
  if (h->iod) {
    nsock_iod_delete(h->iod, NSOCK_PENDING_SILENT);
    h->iod = NULL;
  }
  h->stage = STAGE_DONE;
  b->active_count--;
  b->hosts_completed.fetch_add(1, std::memory_order_relaxed);
  try_admit(b);
}

/* Pull a pending host off the queue, resolve its address, kick off its
   first port connect.  Repeats until we hit max_in_flight or the queue
   drains. */
static void try_admit(AsyncEnrichBatch *b) {
  while (b->active_count < b->max_in_flight && !b->pending_idx.empty()) {
    size_t idx = b->pending_idx.front();
    b->pending_idx.pop_front();
    AsyncHostState *h = &b->hosts[idx];

    /* Empty port list: nothing to do, finalize immediately. */
    if (h->ports->empty()) {
      h->stage = STAGE_DONE;
      b->hosts_completed.fetch_add(1, std::memory_order_relaxed);
      continue;
    }

    /* Resolve the IP exactly once per host.  An unparseable IP just
       skips the host with empty outputs; we don't fail the whole batch. */
    if (!resolve_ip(h->ip, &h->ss, &h->sslen)) {
      h->stage = STAGE_DONE;
      b->hosts_completed.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    h->addr_ok = true;

    /* Start the deadline clock NOW (not at batch admission) so each
       host gets the full budget even if it was queued for a while. */
    h->deadline = std::chrono::steady_clock::now() +
                  std::chrono::milliseconds(b->budget_ms);
    h->port_idx = 0;

    b->active_count++;
    submit_connect(b, h);
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
    std::vector<std::vector<std::string>> &out_cves_per_host)
{
  size_t N = ips.size();
  if (ports_per_host.size() != N) {
    /* Caller contract violation: parallel arrays must match.  Treat as
       a no-op rather than fataling -- this is library code. */
    return 0;
  }

  /* Pre-size outer vectors. */
  out_services_per_host.assign(N, std::vector<std::string>{});
  out_versions_per_host.assign(N, std::vector<std::string>{});
  out_cves_per_host    .assign(N, std::vector<std::string>{});

  /* Pre-size inner vectors so the recv callback can write
     (*h->out_services)[port_idx] = ... without resizing under our feet. */
  for (size_t i = 0; i < N; i++) {
    size_t p = ports_per_host[i].size();
    out_services_per_host[i].assign(p, std::string{});
    out_versions_per_host[i].assign(p, std::string{});
    out_cves_per_host    [i].assign(p, std::string{});
  }

  if (N == 0) return 0;

  /* Allocate the batch driver.  AsyncEnrichBatch contains atomics which
     are not movable; use new+RAII via unique_ptr if we ever need to
     return it to the caller, but here it's stack-locally owned. */
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
  batch.active_count        = 0;
  batch.hosts_completed.store(0, std::memory_order_relaxed);
  batch.ports_attempted.store(0, std::memory_order_relaxed);
  batch.banners_classified.store(0, std::memory_order_relaxed);
  batch.budget_bails.store(0, std::memory_order_relaxed);

  /* Build host state list and pending queue.  Pointer stability of
     std::deque elements is documented (insert/erase at ends preserves
     all references) -- and we only push_back here, so the raw AsyncHostState*
     we hand to nsock callbacks below stays valid for the whole batch. */
  for (size_t i = 0; i < N; i++) {
    AsyncHostState h;
    h.batch_idx     = i;
    h.ip            = ips[i];
    h.ports         = &ports_per_host[i];
    h.out_services  = &out_services_per_host[i];
    h.out_versions  = &out_versions_per_host[i];
    h.out_cves      = &out_cves_per_host[i];
    h.port_idx      = 0;
    h.stage         = STAGE_BANNER_CONNECT;
    h.iod           = NULL;
    h.sslen         = 0;
    h.addr_ok       = false;
    /* deadline set on admit */
    std::memset(&h.ss, 0, sizeof(h.ss));
    batch.hosts.push_back(std::move(h));
    batch.pending_idx.push_back(i);
  }

  /* Create the nsock pool.  The pool's udata is the batch driver -- the
     connect/recv handlers look it up via nsock_pool_get_udata(). */
  batch.pool = nsock_pool_new(&batch);
  if (!batch.pool) {
    /* Out of memory or other catastrophic init failure.  Outputs are
       already pre-sized empty; return 0 to signal "no work done". */
    return 0;
  }

  /* Prime the pump with the first wave of hosts. */
  try_admit(&batch);

  /* Drive the event loop.  -1 = no overall timeout; nsock returns when
     all events have completed.  We re-enter the loop until both the
     pending queue and the active set drain, in case the loop bailed
     early (it shouldn't, but the loop docs allow it). */
  while (batch.active_count > 0 || !batch.pending_idx.empty()) {
    enum nsock_loopstatus rc = nsock_loop(batch.pool, -1);
    if (rc == NSOCK_LOOP_NOEVENTS) {
      /* No events scheduled.  If we still have pending hosts, admit
         them (try_admit at the start of a callback would normally
         handle this, but with zero callbacks pending we need to nudge
         it manually). */
      if (!batch.pending_idx.empty()) {
        try_admit(&batch);
        if (batch.active_count == 0) break;  /* nothing admit-able */
        continue;
      }
      break;
    }
    if (rc == NSOCK_LOOP_ERROR) {
      /* Unexpected loop-level error.  Bail with whatever we collected.
         The synchronous path treats this as fatal; here we'd rather
         finish degraded than abort an in-progress integration test. */
      break;
    }
    if (rc == NSOCK_LOOP_QUIT) break;
    /* NSOCK_LOOP_TIMEOUT can't happen with msec_timeout=-1, but if it
       did we'd just iterate again. */
  }

  /* Tear down the pool.  Pending events get NSE_STATUS_KILL callbacks
     thanks to nsock_pool_delete's contract; our callbacks no-op on
     KILL (see top of on_banner_connect / on_banner_recv). */
  nsock_pool_delete(batch.pool);

  return 0;
}
