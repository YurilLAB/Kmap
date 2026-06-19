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
#include "net_hash_helpers.h"   /* derive_cpe, favicon_mmh3 */
#include "sha256.h"             /* sha256_hex for http_body_sha256 */
#include "ssh_hassh.h"          /* ssh_hassh_server_from_buffer (ssh.hassh) */
#include "json_escape.h"      /* kmap_json_escape -- shared JSON escaper */
#include "cloud_map.h"          /* lookup_cloud, cloud_ranges_load */
#include "net_db.h"
#include "net_scan.h"   /* net_event_log: mirror key events into kmap.log */
#include "asn_lookup.h"
#include "KmapOps.h"
#include "sys_resources.h"
#include "cpu_meter.h"
#include "kmap.h"
#include "kmap_dns.h"
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
#include <chrono>

#ifndef WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>          /* getnameinfo, NI_MAXHOST, NI_NAMEREQD */
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
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

/* Per-port banner/HTTP/TLS connect timeout. Halved from 5000ms because
   real services answer in <200ms; the longer timeout only padded dead
   ports without recovering anything. The hard per-host budget in
   enrich_single_host bounds total wall time anyway, so this just lets a
   host's budget cover more port attempts before bailing. Tunable via
   KMAP_ENRICH_CONNECT_TIMEOUT_MS env. */
#define ENRICH_CONNECT_TIMEOUT  3000  /* ms */
#define ENRICH_READ_TIMEOUT     2000  /* ms -- recv deadline; see enrich_read_timeout() */
#define ENRICH_BANNER_MAX       1024  /* bytes */

/* -----------------------------------------------------------------------
 * Low-level TCP helpers -- same pattern as default_creds.cc
 * ----------------------------------------------------------------------- */

/* Use intptr_t for socket handles to avoid SOCKET-to-int truncation
   on 64-bit Windows (SOCKET is UINT_PTR = 64 bits on Win64). */
typedef intptr_t kmap_fd_t;
#define KMAP_INVALID_FD ((kmap_fd_t)-1)

/* Wait for fd readiness (write when want_write, else read) or timeout.
   Returns >0 ready, 0 timeout, <0 error.

   poll() on POSIX, NOT select(): an fd_set is a fixed bitmask indexed by the
   fd VALUE and capped at FD_SETSIZE (1024). The enrichment workers keep many
   sockets open at once (KMAP_NETSCAN_ENRICH_CONCURRENCY * KMAP_HOST_PORT_
   PARALLELISM, plus the 32 shard DBs and the log), so an fd value can climb
   past 1024 -- FD_SET(fd >= 1024, &set) then writes past the end of the
   fd_set and corrupts the stack. poll passes the fd by value in a one-element
   array with no FD_SETSIZE ceiling. Windows fd_set is a counted array of
   SOCKET handles, so a single-fd select there is safe at any handle value. */
static int enrich_wait_fd(kmap_fd_t fd, bool want_write, int timeout_ms) {
#ifdef WIN32
  fd_set set;
  FD_ZERO(&set);
  FD_SET(static_cast<SOCKET>(fd), &set);
  struct timeval tv;
  tv.tv_sec  = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  return select(static_cast<int>(fd) + 1,
                want_write ? nullptr : &set,
                want_write ? &set : nullptr,
                nullptr, &tv);
#else
  struct pollfd pfd;
  pfd.fd      = static_cast<int>(fd);
  pfd.events  = want_write ? POLLOUT : POLLIN;
  pfd.revents = 0;
  return poll(&pfd, 1, timeout_ms);
#endif
}

/* Raise the open-file-descriptor soft limit toward the hard limit so the
   enrichment pool can hold its peak concurrent sockets
   (KMAP_NETSCAN_ENRICH_CONCURRENCY hosts * KMAP_HOST_PORT_PARALLELISM ports).
   Without this, --enrich-only (which runs no discovery first, so nothing else
   raised the limit) or a high enrich concurrency hits the default
   RLIMIT_NOFILE (1024); socket() then fails EMFILE and the host's services go
   undetected. Only raises, never lowers; best-effort; no-op on Windows. */
static void raise_fd_limit(int desired) {
#ifndef WIN32
  struct rlimit r;
  if (getrlimit(RLIMIT_NOFILE, &r) != 0) return;
  if (r.rlim_cur == RLIM_INFINITY || r.rlim_cur >= (rlim_t)desired) return;
  r.rlim_cur = (r.rlim_max == RLIM_INFINITY || (rlim_t)desired < r.rlim_max)
                 ? (rlim_t)desired : r.rlim_max;
  setrlimit(RLIMIT_NOFILE, &r);   /* best-effort */
  if (getrlimit(RLIMIT_NOFILE, &r) == 0 &&
      r.rlim_cur != RLIM_INFINITY && r.rlim_cur < (rlim_t)desired) {
    log_write(LOG_STDOUT,
      "  WARNING: open-file limit is %lu but enrichment needs ~%d descriptors; "
      "raise it (ulimit -Hn) or lower KMAP_NETSCAN_ENRICH_CONCURRENCY / "
      "KMAP_HOST_PORT_PARALLELISM, else some probes fail with EMFILE.\n",
      (unsigned long)r.rlim_cur, desired);
  }
#else
  (void)desired;
#endif
}

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

  if (enrich_wait_fd(fd, /*want_write=*/true, timeout_ms) <= 0) {
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
  if (enrich_wait_fd(fd, /*want_write=*/false, timeout_ms) <= 0)
    return -1;
#ifdef WIN32
  return static_cast<int>(recv(static_cast<SOCKET>(fd), buf, static_cast<int>(len), 0));
#else
  return static_cast<int>(recv(static_cast<int>(fd), buf, static_cast<int>(len), 0));
#endif
}

/* Recv deadline for the enrichment probes.  enrich_tcp_connect already spent up
   to connect_timeout_ms on the CONNECT; reusing that full value for the recv
   means a TCP-open-but-silent port -- e.g. EVERY plain HTTP server, which never
   speaks first -- burns the entire connect timeout AGAIN waiting for a banner
   that never arrives, before we even send the GET.  A host that completed the
   handshake but is silent past a couple of seconds is not going to speak.  Cap
   the recv wait at KMAP_ENRICH_READ_TIMEOUT_MS (default ENRICH_READ_TIMEOUT),
   never exceeding the caller's remaining budget.  Thread-safe one-time init via
   a C++11 magic static. */
static int enrich_read_timeout(int connect_timeout_ms) {
  static const int cap = [](){
    int v = ENRICH_READ_TIMEOUT;
    if (const char *e = getenv("KMAP_ENRICH_READ_TIMEOUT_MS")) {
      int p = atoi(e);
      if (p >= 50 && p <= 60000) v = p;
    }
    return v;
  }();
  return connect_timeout_ms < cap ? connect_timeout_ms : cap;
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

/* Parse "2.4.49p1" -> {2, 4, 49} (component-wise, stops at first non-digit
   within each dotted token). */
static std::vector<int> parse_ver_enrich(const std::string &s) {
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
}

/* Compare two already-parsed version vectors -- returns -1/0/1. */
static int ver_cmp_parsed(const std::vector<int> &va,
                          const std::vector<int> &vb) {
  size_t n = std::max(va.size(), vb.size());
  for (size_t i = 0; i < n; i++) {
    int ai = (i < va.size()) ? va[i] : 0;
    int bi = (i < vb.size()) ? vb[i] : 0;
    if (ai < bi) return -1;
    if (ai > bi) return  1;
  }
  return 0;
}

/* Numeric version comparison -- returns -1/0/1 for a<b, a==b, a>b.
   Parses "2.4.49p1" -> {2, 4, 49} and compares component-by-component. */
static int ver_cmp_enrich(const std::string &a, const std::string &b) {
  return ver_cmp_parsed(parse_ver_enrich(a), parse_ver_enrich(b));
}

/* Escape a string for JSON embedding (RFC 8259). Escapes the structural
   chars plus ALL control characters U+0000..U+001F -- service banners, HTTP
   headers and TLS fields are raw network bytes and routinely contain control
   bytes (NUL, ESC 0x1B, vertical tab, etc.); emitting them raw produced
   invalid JSON that broke downstream parsers. Iterate as unsigned char so
   UTF-8 high bytes (0x80..0xFF) are passed through, not mis-escaped. */
static std::string json_escape(const std::string &s) {
  return kmap_json_escape(s);   /* single source of truth: json_escape.h */
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
  std::string hassh;         /* HASSH server fingerprint (ssh ports only); "" otherwise */
};

/* Try to grab a banner by just reading what the server sends after connect */
static BannerResult grab_banner(const char *ip, int port, int timeout_ms) {
  BannerResult result;

  kmap_fd_t fd = enrich_tcp_connect(ip, static_cast<uint16_t>(port), timeout_ms);
  if (fd == KMAP_INVALID_FD)
    return result;

  int read_to = enrich_read_timeout(timeout_ms);
  char buf[ENRICH_BANNER_MAX]{};
  int n = enrich_fd_recv(fd, buf, sizeof(buf) - 1, read_to);

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
      n = enrich_fd_recv(fd, buf, sizeof(buf) - 1, read_to);
    }
  }

  /* SSH is speak-first: the server sends its "SSH-..." identification line
     immediately followed by the SSH_MSG_KEXINIT packet, frequently larger than
     ENRICH_BANNER_MAX (a stock OpenSSH KEXINIT is ~1.1 KB).  Drain a little
     more here so the HASSH fingerprint sees the whole packet.  The bytes are
     already in the socket buffer (the server then waits for our id, which we
     never send), so each recv returns at once -- no extra round-trip, no new
     timeout budget -- and we stop the instant a complete KEXINIT parses.
     Hard-capped on iterations and total size so a dribbling/malicious server
     can never stall the pipeline. */
  std::string ssh_more;
  if (n >= 4 && memcmp(buf, "SSH-", 4) == 0) {
    std::string acc(buf, static_cast<size_t>(n));
    char xb[ENRICH_BANNER_MAX];
    for (int it = 0; it < 8 && acc.size() < 16384; it++) {
      SshKexInit probe;
      if (ssh_kexinit_from_server_buffer(acc, probe)) break;  /* have full KEXINIT */
      int m = enrich_fd_recv(fd, xb, sizeof(xb), read_to);
      if (m <= 0) break;
      acc.append(xb, static_cast<size_t>(m));
      ssh_more.append(xb, static_cast<size_t>(m));
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
    /* HASSH server fingerprint from the KEXINIT that followed the id line
       (banner holds the first ENRICH_BANNER_MAX bytes, ssh_more the drained
       remainder).  Best-effort: "" when the packet never fully arrived. */
    result.hassh = ssh_hassh_server_from_buffer(banner + ssh_more);
    return result;
  }

  /* VNC / RFB: the server speaks first with "RFB <major>.<minor>\n" (RFC 6143),
     e.g. "RFB 003.008". Distinctive prefix, captured by the initial recv. */
  if (banner.size() >= 8 && banner.compare(0, 4, "RFB ") == 0 &&
      isdigit(static_cast<unsigned char>(banner[4]))) {
    result.service = "vnc";
    result.version = first_line;
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

  /* MySQL/MariaDB greeting: starts with a packet length + protocol version 0x0a */
  if (n >= 5 && static_cast<unsigned char>(buf[4]) == 0x0a) {
    result.service = "mysql";
    /* Version string follows after byte 5 until null terminator */
    const char *verp = buf + 5;
    size_t vlen = strnlen(verp,
                          static_cast<size_t>(n) > 5 ? static_cast<size_t>(n) - 5 : 0);
    if (vlen > 0) result.version = std::string(verp, vlen);
    /* MariaDB speaks the MySQL wire protocol, so the 0x0a handshake alone
       cannot tell them apart. MariaDB advertises a legacy compatibility
       greeting "5.5.5-<real-version>-MariaDB-...". Detect it and route to the
       mariadb product with the REAL version, otherwise the host gets matched
       against Oracle MySQL CVEs (false positive) and misses every MariaDB CVE
       (false negative). */
    if (str_lower(result.version).find("mariadb") != std::string::npos) {
      result.service = "mariadb";
      if (result.version.rfind("5.5.5-", 0) == 0)
        result.version = result.version.substr(6);  /* drop bogus compat prefix */
    }
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

  /* PostgreSQL: 'R' AuthenticationRequest -- byte 'R', then a big-endian
     Int32 length (message length incl. itself) and an Int32 auth code. Bound
     the length to the real range (AuthenticationOk=8 .. SASL ~ tens of bytes)
     so a bare 'R'+9 no longer matches any R-prefixed banner (e.g. malformed
     "RFB..." that slipped past the VNC check). */
  if (n >= 9 && buf[0] == 'R') {
    uint32_t pg_len = (static_cast<uint32_t>(static_cast<unsigned char>(buf[1])) << 24) |
                      (static_cast<uint32_t>(static_cast<unsigned char>(buf[2])) << 16) |
                      (static_cast<uint32_t>(static_cast<unsigned char>(buf[3])) << 8)  |
                       static_cast<uint32_t>(static_cast<unsigned char>(buf[4]));
    if (pg_len >= 8 && pg_len <= 64) {
      result.service = "postgresql";
      return result;
    }
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
  /* Tier-1 confidence fields (NULL in DB -> empty / -1 here, which
     callers render as "(unknown confidence)"). cvss_vector is the
     full CVSS v3 string; remote_unauthed is -1 unknown / 0 no / 1
     yes for "this CVE can be triggered by a remote unauthed network
     attacker". */
  std::string cvss_vector;
  int         remote_unauthed = -1;
  /* Exploit-triage signals (see cve_map.h). epss -1 = column absent in DB. */
  float       epss = -1.0f;
  bool        kev = false;
  bool        kev_ransomware = false;
};

/* Normalize a service/version pair to a product name for DB lookup.
 * Returns the DB product name or empty string if unmappable. */
static std::string normalize_product(const std::string &service,
                                     const std::string &version) {
  std::string svc  = str_lower(service);
  std::string ver  = str_lower(version);

  /* SSH service classification needs care: a bare "service==ssh" fallback
     to product=openssh produced false-positive CVE matches for every
     non-OpenSSH SSH implementation on the internet. AWS Transfer Family
     (banner "AWS_SFTP"), Dropbear (busybox / embedded), libssh-based
     servers (many appliances), Bitvise (Windows), Tectia (commercial),
     and Erlang/OTP SSH all speak SSH protocol but are NOT OpenSSH source
     and don't share OpenSSH's CVE history.

     New rules:
     1. Banner names a known non-OpenSSH SSH server -> return empty (or
        the variant's product name once we have CVE rows for it). Empty
        means "no match" because lookup_cves early-returns on empty
        product. This drops 7 false REMOTE matches per AWS-SFTP-style
        host in the 1000-IP test.
     2. Banner explicitly names OpenSSH -> openssh.
     3. Banner-less SSH service (svc=ssh, version empty/unknown) ->
        empty. We can't claim openssh CVEs apply to a server whose
        implementation we don't know. */
  if (svc == "ssh" || ver.find("ssh") != std::string::npos) {
    /* Non-OpenSSH variants: bow out of CVE matching rather than
       producing 12 OpenSSH false positives. Once we add CVE coverage
       for these products in the DB, return their product names here. */
    if (ver.find("aws_sftp")  != std::string::npos ||
        ver.find("aws sftp")  != std::string::npos ||
        ver.find("aws-sftp")  != std::string::npos)
      return "";  /* AWS Transfer Family SFTP */
    if (ver.find("dropbear")  != std::string::npos)
      return "";  /* Dropbear -- embedded / busybox */
    if (ver.find("bitvise")   != std::string::npos ||
        ver.find("wsshd")     != std::string::npos)
      return "";  /* Bitvise SSH Server (Windows) */
    if (ver.find("tectia")    != std::string::npos ||
        ver.find("sshcom")    != std::string::npos)
      return "";  /* SSH Communications Security / Tectia */
    if (ver.find("erlangshell") != std::string::npos ||
        ver.find("erlang")    != std::string::npos)
      return "";  /* Erlang/OTP SSH daemon */
    if (ver.find("paramiko")  != std::string::npos)
      return "";  /* Paramiko -- often Python SSH bots / honeypots */
    if (ver.find("libssh")    != std::string::npos &&
        ver.find("openssh")   == std::string::npos)
      return "";  /* libssh-based, not OpenSSH */

    /* Default: only match OpenSSH CVEs when the banner explicitly says
       OpenSSH. "OpenSSH_for_Windows_x.y" (Microsoft port -- still
       OpenSSH-derived source) hits this branch correctly. */
    if (ver.find("openssh") != std::string::npos)
      return "openssh";

    /* SSH service but unrecognized implementation -- refuse to match. */
    return "";
  }
  if (ver.find("apache") != std::string::npos &&
      (ver.find("http") != std::string::npos || svc == "http"))
    return "http_server";
  if (ver.find("nginx") != std::string::npos) return "nginx";
  if (ver.find("lighttpd") != std::string::npos) return "lighttpd";
  if (ver.find("iis") != std::string::npos) return "iis";
  if (ver.find("tomcat") != std::string::npos) return "tomcat";
  /* MariaDB before MySQL: MariaDB greetings/banners contain "mariadb" and must
     not fall through to the Oracle MySQL product (different CVE history). */
  if (ver.find("mariadb") != std::string::npos || svc == "mariadb")
    return "mariadb";
  if (ver.find("mysql") != std::string::npos || svc == "mysql")
    return "mysql";
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

/* Public CPE deriver (declared in net_enrich.h).  Runs the same product
   normalization the CVE matcher uses, then maps to a CPE 2.3 string.  Returns
   "" when the service/version did not resolve to a known product so callers
   can pass NULL to net_db_update_enrichment (COALESCE leaves the column). */
std::string net_enrich_cpe_for(const std::string &service,
                               const std::string &version) {
  std::string product = normalize_product(service, version);
  if (product.empty()) return "";
  return derive_cpe(product, version);
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

  /* Refuse to match CVEs when the host's banner did not produce a
     dotted-decimal version. Many CVE rows in the DB have NULL version
     bounds even when the CVE itself is version-specific (e.g. Apache
     CVE-2021-41773 explicitly names 2.4.49 but the bounds are empty in
     the DB; libexpat CVEs are sometimes tagged product=http_server).
     Without a detected version we cannot decide whether any of those
     apply, so the conservative answer is "no matches" rather than
     "match every row tagged with this product" -- the latter produces
     dozens of false positives on hosts whose Server header is just
     "Apache" or whose SSH banner lacks a version. The Finding 8 fix
     below catches the row-has-bounds case; this catches the row-has-
     no-bounds case. */
  std::string det_ver = extract_version_number(version);
  if (det_ver.empty()) return results;

  /* Stored-result cap is 100 *applicable* CVEs (KMAP_CVE_RESULT_CAP, the
   * break below).  History: the cap was 15, which silently evicted
   * lower-CVSS CVEs from the hosts.cves column on each rescan -- a product
   * with 16+ applicable CVEs lost every CVE past rank 15.  100 covers every
   * mainstream product's real-world CVE count (Apache 2.2, OpenSSH 7.x,
   * legacy nginx) without bloating the row: 100 rows of CVE JSON is ~8 KB
   * per port, negligible at shard scale.
   *
   * The SQL LIMIT (2000) is a backstop, NOT the cap.  The version-range
   * filter runs in C++ below, so applying LIMIT 100 in SQL would keep the
   * 100 highest-CVSS rows *before* version filtering and drop an older CVE
   * that actually applies to the detected version but ranks beyond 100 by
   * CVSS for a product with many high-severity entries.  Walk up to 2000
   * rows (indexed on product) and stop once 100 applicable ones collect. */
  const int KMAP_CVE_RESULT_CAP = 100;

  /* The CVE DB handle is opened once and shared across every enrichment
     worker thread and their per-port sub-workers, but sqlite is built with
     SQLITE_THREADSAFE=0, which compiles out all of its internal mutexes.
     A single sqlite3 connection is a shared mutable object (pager, page
     cache, prepared-statement list, error buffers), so concurrent
     prepare/step/finalize on it is a data race that can corrupt the heap
     or return garbage rows.  Serialize all access to the connection.  The
     query is one indexed SELECT held for microseconds while the
     surrounding enrichment is network-I/O bound, so this lock adds no
     meaningful contention and preserves the open-once design. */
  static std::mutex cve_db_mu;
  std::lock_guard<std::mutex> cve_lock(cve_db_mu);

  /* Detect once whether the DB carries the version-exclusivity columns. They
     let the matcher honour NVD's versionEndExcluding ("fixed in X" => affected
     < X) with a strict comparison instead of <=, which otherwise flags the
     patched version itself (off-by-one FP, e.g. OpenSSH 9.3 / CVE-2023-28531).
     Older or externally-supplied DBs without the columns fall back to
     inclusive bounds. */
  static int has_excl = -1;
  if (has_excl < 0) {
    sqlite3_stmt *probe = nullptr;
    has_excl = (sqlite3_prepare_v2(cve_db,
        "SELECT version_min_exclusive, version_max_exclusive FROM cves LIMIT 1",
        -1, &probe, nullptr) == SQLITE_OK) ? 1 : 0;
    if (probe) sqlite3_finalize(probe);
  }

  /* EPSS / CISA-KEV enrichment columns (scripts/update_epss_kev.py); absent in
     older/external DBs.  Appended after the optional excl columns so offsets
     stay deterministic. */
  static int has_epss = -1;
  if (has_epss < 0) {
    sqlite3_stmt *probe = nullptr;
    has_epss = (sqlite3_prepare_v2(cve_db,
        "SELECT epss_score, kev, kev_ransomware FROM cves LIMIT 1",
        -1, &probe, nullptr) == SQLITE_OK) ? 1 : 0;
    if (probe) sqlite3_finalize(probe);
  }
  const int epss_off = 8 + (has_excl ? 2 : 0);

  std::string sql =
      "SELECT cve_id, cvss_score, severity, description, version_min, "
      "version_max, cvss_vector, remote_unauthed";
  if (has_excl) sql += ", version_min_exclusive, version_max_exclusive";
  if (has_epss) sql += ", epss_score, kev, kev_ransomware";
  sql += " FROM cves WHERE product = ? AND cvss_score >= 0.0 "
         "ORDER BY cvss_score DESC LIMIT 2000";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(cve_db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    return results;

  sqlite3_bind_text(stmt, 1, product.c_str(), -1, SQLITE_TRANSIENT);

  /* det_ver is constant for this lookup, so parse it once instead of
     re-parsing it inside ver_cmp_enrich for every candidate row. */
  const std::vector<int> det_parts = parse_ver_enrich(det_ver);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    auto col_str = [&](int c) -> std::string {
      const unsigned char *p = sqlite3_column_text(stmt, c);
      return p ? reinterpret_cast<const char *>(p) : "";
    };

    std::string vmin = col_str(4);
    std::string vmax = col_str(5);
    int vmin_excl = has_excl ? sqlite3_column_int(stmt, 8) : 0;
    int vmax_excl = has_excl ? sqlite3_column_int(stmt, 9) : 0;

    /* Require at least one version bound to assert a match.  A row with
       NEITHER a version_min NOR a version_max carries no version
       applicability at all, so it would match EVERY version of the
       product -- a guaranteed false-positive class.  These rows come from
       the NVD importer's description-keyword fallback (a CVE with no CPE
       data, tagged to a product purely by a word in its text) and from
       product-name collisions (e.g. CVE-2025-1974 "IngressNightmare" is a
       Kubernetes ingress-nginx Controller RCE, NOT the nginx web server,
       yet keyword-matches product=nginx).  Without a version range we
       cannot say a detected host is vulnerable, so skip it. */
    if (vmin.empty() && vmax.empty()) continue;

    /* Version range filtering with inclusive/exclusive bounds.  An exclusive
       upper bound (NVD versionEndExcluding = the FIXED version) means affected
       < vmax, so the fixed version must NOT match; inclusive means <= vmax.
       Symmetric for the lower bound.  det_ver non-empty (early-returned). */
    if (!vmin.empty()) {
      int cmp = ver_cmp_parsed(det_parts, parse_ver_enrich(vmin));
      if (cmp < 0 || (vmin_excl && cmp == 0)) continue;
    }
    if (!vmax.empty()) {
      int cmp = ver_cmp_parsed(det_parts, parse_ver_enrich(vmax));
      if (cmp > 0 || (vmax_excl && cmp == 0)) continue;
    }

    EnrichCve e;
    e.id          = col_str(0);
    e.cvss        = static_cast<float>(sqlite3_column_double(stmt, 1));
    e.severity    = col_str(2);
    e.description = col_str(3);
    e.cvss_vector = col_str(6);
    /* remote_unauthed: NULL -> -1 (unknown); 0/1 stored verbatim. */
    e.remote_unauthed = (sqlite3_column_type(stmt, 7) == SQLITE_NULL)
                          ? -1
                          : sqlite3_column_int(stmt, 7);
    if (has_epss) {
      e.epss = (sqlite3_column_type(stmt, epss_off) == SQLITE_NULL)
                 ? -1.0f : static_cast<float>(sqlite3_column_double(stmt, epss_off));
      e.kev            = sqlite3_column_int(stmt, epss_off + 1) != 0;
      e.kev_ransomware = sqlite3_column_int(stmt, epss_off + 2) != 0;
    }
    results.push_back(std::move(e));
    if (static_cast<int>(results.size()) >= KMAP_CVE_RESULT_CAP) break;
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
        << "\",\"desc\":\"" << json_escape(desc) << "\"";
    if (!cves[i].cvss_vector.empty())
      oss << ",\"vec\":\"" << json_escape(cves[i].cvss_vector) << "\"";
    if (cves[i].remote_unauthed >= 0)
      oss << ",\"remote\":" << cves[i].remote_unauthed;
    if (cves[i].epss >= 0.0f) {
      char epss_buf[16];
      snprintf(epss_buf, sizeof(epss_buf), "%.4f", cves[i].epss);
      oss << ",\"epss\":" << epss_buf;
    }
    if (cves[i].kev) oss << ",\"kev\":1";
    if (cves[i].kev_ransomware) oss << ",\"ransomware\":1";
    oss << "}";
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
  std::string favicon_mmh3;     /* Shodan favicon hash; "" if not captured */
  std::string body_sha256;      /* SHA-256 of the "/" body; "" if no body */
};

/* Extract a header value. `lower_resp` MUST be str_lower(resp) — the caller
   passes it in so a response with many interesting headers is lowercased once
   instead of once per header (the HTTP enrichment hot path pulls ~8 headers
   per host; at internet scale that redundant copy of a 64 KB response dominated
   the per-host CPU). `resp` (original case) is used only to slice the value so
   the stored header keeps its original casing. */
static std::string extract_header_val(const std::string &resp,
                                      const std::string &lower_resp,
                                      const char *name) {
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

/* Fetch /favicon.ico over plaintext HTTP and return its Shodan-style hash
   (mmh3 of the base64-encoded body) or "" on any failure / non-2xx / empty
   body.  One extra TCP connect per HTTP host; only called when the net-scan
   path opted into fingerprint capture.  HTTPS favicons are out of scope here
   (this reuses the plaintext probe_http transport). */
static std::string probe_favicon_mmh3(const char *ip, int port, int timeout_ms) {
  kmap_fd_t fd = enrich_tcp_connect(ip, static_cast<uint16_t>(port), timeout_ms);
  if (fd == KMAP_INVALID_FD) return "";
  int read_to = enrich_read_timeout(timeout_ms);

  std::string req = os_profile_http_request(
      "/favicon.ico", ip,
      os_profile_get_for_target(o.spoof_os, os_profile_seed_from_text(ip)));
  if (!enrich_fd_send(fd, req.c_str(), req.size())) {
    enrich_close_fd(fd);
    return "";
  }

  /* Favicons are small; cap the read well below a runaway response. */
  std::string response;
  response.reserve(4096);
  char chunk[4096];
  while (response.size() < 262144) {
    if (enrich_wait_fd(fd, /*want_write=*/false, read_to) <= 0) break;
#ifdef WIN32
    int n = static_cast<int>(recv(static_cast<SOCKET>(fd), chunk, sizeof(chunk), 0));
#else
    int n = static_cast<int>(recv(static_cast<int>(fd), chunk, sizeof(chunk), 0));
#endif
    if (n <= 0) break;
    response.append(chunk, static_cast<size_t>(n));
  }
  enrich_close_fd(fd);

  if (response.empty()) return "";
  int status = extract_status(response);
  if (status < 200 || status >= 300) return "";
  size_t body_start = response.find("\r\n\r\n");
  if (body_start == std::string::npos) return "";
  std::string body = response.substr(body_start + 4);
  if (body.empty()) return "";
  return favicon_mmh3(body);
}

/* probe_http -- if cached_response is non-empty, reuse it instead of
   making a new TCP connection (avoids the double-connect from grab_banner). */
static WebResult probe_http(const char *ip, int port, int timeout_ms,
                            const std::string &cached_response = "",
                            bool capture_fp = false) {
  WebResult wr;

  std::string response;
  if (!cached_response.empty()) {
    response = cached_response;
  } else {
    kmap_fd_t fd = enrich_tcp_connect(ip, static_cast<uint16_t>(port), timeout_ms);
    if (fd == KMAP_INVALID_FD) return wr;
    int read_to = enrich_read_timeout(timeout_ms);

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
      if (enrich_wait_fd(fd, /*want_write=*/false, read_to) <= 0)
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

  wr.title = extract_html_title(body);

  /* Lowercase the response ONCE here; every header lookup below reuses it
     (extract_header_val no longer lowercases internally).  The dedicated
     columns (Server / X-Powered-By / X-Generator) are captured from the same
     single pass that builds the headers JSON, so each header is located once. */
  std::string lower_resp = str_lower(response);

  /* Build headers JSON object with selected interesting headers */
  std::ostringstream hdr_json;
  hdr_json << "{";
  bool first = true;
  const char *interesting[] = {
    "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
    "X-Frame-Options", "Content-Type", "Set-Cookie", nullptr
  };
  for (const char **hp = interesting; *hp; hp++) {
    std::string val = extract_header_val(response, lower_resp, *hp);
    if (val.empty()) continue;
    /* Mirror the ones we persist as dedicated WebResult columns. */
    if      (strcmp(*hp, "Server") == 0)       wr.server      = val;
    else if (strcmp(*hp, "X-Powered-By") == 0) wr.powered_by  = val;
    else if (strcmp(*hp, "X-Generator") == 0)  wr.x_generator = val;
    if (!first) hdr_json << ",";
    hdr_json << "\"" << json_escape(*hp) << "\":\""
             << json_escape(val) << "\"";
    first = false;
  }
  hdr_json << "}";
  if (!first) wr.headers_json = hdr_json.str();

  /* Location is not in the JSON header set but is needed for redirect
     analysis; extract it from the same lowercased response. */
  wr.redirect_target = extract_header_val(response, lower_resp, "Location");

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

  /* Active fingerprints (net-scan path only).  body_sha256 reuses the body we
     already decoded; favicon needs one extra plaintext GET to /favicon.ico
     (probe_favicon_mmh3 self-gates on a 2xx). */
  if (capture_fp) {
    if (!body.empty()) wr.body_sha256 = sha256_hex(body);
    std::string fav = probe_favicon_mmh3(ip, port, timeout_ms);
    if (!fav.empty()) wr.favicon_mmh3 = fav;
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

  /* Bounded, poll-driven handshake.  enrich_tcp_connect hands back a BLOCKING
     socket, and SSL_connect() on a blocking fd has NO read deadline: a host
     that completes the TCP handshake but then stalls the TLS handshake (a
     silent / tarpit 443, which you WILL meet at internet scale) blocks this
     worker forever.  enrich_single_host join()s all its port-threads and
     run_enrichment join()s all its host-workers, so one stalled handshake
     hangs the entire enrichment phase with nothing ever committed.  The
     timeout_ms passed in was previously only honoured by the TCP connect;
     apply it to the handshake too by driving SSL_connect non-blocking through
     the same poll helper the banner/HTTP recv loops use, with an overall
     deadline that is cumulative across WANT_READ/WANT_WRITE waits (so a
     byte-at-a-time tarpit cannot extend it past timeout_ms). */
#ifdef WIN32
  { u_long nb = 1; ioctlsocket(static_cast<SOCKET>(fd), FIONBIO, &nb); }
#else
  fcntl(static_cast<int>(fd), F_SETFL,
        fcntl(static_cast<int>(fd), F_GETFL, 0) | O_NONBLOCK);
#endif
  {
    auto hs_deadline = std::chrono::steady_clock::now() +
                       std::chrono::milliseconds(timeout_ms > 0 ? timeout_ms : 1);
    bool hs_ok = false;
    for (;;) {
      int r = SSL_connect(ssl);
      if (r == 1) { hs_ok = true; break; }
      int err = SSL_get_error(ssl, r);
      bool want_write;
      if      (err == SSL_ERROR_WANT_READ)  want_write = false;
      else if (err == SSL_ERROR_WANT_WRITE) want_write = true;
      else break;                        /* fatal handshake error -> give up */
      int rem = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
          hs_deadline - std::chrono::steady_clock::now()).count());
      if (rem <= 0) break;               /* handshake deadline exceeded */
      if (enrich_wait_fd(fd, want_write, rem) <= 0) break;  /* timeout / error */
    }
    if (!hs_ok) {
      SSL_free(ssl);
      enrich_close_fd(fd);
      return -1;
    }
  }
  /* Socket stays non-blocking through the in-memory cert reads (which touch
     no fd) and the single best-effort SSL_shutdown below, so neither can
     re-introduce an unbounded blocking read. */

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

/* Aggregate metrics for the per-host enrichment budget. Bumped from
   enrich_single_host whenever a single host exceeds the wall budget,
   so callers can report "N hosts bailed at budget" in the scan summary
   without each call site needing its own counter. Reset by the scan
   driver via enrich_reset_metrics() at the start of each phase. */
std::atomic<uint64_t> g_enrich_budget_bails{0};
std::atomic<uint64_t> g_enrich_hosts_done{0};
std::atomic<uint64_t> g_enrich_total_ms{0};
std::atomic<uint64_t> g_enrich_max_ms{0};

void enrich_reset_metrics() {
  g_enrich_budget_bails.store(0, std::memory_order_relaxed);
  g_enrich_hosts_done.store(0, std::memory_order_relaxed);
  g_enrich_total_ms.store(0, std::memory_order_relaxed);
  g_enrich_max_ms.store(0, std::memory_order_relaxed);
}

EnrichMetrics enrich_get_metrics() {
  EnrichMetrics m;
  m.budget_bails = g_enrich_budget_bails.load(std::memory_order_relaxed);
  m.hosts_done   = g_enrich_hosts_done.load(std::memory_order_relaxed);
  m.total_ms     = g_enrich_total_ms.load(std::memory_order_relaxed);
  m.max_ms       = g_enrich_max_ms.load(std::memory_order_relaxed);
  return m;
}

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
                       std::vector<TlsCapture> *out_tls,
                       std::vector<HostFingerprints> *out_fp) {
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
  /* resize, not assign: preserves any pre-populated TlsCapture entries
     (e.g. from an async pre-pass under KMAP_ASYNC_ENRICH=1). The other
     out_* vectors use resize() for the same reason; this one used to
     use assign() and clobbered async-filled cert data. */
  if (out_tls) out_tls->resize(nports);
  if (out_fp)  out_fp->resize(nports);

  /* Per-host wall-clock budget. The hard requirement: one slow host
     must not block the worker pool indefinitely. A box with 30 filtered
     ports + 5 sec banner-grab timeout each would otherwise occupy a
     worker for 150 seconds while 39 other workers process the rest of
     the queue at full speed -- one stuck host = one worker permanently
     down, scaling badly at internet scale.

     KMAP_HOST_ENRICH_BUDGET_MS caps total wall time per host. Each
     per-port step (banner / web probe / TLS) gets a timeout reduced to
     min(per_step_timeout, budget_remaining), so the last step never
     overshoots. When the budget runs out, the port loop breaks and the
     caller proceeds with whatever data we already collected.

     Default 15s -- empirically covers ~95% of hosts with a few open
     ports while bounding the worst case. Tune up for slower links or
     deeper enrichment; down for tighter sweep performance. */
  int budget_ms = 15000;
  if (const char *env = getenv("KMAP_HOST_ENRICH_BUDGET_MS")) {
    int v = atoi(env);
    if (v > 0) budget_ms = v;
  }
  auto host_start = std::chrono::steady_clock::now();
  auto budget_remaining = [&]() -> int {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - host_start).count();
    int rem = budget_ms - static_cast<int>(elapsed);
    return rem > 0 ? rem : 0;
  };

  /* Phase 0 parallel-ports model. The sequential for-loop here used to
     run each port's banner -> CVE -> HTTP -> TLS pipeline back-to-back,
     so a host with 5 filtered ports took 5 * (banner_timeout +
     http_timeout + tls_timeout) of wall time before the worker could
     move on. Even with the 15-second per-host budget bounding the
     worst case, the average wall per host stayed near the budget
     ceiling because every port's timeout stacked sequentially.

     Now: up to KMAP_HOST_PORT_PARALLELISM ports (default 8) run their
     full pipeline concurrently within the host. Each port-worker
     thread atomically claims the next port index, does its
     banner/CVE/HTTP/TLS work independently, and writes only to its
     own slot in out_*[i] (no shared-vector mutex needed). Wall time
     per host drops from O(nports * step_timeout) to roughly
     O(step_timeout) for hosts with <= 8 open ports, which is the
     common case at scan scale.

     The shared deadline-based budget still bounds total wall time
     (any thread that finds budget_remaining() == 0 returns early), so
     the "one slow host stalls a worker" guarantee from the previous
     commit is preserved. The dead-host fast-path skipped HTTP/TLS on
     filtered ports; we drop that here because in parallel mode each
     filtered port already costs only one banner_timeout regardless,
     and we no longer have "first N ports" to gate on. */
  int port_parallelism = 8;
  if (const char *env = getenv("KMAP_HOST_PORT_PARALLELISM")) {
    int v = atoi(env);
    if (v >= 1 && v <= 32) port_parallelism = v;
  }
  size_t worker_count = static_cast<size_t>(port_parallelism);
  if (worker_count > nports) worker_count = nports;
  if (worker_count < 1) worker_count = 1;

  /* Async-preset skip: when the caller has already filled
     out_services/out_versions/out_cves (and after Phase 1b/1c, web_* and
     TLS) via an upstream async pre-pass (async_enrich_batch), we have no
     reason to re-do that work -- we'd just spend TCP RTTs to confirm what
     the async pass already learned.  KMAP_ASYNC_ENRICH=1 is the
     caller-set contract: "everything in out_*[i] that is already
     non-empty was filled authoritatively; do not overwrite it".  After
     Phase 1c the async path covers banner+CVE+HTTP+TLS; only reverse-DNS
     and ASN lookup remain on the sync side (and those happen in the
     caller, not in this function). */
  bool async_preset_mode = false;
  if (const char *env = getenv("KMAP_ASYNC_ENRICH")) {
    if (atoi(env) > 0) async_preset_mode = true;
  }

  std::atomic<size_t> next_port_idx{0};
  std::atomic<int> budget_hit_count{0};

  auto port_worker = [&]() {
    while (true) {
      size_t i = next_port_idx.fetch_add(1, std::memory_order_relaxed);
      if (i >= nports) return;

      int rem = budget_remaining();
      if (rem == 0) {
        budget_hit_count.fetch_add(1, std::memory_order_relaxed);
        return;
      }
      int port_timeout = timeout_ms < rem ? timeout_ms : rem;

      /* Step 1: Banner grab. Skip when async pre-pass already filled
         this slot. The async path's classifier is the same code (copied
         to net_enrich_async.cc) so we can trust its verdict. */
      BannerResult br;
      bool skip_banner = async_preset_mode && !out_services[i].empty();
      if (!skip_banner) {
        br = grab_banner(ip, ports[i], port_timeout);
        if (!br.service.empty()) out_services[i] = br.service;
        if (!br.version.empty()) out_versions[i] = br.version;
        if (out_fp && !br.hassh.empty()) (*out_fp)[i].hassh = br.hassh;
      } else {
        /* Use pre-populated values for downstream branching
           (is_http_port / is_https_port read br.service). */
        br.service = out_services[i];
        br.version = out_versions[i];
      }

      /* Step 2: CVE lookup. Skip in async-preset mode too -- already
         done by the async pass. */
      if (!skip_banner && cve_db && !out_services[i].empty()) {
        std::vector<EnrichCve> cves = lookup_cves(cve_db, out_services[i], out_versions[i]);
        out_cves[i] = cves_to_json(cves);
      }

      /* Step 3: HTTP recon on plaintext web ports.  Skip when async
         pre-pass already filled this slot -- the heuristic "out_web_servers
         is non-empty OR out_web_headers is non-empty" is the cleanest
         signal that the async HTTP stage ran (a server with no Server
         header and no parseable response is rare; if it happens we redo
         a tiny extra probe rather than miss data on the common case). */
      bool skip_http = async_preset_mode &&
                       (!out_web_servers[i].empty() ||
                        !out_web_headers[i].empty() ||
                        !out_web_titles[i].empty());
      rem = budget_remaining();
      if (!skip_http && rem > 0 &&
          is_http_port(ports[i], br.service) &&
          !is_https_port(ports[i], br.service)) {
        int http_timeout = timeout_ms < rem ? timeout_ms : rem;
        WebResult wr = probe_http(ip, ports[i], http_timeout, br.http_response,
                                  /*capture_fp=*/out_fp != nullptr);
        out_web_titles[i]   = wr.title;
        out_web_servers[i]  = wr.server;
        out_web_headers[i]  = wr.headers_json;
        out_web_paths[i]    = wr.paths_json;
        out_powered_by[i]   = wr.powered_by;
        out_x_generator[i]  = wr.x_generator;
        out_redirects[i]    = wr.redirect_target;
        if (out_fp) {
          (*out_fp)[i].favicon_mmh3 = wr.favicon_mmh3;
          (*out_fp)[i].body_sha256  = wr.body_sha256;
        }
      }

      /* Step 4: TLS handshake on HTTPS ports.  Skip when async pre-pass
         already populated a TlsCapture (self_signed != -1 means the
         async TLS stage at least observed the connect succeed; a non-
         empty subject/issuer/sha256 confirms cert details were captured). */
      bool skip_tls = async_preset_mode && out_tls && i < out_tls->size() &&
                      ((*out_tls)[i].self_signed != -1 ||
                       !(*out_tls)[i].subject_cn.empty() ||
                       !(*out_tls)[i].issuer.empty()     ||
                       !(*out_tls)[i].sha256.empty());
      rem = budget_remaining();
      if (!skip_tls && rem > 0 && out_tls && is_https_port(ports[i], br.service)) {
        int tls_timeout = timeout_ms < rem ? timeout_ms : rem;
        tls_capture_cert(ip, ports[i], tls_timeout, (*out_tls)[i]);
      }
    }
  };

  {
    std::vector<std::thread> port_threads;
    port_threads.reserve(worker_count);
    for (size_t w = 0; w < worker_count; w++)
      port_threads.emplace_back(port_worker);
    for (auto &t : port_threads) t.join();
  }

  bool budget_hit = budget_hit_count.load(std::memory_order_relaxed) > 0;

  /* Metrics: total wall time, max-seen, budget-bail counter. */
  uint64_t elapsed_ms = static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - host_start).count());
  g_enrich_hosts_done.fetch_add(1, std::memory_order_relaxed);
  g_enrich_total_ms.fetch_add(elapsed_ms, std::memory_order_relaxed);
  uint64_t prev_max = g_enrich_max_ms.load(std::memory_order_relaxed);
  while (elapsed_ms > prev_max &&
         !g_enrich_max_ms.compare_exchange_weak(prev_max, elapsed_ms,
                                                std::memory_order_relaxed)) {}
  if (budget_hit) {
    g_enrich_budget_bails.fetch_add(1, std::memory_order_relaxed);
  }

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
    net_event_log("WARN", "kmap-cve.db not found -- CVE enrichment skipped");
  } else {
    log_write(LOG_STDOUT,
      "net-scan: CVE database: %s\n", cve_path.c_str());
    net_event_log("INFO", "CVE database: %s", cve_path.c_str());
  }

  /* Open the CVE DB ONCE for the entire enrichment phase, shared
   * read-only across all shards' worker pools.  sqlite is built
   * SQLITE_THREADSAFE=0 (no internal mutexes), so concurrent use of this
   * one handle is NOT safe by itself -- access is serialized by the
   * static mutex inside lookup_cves(), the only function that touches it
   * from the worker threads.  Previously enrich_single_host opened+closed
   * the DB on every host call -- 5x or more per batch with the parallel
   * workers spinning through hundreds of thousands of stat+open+
   * page-cache-warm cycles on a full sweep. */
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

  /* Load the offline cloud-provider range table ONCE for the whole phase
     (before any worker runs lookup_cloud).  A missing file just means no
     host receives a cloud tag -- graceful, like a missing CVE DB. */
  {
    char cbuf[1024];
    std::string cloud_path;
    if (kmap_fetchfile(cbuf, sizeof(cbuf), "kmap-cloud-ranges.csv") > 0) {
      cloud_path = cbuf;
    } else {
      FILE *cwd = fopen("kmap-cloud-ranges.csv", "rb");
      if (cwd) { fclose(cwd); cloud_path = "kmap-cloud-ranges.csv"; }
    }
    size_t nranges = cloud_ranges_load(cloud_path.empty() ? "" : cloud_path.c_str());
    if (nranges > 0) {
      log_write(LOG_STDOUT, "net-scan: cloud ranges: %llu from %s\n",
                (unsigned long long)nranges, cloud_path.c_str());
      net_event_log("INFO", "cloud-ranges: %llu ranges from %s",
                    (unsigned long long)nranges, cloud_path.c_str());
    } else {
      net_event_log("INFO",
                    "cloud-ranges: none loaded (kmap-cloud-ranges.csv not found)");
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
    std::vector<HostFingerprints> host_fps;
    std::string hostname;
    AsnInfo asn_info{};
    CloudInfo cloud_info{};
    int rc = 0;
    bool empty_host = false;
  };

  /* Worker / retry counts read once, applied globally. */
  int enrich_worker_count = 40;
  /* --efficient / --fast derive a resource-aware default; the env var
   * still overrides (checked after) so explicit tuning wins. */
  {
    const KmapPerfProfile &pp = kmap_perf_profile();
    if (pp.mode != KMAP_PERF_NORMAL && pp.enrich_workers > 0)
      enrich_worker_count = pp.enrich_workers;
  }
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

  /* Stage A-bis (Phase 1d): batched parallel reverse-DNS via the
     existing kmap_mass_dns resolver (nsock-driven under the hood).
     Replaces per-host blocking getnameinfo() calls that the workers
     used to do. Each EnrichResult.hostname is filled in-place here so
     the worker loop just reads from it.

     At 7000-host scale the sync per-host PTR took ~5s each (often
     timeouts on PTR-less IPs) -- about 16 min of cumulative DNS wall
     time even across 40 workers. kmap_mass_dns resolves the whole
     batch in seconds. KMAP_NO_DNS=1 skips the batch entirely
     (workers leave hostname empty) for operators who don't want
     reverse-DNS traffic on a scan. */
  bool do_reverse_dns = true;
  if (const char *env = getenv("KMAP_NO_DNS")) {
    if (atoi(env) > 0) do_reverse_dns = false;
  }
  if (do_reverse_dns && !results.empty()) {
    std::vector<DNS::Request> dns_requests(results.size());
    int dns_query_count = 0;
    for (size_t i = 0; i < results.size(); i++) {
      if (results[i].empty_host) continue;
      struct sockaddr_storage ss{};
      socklen_t slen = 0;
      struct sockaddr_in  *sa4 = reinterpret_cast<struct sockaddr_in  *>(&ss);
      struct sockaddr_in6 *sa6 = reinterpret_cast<struct sockaddr_in6 *>(&ss);
      if (inet_pton(AF_INET, results[i].ip.c_str(), &sa4->sin_addr) == 1) {
        sa4->sin_family = AF_INET;
        slen = sizeof(struct sockaddr_in);
      } else if (inet_pton(AF_INET6, results[i].ip.c_str(), &sa6->sin6_addr) == 1) {
        sa6->sin6_family = AF_INET6;
        slen = sizeof(struct sockaddr_in6);
      } else {
        continue;  /* unparseable IP, leave hostname empty */
      }
      (void)slen;
      dns_requests[i].ssv.push_back(ss);
      dns_requests[i].type = DNS::PTR;
      dns_query_count++;
    }
    if (dns_query_count > 0) {
      auto dns_start = std::chrono::steady_clock::now();
      log_write(LOG_STDOUT,
        "net-scan: batched reverse DNS for %d hosts...\n", dns_query_count);
      kmap_mass_dns(dns_requests.data(),
                    static_cast<int>(dns_requests.size()));
      auto dns_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - dns_start).count();
      int resolved = 0;
      for (size_t i = 0; i < results.size(); i++) {
        if (!dns_requests[i].name.empty()) {
          results[i].hostname = dns_requests[i].name;
          resolved++;
        }
      }
      log_write(LOG_STDOUT,
        "net-scan: reverse DNS: %d/%d resolved in %.2fs\n",
        resolved, dns_query_count,
        static_cast<double>(dns_ms) / 1000.0);
    }
  }

  /* Stage A.5: batched ASN lookups.  lookup_asn does up to two Cymru UDP
     round-trips (origin + AS-name) per host; left in the per-host Stage-B
     worker it serialized behind that host's port pipeline -- the last per-host
     NETWORK leg that was not batched (reverse-DNS already is, above).  A
     dedicated pool resolves the whole batch up front, so the round-trips
     overlap each OTHER instead of each host's port enrichment, and the prefix
     cache collapses same-/24 hosts.  Concurrency is moderate by default (Team
     Cymru rate-limits, so a huge in-flight count would lose coverage); tune
     with KMAP_ASN_BATCH_CONCURRENCY.  KMAP_NO_ASN=1 skips it entirely.  Each
     worker writes only its own results[i].asn_info slot (no shared state), and
     this completes before Stage B, which no longer touches asn_info. */
  bool do_asn = true;
  if (const char *env = getenv("KMAP_NO_ASN")) {
    if (atoi(env) > 0) do_asn = false;
  }
  if (do_asn && !results.empty()) {
    int asn_hosts = 0;
    for (auto &r : results) if (!r.empty_host) asn_hosts++;
    if (asn_hosts > 0) {
      int asn_workers = 64;
      if (const char *env = getenv("KMAP_ASN_BATCH_CONCURRENCY")) {
        int v = atoi(env);
        if (v >= 1 && v <= 1024) asn_workers = v;
      }
      if (asn_workers > asn_hosts) asn_workers = asn_hosts;
      uint64_t aq_before = asn_origin_query_count();
      auto asn_start = std::chrono::steady_clock::now();
      log_write(LOG_STDOUT,
        "net-scan: batched ASN lookups for %d hosts (%d workers)...\n",
        asn_hosts, asn_workers);
      std::atomic<size_t> asn_next{0};
      {
        std::vector<std::thread> asn_pool;
        asn_pool.reserve(asn_workers);
        for (int w = 0; w < asn_workers; w++) {
          asn_pool.emplace_back([&]() {
            for (;;) {
              size_t i = asn_next.fetch_add(1, std::memory_order_relaxed);
              if (i >= results.size()) return;
              if (results[i].empty_host) continue;
              results[i].asn_info = lookup_asn(results[i].ip.c_str(), 2000);
            }
          });
        }
        for (auto &t : asn_pool) t.join();
      }
      auto asn_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - asn_start).count();
      uint64_t aq_delta = asn_origin_query_count() - aq_before;
      log_write(LOG_STDOUT,
        "net-scan: ASN: %d host(s) -> %llu Cymru origin quer%s in %.2fs\n",
        asn_hosts, (unsigned long long)aq_delta,
        aq_delta == 1 ? "y" : "ies",
        static_cast<double>(asn_ms) / 1000.0);
    }
  }

  /* Stage B: ONE global parallel worker pool over the entire results
   * vector.  No mutex on results because each worker writes only its
   * own slot. */
  int actual_workers = enrich_worker_count;
  if (static_cast<size_t>(actual_workers) > results.size())
    actual_workers = static_cast<int>(results.size());
  if (actual_workers < 1) actual_workers = 1;

  /* Per-port connect timeout: env-tunable so a sweep can dial it down on
     a low-RTT LAN or up on a high-RTT path without recompiling. The
     KMAP_HOST_ENRICH_BUDGET_MS budget caps total host wall time
     regardless of how generous this per-port value is. */
  int enrich_connect_timeout = ENRICH_CONNECT_TIMEOUT;
  if (const char *env = getenv("KMAP_ENRICH_CONNECT_TIMEOUT_MS")) {
    int v = atoi(env);
    if (v > 0) enrich_connect_timeout = v;
  }
  enrich_reset_metrics();

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
                   enrich_connect_timeout,
                   r.services, r.versions, r.cves_json,
                   r.web_titles, r.web_servers,
                   r.web_headers, r.web_paths,
                   r.powered_by, r.x_generator, r.redirects,
                   &r.tls_caps, &r.host_fps);
        if (r.rc == 0) break;
        if (attempt >= enrich_retries) break;
        attempt++;
      }

      if (r.rc == 0) {
        /* r.hostname was filled by the batched reverse-DNS pre-pass and
           r.asn_info by the batched ASN pre-pass above, so neither blocks
           this worker. Only the offline cloud-provider match (pure,
           lock-free, no network) remains per-host here. */
        uint32_t ipu = ip_to_u32(r.ip.c_str());
        if (ipu) r.cloud_info = lookup_cloud(ipu);
      }
      processed_atomic.fetch_add(1, std::memory_order_relaxed);

      /* --fast / --efficient: hold sustained CPU at/below the configured
       * share. No-op in normal mode or when CPU is unmeasurable. */
      kmap_cpu_governor_throttle();
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

  /* Arm the CPU governor with a fresh baseline right before the CPU-heavy
   * enrichment pool runs (--fast/--efficient only). */
  kmap_cpu_governor_init(kmap_perf_cpu_target_cores());

  /* Peak concurrent sockets = hosts in flight * ports probed per host.
     Read the port-parallelism env here too so the limit matches what
     enrich_single_host will actually open. */
  int enrich_pp = 8;
  if (const char *env = getenv("KMAP_HOST_PORT_PARALLELISM")) {
    int v = atoi(env);
    if (v >= 1 && v <= 32) enrich_pp = v;
  }
  raise_fd_limit(actual_workers * enrich_pp + 64);

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
        std::string enr_cpe = net_enrich_cpe_for(
          j < r.services.size() ? r.services[j] : std::string(),
          j < r.versions.size() ? r.versions[j] : std::string());
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
          nullptr,                                  /* robots_disallowed_json */
          enr_cpe.empty() ? nullptr : enr_cpe.c_str());

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
      /* Cloud match is independent of ASN -- a host can be in a cloud range
         with no ASN result, so this is NOT gated on asn > 0. */
      if (!r.cloud_info.provider.empty()) {
        net_db_update_cloud(db, r.ip.c_str(),
                            r.cloud_info.provider.c_str(),
                            r.cloud_info.region.empty()  ? nullptr : r.cloud_info.region.c_str(),
                            r.cloud_info.service.empty() ? nullptr : r.cloud_info.service.c_str());
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
          /* Active fingerprints (ASCII-safe values: a decimal mmh3 and a hex
             SHA-256 -- no JSON/control-char escaping needed). */
          if (j < r.host_fps.size()) {
            const HostFingerprints &fp = r.host_fps[j];
            if (!fp.favicon_mmh3.empty()) {
              net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                        "favicon_mmh3",
                                        fp.favicon_mmh3.c_str(), fp_ts);
            }
            if (!fp.body_sha256.empty()) {
              net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                        "http_body_sha256",
                                        fp.body_sha256.c_str(), fp_ts);
            }
            if (!fp.hassh.empty()) {
              net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                        "hassh",
                                        fp.hassh.c_str(), fp_ts);
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
  net_event_log("INFO", "enrichment pass: %lld host(s) written%s",
                (long long)processed,
                errors > 0 ? " (with shard open errors)" : "");
  {
    EnrichMetrics m = enrich_get_metrics();
    if (m.hosts_done > 0) {
      log_write(LOG_STDOUT,
        "net-scan: enrichment timing: avg=%.2fs max=%.2fs budget-bailed=%llu/%llu\n",
        static_cast<double>(m.total_ms) / static_cast<double>(m.hosts_done) / 1000.0,
        static_cast<double>(m.max_ms) / 1000.0,
        (unsigned long long)m.budget_bails,
        (unsigned long long)m.hosts_done);
    }
  }
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
