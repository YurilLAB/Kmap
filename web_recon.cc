/*
 * web_recon.cc -- HTTP/HTTPS recon engine for Kmap.
 *
 * Grabs page title, server headers, robots.txt, TLS cert info,
 * and probes a curated list of high-value paths.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "web_recon.h"
#include "output.h"
#include "portlist.h"
#include "service_scan.h"
#include "utils.h"
#include "kmap_error.h"
#include "nbase.h"

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdio>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#endif

#define WEB_RECON_KEY    "kmap_web_recon"
#define CONNECT_TIMEOUT  5000  /* ms */
#define READ_TIMEOUT     5000  /* ms */

/* -----------------------------------------------------------------------
 * Built-in high-value path list
 * ----------------------------------------------------------------------- */
static const char *builtin_paths[] = {
  /* Admin panels / login pages */
  "/admin", "/login", "/admin/login", "/administrator",
  "/manager/html", "/webadmin", "/cpanel", "/dashboard",
  "/portal", "/admin/dashboard", "/cgi-bin/",
  /* PHP tooling */
  "/phpMyAdmin", "/phpmyadmin", "/adminer.php", "/config.php",
  /* WordPress */
  "/wp-login.php", "/wp-admin/", "/wp-config.php.bak", "/wp-json/wp/v2/users",
  "/xmlrpc.php",
  /* API / documentation endpoints */
  "/api/v1", "/api/v2", "/api/docs", "/api/swagger.json",
  "/swagger-ui.html", "/swagger/v1/swagger.json",
  "/graphql", "/graphiql", "/v1/api-docs", "/openapi.json",
  /* Java / Spring */
  "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
  "/actuator/configprops", "/actuator/beans", "/console", "/jolokia",
  "/jmx-console", "/web-console", "/invoker/JMXInvokerServlet",
  "/h2-console",
  /* Debug / profiling endpoints */
  "/_profiler", "/debug", "/debug/vars", "/debug/pprof",
  "/server-status", "/server-info", "/trace.axd", "/elmah.axd",
  "/_debug_toolbar/", "/telescope",
  /* Sensitive files / directories */
  "/.env", "/.env.bak", "/.env.local", "/.env.production",
  "/.git/HEAD", "/.git/config", "/.gitignore",
  "/.htaccess", "/.htpasswd", "/.svn/entries", "/.DS_Store",
  "/web.config", "/WEB-INF/web.xml", "/crossdomain.xml",
  "/backup", "/backup.sql", "/backup.zip", "/db.sql",
  "/dump.sql", "/database.sql", "/config.yml", "/config.json",
  "/credentials.json", "/application.yml", "/application.properties",
  "/.npmrc", "/.dockerenv",
  /* Framework / CMS detection */
  "/wp-includes/version.php", "/joomla.xml", "/RELEASE_NOTES.txt",
  "/vendor/composer/installed.json",
  /* Kubernetes / Docker / cloud */
  "/.kube/config", "/v2/_catalog",
  "/api/v1/namespaces", "/metadata",
  /* Common test / staging endpoints */
  "/staging", "/test", "/info.php", "/phpinfo.php",
  /* Metadata / discovery */
  "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
  "/.well-known/openid-configuration",
  "/README.md", "/CHANGELOG.md",
  /* Additional sensitive files */
  "/composer.json", "/package.json", "/Gemfile", "/requirements.txt",
  "/Pipfile", "/yarn.lock", "/pom.xml", "/build.gradle",
  "/.travis.yml", "/.circleci/config.yml", "/Dockerfile",
  "/docker-compose.yml", "/.aws/credentials",
  /* Version control / CI artifacts */
  "/.hg/", "/.bzr/", "/CVS/Entries",
  "/.github/workflows/", "/Jenkinsfile", "/Vagrantfile",
  /* Server config files */
  "/nginx.conf", "/httpd.conf", "/php.ini", "/.user.ini",
  "/wp-config.php", "/configuration.php", "/settings.php",
  "/local_settings.py", "/config/database.yml",
  /* Error pages and info disclosure */
  "/error", "/errors", "/404", "/500",
  "/error_log", "/access_log",
  /* Additional admin endpoints */
  "/admin.php", "/administrator.php", "/cms", "/cms/admin",
  "/controlpanel", "/panel", "/management",
  "/siteadmin", "/webmaster",
  /* Additional API endpoints */
  "/api/v3", "/api/graphql", "/api/health",
  "/api/status", "/api/config", "/api/users",
  "/rest/api/latest",
  /* Backup and dump patterns */
  "/backup.tar.gz", "/site.tar.gz", "/www.zip",
  "/old", "/archive", "/temp", "/tmp",
  "/.backup", "/data.sql", "/site.sql",
  /* Additional cloud/container metadata */
  "/latest/meta-data/", "/computeMetadata/v1/",
  "/v1/agent/self", "/v1/catalog/services",
  /* Additional CMS/framework paths */
  "/typo3/", "/typo3conf/LocalConfiguration.php",
  "/sites/default/settings.php", "/app/config/parameters.yml",
  "/laravel/.env", "/storage/logs/laravel.log",
  "/rails/info/properties", "/.svn/wc.db",
  /* Additional sensitive endpoints */
  "/metrics", "/prometheus", "/health",
  "/status", "/server-status?auto",
  "/debug/default/view", "/trace",
  "/.well-known/apple-app-site-association",
  "/feed", "/feeds", "/rss",
  nullptr
};

/* -----------------------------------------------------------------------
 * Low-level TCP helpers — IPv4 and IPv6 aware.
 * Use intptr_t for socket handles to avoid SOCKET-to-int truncation
 * on 64-bit Windows (SOCKET is UINT_PTR = 64 bits on Win64).
 * ----------------------------------------------------------------------- */
typedef intptr_t wr_fd_t;
#define WR_INVALID_FD ((wr_fd_t)-1)

static wr_fd_t tcp_connect_wr(const char *ip, uint16_t port, int timeout_ms) {
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
    return -1;
  }

#ifdef WIN32
  SOCKET fd = socket(af, SOCK_STREAM, 0);
  if (fd == INVALID_SOCKET) return WR_INVALID_FD;
  u_long nb = 1; ioctlsocket(fd, FIONBIO, &nb);
#else
  int fd = socket(af, SOCK_STREAM, 0);
  if (fd < 0) return WR_INVALID_FD;
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif

  connect(fd, reinterpret_cast<struct sockaddr *>(&ss), slen);
  fd_set wset; FD_ZERO(&wset); FD_SET(fd, &wset);
  struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
  if (select(static_cast<int>(fd) + 1, nullptr, &wset, nullptr, &tv) <= 0) {
#ifdef WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return WR_INVALID_FD;
  }
  /* Verify connect() succeeded */
  int sockerr = 0; socklen_t errlen = sizeof(sockerr);
  getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&sockerr), &errlen);
  if (sockerr != 0) {
#ifdef WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return WR_INVALID_FD;
  }
#ifdef WIN32
  nb = 0; ioctlsocket(fd, FIONBIO, &nb);
#else
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
#endif
  return static_cast<wr_fd_t>(fd);
}

static void close_fd_wr(wr_fd_t fd) {
#ifdef WIN32
  closesocket(static_cast<SOCKET>(fd));
#else
  close(static_cast<int>(fd));
#endif
}

static bool send_all(wr_fd_t fd, const char *buf, size_t len) {
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

static std::string recv_response(wr_fd_t fd, int timeout_ms, size_t max_bytes = 65536) {
  std::string response;
  response.reserve(4096);
  char chunk[4096];
  while (response.size() < max_bytes) {
    fd_set rset; FD_ZERO(&rset);
#ifdef WIN32
    FD_SET(static_cast<SOCKET>(fd), &rset);
#else
    FD_SET(static_cast<int>(fd), &rset);
#endif
    struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
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
  return response;
}

/* -----------------------------------------------------------------------
 * HTTP helpers
 * ----------------------------------------------------------------------- */
static std::string extract_header(const std::string &response, const char *name) {
  std::string lower_resp = response;
  std::transform(lower_resp.begin(), lower_resp.end(), lower_resp.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  std::string lower_name = name;
  std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });

  size_t pos = lower_resp.find(lower_name + ":");
  if (pos == std::string::npos) return "";
  size_t start = response.find(':', pos) + 1;
  while (start < response.size() && response[start] == ' ') ++start;
  size_t end = response.find('\r', start);
  if (end == std::string::npos) end = response.find('\n', start);
  if (end == std::string::npos) end = response.size();
  return response.substr(start, end - start);
}

static std::string extract_title(const std::string &body) {
  std::string lower = body;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  size_t ts = lower.find("<title>");
  if (ts == std::string::npos) return "";
  ts += 7;
  size_t te = lower.find("</title>", ts);
  if (te == std::string::npos) te = std::min(ts + 200, body.size());
  std::string t = body.substr(ts, te - ts);
  // Strip whitespace
  size_t a = t.find_first_not_of(" \t\r\n");
  size_t b = t.find_last_not_of(" \t\r\n");
  return (a == std::string::npos) ? "" : t.substr(a, b - a + 1);
}

static int extract_status_code(const std::string &response) {
  if (response.size() < 12) return 0;
  if (response.substr(0, 4) != "HTTP") return 0;
  size_t sp = response.find(' ');
  if (sp == std::string::npos || sp + 3 >= response.size()) return 0;
  /* Validate that the status code chars are digits before parsing */
  char c1 = response[sp + 1], c2 = response[sp + 2], c3 = response[sp + 3];
  if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9' || c3 < '0' || c3 > '9')
    return 0;
  return (c1 - '0') * 100 + (c2 - '0') * 10 + (c3 - '0');
}

static std::string extract_redirect(const std::string &response) {
  return extract_header(response, "Location");
}

/* Build a minimal HTTP/1.0 GET request */
static std::string build_request(const char *path, const char *host) {
  return std::string("GET ") + path + " HTTP/1.0\r\n"
       + "Host: " + host + "\r\n"
       + "User-Agent: Kmap Web Recon\r\n"
       + "Connection: close\r\n\r\n";
}

/* -----------------------------------------------------------------------
 * Plain HTTP probe
 * ----------------------------------------------------------------------- */
static std::string http_get(const char *ip, uint16_t port,
                            const char *path, int timeout_ms) {
  wr_fd_t fd = tcp_connect_wr(ip, port, timeout_ms);
  if (fd == WR_INVALID_FD) return "";
  std::string req = build_request(path, ip);
  if (!send_all(fd, req.c_str(), req.size())) { close_fd_wr(fd); return ""; }
  std::string resp = recv_response(fd, timeout_ms);
  close_fd_wr(fd);
  return resp;
}

/* -----------------------------------------------------------------------
 * HTTPS probe via OpenSSL
 * ----------------------------------------------------------------------- */
#ifdef HAVE_OPENSSL
static SSL_CTX *get_ssl_ctx() {
  static SSL_CTX *ctx = nullptr;
  if (!ctx) {
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx) {
      // Skip verification — self-signed certs are common in internal nets
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
  }
  return ctx;
}

static std::string https_get(const char *ip, uint16_t port,
                              const char *path, int timeout_ms,
                              TlsInfo *tls_out) {
  SSL_CTX *ctx = get_ssl_ctx();
  if (!ctx) return "";

  wr_fd_t fd = tcp_connect_wr(ip, port, timeout_ms);
  if (fd == WR_INVALID_FD) return "";

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, static_cast<int>(fd));
  /* SNI must be a hostname, not an IP — skip for bare IPs (RFC 6066) */
  { struct in_addr dummy4; struct in6_addr dummy6;
    if (inet_pton(AF_INET, ip, &dummy4) != 1 &&
        inet_pton(AF_INET6, ip, &dummy6) != 1)
      SSL_set_tlsext_host_name(ssl, ip);
  }

  if (SSL_connect(ssl) != 1) {
    SSL_free(ssl); close_fd_wr(fd); return "";
  }

  // Extract TLS info
  if (tls_out) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
      char buf[256]{};
      X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
                                 NID_commonName, buf, sizeof(buf));
      tls_out->subject_cn = buf;

      memset(buf, 0, sizeof(buf));
      X509_NAME_get_text_by_NID(X509_get_issuer_name(cert),
                                  NID_commonName, buf, sizeof(buf));
      tls_out->issuer = buf;

      ASN1_TIME *exp = X509_get_notAfter(cert);
      if (exp) {
        BIO *b = BIO_new(BIO_s_mem());
        ASN1_TIME_print(b, exp);
        char tbuf[64]{};
        BIO_read(b, tbuf, sizeof(tbuf) - 1);
        BIO_free(b);
        tls_out->not_after = tbuf;
      }

      tls_out->self_signed =
        (X509_NAME_cmp(X509_get_subject_name(cert),
                        X509_get_issuer_name(cert)) == 0);
      X509_free(cert);
    }
    tls_out->protocol = SSL_get_version(ssl);
  }

  std::string req = build_request(path, ip);
  if (SSL_write(ssl, req.c_str(), static_cast<int>(req.size())) <= 0) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close_fd_wr(fd);
    return "";
  }

  std::string response;
  char chunk[4096];
  while (true) {
    /* Timeout guard to prevent blocking on slow/malicious servers */
    fd_set rset; FD_ZERO(&rset);
#ifdef WIN32
    FD_SET(static_cast<SOCKET>(fd), &rset);
#else
    FD_SET(static_cast<int>(fd), &rset);
#endif
    struct timeval rtv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    if (select(static_cast<int>(fd) + 1, &rset, nullptr, nullptr, &rtv) <= 0)
      break;
    int n = SSL_read(ssl, chunk, sizeof(chunk));
    if (n <= 0) break;
    response.append(chunk, static_cast<size_t>(n));
    if (response.size() > 65536) break;
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  close_fd_wr(fd);
  return response;
}
#else
static std::string https_get(const char *ip, uint16_t port,
                              const char *path, int timeout_ms,
                              TlsInfo *tls_out) {
  (void)ip; (void)port; (void)path; (void)timeout_ms; (void)tls_out;
  return ""; // No OpenSSL
}
#endif

/* -----------------------------------------------------------------------
 * Robots.txt parser
 * ----------------------------------------------------------------------- */
static std::vector<std::string> parse_robots(const std::string &body) {
  std::vector<std::string> disallowed;
  std::istringstream ss(body);
  std::string line;
  while (std::getline(ss, line)) {
    if (line.find("Disallow:") != std::string::npos) {
      size_t colon = line.find(':');
      if (colon != std::string::npos) {
        std::string path = line.substr(colon + 1);
        size_t a = path.find_first_not_of(" \t\r\n");
        if (a != std::string::npos) {
          path = path.substr(a);
          path.erase(path.find_last_not_of(" \t\r\n") + 1);
          if (!path.empty() && path != "/")
            disallowed.push_back(path);
        }
      }
    }
  }
  return disallowed;
}

/* -----------------------------------------------------------------------
 * Core per-port recon logic
 * ----------------------------------------------------------------------- */
static WebReconResult probe_web_port(const char *ip, uint16_t port,
                                     bool is_https,
                                     const std::vector<std::string> &paths) {
  WebReconResult r{};
  r.portno   = port;
  r.is_https = is_https;

  auto do_get = [&](const char *path) -> std::string {
    if (is_https)
      return https_get(ip, port, path, READ_TIMEOUT,
                       (path[1] == '\0') ? &r.tls : nullptr);
    return http_get(ip, port, path, READ_TIMEOUT);
  };

  // GET /
  std::string root = do_get("/");
  if (!root.empty()) {
    // Find the body (after \r\n\r\n)
    size_t body_start = root.find("\r\n\r\n");
    std::string body = (body_start != std::string::npos)
                       ? root.substr(body_start + 4) : root;
    r.title      = extract_title(body);
    r.server     = extract_header(root, "Server");
    r.powered_by = extract_header(root, "X-Powered-By");
    r.generator  = extract_header(root, "X-Generator");
  }

  // robots.txt
  std::string robots_resp = do_get("/robots.txt");
  if (!robots_resp.empty() && extract_status_code(robots_resp) == 200) {
    size_t body_start = robots_resp.find("\r\n\r\n");
    if (body_start != std::string::npos)
      r.robots_disallowed = parse_robots(robots_resp.substr(body_start + 4));
  }

  // TLS: already populated above if is_https and get("/") succeeded

  // Path probing
  for (const std::string &path : paths) {
    if (path == "/robots.txt") continue; // already done
    std::string resp = do_get(path.c_str());
    if (resp.empty()) continue;
    int code = extract_status_code(resp);
    if (code == 0 || code == 404 || code == 400) continue;

    WebPath wp{};
    wp.path        = path;
    wp.status_code = code;
    if (code >= 300 && code < 400)
      wp.redirect_to = extract_redirect(resp);
    if (code == 200) {
      size_t body_start = resp.find("\r\n\r\n");
      if (body_start != std::string::npos)
        wp.title = extract_title(resp.substr(body_start + 4));
    }
    r.paths.push_back(wp);
  }

  return r;
}

/* -----------------------------------------------------------------------
 * Storage on Target
 * ----------------------------------------------------------------------- */

static TargetWebData *get_or_create_web_data(Target *t) {
  void *existing = t->attribute.get(WEB_RECON_KEY);
  if (existing) return static_cast<TargetWebData *>(existing);
  auto *data = new TargetWebData();
  t->attribute.set(WEB_RECON_KEY, data);
  return data;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */
void run_web_recon(std::vector<Target *> &targets,
                   const char *extra_paths_file) {
  // Build path list
  std::vector<std::string> paths;
  for (const char **p = builtin_paths; *p; ++p)
    paths.emplace_back(*p);

  if (extra_paths_file) {
    std::ifstream f(extra_paths_file);
    std::string line;
    while (std::getline(f, line)) {
      if (!line.empty() && line[0] != '#')
        paths.push_back(line);
    }
  }

  for (Target *t : targets) {
    const char *ip = t->targetipstr();
    Port *port = nullptr;
    Port portstore{};

    while ((port = t->ports.nextPort(port, &portstore,
                                      TCPANDUDPANDSCTP, PORT_OPEN)) != nullptr) {
      struct serviceDeductions sd{};
      t->ports.getServiceDeductions(port->portno, port->proto, &sd);
      if (!sd.name) continue;

      std::string svc = sd.name;
      std::transform(svc.begin(), svc.end(), svc.begin(),
                     [](unsigned char c){ return static_cast<char>(tolower(c)); });

      bool is_http  = (svc.find("http")  != std::string::npos);
      bool is_https = (svc.find("https") != std::string::npos ||
                       port->portno == 443 || port->portno == 8443);

      if (!is_http && !is_https) continue;

      /* Per-port isolation: if probing one port fails, continue to others */
      try {
        WebReconResult result = probe_web_port(ip, port->portno, is_https, paths);
        TargetWebData *data = get_or_create_web_data(t);
        data->results.push_back(std::move(result));
      } catch (...) {
        log_write(LOG_STDOUT,
          "  WARNING: web-recon exception for %s:%d, skipping port\n",
          ip, port->portno);
        continue;
      }
    }
  }
}

void print_web_recon_output(const Target *t) {
  void *raw = t->attribute.get(WEB_RECON_KEY);
  if (!raw) return;
  const auto *data = static_cast<const TargetWebData *>(raw);

  for (const WebReconResult &r : data->results) {
    log_write(LOG_PLAIN, "  |  Web Recon (%d/%s):\n",
              r.portno, r.is_https ? "https" : "http");

    if (!r.title.empty())
      log_write(LOG_PLAIN, "  |    Title:   %s\n", r.title.c_str());
    if (!r.server.empty())
      log_write(LOG_PLAIN, "  |    Server:  %s\n", r.server.c_str());
    if (!r.powered_by.empty())
      log_write(LOG_PLAIN, "  |    Tech:    %s\n", r.powered_by.c_str());

    if (r.is_https && !r.tls.subject_cn.empty()) {
      log_write(LOG_PLAIN, "  |    TLS CN:  %s%s\n",
                r.tls.subject_cn.c_str(),
                r.tls.self_signed ? " [self-signed]" : "");
      if (!r.tls.not_after.empty())
        log_write(LOG_PLAIN, "  |    Expiry:  %s\n", r.tls.not_after.c_str());
    }

    if (!r.robots_disallowed.empty()) {
      log_write(LOG_PLAIN, "  |    Robots:  ");
      for (size_t i = 0; i < r.robots_disallowed.size(); ++i) {
        log_write(LOG_PLAIN, "%s%s", r.robots_disallowed[i].c_str(),
                  (i + 1 < r.robots_disallowed.size()) ? ", " : "\n");
      }
    }

    for (const WebPath &wp : r.paths) {
      if (wp.redirect_to.empty())
        log_write(LOG_PLAIN, "  |    [%d] %s%s\n",
                  wp.status_code, wp.path.c_str(),
                  wp.title.empty() ? "" : (" — " + wp.title).c_str());
      else
        log_write(LOG_PLAIN, "  |    [%d] %s → %s\n",
                  wp.status_code, wp.path.c_str(), wp.redirect_to.c_str());
    }
  }
}

/* =======================================================================
 * Screenshot Capture (--screenshot)
 *
 * Detects an installed headless browser (Chrome, Chromium, Edge, Firefox)
 * and captures a screenshot of each discovered web port.
 * ======================================================================= */

#ifdef WIN32
#include <direct.h>
#define kmap_mkdir(d) _mkdir(d)
#else
#include <sys/stat.h>
#define kmap_mkdir(d) mkdir(d, 0755)
#endif

/* Try to find a headless browser on the system.
   Returns the full command prefix or empty string if none found. */
static std::string find_browser() {
#ifdef WIN32
    /* Windows: check common Chrome/Edge install paths */
    const char *candidates[] = {
        "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
        "\"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\"",
        "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\"",
        "\"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe\"",
        nullptr
    };
    for (const char **c = candidates; *c; ++c) {
        /* Strip quotes and check if file exists */
        std::string path = *c;
        std::string unquoted = path.substr(1, path.size() - 2);
        FILE *f = fopen(unquoted.c_str(), "r");
        if (f) { fclose(f); return path; }
    }
#else
    /* Unix: check common absolute paths first, then PATH-relative names */
    const char *abs_paths[] = {
        "/usr/bin/chromium-browser", "/usr/bin/chromium",
        "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
        "/usr/local/bin/chromium", "/usr/local/bin/google-chrome",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/firefox", "/usr/local/bin/firefox",
        nullptr
    };
    for (const char **c = abs_paths; *c; ++c) {
        if (access(*c, X_OK) == 0)
            return std::string("'") + *c + "'";
    }
#endif
    return "";
}

void run_screenshot_capture(std::vector<Target *> &targets,
                            const char *out_dir) {
    std::string dir = out_dir ? out_dir : "kmap-screenshots";

    /* Create output directory */
    kmap_mkdir(dir.c_str());

    std::string browser = find_browser();
    if (browser.empty()) {
        log_write(LOG_STDOUT,
            "WARNING: --screenshot: No headless browser found.\n"
            "  Install Chrome, Chromium, or Edge for screenshot support.\n");
        return;
    }

    bool is_firefox = (browser.find("firefox") != std::string::npos);

    log_write(LOG_STDOUT, "Screenshot: using %s\n", browser.c_str());

    int captured = 0;
    int screenshot_errors = 0;
    for (Target *t : targets) {
        const char *ip = t->targetipstr();
        Port *port = nullptr;
        Port portstore{};

        while ((port = t->ports.nextPort(port, &portstore,
                                          TCPANDUDPANDSCTP, PORT_OPEN)) != nullptr) {
            struct serviceDeductions sd{};
            t->ports.getServiceDeductions(port->portno, port->proto, &sd);
            if (!sd.name) continue;

            std::string svc = sd.name;
            std::transform(svc.begin(), svc.end(), svc.begin(),
                           [](unsigned char c){ return static_cast<char>(tolower(c)); });

            bool is_http  = (svc.find("http") != std::string::npos);
            bool is_https = (svc.find("https") != std::string::npos ||
                             port->portno == 443 || port->portno == 8443);
            if (!is_http && !is_https) continue;

            std::string proto = is_https ? "https" : "http";
            std::string url = proto + "://" + ip + ":" + std::to_string(port->portno) + "/";

            /* Output filename: ip_port.png */
            std::string safe_ip = ip;
            for (char &c : safe_ip) if (c == ':') c = '_'; /* IPv6 colons */
            std::string outfile = dir + "/" + safe_ip + "_" + std::to_string(port->portno) + ".png";

            std::string cmd;
            if (is_firefox) {
                cmd = browser + " --screenshot \"" + outfile
                    + "\" --window-size=1280,720 \"" + url + "\" 2>/dev/null";
            } else {
                /* Chrome/Chromium/Edge */
                cmd = browser
                    + " --headless --disable-gpu --no-sandbox"
                    + " --screenshot=\"" + outfile + "\""
                    + " --window-size=1280,720"
                    + " --ignore-certificate-errors"
                    + " \"" + url + "\" 2>/dev/null";
            }

#ifdef WIN32
            /* Windows: redirect stderr to NUL */
            size_t nulpos = cmd.rfind("2>/dev/null");
            if (nulpos != std::string::npos)
                cmd.replace(nulpos, 11, "2>NUL");
#endif

            log_write(LOG_STDOUT, "  Capturing %s -> %s\n", url.c_str(), outfile.c_str());
            int rc = system(cmd.c_str());
            if (rc == 0) {
                captured++;
            } else {
                screenshot_errors++;
                log_write(LOG_STDOUT, "  WARNING: Screenshot failed for %s (exit %d), continuing\n",
                          url.c_str(), rc);
                /* Continue to next URL -- one failure should not stop the batch */
            }
        }
    }

    log_write(LOG_STDOUT, "Screenshots: %d captured in %s/", captured, dir.c_str());
    if (screenshot_errors > 0)
        log_write(LOG_STDOUT, " (%d failed)", screenshot_errors);
    log_write(LOG_STDOUT, "\n");
}
