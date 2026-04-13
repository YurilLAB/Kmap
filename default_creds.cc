/*
 * default_creds.cc -- Default credential probe engine for Kmap.
 *
 * Probes SSH, FTP, Telnet, HTTP Basic, MySQL, PostgreSQL, MSSQL, MongoDB
 * using a bundled or user-supplied credential list.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "default_creds.h"
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
#include <cstring>
#include <cstdio>
#include <cctype>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in6.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef HAVE_LIBSSH2
#include <libssh2.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#include <openssl/md5.h>
#endif

/* Key used to attach PortCredResults list to a Target */
#define CRED_RESULTS_KEY "kmap_default_creds"

/* -----------------------------------------------------------------------
 * Built-in credential pairs per service
 * Format: { "service", "username", "password" }  (empty pw = "")
 * ----------------------------------------------------------------------- */
struct CredPair {
  const char *service;
  const char *username;
  const char *password;
};

static const CredPair builtin_creds[] = {
  /* ---- SSH (25 entries) ----
   * Root common passwords, admin accounts, IoT/embedded defaults,
   * cloud VM defaults, common service accounts. */
  {"ssh", "root",      "root"},
  {"ssh", "root",      ""},
  {"ssh", "root",      "toor"},
  {"ssh", "root",      "password"},
  {"ssh", "root",      "123456"},
  {"ssh", "root",      "12345678"},
  {"ssh", "root",      "admin"},
  {"ssh", "root",      "changeme"},
  {"ssh", "root",      "letmein"},
  {"ssh", "root",      "default"},
  {"ssh", "admin",     "admin"},
  {"ssh", "admin",     "password"},
  {"ssh", "admin",     ""},
  {"ssh", "admin",     "1234"},
  {"ssh", "admin",     "admin123"},
  {"ssh", "admin",     "changeme"},
  {"ssh", "ubnt",      "ubnt"},          /* Ubiquiti devices */
  {"ssh", "pi",        "raspberry"},     /* Raspberry Pi */
  {"ssh", "user",      "user"},
  {"ssh", "support",   "support"},       /* Various appliances */
  {"ssh", "ubuntu",    "ubuntu"},        /* Ubuntu cloud images */
  {"ssh", "vagrant",   "vagrant"},       /* Vagrant boxes */
  {"ssh", "ec2-user",  "ec2-user"},      /* AWS EC2 (rare but tested) */
  {"ssh", "centos",    "centos"},        /* CentOS cloud images */
  {"ssh", "deploy",    "deploy"},        /* Deployment accounts */
  {"ssh", "oracle",    "oracle"},        /* Oracle appliances */
  {"ssh", "postgres",  "postgres"},      /* PostgreSQL system user */
  {"ssh", "guest",     "guest"},
  {"ssh", "test",      "test"},
  {"ssh", "git",       "git"},           /* Gitea/GitLab instances */
  {"ssh", "nagios",    "nagios"},        /* Nagios monitoring */
  {"ssh", "tomcat",    "tomcat"},        /* Tomcat SSH access */
  {"ssh", "ftpuser",   "ftpuser"},       /* Embedded NAS */

  /* ---- FTP (22 entries) ----
   * Anonymous access variants, common server defaults,
   * embedded device / NAS defaults. */
  {"ftp", "anonymous", ""},
  {"ftp", "anonymous", "anonymous"},
  {"ftp", "anonymous", "guest@"},
  {"ftp", "anonymous", "anonymous@"},
  {"ftp", "anonymous", "ftp@example.com"},
  {"ftp", "ftp",       "ftp"},
  {"ftp", "ftp",       ""},
  {"ftp", "admin",     "admin"},
  {"ftp", "admin",     "password"},
  {"ftp", "admin",     "1234"},
  {"ftp", "admin",     "admin123"},
  {"ftp", "admin",     ""},
  {"ftp", "root",      "root"},
  {"ftp", "root",      "password"},
  {"ftp", "root",      ""},
  {"ftp", "user",      "user"},
  {"ftp", "user",      "password"},
  {"ftp", "test",      "test"},
  {"ftp", "guest",     "guest"},
  {"ftp", "ftpuser",   "ftpuser"},       /* Embedded / NAS devices */
  {"ftp", "ftpuser",   "password"},
  {"ftp", "upload",    "upload"},        /* Upload-only accounts */
  {"ftp", "backup",    "backup"},        /* Backup service accounts */

  /* ---- Telnet (25 entries) ----
   * Router/gateway defaults, IoT/embedded systems,
   * SCADA/ICS common credentials. */
  {"telnet", "admin",      "admin"},
  {"telnet", "admin",      "password"},
  {"telnet", "admin",      "1234"},
  {"telnet", "admin",      ""},
  {"telnet", "admin",      "admin1234"},
  {"telnet", "admin",      "default"},
  {"telnet", "admin",      "changeme"},
  {"telnet", "admin",      "meinsm"},     /* ZTE routers */
  {"telnet", "root",       "root"},
  {"telnet", "root",       ""},
  {"telnet", "root",       "toor"},
  {"telnet", "root",       "password"},
  {"telnet", "root",       "default"},
  {"telnet", "root",       "vizxv"},      /* Dahua DVRs */
  {"telnet", "root",       "xc3511"},     /* Xiongmai IP cameras */
  {"telnet", "root",       "juantech"},   /* Juanvision cameras */
  {"telnet", "user",       "user"},
  {"telnet", "guest",      "guest"},
  {"telnet", "",           ""},           /* No-auth telnet */
  {"telnet", "supervisor", "supervisor"}, /* SCADA/ICS systems */
  {"telnet", "tech",       "tech"},       /* Telecom equipment */
  {"telnet", "support",    "support"},    /* Support accounts */
  {"telnet", "manager",    "manager"},    /* Management interfaces */
  {"telnet", "operator",   "operator"},   /* SCADA operator */
  {"telnet", "service",    "service"},    /* Service/maintenance */
  {"telnet", "mother",     "fucker"},     /* Mirai botnet default */

  /* ---- HTTP Basic Auth (24 entries) ----
   * Generic admin panels, router/appliance web interfaces,
   * web server / framework defaults. */
  {"http", "admin",    "admin"},
  {"http", "admin",    "password"},
  {"http", "admin",    "1234"},
  {"http", "admin",    ""},
  {"http", "admin",    "admin123"},
  {"http", "admin",    "12345"},
  {"http", "admin",    "changeme"},
  {"http", "admin",    "default"},
  {"http", "admin",    "letmein"},
  {"http", "admin",    "admin1"},
  {"http", "admin",    "password1"},
  {"http", "admin",    "1234567890"},
  {"http", "root",     "root"},
  {"http", "root",     "password"},
  {"http", "root",     "admin"},
  {"http", "user",     "user"},
  {"http", "test",     "test"},
  {"http", "guest",    "guest"},
  {"http", "cisco",    "cisco"},         /* Cisco web management */
  {"http", "manager",  "manager"},       /* Tomcat manager */
  {"http", "tomcat",   "tomcat"},        /* Apache Tomcat */
  {"http", "tomcat",   "s3cret"},        /* Tomcat common default */
  {"http", "manager",  "tomcat"},        /* Tomcat manager variant */
  {"http", "pi",       "raspberry"},     /* Raspberry Pi web UIs */

  /* ---- MySQL (21 entries) ----
   * Default installations, common DBA passwords,
   * MariaDB defaults. */
  {"mysql", "root",    ""},
  {"mysql", "root",    "root"},
  {"mysql", "root",    "password"},
  {"mysql", "root",    "mysql"},
  {"mysql", "root",    "123456"},
  {"mysql", "root",    "toor"},
  {"mysql", "root",    "changeme"},
  {"mysql", "root",    "admin"},
  {"mysql", "root",    "default"},
  {"mysql", "admin",   "admin"},
  {"mysql", "admin",   "password"},
  {"mysql", "admin",   ""},
  {"mysql", "mysql",   "mysql"},
  {"mysql", "test",    "test"},
  {"mysql", "test",    ""},
  {"mysql", "user",    ""},
  {"mysql", "user",    "user"},
  {"mysql", "dbadmin", "dbadmin"},       /* Common DBA account */
  {"mysql", "db",      "db"},
  {"mysql", "dba",     "dba"},
  {"mysql", "guest",   "guest"},

  /* ---- PostgreSQL (17 entries) ----
   * Default installations, common DBA passwords. */
  {"postgresql", "postgres",  ""},
  {"postgresql", "postgres",  "postgres"},
  {"postgresql", "postgres",  "password"},
  {"postgresql", "postgres",  "admin"},
  {"postgresql", "postgres",  "123456"},
  {"postgresql", "postgres",  "changeme"},
  {"postgresql", "postgres",  "default"},
  {"postgresql", "admin",     "admin"},
  {"postgresql", "admin",     "password"},
  {"postgresql", "root",      "root"},
  {"postgresql", "root",      "password"},
  {"postgresql", "user",      "user"},
  {"postgresql", "user",      "password"},
  {"postgresql", "dbuser",    "dbuser"},   /* Common dev setup */
  {"postgresql", "pgsql",     "pgsql"},    /* Legacy alias */
  {"postgresql", "test",      "test"},
  {"postgresql", "guest",     "guest"},

  /* ---- MSSQL (17 entries) ----
   * SQL Server Express defaults, common sa passwords. */
  {"mssql", "sa",      ""},
  {"mssql", "sa",      "sa"},
  {"mssql", "sa",      "password"},
  {"mssql", "sa",      "Password1"},
  {"mssql", "sa",      "Password123"},
  {"mssql", "sa",      "1234"},
  {"mssql", "sa",      "changeme"},
  {"mssql", "sa",      "master"},
  {"mssql", "sa",      "sql"},
  {"mssql", "sa",      "sa123"},
  {"mssql", "sa",      "sqlserver"},
  {"mssql", "admin",   "admin"},
  {"mssql", "admin",   "password"},
  {"mssql", "sql",     "sql"},
  {"mssql", "guest",   "guest"},
  {"mssql", "test",    "test"},
  {"mssql", "dba",     "dba"},

  /* ---- MongoDB (16 entries) ----
   * Unauthenticated access (pre-3.0 default, still common),
   * common admin credentials when auth is enabled. */
  {"mongodb", "",        ""},             /* No-auth (old default) */
  {"mongodb", "admin",   "admin"},
  {"mongodb", "admin",   "password"},
  {"mongodb", "admin",   "changeme"},
  {"mongodb", "admin",   "123456"},
  {"mongodb", "admin",   "mongo"},
  {"mongodb", "admin",   ""},
  {"mongodb", "root",    "root"},
  {"mongodb", "root",    "password"},
  {"mongodb", "root",    "mongo"},
  {"mongodb", "root",    "changeme"},
  {"mongodb", "mongodb", "mongodb"},     /* Service account */
  {"mongodb", "user",    "user"},
  {"mongodb", "user",    "password"},
  {"mongodb", "test",    "test"},
  {"mongodb", "guest",   "guest"},

  {nullptr, nullptr, nullptr}
};

/* -----------------------------------------------------------------------
 * Internal credential list (loaded from file or built-in)
 * ----------------------------------------------------------------------- */
struct LoadedCred {
  std::string service;
  std::string username;
  std::string password;
};

static std::vector<LoadedCred> load_creds(const char *creds_file) {
  std::vector<LoadedCred> creds;

  if (creds_file) {
    std::ifstream f(creds_file);
    if (!f.is_open()) {
      error("--default-creds: cannot open creds file: %s", creds_file);
      return creds;
    }
    std::string line;
    while (std::getline(f, line)) {
      if (line.empty() || line[0] == '#') continue;
      std::istringstream ss(line);
      LoadedCred c;
      ss >> c.service >> c.username >> c.password;
      if (!c.service.empty() && !c.username.empty())
        creds.push_back(std::move(c));
    }
  } else {
    for (const CredPair *p = builtin_creds; p->service; ++p)
      creds.push_back({p->service, p->username, p->password});
  }
  return creds;
}

/* -----------------------------------------------------------------------
 * Low-level TCP connect helper (blocking, timeout via select)
 * Supports both IPv4 and IPv6 targets.
 * ----------------------------------------------------------------------- */
static int tcp_connect(const char *ip, uint16_t port, int timeout_ms) {
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
  if (fd == INVALID_SOCKET) return -1;
  u_long nb = 1;
  ioctlsocket(fd, FIONBIO, &nb);
#else
  int fd = socket(af, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif

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
    return -1;
  }

  /* Verify the connection actually succeeded (not just select woke on error) */
  int sockerr = 0;
  socklen_t errlen = sizeof(sockerr);
  getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&sockerr), &errlen);
  if (sockerr != 0) {
#ifdef WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return -1;
  }

#ifdef WIN32
  nb = 0;
  ioctlsocket(fd, FIONBIO, &nb);
#else
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
#endif
  return static_cast<int>(fd);
}

static void close_fd(int fd) {
#ifdef WIN32
  closesocket(fd);
#else
  close(fd);
#endif
}

static bool fd_send(int fd, const char *buf, size_t len) {
  return send(fd, buf, static_cast<int>(len), 0) == static_cast<int>(len);
}

static int fd_recv(int fd, char *buf, size_t len, int timeout_ms) {
  fd_set rset;
  FD_ZERO(&rset);
  FD_SET(fd, &rset);
  struct timeval tv;
  tv.tv_sec  = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  if (select(static_cast<int>(fd) + 1, &rset, nullptr, nullptr, &tv) <= 0)
    return -1;
  return static_cast<int>(recv(fd, buf, static_cast<int>(len), 0));
}

/* -----------------------------------------------------------------------
 * Service-specific probe implementations
 * ----------------------------------------------------------------------- */

/* FTP: connect, read banner, send USER + PASS, check 230 response */
static bool probe_ftp(const char *ip, uint16_t port,
                      const std::string &user, const std::string &pass,
                      int timeout_ms) {
  int fd = tcp_connect(ip, port, timeout_ms);
  if (fd < 0) return false;

  char buf[512]{};
  if (fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms) <= 0) {
    close_fd(fd); return false;
  }
  // Send USER
  std::string cmd = "USER " + user + "\r\n";
  fd_send(fd, cmd.c_str(), cmd.size());
  memset(buf, 0, sizeof(buf));
  fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);

  // Send PASS
  cmd = "PASS " + pass + "\r\n";
  fd_send(fd, cmd.c_str(), cmd.size());
  memset(buf, 0, sizeof(buf));
  int n = fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);
  close_fd(fd);

  return (n > 0 && strncmp(buf, "230", 3) == 0);
}

/* Base64-encode a string (for HTTP Basic Auth) */
static std::string base64_encode(const std::string &input) {
  static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  const auto *src = reinterpret_cast<const unsigned char *>(input.c_str());
  size_t len = input.size();
  for (size_t i = 0; i < len; i += 3) {
    uint32_t b = static_cast<uint32_t>(src[i]) << 16;
    if (i + 1 < len) b |= static_cast<uint32_t>(src[i+1]) << 8;
    if (i + 2 < len) b |= src[i+2];
    out += b64[(b >> 18) & 0x3f];
    out += b64[(b >> 12) & 0x3f];
    out += (i + 1 < len) ? b64[(b >> 6) & 0x3f] : '=';
    out += (i + 2 < len) ? b64[b & 0x3f] : '=';
  }
  return out;
}

/* HTTP Basic Auth probe.
 * Step 1: GET / without credentials — must return 401 (auth required).
 * Step 2: GET / with Authorization header — success if response is not 401.
 * This two-step approach avoids false positives on servers that don't use
 * Basic Auth at all (which would otherwise look like successful empty creds). */
static bool probe_http_basic(const char *ip, uint16_t port,
                              const std::string &user, const std::string &pass,
                              int timeout_ms) {
  /* Step 1: confirm 401 without credentials */
  int fd = tcp_connect(ip, port, timeout_ms);
  if (fd < 0) return false;

  std::string bare_req =
    std::string("GET / HTTP/1.0\r\nHost: ") + ip +
    "\r\nConnection: close\r\n\r\n";
  fd_send(fd, bare_req.c_str(), bare_req.size());
  char buf[512]{};
  int n = fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);
  close_fd(fd);

  if (n <= 0 || strstr(buf, " 401 ") == nullptr)
    return false;  /* Not a Basic-Auth–protected endpoint */

  /* Step 2: try with credentials */
  fd = tcp_connect(ip, port, timeout_ms);
  if (fd < 0) return false;

  std::string encoded = base64_encode(user + ":" + pass);
  std::string auth_req =
    std::string("GET / HTTP/1.0\r\nHost: ") + ip +
    "\r\nAuthorization: Basic " + encoded +
    "\r\nConnection: close\r\n\r\n";

  fd_send(fd, auth_req.c_str(), auth_req.size());
  memset(buf, 0, sizeof(buf));
  n = fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);
  close_fd(fd);

  return (n > 0 &&
          strstr(buf, "HTTP/") != nullptr &&
          strstr(buf, " 401 ") == nullptr &&
          strstr(buf, " 403 ") == nullptr);
}

/* -----------------------------------------------------------------------
 * MSSQL TDS probe (SQL Server default credential check)
 * Uses TDS 7.1 Login7 packet. Detects success via LOGINACK token (0xAD).
 * ----------------------------------------------------------------------- */

/* TDS password encoding: for each byte of UTF-16LE, nibble-swap then XOR 0xA5 */
static std::vector<uint8_t> tds_encode_password(const std::string &pass) {
  std::vector<uint8_t> enc;
  enc.reserve(pass.size() * 2);
  for (unsigned char c : pass) {
    uint8_t lo = c;
    uint8_t hi = 0x00;
    lo = static_cast<uint8_t>(((lo << 4) | (lo >> 4)) ^ 0xA5);
    hi = static_cast<uint8_t>(((hi << 4) | (hi >> 4)) ^ 0xA5);
    enc.push_back(lo);
    enc.push_back(hi);
  }
  return enc;
}

/* Encode an ASCII string as UTF-16LE bytes */
static std::vector<uint8_t> to_utf16le(const std::string &s) {
  std::vector<uint8_t> out;
  out.reserve(s.size() * 2);
  for (unsigned char c : s) {
    out.push_back(c);
    out.push_back(0x00);
  }
  return out;
}

static bool probe_mssql(const char *ip, uint16_t port,
                         const std::string &user, const std::string &pass,
                         int timeout_ms) {
  int fd = tcp_connect(ip, port, timeout_ms);
  if (fd < 0) return false;

  /* ---- TDS Pre-Login packet ----
   * Body layout: 2 options × 5 bytes each + 1 terminator + version(6) + encrypt(1) = 18 bytes
   * Option offsets are from start of pre-login body. Data area starts at byte 11. */
  static const uint8_t prelogin[] = {
    0x12, 0x01, 0x00, 0x1A, 0x00, 0x00, 0x01, 0x00,  /* TDS header */
    0x00, 0x00, 0x0B, 0x00, 0x06,  /* VERSION: type=0, offset=11, len=6 */
    0x01, 0x00, 0x11, 0x00, 0x01,  /* ENCRYPTION: type=1, offset=17, len=1 */
    0xFF,                           /* TERMINATOR */
    0x0E, 0x00, 0x00, 0x00, 0x00, 0x00,  /* SQL Server 2017 version */
    0x02                            /* ENCRYPT_NOT_SUP */
  };
  fd_send(fd, reinterpret_cast<const char *>(prelogin), sizeof(prelogin));

  char prebuf[256]{};
  int pn = fd_recv(fd, prebuf, sizeof(prebuf) - 1, timeout_ms);
  if (pn < 8 || static_cast<uint8_t>(prebuf[0]) != 0x04) {
    close_fd(fd); return false;
  }

  /* ---- TDS Login7 packet ----
   * Fixed section: 36 bytes  |  OffLen section: 58 bytes  |  Total header = 94 bytes
   * Variable data follows at body offset 94. */
  auto user_u16  = to_utf16le(user);
  auto pass_enc  = tds_encode_password(pass);
  auto app_u16   = to_utf16le("kmap");
  auto db_u16    = to_utf16le("master");

  /* Variable data layout starting at body offset 94 */
  uint16_t base    = 94;
  uint16_t uname_o = base;
  uint16_t uname_l = static_cast<uint16_t>(user.size());
  uint16_t pass_o  = static_cast<uint16_t>(uname_o + user_u16.size());
  uint16_t pass_l  = static_cast<uint16_t>(pass.size());
  uint16_t app_o   = static_cast<uint16_t>(pass_o + pass_enc.size());
  uint16_t app_l   = 4; /* "kmap" */
  uint16_t db_o    = static_cast<uint16_t>(app_o + app_u16.size());
  uint16_t db_l    = 6; /* "master" */
  uint16_t tail_o  = static_cast<uint16_t>(db_o + db_u16.size());

  uint32_t body_len = tail_o; /* total body bytes */

  std::vector<uint8_t> body;
  body.reserve(body_len);

  auto p32 = [&](uint32_t v) {
    body.push_back(v & 0xFF); body.push_back((v >> 8) & 0xFF);
    body.push_back((v >> 16) & 0xFF); body.push_back((v >> 24) & 0xFF);
  };
  auto p16 = [&](uint16_t v) {
    body.push_back(v & 0xFF); body.push_back((v >> 8) & 0xFF);
  };

  /* Fixed section */
  p32(body_len);      /* body length (LE) */
  p32(0x71000001);    /* TDS version 7.1 — broad compatibility */
  p32(0x00001000);    /* PacketSize = 4096 */
  p32(0x00000007);    /* ClientVersion */
  p32(0x00000001);    /* ClientPID */
  p32(0x00000000);    /* ConnectionID */
  body.push_back(0xE0); body.push_back(0x03); /* OptionalFlags 1/2 */
  body.push_back(0x00); body.push_back(0x00); /* TypeFlags, Flags3 */
  p32(0x00000000);    /* ClientTimeZone */
  p32(0x00000409);    /* ClientLCID = en-US */

  /* OffLen section */
  p16(base);    p16(0);       /* HostName: empty */
  p16(uname_o); p16(uname_l); /* UserName */
  p16(pass_o);  p16(pass_l);  /* Password */
  p16(app_o);   p16(app_l);   /* AppName */
  p16(tail_o);  p16(0);       /* ServerName: empty */
  p16(tail_o);  p16(0);       /* Unused */
  p16(tail_o);  p16(0);       /* CltIntName */
  p16(tail_o);  p16(0);       /* Language */
  p16(db_o);    p16(db_l);    /* Database */
  /* ClientID (6 bytes — use zeros) */
  for (int i = 0; i < 6; ++i) body.push_back(0x00);
  p16(tail_o); p16(0);        /* SSPI */
  p16(tail_o); p16(0);        /* AttachDBFile */
  p16(tail_o); p16(0);        /* ChangePassword */
  p32(0);                      /* SSPILong */

  /* Variable data */
  body.insert(body.end(), user_u16.begin(), user_u16.end());
  body.insert(body.end(), pass_enc.begin(), pass_enc.end());
  body.insert(body.end(), app_u16.begin(), app_u16.end());
  body.insert(body.end(), db_u16.begin(), db_u16.end());

  /* TDS packet header for Login7 */
  uint32_t total = 8 + body_len;
  uint8_t hdr[8] = {
    0x10, 0x01,
    static_cast<uint8_t>((total >> 8) & 0xFF),
    static_cast<uint8_t>(total & 0xFF),
    0x00, 0x00, 0x01, 0x00
  };
  fd_send(fd, reinterpret_cast<const char *>(hdr), 8);
  fd_send(fd, reinterpret_cast<const char *>(body.data()), body.size());

  char respbuf[1024]{};
  int n = fd_recv(fd, respbuf, sizeof(respbuf) - 1, timeout_ms);
  close_fd(fd);

  if (n < 9) return false;

  /* Scan response tokens: 0xAD = LOGINACK (success), 0xAA = ERROR */
  for (int i = 8; i < n; ++i) {
    uint8_t tok = static_cast<uint8_t>(respbuf[i]);
    if (tok == 0xAD) return true;
    if (tok == 0xAA) return false;
  }
  return false;
}

/* Telnet: connect, skip banner, send login+password, check for shell prompt */
static bool probe_telnet(const char *ip, uint16_t port,
                         const std::string &user, const std::string &pass,
                         int timeout_ms) {
  int fd = tcp_connect(ip, port, timeout_ms);
  if (fd < 0) return false;

  char buf[1024]{};
  // Read banner / negotiate
  fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);

  // Look for login prompt — send username
  std::string cmd = user + "\r\n";
  fd_send(fd, cmd.c_str(), cmd.size());
  memset(buf, 0, sizeof(buf));
  fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);

  // Send password
  cmd = pass + "\r\n";
  fd_send(fd, cmd.c_str(), cmd.size());
  memset(buf, 0, sizeof(buf));
  int n = fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);
  close_fd(fd);

  if (n <= 0) return false;
  /* Heuristic: look for shell prompt indicators while rejecting known failure
   * messages.  Avoid bare '>' — it matches HTML tags and many non-prompt
   * contexts.  Instead look for common prompt suffixes like "$ ", "# ",
   * or "> " (space after the character) that indicate a real shell. */
  bool has_prompt = (strstr(buf, "$ ") || strstr(buf, "# ") ||
                     strstr(buf, "> ") || strstr(buf, "~]") ||
                     strstr(buf, ":~") || strstr(buf, ":/"));
  bool has_fail   = (strstr(buf, "incorrect") || strstr(buf, "failed") ||
                     strstr(buf, "denied")    || strstr(buf, "Password:") ||
                     strstr(buf, "invalid")   || strstr(buf, "bad password") ||
                     strstr(buf, "Login fail") || strstr(buf, "Access denied"));
  return has_prompt && !has_fail;
}

/* MySQL: authenticate using native_password (SHA1-based) when OpenSSL is
 * available, falling back to empty-password for no-auth servers otherwise.
 *
 * Protocol: HandshakeV10 → parse 20-byte scramble → SHA1 auth response.
 * Works with MySQL 5.x and MySQL 8.x servers still configured for
 * mysql_native_password. Also detects servers with no-password (auth_type=0). */
static bool probe_mysql(const char *ip, uint16_t port,
                        const std::string &user, const std::string &pass,
                        int timeout_ms) {
  int fd = tcp_connect(ip, port, timeout_ms);
  if (fd < 0) return false;

  char buf[512]{};
  int n = fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);
  if (n < 5) { close_fd(fd); return false; }

  /* Packet header: 3-byte length + 1-byte seq; then protocol byte must be 0x0a */
  if (static_cast<unsigned char>(buf[4]) != 0x0a) { close_fd(fd); return false; }

  /* Parse HandshakeV10 to extract the 20-byte auth scramble.
   * Layout after the protocol byte:
   *   server version (null-terminated) | connID(4) | scramble_pt1(8) | filler(1)
   *   cap_lower(2) | charset(1) | status(2) | cap_upper(2) | plugin_data_len(1)
   *   reserved(10) | scramble_pt2(max(13, plugin_data_len-8)) */
  uint8_t scramble[20]{};
  int pos = 5;
  while (pos < n && buf[pos] != '\0') pos++;
  pos++;        /* skip null terminator of server version */
  if (pos + 13 <= n) {
    pos += 4;   /* skip connection ID */
    memcpy(scramble, buf + pos, 8);  /* scramble part 1 */
    pos += 9;   /* skip 8-byte scramble + 1-byte filler */
    /* Skip capability lower(2) + charset(1) + status(2) + capability upper(2) */
    if (pos + 8 + 10 <= n) {
      pos += 7;
      int pdata_len = static_cast<int>(static_cast<unsigned char>(buf[pos])); pos++;
      pos += 10;  /* skip reserved */
      int part2_len = std::max(13, pdata_len - 8);
      if (pos + part2_len <= n)
        memcpy(scramble + 8, buf + pos, std::min(12, part2_len));
    }
  }

  /* Compute auth token — SHA1(pass) XOR SHA1(scramble + SHA1(SHA1(pass))) */
  uint8_t token[20]{};
  bool    has_token = false;
#ifdef HAVE_OPENSSL
  if (!pass.empty()) {
    uint8_t sha1_pw[20], sha1_sha1_pw[20], hash_input[40], sha1_combined[20];
    SHA1(reinterpret_cast<const uint8_t *>(pass.data()), pass.size(), sha1_pw);
    SHA1(sha1_pw, 20, sha1_sha1_pw);
    memcpy(hash_input, scramble, 20);
    memcpy(hash_input + 20, sha1_sha1_pw, 20);
    SHA1(hash_input, 40, sha1_combined);
    for (int i = 0; i < 20; i++) token[i] = sha1_pw[i] ^ sha1_combined[i];
    has_token = true;
  }
#endif

  /* Build HandshakeResponse41 */
  uint8_t resp[128]{};
  resp[0] = 0x85; resp[1] = 0xa6; resp[2] = 0x03; resp[3] = 0x00; /* CLIENT flags */
  resp[4] = 0x00; resp[5] = 0x00; resp[6] = 0x00; resp[7] = 0x01; /* max packet */
  resp[8] = 0x21; /* utf8 charset */
  /* resp[9..31] = zeros (filler) */
  size_t off = 32;
  size_t ulen = std::min(user.size(), static_cast<size_t>(16));
  memcpy(resp + off, user.c_str(), ulen);
  off += ulen + 1; /* username + null terminator (zero from {} init) */
  if (has_token) {
    resp[off++] = 20;              /* auth-response length */
    memcpy(resp + off, token, 20); off += 20;
  } else {
    resp[off++] = 0x00;            /* empty password */
  }

  uint8_t pkt[136]{};
  uint8_t plen = static_cast<uint8_t>(off);
  pkt[0] = plen; pkt[1] = 0; pkt[2] = 0; pkt[3] = 1; /* seq=1 */
  memcpy(pkt + 4, resp, off);

  fd_send(fd, reinterpret_cast<char *>(pkt), off + 4);
  memset(buf, 0, sizeof(buf));
  n = fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);
  close_fd(fd);

  /* OK packet: 3-byte len + 1-byte seq + 0x00 */
  return (n > 4 && static_cast<unsigned char>(buf[4]) == 0x00);
}

/* PostgreSQL: send startup message, then handle the auth challenge.
 *   auth_type 0 → trust auth (no password, detected regardless of cred pair)
 *   auth_type 5 → MD5 password auth (when OpenSSL is available)
 *
 * MD5 auth: MD5("md5" + hex(MD5(password + username)) + hex(salt))
 * Salt is the 4-byte value returned with auth_type 5. */
static bool probe_postgresql(const char *ip, uint16_t port,
                              const std::string &user, const std::string &pass,
                              int timeout_ms) {
  int fd = tcp_connect(ip, port, timeout_ms);
  if (fd < 0) return false;

  /* StartupMessage: length(4) + protocol 3.0(4) + "user\0<user>\0\0" */
  std::vector<uint8_t> msg;
  msg.push_back(0); msg.push_back(0); msg.push_back(0); msg.push_back(0);
  msg.push_back(0); msg.push_back(3); msg.push_back(0); msg.push_back(0);
  for (const char *k = "user"; *k; k++) msg.push_back(static_cast<uint8_t>(*k));
  msg.push_back(0);
  for (char c : user) msg.push_back(static_cast<uint8_t>(c));
  msg.push_back(0);
  msg.push_back(0); /* end of params */
  uint32_t total = static_cast<uint32_t>(msg.size());
  msg[0] = static_cast<uint8_t>((total >> 24) & 0xff);
  msg[1] = static_cast<uint8_t>((total >> 16) & 0xff);
  msg[2] = static_cast<uint8_t>((total >>  8) & 0xff);
  msg[3] = static_cast<uint8_t>(total & 0xff);

  fd_send(fd, reinterpret_cast<const char *>(msg.data()), msg.size());
  char buf[256]{};
  int n = fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);

  if (n < 9 || buf[0] != 'R') { close_fd(fd); return false; }

  uint32_t auth_type = (static_cast<uint8_t>(buf[5]) << 24) |
                       (static_cast<uint8_t>(buf[6]) << 16) |
                       (static_cast<uint8_t>(buf[7]) <<  8) |
                        static_cast<uint8_t>(buf[8]);

  if (auth_type == 0) { close_fd(fd); return true; } /* trust auth */

#ifdef HAVE_OPENSSL
  if (auth_type == 5 && n >= 13 && !pass.empty()) {
    /* MD5 auth: server sends 4-byte salt at buf[9..12] */
    uint8_t salt[4];
    memcpy(salt, buf + 9, 4);

    /* inner = hex(MD5(password + username)) */
    std::string inner_src = pass + user;
    uint8_t md5_inner[16];
    MD5(reinterpret_cast<const uint8_t *>(inner_src.data()), inner_src.size(), md5_inner);
    char hex_inner[33];
    for (int i = 0; i < 16; i++) snprintf(hex_inner + i*2, 3, "%02x", md5_inner[i]);

    /* outer = hex(MD5(hex_inner + salt)) */
    uint8_t combined[36];
    memcpy(combined, hex_inner, 32);
    memcpy(combined + 32, salt, 4);
    uint8_t md5_outer[16];
    MD5(combined, 36, md5_outer);
    char hex_outer[33];
    for (int i = 0; i < 16; i++) snprintf(hex_outer + i*2, 3, "%02x", md5_outer[i]);

    /* Final password string: "md5" + hex_outer + '\0' */
    std::string pg_pass = std::string("md5") + hex_outer;

    /* PasswordMessage: 'p' + int32(4 + len + 1) + password + '\0' */
    uint32_t pw_len = static_cast<uint32_t>(4 + pg_pass.size() + 1);
    std::vector<uint8_t> pw_msg;
    pw_msg.push_back('p');
    pw_msg.push_back((pw_len >> 24) & 0xff);
    pw_msg.push_back((pw_len >> 16) & 0xff);
    pw_msg.push_back((pw_len >>  8) & 0xff);
    pw_msg.push_back( pw_len        & 0xff);
    for (char c : pg_pass) pw_msg.push_back(static_cast<uint8_t>(c));
    pw_msg.push_back(0);

    fd_send(fd, reinterpret_cast<const char *>(pw_msg.data()), pw_msg.size());
    memset(buf, 0, sizeof(buf));
    n = fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);
    close_fd(fd);

    if (n >= 9 && buf[0] == 'R') {
      uint32_t at = (static_cast<uint8_t>(buf[5]) << 24) |
                    (static_cast<uint8_t>(buf[6]) << 16) |
                    (static_cast<uint8_t>(buf[7]) <<  8) |
                     static_cast<uint8_t>(buf[8]);
      return (at == 0);
    }
    return false;
  }
#endif

  close_fd(fd);
  return false;
}

/* MongoDB: try unauthenticated isMaster — old MongoDB allows this without creds */
static bool probe_mongodb(const char *ip, uint16_t port,
                          const std::string & /*user*/, const std::string & /*pass*/,
                          int timeout_ms) {
  int fd = tcp_connect(ip, port, timeout_ms);
  if (fd < 0) return false;

  // Minimal MongoDB wire protocol: OP_QUERY for isMaster
  static const uint8_t ismaster_msg[] = {
    0x3A,0x00,0x00,0x00, // total length = 58
    0x01,0x00,0x00,0x00, // requestID
    0x00,0x00,0x00,0x00, // responseTo
    0xd4,0x07,0x00,0x00, // opCode = OP_QUERY (2004)
    0x00,0x00,0x00,0x00, // flags
    0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,0x6d,0x64,0x00, // "admin.$cmd\0"
    0x00,0x00,0x00,0x00, // numberToSkip
    0x01,0x00,0x00,0x00, // numberToReturn
    // BSON: {isMaster: 1}
    0x13,0x00,0x00,0x00,0x10,0x69,0x73,0x4d,0x61,0x73,0x74,
    0x65,0x72,0x00,0x01,0x00,0x00,0x00,0x00
  };

  fd_send(fd, reinterpret_cast<const char *>(ismaster_msg), sizeof(ismaster_msg));
  char buf[256]{};
  int n = fd_recv(fd, buf, sizeof(buf) - 1, timeout_ms);
  close_fd(fd);

  // Any valid OP_REPLY (opCode 1) means server responded — unauthenticated access
  return (n > 16 && static_cast<uint8_t>(buf[12]) == 0x01 &&
                    static_cast<uint8_t>(buf[13]) == 0x00);
}

/* SSH via libssh2 */
static bool probe_ssh(const char *ip, uint16_t port,
                      const std::string &user, const std::string &pass,
                      int timeout_ms) {
#ifdef HAVE_LIBSSH2
  int fd = tcp_connect(ip, port, timeout_ms);
  if (fd < 0) return false;

  LIBSSH2_SESSION *session = libssh2_session_init();
  if (!session) { close_fd(fd); return false; }
  libssh2_session_set_timeout(session, timeout_ms);

  bool ok = false;
  if (libssh2_session_handshake(session, fd) == 0) {
    ok = (libssh2_userauth_password(session, user.c_str(), pass.c_str()) == 0);
  }
  libssh2_session_disconnect(session, "bye");
  libssh2_session_free(session);
  close_fd(fd);
  return ok;
#else
  (void)ip; (void)port; (void)user; (void)pass; (void)timeout_ms;
  return false; // libssh2 not available
#endif
}

/* -----------------------------------------------------------------------
 * Service dispatcher
 * ----------------------------------------------------------------------- */
static std::string normalize_service(const char *name) {
  if (!name) return "";
  std::string s = name;
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  if (s.find("ssh")        != std::string::npos) return "ssh";
  if (s.find("ftp")        != std::string::npos) return "ftp";
  if (s.find("telnet")     != std::string::npos) return "telnet";
  /* Only probe plaintext HTTP — HTTPS (SSL/TLS) cannot be probed with raw TCP */
  if (s == "http" || s == "http-alt" || s == "http-proxy") return "http";
  if (s.find("mysql")      != std::string::npos) return "mysql";
  if (s.find("postgres")   != std::string::npos) return "postgresql";
  if (s.find("ms-sql")     != std::string::npos) return "mssql";
  if (s.find("mssql")      != std::string::npos) return "mssql";
  if (s.find("mongodb")    != std::string::npos) return "mongodb";
  return "";
}

static bool probe_service(const std::string &svc, const char *ip,
                           uint16_t port, const std::string &user,
                           const std::string &pass, int timeout_ms) {
  if (svc == "ssh")        return probe_ssh(ip, port, user, pass, timeout_ms);
  if (svc == "ftp")        return probe_ftp(ip, port, user, pass, timeout_ms);
  if (svc == "telnet")     return probe_telnet(ip, port, user, pass, timeout_ms);
  if (svc == "http")       return probe_http_basic(ip, port, user, pass, timeout_ms);
  if (svc == "mysql")      return probe_mysql(ip, port, user, pass, timeout_ms);
  if (svc == "postgresql") return probe_postgresql(ip, port, user, pass, timeout_ms);
  if (svc == "mssql")      return probe_mssql(ip, port, user, pass, timeout_ms);
  if (svc == "mongodb")    return probe_mongodb(ip, port, user, pass, timeout_ms);
  return false;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

/* We store results on the Target via a simple map keyed by portno */
struct TargetCredData {
  std::vector<PortCredResults> results;
};

static TargetCredData *get_or_create_cred_data(Target *t) {
  void *existing = t->attribute.get(CRED_RESULTS_KEY);
  if (existing)
    return static_cast<TargetCredData *>(existing);
  auto *data = new TargetCredData();
  t->attribute.set(CRED_RESULTS_KEY, data);
  return data;
}

void run_default_creds(std::vector<Target *> &targets,
                       const char *creds_file,
                       int timeout_ms) {
  std::vector<LoadedCred> creds = load_creds(creds_file);
  if (creds.empty()) return;

  for (Target *t : targets) {
    const char *ip = t->targetipstr();
    Port *port = nullptr;
    Port portstore{};

    while ((port = t->ports.nextPort(port, &portstore,
                                      TCPANDUDPANDSCTP, PORT_OPEN)) != nullptr) {
      struct serviceDeductions sd{};
      t->ports.getServiceDeductions(port->portno, port->proto, &sd);
      if (!sd.name) continue;

      std::string svc = normalize_service(sd.name);
      if (svc.empty()) continue;

      PortCredResults pcr{};
      pcr.portno = port->portno;
      pcr.proto  = port->proto;

      for (const LoadedCred &c : creds) {
        if (c.service != svc) continue;
        if (probe_service(svc, ip, port->portno, c.username, c.password, timeout_ms)) {
          CredResult r{};
          r.service  = svc;
          r.portno   = port->portno;
          r.username = c.username;
          r.password = c.password;
          r.found    = true;
          pcr.hits.push_back(r);
          break; // stop on first hit per port
        }
      }

      if (!pcr.hits.empty()) {
        TargetCredData *data = get_or_create_cred_data(t);
        data->results.push_back(pcr);
      }
    }
  }
}

void print_default_creds_output(const Target *t) {
  void *raw = t->attribute.get(CRED_RESULTS_KEY);
  if (!raw) return;
  const auto *data = static_cast<const TargetCredData *>(raw);

  for (const PortCredResults &pcr : data->results) {
    for (const CredResult &r : pcr.hits) {
      if (r.found) {
        log_write(LOG_PLAIN,
          "  |  DEFAULT CREDS %d/%s: %s:%s [FOUND]\n",
          pcr.portno,
          (pcr.proto == IPPROTO_TCP) ? "tcp" : "udp",
          r.username.c_str(),
          r.password.empty() ? "(empty)" : r.password.c_str());
      }
    }
  }
}
