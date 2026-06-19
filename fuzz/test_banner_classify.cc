/*
 * test_banner_classify.cc -- pins the banner -> service classifier.
 *
 * net_enrich_async.cc::classify_banner and net_enrich.cc::grab_banner share the
 * same banner-pattern logic ("MUST stay in sync") and were untested. This KATs
 * the classifier (the pure async form, copied VERBATIM) across every protocol
 * branch -- HTTP/HTTPS, SSH, the new VNC/RFB branch, FTP/SMTP 220, IMAP, POP3,
 * MySQL, Redis, MongoDB, PostgreSQL -- plus negative cases and a random-byte
 * fuzz loop (must never fault under ASan/UBSan).
 *
 * Build: g++ -O2 -g -std=gnu++17 -Wall fuzz/test_banner_classify.cc -o t && ./t
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <algorithm>
#include <cctype>

/* ===== VERBATIM from net_enrich_async.cc ===== */
struct AsyncBannerResult {
  std::string service;
  std::string version;
  std::string http_response;
};
static std::string a_str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}
static AsyncBannerResult classify_banner(const char *buf, int n, int port) {
  AsyncBannerResult result;
  if (n <= 0 || !buf) return result;

  std::string banner(buf, static_cast<size_t>(n));
  std::string banner_lower = a_str_lower(banner);

  std::string first_line = banner;
  size_t nl = first_line.find('\n');
  if (nl != std::string::npos) first_line = first_line.substr(0, nl);
  while (!first_line.empty() &&
         (first_line.back() == '\r' || first_line.back() == '\n'))
    first_line.pop_back();

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

  if (banner.size() >= 4 && banner.substr(0, 4) == "SSH-") {
    result.service = "ssh";
    size_t dash3 = banner.find('-', 4);
    if (dash3 != std::string::npos && dash3 + 1 < first_line.size()) {
      result.version = first_line.substr(dash3 + 1);
      std::replace(result.version.begin(), result.version.end(), '_', ' ');
    }
    return result;
  }

  if (banner.size() >= 8 && banner.compare(0, 4, "RFB ") == 0 &&
      isdigit(static_cast<unsigned char>(banner[4]))) {
    result.service = "vnc";
    result.version = first_line;
    return result;
  }

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

  if (n >= 5 && static_cast<unsigned char>(buf[4]) == 0x0a) {
    result.service = "mysql";
    const char *verp = buf + 5;
    size_t vlen = strnlen(verp,
                          static_cast<size_t>(n) > 5 ? static_cast<size_t>(n) - 5 : 0);
    if (vlen > 0) result.version = std::string(verp, vlen);
    return result;
  }

  if (banner_lower.find("-err") == 0 || banner_lower.find("+pong") == 0 ||
      banner_lower.find("$") == 0) {
    result.service = "redis";
    return result;
  }

  if (n >= 16 && static_cast<unsigned char>(buf[12]) == 0x01) {
    result.service = "mongodb";
    return result;
  }

  if (n >= 9 && buf[0] == 'R') {
    result.service = "postgresql";
    return result;
  }

  if (!first_line.empty()) {
    result.service = "unknown";
    if (first_line.size() > 64)
      result.version = first_line.substr(0, 64);
    else
      result.version = first_line;
  }

  return result;
}
/* ===== end verbatim ===== */

static int g_fail = 0;
static AsyncBannerResult clf(const std::string &s, int port = 0) {
  return classify_banner(s.data(), (int)s.size(), port);
}
static void want(const std::string &banner, int port,
                 const char *svc, const char *label) {
  AsyncBannerResult r = clf(banner, port);
  if (r.service != svc) {
    printf("  FAIL %s: got service '%s' want '%s'\n", label, r.service.c_str(), svc);
    g_fail++;
  }
}

int main(int argc, char **argv) {
  uint32_t seed = argc > 1 ? (uint32_t)strtoul(argv[1], nullptr, 0) : 1;
  printf("banner-classify test\n====================\n");

  want("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", 80, "http", "http");
  want("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n", 443, "https", "https-by-port");
  { AsyncBannerResult r = clf("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", 80);
    if (r.version != "nginx/1.18.0") { printf("  FAIL http server-version '%s'\n", r.version.c_str()); g_fail++; } }
  want("SSH-2.0-OpenSSH_8.9p1\r\n", 22, "ssh", "ssh");
  { AsyncBannerResult r = clf("SSH-2.0-OpenSSH_8.9p1\r\n", 22);
    if (r.version != "OpenSSH 8.9p1") { printf("  FAIL ssh version '%s'\n", r.version.c_str()); g_fail++; } }
  /* NEW: VNC / RFB */
  want("RFB 003.008\n", 5900, "vnc", "vnc");
  { AsyncBannerResult r = clf("RFB 003.008\n", 5900);
    if (r.version != "RFB 003.008") { printf("  FAIL vnc version '%s'\n", r.version.c_str()); g_fail++; } }
  want("RFB 004.001\n", 5901, "vnc", "vnc 4.x");
  want("RFB abc!", 5900, "unknown", "RFB + non-digit is not vnc");
  /* Note: "RFB" followed by >=9 bytes and no space hits the (pre-existing,
     deliberately loose) PostgreSQL 'R'+n>=9 branch -- VNC is ordered before it
     so real "RFB <digit>" banners are never misclassified. */

  want("220 ProFTPD 1.3.5 Server ready\r\n", 21, "ftp", "ftp");
  want("220 mail.example.com ESMTP Postfix\r\n", 25, "smtp", "smtp");
  want("220-FileZilla Server\r\n", 21, "ftp", "ftp 220-dash by port");
  want("* OK [CAPABILITY IMAP4rev1] ready\r\n", 143, "imap", "imap");
  want("+OK POP3 ready\r\n", 110, "pop3", "pop3");
  { std::string m; m += '\x36'; m += '\x00'; m += '\x00'; m += '\x00'; m += '\x0a';
    m += "5.7.38\x00"; want(m, 3306, "mysql", "mysql handshake"); }
  want("-ERR unknown command\r\n", 6379, "redis", "redis");
  { std::string pg; pg += 'R'; pg += std::string(8, '\x00'); want(pg, 5432, "postgresql", "postgresql R"); }
  { std::string mg(16, '\x00'); mg[12] = '\x01'; want(mg, 27017, "mongodb", "mongodb OP_REPLY"); }
  want("", 80, "", "empty banner -> empty");
  want("garbage banner text", 12345, "unknown", "unknown fallback");

  printf("KATs: %s\n", g_fail ? "FAIL" : "OK");

  /* fuzz: never fault on arbitrary bytes/ports */
  uint32_t r = seed ? seed : 1;
  auto xr = [&](){ r^=r<<13; r^=r>>17; r^=r<<5; return r; };
  for (int it = 0; it < 300000; it++) {
    int len = xr() % 80;
    std::string s; s.resize(len);
    for (int i = 0; i < len; i++) s[i] = (char)(xr() & 0xff);
    volatile size_t z = classify_banner(s.data(), len, (int)(xr()%70000)-2000).service.size();
    (void)z;
  }
  printf("fuzz (300000 iters): no fault\n");

  printf("\n%s\n", g_fail == 0 ? "banner-classify test: ALL PASS"
                               : "banner-classify test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
