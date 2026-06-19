/*
 * test_banner_classify.cc -- KATs for the shared banner classifier
 * kmap_classify_banner() in banner_classify.h.
 *
 * net_enrich.cc::grab_banner and net_enrich_async.cc::classify_banner now both
 * call this one function (they were duplicated and had drifted -- grab_banner
 * had MariaDB detection + the tightened PostgreSQL length check, the async copy
 * had neither). This tests the REAL shared header across every protocol branch
 * plus negatives and a random-byte fuzz loop (no fault under ASan/UBSan).
 *
 * Build: g++ -O2 -g -std=gnu++17 -Wall fuzz/test_banner_classify.cc -o t && ./t
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../banner_classify.h"   /* the REAL shared classifier */

static int g_fail = 0;
static BannerClass clf(const std::string &s, int port = 0) {
  return kmap_classify_banner(s.data(), (int)s.size(), port);
}
static void want(const std::string &banner, int port,
                 const char *svc, const char *label) {
  BannerClass r = clf(banner, port);
  if (r.service != svc) {
    printf("  FAIL %s: got service '%s' want '%s'\n", label, r.service.c_str(), svc);
    g_fail++;
  }
}

int main(int argc, char **argv) {
  uint32_t seed = argc > 1 ? (uint32_t)strtoul(argv[1], nullptr, 0) : 1;
  printf("banner-classify test (shared header)\n=====================================\n");

  want("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", 80, "http", "http");
  want("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n", 443, "https", "https-by-port");
  { BannerClass r = clf("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", 80);
    if (r.version != "nginx/1.18.0") { printf("  FAIL http server-version '%s'\n", r.version.c_str()); g_fail++; } }
  want("SSH-2.0-OpenSSH_8.9p1\r\n", 22, "ssh", "ssh");
  { BannerClass r = clf("SSH-2.0-OpenSSH_8.9p1\r\n", 22);
    if (r.version != "OpenSSH 8.9p1") { printf("  FAIL ssh version '%s'\n", r.version.c_str()); g_fail++; } }
  /* VNC / RFB */
  want("RFB 003.008\n", 5900, "vnc", "vnc");
  { BannerClass r = clf("RFB 003.008\n", 5900);
    if (r.version != "RFB 003.008") { printf("  FAIL vnc version '%s'\n", r.version.c_str()); g_fail++; } }
  want("RFB 004.001\n", 5901, "vnc", "vnc 4.x");
  want("RFB abc!", 5900, "unknown", "RFB + non-digit is not vnc");
  want("RFBxx no space here", 5900, "unknown", "RFBxx no longer false-postgresql");
  /* Telnet IAC + rsync */
  { std::string t; t += (char)0xFF; t += (char)0xFD; t += (char)0x18;
    want(t, 23, "telnet", "telnet IAC DO"); }
  { std::string t; t += (char)0xFF; t += (char)0xFB; t += (char)0x01;
    want(t, 23, "telnet", "telnet IAC WILL"); }
  { std::string t; t += (char)0xFF; t += (char)0x05;
    want(t, 23, "unknown", "0xFF + non-WILL/DO is not telnet"); }
  want("@RSYNCD: 31.0\n", 873, "rsync", "rsync daemon greeting");
  { BannerClass r = clf("@RSYNCD: 31.0\n", 873);
    if (r.version != "@RSYNCD: 31.0") { printf("  FAIL rsync version '%s'\n", r.version.c_str()); g_fail++; } }
  /* FTP / SMTP / IMAP / POP3 */
  want("220 ProFTPD 1.3.5 Server ready\r\n", 21, "ftp", "ftp");
  want("220 mail.example.com ESMTP Postfix\r\n", 25, "smtp", "smtp");
  want("220-FileZilla Server\r\n", 21, "ftp", "ftp 220-dash by port");
  want("* OK [CAPABILITY IMAP4rev1] ready\r\n", 143, "imap", "imap");
  want("+OK POP3 ready\r\n", 110, "pop3", "pop3");
  /* MySQL handshake + the MariaDB sub-detection (the divergence consolidation
     fixes: the async path lacked this entirely). */
  { std::string m; m += '\x36'; m += '\x00'; m += '\x00'; m += '\x00'; m += '\x0a';
    m += "5.7.38"; m += '\x00'; want(m, 3306, "mysql", "mysql handshake"); }
  { std::string m; m += '\x50'; m += '\x00'; m += '\x00'; m += '\x00'; m += '\x0a';
    m += "5.5.5-10.11.6-MariaDB-1"; m += '\x00';
    BannerClass r = clf(m, 3306);
    if (r.service != "mariadb") { printf("  FAIL mariadb service '%s'\n", r.service.c_str()); g_fail++; }
    if (r.version != "10.11.6-MariaDB-1") { printf("  FAIL mariadb version '%s'\n", r.version.c_str()); g_fail++; } }
  /* Elasticsearch root JSON (reclassified from http for CVE/EOL matching). */
  { std::string es = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
      "{\"name\":\"n1\",\"cluster_name\":\"docker-cluster\","
      "\"version\":{\"number\":\"8.12.0\",\"lucene_version\":\"9.9.1\"},"
      "\"tagline\":\"You Know, for Search\"}";
    BannerClass r = clf(es, 9200);
    if (r.service != "elasticsearch") { printf("  FAIL es service '%s'\n", r.service.c_str()); g_fail++; }
    if (r.version != "8.12.0") { printf("  FAIL es version '%s'\n", r.version.c_str()); g_fail++; } }
  /* Jenkins advertises its version in the X-Jenkins header. */
  { std::string j = "HTTP/1.1 403 Forbidden\r\nX-Jenkins: 2.401.3\r\n"
      "X-Jenkins-Session: abc\r\nContent-Type: text/html\r\n\r\n";
    BannerClass r = clf(j, 8080);
    if (r.service != "jenkins") { printf("  FAIL jenkins service '%s'\n", r.service.c_str()); g_fail++; }
    if (r.version != "2.401.3") { printf("  FAIL jenkins version '%s'\n", r.version.c_str()); g_fail++; } }
  /* SharePoint version from the MicrosoftSharePointTeamServices header. */
  { std::string sp = "HTTP/1.1 200 OK\r\nMicrosoftSharePointTeamServices: 16.0.0.10337\r\n"
      "Content-Type: text/html\r\n\r\n";
    BannerClass r = clf(sp, 443);
    if (r.service != "sharepoint") { printf("  FAIL sharepoint service '%s'\n", r.service.c_str()); g_fail++; }
    if (r.version != "16.0.0.10337") { printf("  FAIL sharepoint version '%s'\n", r.version.c_str()); g_fail++; } }
  /* A normal HTTP server is NOT reclassified. */
  want("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html>hi</html>", 80, "http", "plain http not es");
  want("-ERR unknown command\r\n", 6379, "redis", "redis");
  /* PostgreSQL AuthOK (len 8) detected; out-of-range length rejected. */
  { std::string pg; pg += 'R'; pg += '\x00'; pg += '\x00'; pg += '\x00'; pg += '\x08';
    pg += std::string(4, '\x00'); want(pg, 5432, "postgresql", "postgresql AuthOK"); }
  { std::string pg; pg += 'R'; pg += '\xff'; pg += '\xff'; pg += '\x00'; pg += '\x00';
    pg += std::string(4, '\x00'); want(pg, 5432, "unknown", "R + huge length not postgresql"); }
  { std::string mg(16, '\x00'); mg[12] = '\x01'; want(mg, 27017, "mongodb", "mongodb OP_REPLY"); }
  want("", 80, "", "empty banner -> empty");
  want("garbage banner text", 12345, "unknown", "unknown fallback");

  printf("KATs: %s\n", g_fail ? "FAIL" : "OK");

  uint32_t r = seed ? seed : 1;
  auto xr = [&](){ r^=r<<13; r^=r>>17; r^=r<<5; return r; };
  for (int it = 0; it < 300000; it++) {
    int len = xr() % 80;
    std::string s; s.resize(len);
    for (int i = 0; i < len; i++) s[i] = (char)(xr() & 0xff);
    volatile size_t z = kmap_classify_banner(s.data(), len, (int)(xr()%70000)-2000).service.size();
    (void)z;
  }
  printf("fuzz (300000 iters): no fault\n");

  printf("\n%s\n", g_fail == 0 ? "banner-classify test: ALL PASS"
                               : "banner-classify test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
