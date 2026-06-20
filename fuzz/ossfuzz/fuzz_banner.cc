/*
 * fuzz_banner.cc -- OSS-Fuzz / ClusterFuzzLite libFuzzer target for the shared
 * service/version banner classifier (banner_classify.h, header-only).
 *
 * kmap_classify_banner runs over the raw first bytes a server sends (or its
 * reply to a probe): HTTP/SSH/VNC/telnet/rsync/220/IMAP/POP3 prefix checks,
 * MySQL/Mongo/PostgreSQL binary offsets, and -- the newest, index-heavy part --
 * HTTP header/body scans for Elasticsearch, Jenkins (X-Jenkins) and SharePoint
 * (MicrosoftSharePointTeamServices). All of it is substring + offset math over
 * attacker-controlled bytes, the over-read class libFuzzer+ASan targets.
 *
 * Includes the REAL shipping header so production code is fuzzed.
 */
#include <cstdint>
#include <cstddef>
#include <string>

#include "../../banner_classify.h"   /* real kmap_classify_banner */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;
  /* Use the first byte as a (fuzzed) port selector across the interesting
     branches, the rest as the banner. */
  static const int ports[] = {0, 22, 23, 80, 443, 8080, 8443, 9200, 3306,
                              5432, 6379, 27017, 5900, 873, 502};
  int port = ports[data[0] % (sizeof(ports) / sizeof(ports[0]))];
  const char *buf = reinterpret_cast<const char *>(data) + 1;
  int n = static_cast<int>(size - 1);

  BannerClass r = kmap_classify_banner(buf, n, port);

  /* Determinism: same bytes must classify identically. */
  BannerClass r2 = kmap_classify_banner(buf, n, port);
  if (r.service != r2.service || r.version != r2.version) __builtin_trap();

  /* The service label is always drawn from a fixed vocabulary -- a value
     outside it would mean memory corruption produced a garbage string. */
  if (!r.service.empty()) {
    static const char *known[] = {
      "http","https","ssh","vnc","telnet","rsync","ftp","smtp","imap","pop3",
      "mysql","mariadb","redis","mongodb","postgresql","elasticsearch",
      "jenkins","sharepoint","unknown"};
    bool ok = false;
    for (const char *k : known) if (r.service == k) { ok = true; break; }
    if (!ok) __builtin_trap();
  }
  return 0;
}
