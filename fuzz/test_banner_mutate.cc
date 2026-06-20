/*
 * test_banner_mutate.cc -- structured mutation fuzzer for the HTTP product
 * detection in the shared classifier kmap_classify_banner() (banner_classify.h).
 *
 * The random-byte fuzz loop in test_banner_classify.cc (and the standalone
 * OSS-Fuzz driver) almost never synthesises a valid HTTP response carrying the
 * X-Jenkins / MicrosoftSharePointTeamServices / X-Confluence-Request-Time
 * headers or the Elasticsearch cluster-info JSON -- so the *version-extraction
 * index math* added for those products (find content=", scan to the closing
 * quote, header value to CRLF, the "version" -> "number" anchor walk) was never
 * actually exercised by it. This harness seeds with real responses for each
 * product and bit-flips / truncates / splices them, keeping the inputs
 * near-valid so the offset math runs over hostile edges: a header at EOF, a
 * content=" with no closing quote, the "version" object cut mid-key, etc.
 *
 * Pure oracle: the classifier must never fault (ASan/UBSan) and must be
 * deterministic. Build:
 *   g++ -O1 -g -std=gnu++17 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       fuzz/test_banner_mutate.cc -o t && ./t 1
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../banner_classify.h"   /* the REAL shared classifier */

int main(int argc, char **argv) {
  uint32_t seed = argc > 1 ? (uint32_t)strtoul(argv[1], nullptr, 0) : 1;
  long iters = argc > 2 ? strtol(argv[2], nullptr, 0) : 3000000;
  uint32_t r = seed ? seed : 1;
  auto xr = [&](){ r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };

  const std::vector<std::string> seeds = {
    "HTTP/1.1 403 Forbidden\r\nX-Jenkins: 2.426.1\r\n"
    "X-Jenkins-Session: a\r\nContent-Type: text/html\r\n\r\n<html>jenkins</html>",
    "HTTP/1.1 200 OK\r\nMicrosoftSharePointTeamServices: 16.0.0.10337\r\n"
    "Content-Type: text/html\r\n\r\n<html>sp</html>",
    "HTTP/1.1 200 OK\r\nX-Confluence-Request-Time: 1718000000\r\n"
    "Content-Type: text/html\r\n\r\n"
    "<meta name=\"ajs-version-number\" content=\"8.5.4\"></head>",
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
    "{\"name\":\"n\",\"cluster_name\":\"c\","
    "\"version\":{\"number\":\"8.12.0\",\"lucene_version\":\"9.9\"},"
    "\"tagline\":\"You Know, for Search\"}",
    "HTTP/1.1 200 OK\r\nServer: nginx/1.25.0\r\n\r\nbody",
  };
  const int ports[] = {80, 443, 8080, 8090, 9200, 8443};

  printf("banner mutation fuzz (HTTP product index math)\n"
         "==============================================\n");
  for (long it = 0; it < iters; it++) {
    std::string s = seeds[xr() % seeds.size()];
    int muts = 1 + xr() % 6;
    for (int m = 0; m < muts && !s.empty(); m++) {
      switch (xr() % 5) {
        case 0: s[xr() % s.size()] ^= (char)(1u << (xr() % 8)); break; /* bit flip */
        case 1: s.resize(xr() % (s.size() + 1)); break;                /* truncate */
        case 2: s.insert(xr() % (s.size() + 1), 1, (char)(xr() & 0xff)); break;
        case 3: s.erase(xr() % s.size(), 1); break;
        case 4: s[xr() % s.size()] = (char)(xr() & 0xff); break;
      }
    }
    int port = ports[xr() % 6];
    BannerClass a = kmap_classify_banner(s.data(), (int)s.size(), port);
    BannerClass b = kmap_classify_banner(s.data(), (int)s.size(), port);
    if (a.service != b.service || a.version != b.version) {
      printf("  FAIL nondeterministic classification\n");
      return 1;
    }
    volatile size_t z = a.service.size() + a.version.size();
    (void)z;
  }
  printf("mutation fuzz (%ld iters, seed=%u): no fault\n", iters, seed);
  printf("\nbanner-mutate test: ALL PASS\n");
  return 0;
}
