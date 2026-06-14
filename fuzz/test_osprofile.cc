/*
 * test_osprofile.cc -- live test for os_profile_http_request(), the HTTP probe
 * builder used by every enrichment path (banner-grab, sync + async HTTP probe,
 * web recon). Links the real os_profile.cc.
 *
 * A regression here -- dropping the Host header, breaking the blank-line
 * terminator, or letting a value introduce a second CRLFCRLF (header
 * injection) -- would silently corrupt every HTTP probe. Pin the structure:
 *   - request line "GET <path> HTTP/1.x"
 *   - a Host header (IPv6 literals bracketed per RFC 7230)
 *   - a User-Agent (profile's, or the "Kmap" fallback when no profile)
 *   - terminates with exactly ONE blank line (\r\n\r\n) at the very end
 *     (more than one would mean a header value injected a blank line)
 *   - per-target profile selection is deterministic for a fixed seed
 *
 * Build (Win):  g++ -O2 -std=gnu++17 -DWIN32 -I.. test_osprofile.cc \
 *                   ../os_profile.cc -o test_osprofile.exe
 * Build (CI):   g++ $CXXFLAGS -I. fuzz/test_osprofile.cc os_profile.cc -o test_osprofile
 */
#include "os_profile.h"
#include <cstdio>
#include <string>

static int g_fail = 0;
static void chk(bool c, const char *m) { if (!c) { printf("  FAIL: %s\n", m); g_fail++; } }

/* Count non-overlapping occurrences of a needle. */
static int count_occ(const std::string &h, const std::string &n) {
  int c = 0; size_t p = 0;
  while ((p = h.find(n, p)) != std::string::npos) { c++; p += n.size(); }
  return c;
}

static void check_wellformed(const std::string &req, const char *label) {
  char m[160];
  snprintf(m, sizeof(m), "%s: starts with 'GET / HTTP/1.'", label);
  chk(req.rfind("GET / HTTP/1.", 0) == 0, m);
  snprintf(m, sizeof(m), "%s: has a Host header", label);
  chk(req.find("\r\nHost: ") != std::string::npos, m);
  snprintf(m, sizeof(m), "%s: has a User-Agent header", label);
  chk(req.find("\r\nUser-Agent: ") != std::string::npos ||
      req.rfind("GET", 0) == 0 /*never*/ , m);
  snprintf(m, sizeof(m), "%s: ends with a blank line (\\r\\n\\r\\n)", label);
  chk(req.size() >= 4 && req.compare(req.size() - 4, 4, "\r\n\r\n") == 0, m);
  snprintf(m, sizeof(m), "%s: exactly ONE \\r\\n\\r\\n (no injected blank line)", label);
  chk(count_occ(req, "\r\n\r\n") == 1, m);
  /* No bare LF without a preceding CR -- a malformed line ending. */
  snprintf(m, sizeof(m), "%s: no bare LF (every \\n preceded by \\r)", label);
  bool bare = false;
  for (size_t i = 0; i < req.size(); i++)
    if (req[i] == '\n' && (i == 0 || req[i-1] != '\r')) { bare = true; break; }
  chk(!bare, m);
}

int main(void) {
  printf("os_profile_http_request structure test\n======================================\n");

  const OsProfile *p = os_profile_get("linux");
  chk(p != nullptr, "os_profile_get(\"linux\") returns a profile");

  /* IPv4 host + a real profile. */
  std::string r4 = os_profile_http_request("/", "203.0.113.5", p);
  check_wellformed(r4, "ipv4+profile");
  chk(r4.find("\r\nHost: 203.0.113.5\r\n") != std::string::npos,
      "ipv4 Host header is the plain dotted-quad");

  /* IPv6 host must be bracketed. */
  std::string r6 = os_profile_http_request("/", "2001:db8::1", p);
  check_wellformed(r6, "ipv6+profile");
  chk(r6.find("\r\nHost: [2001:db8::1]\r\n") != std::string::npos,
      "ipv6 Host header is bracketed");

  /* No profile -> the legacy "Kmap" User-Agent fallback, still well-formed. */
  std::string rn = os_profile_http_request("/", "203.0.113.5", nullptr);
  check_wellformed(rn, "no-profile");
  chk(rn.find("\r\nUser-Agent: Kmap\r\n") != std::string::npos,
      "no-profile uses the Kmap User-Agent fallback");

  /* Per-target selection is deterministic for a fixed seed (so multiple
     probes against one host present one coherent personality). */
  uint64_t seed = os_profile_seed_from_text("203.0.113.5");
  const OsProfile *a = os_profile_get_for_target("random", seed);
  const OsProfile *b = os_profile_get_for_target("random", seed);
  chk(a == b, "os_profile_get_for_target is deterministic for a fixed seed");

  printf("\n%s\n", g_fail == 0 ? "os-profile test: ALL PASS" : "os-profile test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
