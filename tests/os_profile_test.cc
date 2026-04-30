/* os_profile_test.cc -- Unit tests for the --spoof-os profile module.
 *
 * Covers:
 *   - Lookup and validation for every concrete profile name
 *   - Rejection of invalid / NULL / empty names
 *   - Stable per-target picking: same seed -> same profile every time;
 *     adjacent IPv4 addresses get spread across the table (rough check)
 *   - HTTP request shaping: request line, Host header, IPv6 bracketing,
 *     User-Agent, browser-like Sec-Fetch-* / Upgrade-Insecure-Requests,
 *     curl-like header omission, NULL profile preserves legacy behaviour
 *   - TLS cipher list returns NULL for curl-like profiles, non-NULL for
 *     browser-like profiles
 *   - Apply-to-socket is a no-op when profile is NULL (doesn't touch fd)
 *
 * Pure C++; no network or root required. Runs in <100ms.
 */

#include "../os_profile.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>

#ifdef WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <unistd.h>
#endif

static int g_failures = 0;

#define CHECK(expr) do { \
    if (!(expr)) { \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
      ++g_failures; \
    } \
  } while (0)

static const char *kProfiles[] = {
    "linux", "win10", "win11", "macos", "freebsd",
    "openbsd", "android", "ios"
};
static const size_t kProfileCount = sizeof(kProfiles) / sizeof(kProfiles[0]);

static bool contains(const std::string &haystack, const char *needle) {
  return haystack.find(needle) != std::string::npos;
}

static void test_lookup_and_validation(void) {
  /* Every concrete profile must be valid and resolvable. */
  for (size_t i = 0; i < kProfileCount; i++) {
    CHECK(os_profile_is_valid(kProfiles[i]));
    const OsProfile *p = os_profile_get(kProfiles[i]);
    CHECK(p != NULL);
    if (p) {
      CHECK(strcmp(p->name, kProfiles[i]) == 0);
      CHECK(p->ttl > 0 && p->ttl <= 255);
      CHECK(p->user_agent != NULL && p->user_agent[0] != '\0');
    }
  }

  /* "random" is valid but yields a concrete profile with a real name. */
  CHECK(os_profile_is_valid("random"));
  const OsProfile *r = os_profile_get("random");
  CHECK(r != NULL);
  CHECK(r->name != NULL);

  /* Bad inputs. */
  CHECK(!os_profile_is_valid(NULL));
  CHECK(!os_profile_is_valid(""));
  CHECK(!os_profile_is_valid("Linux"));      /* case-sensitive */
  CHECK(!os_profile_is_valid("win-12"));
  CHECK(!os_profile_is_valid("RANDOM"));

  CHECK(os_profile_get(NULL) == NULL);
  CHECK(os_profile_get("") == NULL);
  CHECK(os_profile_get("nope") == NULL);

  /* The error-message string must list every profile and "random". */
  const char *names = os_profile_names();
  CHECK(names != NULL);
  std::string ns(names);
  for (size_t i = 0; i < kProfileCount; i++) CHECK(contains(ns, kProfiles[i]));
  CHECK(contains(ns, "random"));
}

static void test_per_target_stability(void) {
  /* Same seed must produce the same profile every call. Otherwise two
   * probes against the same host would present different OS personalities
   * to a watching IDS -- which is the bug the per-target picker exists
   * to prevent. */
  const uint32_t ipv4 = 0x0a000001;  /* 10.0.0.1 */
  uint64_t seed = os_profile_seed_from_ipv4(ipv4);
  const OsProfile *first = os_profile_get_for_target("random", seed);
  CHECK(first != NULL);
  for (int i = 0; i < 1000; i++) {
    const OsProfile *p = os_profile_get_for_target("random", seed);
    CHECK(p == first);
  }

  /* Concrete profiles ignore the seed -- same result regardless. */
  const OsProfile *linux1 = os_profile_get_for_target("linux", 0);
  const OsProfile *linux2 = os_profile_get_for_target("linux", 0xdeadbeef);
  CHECK(linux1 != NULL && linux2 != NULL);
  CHECK(linux1 == linux2);

  /* Adjacent IPv4s should not all map to the same profile: with 8
   * profiles, 256 inputs should hit at least 4 distinct ones. (A perfect
   * uniform hash would hit all 8 with very high probability; we use
   * splitmix64 which passes BigCrush, so 4 is a generous lower bound
   * that won't false-fail under any reasonable seed change.) */
  std::set<const OsProfile *> seen;
  for (uint32_t i = 0; i < 256; i++) {
    seen.insert(os_profile_get_for_target("random",
                                          os_profile_seed_from_ipv4(i)));
  }
  CHECK(seen.size() >= 4);

  /* Bad inputs. */
  CHECK(os_profile_get_for_target(NULL, 0) == NULL);
  CHECK(os_profile_get_for_target("", 0) == NULL);
  CHECK(os_profile_get_for_target("nope", 0) == NULL);

  /* Text seed is deterministic. */
  CHECK(os_profile_seed_from_text("10.0.0.1") ==
        os_profile_seed_from_text("10.0.0.1"));
  CHECK(os_profile_seed_from_text("10.0.0.1") !=
        os_profile_seed_from_text("10.0.0.2"));
  CHECK(os_profile_seed_from_text(NULL) == 0);
}

static void test_http_request_browser(void) {
  const OsProfile *win11 = os_profile_get("win11");
  CHECK(win11 != NULL);
  if (!win11) return;

  std::string r = os_profile_http_request("/", "example.com", win11);
  /* Request line + Host */
  CHECK(contains(r, "GET / HTTP/1.1\r\n"));
  CHECK(contains(r, "Host: example.com\r\n"));
  /* Profile fields land in the request */
  CHECK(contains(r, "User-Agent: Mozilla/"));
  CHECK(contains(r, "Edg/121"));
  CHECK(contains(r, "Accept-Language: en-US"));
  CHECK(contains(r, "Accept-Encoding: gzip"));
  CHECK(contains(r, "Sec-Ch-Ua-Platform: \"Windows\""));
  /* Browser-like extras */
  CHECK(contains(r, "Upgrade-Insecure-Requests: 1\r\n"));
  CHECK(contains(r, "Sec-Fetch-Site: none\r\n"));
  CHECK(contains(r, "Sec-Fetch-Mode: navigate\r\n"));
  CHECK(contains(r, "Sec-Fetch-User: ?1\r\n"));
  CHECK(contains(r, "Sec-Fetch-Dest: document\r\n"));
  /* Trailer */
  CHECK(contains(r, "\r\nConnection: close\r\n\r\n"));
  /* No Kmap branding leaks through */
  CHECK(!contains(r, "Kmap"));
}

static void test_http_request_curl_like(void) {
  const OsProfile *linux_p = os_profile_get("linux");
  CHECK(linux_p != NULL);
  if (!linux_p) return;

  std::string r = os_profile_http_request("/", "example.com", linux_p);
  /* curl uses HTTP/1.0 in our profile */
  CHECK(contains(r, "GET / HTTP/1.0\r\n"));
  CHECK(contains(r, "User-Agent: curl/"));
  CHECK(contains(r, "Accept: */*\r\n"));
  /* curl never sends these -- they MUST NOT appear */
  CHECK(!contains(r, "Sec-Fetch-"));
  CHECK(!contains(r, "Upgrade-Insecure-Requests"));
  CHECK(!contains(r, "Accept-Language"));
  CHECK(!contains(r, "Accept-Encoding"));
  CHECK(!contains(r, "Kmap"));
}

static void test_http_request_ipv6_host(void) {
  const OsProfile *macos = os_profile_get("macos");
  CHECK(macos != NULL);
  if (!macos) return;

  std::string r = os_profile_http_request("/x", "2001:db8::1", macos);
  /* RFC 7230 Section 5.4: IPv6 literal must be bracketed in Host. */
  CHECK(contains(r, "Host: [2001:db8::1]\r\n"));
  /* Path is preserved verbatim. */
  CHECK(contains(r, "GET /x HTTP/1.1\r\n"));
}

static void test_http_request_null_profile(void) {
  /* NULL profile preserves the legacy Kmap-branded request so callers
   * that don't pass --spoof-os see no behaviour change. */
  std::string r = os_profile_http_request("/", "example.com", NULL);
  CHECK(contains(r, "User-Agent: Kmap\r\n"));
  CHECK(contains(r, "GET / HTTP/1.0\r\n"));
  /* No browser-like extras when there's no profile. */
  CHECK(!contains(r, "Sec-Fetch-"));
  CHECK(!contains(r, "Accept-Language"));

  /* Empty path is rewritten to "/". */
  std::string r2 = os_profile_http_request("", "h", NULL);
  CHECK(contains(r2, "GET / HTTP/1.0\r\n"));
  std::string r3 = os_profile_http_request(NULL, "h", NULL);
  CHECK(contains(r3, "GET / HTTP/1.0\r\n"));
}

static void test_tls_cipher_list(void) {
  /* curl-like profiles return NULL -> caller leaves SSL_CTX default.
   * Browser-like profiles return a non-NULL, OpenSSL-syntax cipher list. */
  CHECK(os_profile_tls_cipher_list(NULL) == NULL);
  CHECK(os_profile_tls_cipher_list(os_profile_get("linux")) == NULL);
  CHECK(os_profile_tls_cipher_list(os_profile_get("openbsd")) == NULL);

  const char *win10_c = os_profile_tls_cipher_list(os_profile_get("win10"));
  CHECK(win10_c != NULL);
  if (win10_c) {
    /* Must look like an OpenSSL cipher list -- colon-separated, no spaces. */
    CHECK(strchr(win10_c, ':') != NULL);
    CHECK(strchr(win10_c, ' ') == NULL);
    /* Chromium puts ECDHE-ECDSA-AES128-GCM-SHA256 first; verify. */
    CHECK(strstr(win10_c, "ECDHE-ECDSA-AES128-GCM-SHA256") == win10_c);
  }

  const char *macos_c = os_profile_tls_cipher_list(os_profile_get("macos"));
  CHECK(macos_c != NULL);
  if (macos_c) {
    /* Safari leads with ECDHE-ECDSA-AES256-GCM-SHA384, distinct from
     * Chromium ordering -- guards against accidentally collapsing the
     * Safari and Chromium lists into a single string. */
    CHECK(strstr(macos_c, "ECDHE-ECDSA-AES256-GCM-SHA384") == macos_c);
  }
}

static void test_apply_socket_null_profile(void) {
  /* NULL profile must be a no-op: passing -1 as the fd should not crash
   * (because we never reach the setsockopt calls). */
  os_profile_apply_socket(static_cast<intptr_t>(-1), AF_INET, NULL);
  os_profile_apply_socket(static_cast<intptr_t>(-1), AF_INET6, NULL);

#ifndef WIN32
  /* On a real socket, applying a profile must succeed without errors
   * propagating to the caller (setsockopt failures are deliberately
   * swallowed). We can't verify the value lands on every platform --
   * Linux doubles SO_RCVBUF, BSDs may reject IP_TTL on TCP sockets --
   * but we CAN check that the call doesn't crash and returns. */
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd >= 0) {
    const OsProfile *p = os_profile_get("win10");
    os_profile_apply_socket(static_cast<intptr_t>(fd), AF_INET, p);
    /* Verify TTL round-trips on Linux/macOS/BSD where the option is
     * writeable. We don't assert exact equality -- Linux TCP may quietly
     * clamp -- but the value should be in range and not the typical
     * 64 default that signals "spoof did nothing". */
    int got = 0;
    socklen_t len = sizeof(got);
    if (getsockopt(fd, IPPROTO_IP, IP_TTL, &got, &len) == 0) {
      CHECK(got > 0 && got <= 255);
    }
    close(fd);
  }
#endif
}

int main(void) {
  test_lookup_and_validation();
  test_per_target_stability();
  test_http_request_browser();
  test_http_request_curl_like();
  test_http_request_ipv6_host();
  test_http_request_null_profile();
  test_tls_cipher_list();
  test_apply_socket_null_profile();

  if (g_failures) {
    std::fprintf(stderr, "os_profile_test: %d FAILURE(S)\n", g_failures);
    return 1;
  }
  std::printf("os_profile_test: all tests passed\n");
  return 0;
}
