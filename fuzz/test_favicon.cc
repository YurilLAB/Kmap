/*
 * test_favicon.cc -- pins net_hash_helpers.cc::favicon_mmh3 and
 * base64_encodebytes against Python's base64.encodebytes + reference mmh3.
 *
 * The #1 source of a Shodan-mismatched favicon hash is the base64 framing:
 * Python's base64.encodebytes inserts a '\n' every 76 output chars AND a
 * trailing '\n'.  These cases pin both the framing and the resulting hash.
 *
 * Build:
 *   g++ -O2 -g -std=gnu++17 -Wall fuzz/test_favicon.cc net_hash_helpers.cc \
 *       -o fuzz/test_favicon.exe && fuzz/test_favicon.exe
 */

#include <cstdio>
#include <string>

#include "../net_hash_helpers.h"

static int g_fail = 0;

static void check_str(const std::string &got, const std::string &expect,
                      const char *label) {
  if (got != expect) {
    printf("  FAIL %-18s\n    got    [%s]\n    expect [%s]\n",
           label, got.c_str(), expect.c_str());
    g_fail++;
  }
}

static std::string seq(int n) {           /* bytes 0,1,2,...,n-1 */
  std::string s;
  for (int i = 0; i < n; i++) s += static_cast<char>(i);
  return s;
}

int main(void) {
  /* Empty input -> empty (no hash, no trailing newline). */
  check_str(favicon_mmh3(""), "", "favicon-empty");
  check_str(base64_encodebytes(""), "", "b64-empty");

  /* base64.encodebytes framing: 50 bytes -> 68 b64 chars (one line) + '\n'. */
  check_str(base64_encodebytes(seq(50)),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDE=\n",
            "b64-50");

  /* 60 bytes -> 80 b64 chars -> wrap after 76 + trailing '\n'. */
  check_str(base64_encodebytes(seq(60)),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4\nOTo7\n",
            "b64-60-wrap");

  /* Favicon hashes (decimal strings), verified against reference mmh3. */
  check_str(favicon_mmh3(std::string("\x89PNG\r\n\x1a\n", 8)), "651593099",
            "favicon-png");
  check_str(favicon_mmh3("icon-bytes-here"), "-379528085", "favicon-text");
  check_str(favicon_mmh3(seq(50)), "-1267721240", "favicon-seq50");
  check_str(favicon_mmh3(std::string("\x00\x00\x01\x00", 4)), "-216455174",
            "favicon-ico-magic");
  check_str(favicon_mmh3("GIF89a"), "-851503336", "favicon-gif");
  check_str(favicon_mmh3(seq(60)), "-609915622", "favicon-seq60");

  printf("\n%s\n",
         g_fail == 0 ? "favicon test: ALL PASS" : "favicon test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
