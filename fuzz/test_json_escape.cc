/*
 * test_json_escape.cc -- correctness test for the shared JSON string escaper
 * kmap_json_escape() in json_escape.h, used by net_enrich.cc,
 * net_enrich_async.cc, net_query.cc and net_scan.cc.
 *
 * History: the escaper was copy-pasted into four TUs and drifted -- three kept
 * a passthrough-high-bytes version while net_query.cc gained UTF-8 validation,
 * so the same host serialised to valid JSON via --net-query and INVALID JSON in
 * the findings report. The copies are now one header-only function; this test
 * includes that real header (no hand-kept duplicate) and proves two invariants
 * over a large fuzz corpus with INDEPENDENT oracles:
 *   1. the output is a well-formed JSON string body (RFC 8259): no raw control
 *      byte < 0x20, no bare '"', every '\' a valid escape;
 *   2. the output is valid UTF-8 (RFC 3629) -- this is the property the three
 *      drifted copies violated, since scan banners are routinely non-UTF-8.
 *
 * Build: g++ -O2 -g -std=gnu++17 -Wall fuzz/test_json_escape.cc \
 *        -o fuzz/test_json_escape.exe && fuzz/test_json_escape.exe
 */
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include "../json_escape.h"   /* the REAL shipping escaper */

static bool is_hex(unsigned char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* INDEPENDENT oracle 1: valid JSON string body (RFC 8259). */
static bool valid_json_string_body(const std::string &esc) {
  size_t i = 0;
  while (i < esc.size()) {
    unsigned char c = (unsigned char)esc[i];
    if (c < 0x20) return false;          /* raw control char -- invalid */
    if (c == '"') return false;          /* unescaped quote -- invalid */
    if (c == '\\') {
      if (i + 1 >= esc.size()) return false;
      unsigned char n = (unsigned char)esc[i + 1];
      if (n == '"' || n == '\\' || n == '/' || n == 'b' || n == 'f' ||
          n == 'n' || n == 'r' || n == 't') { i += 2; continue; }
      if (n == 'u') {
        if (i + 5 >= esc.size()) return false;
        for (int k = 2; k <= 5; k++) if (!is_hex((unsigned char)esc[i + k])) return false;
        i += 6; continue;
      }
      return false;                      /* invalid escape */
    }
    i++;
  }
  return true;
}

/* INDEPENDENT oracle 2: valid UTF-8 (RFC 3629), written from scratch (does not
 * share code with json_escape.h's validator). */
static bool valid_utf8(const std::string &s) {
  size_t i = 0, n = s.size();
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x80) { i++; continue; }
    int len; uint32_t cp; unsigned char lo = 0x80, hi = 0xBF;
    if (c >= 0xC2 && c <= 0xDF) { len = 2; cp = c & 0x1F; }
    else if (c == 0xE0)         { len = 3; cp = c & 0x0F; lo = 0xA0; }
    else if (c >= 0xE1 && c <= 0xEC) { len = 3; cp = c & 0x0F; }
    else if (c == 0xED)         { len = 3; cp = c & 0x0F; hi = 0x9F; }
    else if (c >= 0xEE && c <= 0xEF) { len = 3; cp = c & 0x0F; }
    else if (c == 0xF0)         { len = 4; cp = c & 0x07; lo = 0x90; }
    else if (c >= 0xF1 && c <= 0xF3) { len = 4; cp = c & 0x07; }
    else if (c == 0xF4)         { len = 4; cp = c & 0x07; hi = 0x8F; }
    else return false;
    if (i + (size_t)len > n) return false;
    for (int k = 1; k < len; k++) {
      unsigned char cc = (unsigned char)s[i + k];
      unsigned char l = (k == 1) ? lo : 0x80, h = (k == 1) ? hi : 0xBF;
      if (cc < l || cc > h) return false;
      cp = (cp << 6) | (cc & 0x3F);
    }
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
    i += len;
  }
  return true;
}

static uint64_t rng = 0xA5A5F00DCAFEBABEULL;
static uint32_t rnd() { rng ^= rng<<13; rng ^= rng>>7; rng ^= rng<<17; return (uint32_t)(rng>>32); }

int main(int argc, char **argv) {
  if (argc > 1) rng = (uint64_t)atoll(argv[1]) * 2654435761ULL + 1;
  int passed = 0, failed = 0;
  #define OK(cond, msg) do { if (cond) passed++; else { failed++; printf("  FAIL %s\n", msg); } } while (0)

  /* ---- ASCII control + metachar mappings (hand-verified) ---- */
  struct M { const char *in; const char *exp; };
  M maps[] = {
    {"\"",  "\\\""}, {"\\", "\\\\"}, {"\b", "\\b"}, {"\f", "\\f"},
    {"\n", "\\n"},  {"\r", "\\r"},  {"\t", "\\t"},
    {"A",  "A"}, {"normal text 1.2.3", "normal text 1.2.3"},
  };
  for (auto &m : maps)
    OK(kmap_json_escape(m.in) == m.exp, (std::string("map ") + m.exp).c_str());
  { std::string e = kmap_json_escape(std::string(1, (char)0x00)); OK(e == "\\u0000", "0x00 -> \\u0000"); }
  { std::string e = kmap_json_escape(std::string(1, (char)0x1b)); OK(e == "\\u001b", "0x1b -> \\u001b"); }
  { std::string e = kmap_json_escape(std::string(1, (char)0x7f)); OK(e == "\x7f", "0x7f DEL passes (ASCII)"); }

  /* ---- valid UTF-8 sequences pass through unchanged ---- */
  OK(kmap_json_escape("\xC3\xA9") == "\xC3\xA9", "U+00E9 (2-byte) passthrough");      /* é */
  OK(kmap_json_escape("\xE2\x82\xAC") == "\xE2\x82\xAC", "U+20AC (3-byte) passthrough"); /* € */
  OK(kmap_json_escape("\xF0\x9F\x98\x80") == "\xF0\x9F\x98\x80", "U+1F600 (4-byte) passthrough"); /* 😀 */

  /* ---- malformed UTF-8 -> U+FFFD (EF BF BD); this is what the old copies
          got wrong (they passed the raw bytes through -> invalid JSON). ---- */
  const char *FFFD = "\xEF\xBF\xBD";
  OK(kmap_json_escape("\xFF") == FFFD, "lone 0xFF -> U+FFFD");
  OK(kmap_json_escape("\x80") == FFFD, "lone continuation 0x80 -> U+FFFD");
  OK(kmap_json_escape("\xC0\xAF") == std::string(FFFD) + FFFD, "overlong C0 AF -> 2x U+FFFD");
  OK(kmap_json_escape("\xE0\x80\xAF") == std::string(FFFD)+FFFD+FFFD, "overlong E0 -> 3x U+FFFD");
  OK(kmap_json_escape("\xED\xA0\x80") == std::string(FFFD)+FFFD+FFFD, "surrogate ED A0 80 -> U+FFFD");
  OK(kmap_json_escape("\xF4\x90\x80\x80") == std::string(FFFD)+FFFD+FFFD+FFFD, "> U+10FFFF -> U+FFFD");
  OK(kmap_json_escape("\xE2\x82") == std::string(FFFD)+FFFD, "truncated 3-byte at EOF -> U+FFFD");
  OK(kmap_json_escape("a\xC3\xA9\xFF""b") == std::string("a")+"\xC3\xA9"+FFFD+"b",
     "mixed valid+invalid preserves good bytes");
  int kat_fail = failed;
  printf("KATs: %s (%d failed)\n", kat_fail ? "FAIL" : "OK", kat_fail);

  /* ---- every single byte 0x00..0xFF -> valid JSON body AND valid UTF-8 ---- */
  for (int b = 0; b < 256; b++) {
    std::string e = kmap_json_escape(std::string(1, (char)(unsigned char)b));
    OK(valid_json_string_body(e), "single-byte valid JSON body");
    OK(valid_utf8(e), "single-byte valid UTF-8");
  }

  /* ---- fuzz: arbitrary byte strings -> always valid JSON body AND UTF-8 ---- */
  const int N = 3000000;
  for (int n = 0; n < N; n++) {
    int len = rnd() % 64;
    std::string in; in.reserve(len);
    for (int i = 0; i < len; i++) in += (char)(unsigned char)(rnd() & 0xFF);
    std::string e = kmap_json_escape(in);
    if (!valid_json_string_body(e)) { failed++; if (failed<=6) printf("  FAIL fuzz json-body n=%d\n", n); }
    else if (!valid_utf8(e))        { failed++; if (failed<=6) printf("  FAIL fuzz utf8 n=%d\n", n); }
    else passed++;
  }

  printf("\njson-escape test: %d passed, %d failed (%d random strings)\n",
         passed, failed, N);
  return failed == 0 ? 0 : 1;
}
