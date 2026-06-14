/*
 * test_json_escape.cc -- live correctness test for JSON string escaping
 * (net_enrich.cc json_escape, net_enrich_async.cc a_json_escape,
 *  net_scan.cc json_escape_topo -- all now identical RFC 8259 escapers).
 *
 * Regression test for: the escapers used to handle only " \ \n \r \t and
 * passed every other control byte (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F) through
 * RAW. Service banners / HTTP headers / TLS fields are raw network bytes that
 * routinely contain control characters, so the emitted JSON was invalid and
 * broke downstream parsers. The fix escapes ALL U+0000..U+001F.
 *
 * The escaper below is byte-identical to the shipping (fixed) code (static,
 * can't be linked -- same pattern as the other fuzz harnesses). The oracle
 * (a minimal JSON-string validator) is an independent implementation.
 *
 * Build: g++ -O2 -g -std=gnu++17 -Wall fuzz/test_json_escape.cc \
 *        -o fuzz/test_json_escape.exe && fuzz/test_json_escape.exe
 */
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

/* ---- byte-identical to the shipping fixed escaper ---- */
static std::string json_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b";  break;
      case '\f': out += "\\f";  break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

static bool is_hex(unsigned char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* INDEPENDENT oracle: validate that `esc` is the body of a well-formed JSON
 * string (RFC 8259): no raw control char < 0x20, no bare '"', and every '\'
 * begins a valid escape (one of " \ / b f n r t, or u + 4 hex digits). */
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

static uint64_t rng = 0xA5A5F00DCAFEBABEULL;
static uint32_t rnd() { rng ^= rng<<13; rng ^= rng>>7; rng ^= rng<<17; return (uint32_t)(rng>>32); }

int main(int argc, char **argv) {
  if (argc > 1) rng = (uint64_t)atoll(argv[1]) * 2654435761ULL + 1;
  int passed = 0, failed = 0;

  /* ---- every single byte 0x00..0xFF escapes to a valid JSON string body ---- */
  for (int b = 0; b < 256; b++) {
    std::string in(1, (char)(unsigned char)b);
    std::string esc = json_escape(in);
    if (valid_json_string_body(esc)) passed++;
    else { failed++; printf("  FAIL byte 0x%02X -> '%s'\n", b, esc.c_str()); }
    /* no raw control byte may survive */
    bool raw_ctrl = false;
    for (unsigned char c : esc) if (c < 0x20) raw_ctrl = true;
    if (b < 0x20 && raw_ctrl) { failed++; printf("  FAIL byte 0x%02X left raw control in output\n", b); }
    else passed++;
  }

  /* ---- specific mappings (independent hand-verified expectations) ---- */
  struct M { unsigned char b; const char *exp; };
  M maps[] = {
    {'"',  "\\\""}, {'\\', "\\\\"}, {'\b', "\\b"}, {'\f', "\\f"},
    {'\n', "\\n"},  {'\r', "\\r"},  {'\t', "\\t"},
    {0x00, "\\u0000"}, {0x01, "\\u0001"}, {0x0B, "\\u000b"},
    {0x1B, "\\u001b"}, {0x1F, "\\u001f"}, {0x7F, "\x7f"}, {0xFF, "\xff"},
    {'A',  "A"},
  };
  for (auto &m : maps) {
    std::string esc = json_escape(std::string(1, (char)m.b));
    if (esc == m.exp) passed++;
    else { failed++; printf("  FAIL map 0x%02X -> '%s' (exp '%s')\n", m.b, esc.c_str(), m.exp); }
  }

  /* high bytes 0x80..0xFF must pass through unescaped (UTF-8 continuation) */
  for (int b = 0x80; b <= 0xFF; b++) {
    std::string esc = json_escape(std::string(1, (char)(unsigned char)b));
    if (esc.size() == 1 && (unsigned char)esc[0] == (unsigned char)b) passed++;
    else { failed++; printf("  FAIL high byte 0x%02X was altered -> len=%zu\n", b, esc.size()); }
  }

  /* ---- fuzz random byte strings: output always a valid JSON string body ---- */
  const int N = 3000000;
  for (int n = 0; n < N; n++) {
    int len = rnd() % 64;
    std::string in;
    in.reserve(len);
    for (int i = 0; i < len; i++) in += (char)(unsigned char)(rnd() & 0xFF);
    std::string esc = json_escape(in);
    if (valid_json_string_body(esc)) passed++;
    else { failed++; if (failed <= 6) printf("  FAIL fuzz n=%d len=%d\n", n, len); }
  }

  printf("\njson-escape test: %d passed, %d failed (%d random strings)\n",
         passed, failed, N);
  return failed == 0 ? 0 : 1;
}
