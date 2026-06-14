/*
 * fuzz_jsonescape.cc -- OSS-Fuzz / ClusterFuzzLite libFuzzer target for the
 * JSON string escaper used to serialize scan data (net_enrich.cc json_escape,
 * etc.). Feeds raw bytes -- exactly what untrusted banners/headers/TLS fields
 * contain -- and asserts the output is a well-formed JSON string body (no raw
 * control char survives), the RFC 8259 property the escaper must guarantee.
 *
 * json_escape() is copied VERBATIM from the shipping (fixed) code.
 */
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <string>

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string in(reinterpret_cast<const char *>(data), size);
  std::string esc = json_escape(in);
  /* RFC 8259: a JSON string body may contain no raw control char < 0x20 and
     no unescaped quote; every backslash must begin a valid escape. A miss
     here means the escaper would emit invalid JSON -- trap so the fuzzer
     flags it. */
  for (size_t i = 0; i < esc.size(); i++) {
    unsigned char c = (unsigned char)esc[i];
    if (c < 0x20) __builtin_trap();          /* raw control char leaked */
    if (c == '"') __builtin_trap();          /* unescaped quote */
    if (c == '\\') {
      if (i + 1 >= esc.size()) __builtin_trap();
      char n = esc[i + 1];
      if (n == '"' || n == '\\' || n == '/' || n == 'b' || n == 'f' ||
          n == 'n' || n == 'r' || n == 't') { i++; continue; }
      if (n == 'u') {
        if (i + 5 >= esc.size()) __builtin_trap();
        i += 5; continue;
      }
      __builtin_trap();                       /* invalid escape */
    }
  }
  return 0;
}
