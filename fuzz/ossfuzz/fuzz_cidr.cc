/*
 * fuzz_cidr.cc -- OSS-Fuzz / ClusterFuzzLite libFuzzer target for the
 * exclude-list CIDR parser (fast_syn.cc parse_cidr + cidr_mask, net_db.cc
 * ip_to_u32). Feeds the raw input bytes as a NUL-terminated CIDR/IP line --
 * the same untrusted text an operator's --exclude-file line provides.
 *
 * Functions copied VERBATIM from the shipping (fixed, strict-prefix) code.
 */
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

static uint32_t cidr_mask(int prefix_len) {
  if (prefix_len <= 0) return 0;
  if (prefix_len >= 32) return 0xFFFFFFFF;
  return ~((1u << (32 - prefix_len)) - 1);
}
static uint32_t ip_to_u32(const char *ip_str) {
  unsigned int a, b, c, d;
  if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
  if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
  return (a << 24) | (b << 16) | (c << 8) | d;
}
static bool parse_cidr(const char *line, uint32_t &net, uint32_t &mask) {
  char ip_buf[64];
  int prefix = 32;
  const char *slash = strchr(line, '/');
  if (slash) {
    size_t ip_len = (size_t)(slash - line);
    if (ip_len >= sizeof(ip_buf)) return false;
    memcpy(ip_buf, line, ip_len);
    ip_buf[ip_len] = '\0';
    const char *pp = slash + 1;
    if (*pp == '\0') return false;
    char *endp = nullptr;
    long pv = strtol(pp, &endp, 10);
    if (endp == pp || *endp != '\0') return false;
    if (pv < 0 || pv > 32) return false;
    prefix = (int)pv;
  } else {
    strncpy(ip_buf, line, sizeof(ip_buf) - 1);
    ip_buf[sizeof(ip_buf) - 1] = '\0';
  }
  net = ip_to_u32(ip_buf);
  if (net == 0 && strcmp(ip_buf, "0.0.0.0") != 0) return false;
  mask = cidr_mask(prefix);
  net &= mask;
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Treat the input as a NUL-terminated line (what parse_cidr expects). The
     value is exercising parse_cidr's byte handling under ASan; the accept/
     reject logic invariants are covered separately by fuzz/test_cidr_parse.cc. */
  std::vector<char> line(data, data + size);
  line.push_back('\0');
  uint32_t net = 0, mask = 0;
  volatile bool ok = parse_cidr(line.data(), net, mask);
  (void)ok; (void)net; (void)mask;
  return 0;
}
