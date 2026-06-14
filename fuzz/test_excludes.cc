/*
 * test_excludes.cc -- semantic tests for fast_syn.cc's exclusion handling:
 * parse_cidr strictness, is_excluded membership, the built-in reserved/DoD
 * list, and the --no-builtin-excludes (empty-list) behaviour.
 *
 * fuzz_core.cc already covers parse_cidr's memory safety (over-read on overlong
 * input). This pins the LOGIC instead:
 *   - a malformed prefix ("1.2.3.4/abc", "x/") is REJECTED, so a single typo in
 *     an exclude file can't collapse to a {net=0,mask=0} "match the whole
 *     internet" range and silently void the scan (the bug fixed in parse_cidr).
 *   - the built-in list actually excludes RFC1918 / loopback / CGNAT / TEST-NET
 *     / multicast / reserved / DoD addresses, and does NOT exclude public ones.
 *   - with the built-in list disabled (--no-builtin-excludes => empty vector),
 *     is_excluded() returns false for everything, including reserved/DoD space,
 *     so an authorized operator can actually reach those ranges.
 *
 * The parse_cidr / is_excluded / builtin_excludes logic is mirrored verbatim
 * from fast_syn.cc (static / heavy-dep TU, can't link). Keep this copy in sync.
 *
 * Build (Win):  g++ -O2 -std=gnu++17 test_excludes.cc -o test_excludes.exe
 * Build (CI):   g++ $CXXFLAGS fuzz/test_excludes.cc -o test_excludes
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static int g_fail = 0;
static void chk(bool c, const char *m) { if (!c) { printf("  FAIL: %s\n", m); g_fail++; } }

/* ---- verbatim mirrors of net_db.cc / fast_syn.cc ---- */
static uint32_t ip_to_u32(const char *ip_str) {
  unsigned int a, b, c, d;
  if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
  if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
  return (a << 24) | (b << 16) | (c << 8) | d;
}

static uint32_t cidr_mask(int prefix_len) {
  if (prefix_len <= 0) return 0;
  if (prefix_len >= 32) return 0xFFFFFFFF;
  return ~((1u << (32 - prefix_len)) - 1);
}

static bool parse_cidr(const char *line, uint32_t &net, uint32_t &mask) {
  char ip_buf[64];
  int prefix = 32;
  const char *slash = strchr(line, '/');
  if (slash) {
    size_t ip_len = static_cast<size_t>(slash - line);
    if (ip_len >= sizeof(ip_buf)) return false;
    memcpy(ip_buf, line, ip_len);
    ip_buf[ip_len] = '\0';
    const char *pp = slash + 1;
    if (*pp == '\0') return false;
    char *endp = nullptr;
    long pv = strtol(pp, &endp, 10);
    if (endp == pp || *endp != '\0') return false;
    if (pv < 0 || pv > 32) return false;
    prefix = static_cast<int>(pv);
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

struct ExcludeRange { uint32_t network; uint32_t mask; };

static std::vector<ExcludeRange> builtin_excludes() {
  std::vector<ExcludeRange> list;
  static const char *ranges[] = {
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "6.0.0.0/8", "7.0.0.0/8", "11.0.0.0/8", "21.0.0.0/8",
    "22.0.0.0/8", "26.0.0.0/8", "28.0.0.0/8", "29.0.0.0/8",
    "30.0.0.0/8", "33.0.0.0/8", "55.0.0.0/8", "214.0.0.0/8", "215.0.0.0/8",
    nullptr
  };
  for (const char **r = ranges; *r; ++r) {
    ExcludeRange er;
    if (parse_cidr(*r, er.network, er.mask)) list.push_back(er);
  }
  return list;
}

static bool is_excluded(uint32_t ip, const std::vector<ExcludeRange> &ex) {
  for (const auto &er : ex)
    if ((ip & er.mask) == er.network) return true;
  return false;
}

/* ---- tests ---- */
static bool pc_ok(const char *s) { uint32_t n, m; return parse_cidr(s, n, m); }

int main(void) {
  printf("exclude-logic test\n==================\n");

  /* 1. parse_cidr strictness -- the typo-safety guard. */
  chk(!pc_ok("1.2.3.4/abc"), "reject non-numeric prefix /abc");
  chk(!pc_ok("1.2.3.4/"),    "reject empty prefix");
  chk(!pc_ok("1.2.3.4/33"),  "reject prefix > 32");
  chk(!pc_ok("1.2.3.4/-1"),  "reject negative prefix");
  chk(!pc_ok("1.2.3.4/24x"), "reject trailing junk after prefix");
  chk(!pc_ok("garbage"),     "reject non-IP");
  chk(!pc_ok("999.1.1.1"),   "reject octet > 255");
  { uint32_t n, m;
    chk(parse_cidr("1.2.3.4/0", n, m) && m == 0, "accept explicit /0 (mask 0)");
    chk(parse_cidr("1.2.3.4", n, m) && m == 0xFFFFFFFF, "bare IP is /32");
    chk(parse_cidr("10.0.0.0/8", n, m) && m == 0xFF000000 && n == 0x0A000000,
        "10.0.0.0/8 parses to net+mask");
    chk(parse_cidr("10.1.2.3/8", n, m) && n == 0x0A000000,
        "host bits masked off to network address");
    chk(parse_cidr("0.0.0.0", n, m), "accept 0.0.0.0 (special-cased)");
  }

  /* 2. built-in list excludes reserved/DoD, not public space. */
  auto bi = builtin_excludes();
  chk(bi.size() >= 28, "built-in list parsed (>= 28 ranges)");
  struct { const char *ip; bool excl; } cases[] = {
    {"10.0.0.5", true}, {"172.16.5.5", true}, {"192.168.1.1", true},
    {"127.0.0.1", true}, {"169.254.1.1", true}, {"100.64.0.1", true},
    {"192.0.2.5", true}, {"198.51.100.7", true}, {"203.0.113.9", true},
    {"198.18.0.1", true}, {"224.0.0.1", true}, {"240.0.0.1", true},
    {"0.1.2.3", true},
    {"6.0.0.1", true}, {"7.255.255.255", true}, {"11.1.1.1", true},
    {"214.0.0.1", true}, {"215.255.255.255", true}, {"55.1.2.3", true},
    /* public addresses must NOT be excluded */
    {"8.8.8.8", false}, {"1.1.1.1", false}, {"9.9.9.9", false},
    {"93.184.216.34", false}, {"140.82.121.4", false}, {"23.0.0.1", false},
  };
  for (auto &c : cases) {
    uint32_t ip = ip_to_u32(c.ip);
    bool got = is_excluded(ip, bi);
    char msg[96];
    snprintf(msg, sizeof(msg), "%s is %sexcluded by built-in list",
             c.ip, c.excl ? "" : "NOT ");
    chk(got == c.excl, msg);
  }

  /* 3. typo-safety: a bad exclude line is dropped (parse_cidr false), so the
     resulting list does not silently match the whole internet. */
  {
    std::vector<ExcludeRange> ex;
    uint32_t n, m;
    if (parse_cidr("1.2.3.4/abc", n, m)) ex.push_back({n, m}); /* must NOT add */
    chk(ex.empty(), "malformed exclude line is not added");
    chk(!is_excluded(ip_to_u32("8.8.8.8"), ex),
        "a typo'd exclude line does not exclude the whole internet");
  }

  /* 4. --no-builtin-excludes semantics: empty list excludes nothing, so an
     authorized operator can reach reserved/DoD ranges. */
  {
    std::vector<ExcludeRange> none;
    chk(!is_excluded(ip_to_u32("6.0.0.1"), none),
        "empty list: DoD range is reachable (--no-builtin-excludes)");
    chk(!is_excluded(ip_to_u32("10.0.0.5"), none),
        "empty list: private range is reachable");
    chk(!is_excluded(ip_to_u32("8.8.8.8"), none),
        "empty list: public range reachable");
  }

  printf("\n%s\n", g_fail == 0 ? "exclude-logic test: ALL PASS"
                               : "exclude-logic test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
