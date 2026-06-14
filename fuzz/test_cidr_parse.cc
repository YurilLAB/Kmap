/*
 * test_cidr_parse.cc -- live correctness test for exclude-list CIDR parsing
 * (fast_syn.cc parse_cidr / cidr_mask / is_excluded + net_db.cc ip_to_u32).
 *
 * Regression test for the silent "malformed prefix excludes everything" bug:
 * parse_cidr used atoi() for the prefix, so "1.2.3.4/abc" or "1.2.3.4/"
 * silently became prefix 0 -> cidr_mask(0)=0 -> a {net=0, mask=0} range that
 * matches EVERY IP in is_excluded(). One typo in an exclude file would
 * silently exclude the whole internet and the scan would find nothing.
 *
 * The parsing functions below are kept byte-identical to the shipping code
 * (they are static in fast_syn.cc and cannot be linked here, same pattern as
 * test_discover_bail.cc). The expected outcomes are hand-verified / derived
 * by an INDEPENDENT formulation, so this is a genuine oracle, not a
 * self-comparison.
 *
 * Build (MinGW):
 *   g++ -O2 -g -std=gnu++17 -Wall fuzz/test_cidr_parse.cc \
 *       -o fuzz/test_cidr_parse.exe && fuzz/test_cidr_parse.exe
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

/* ---- copies of the shipping functions (keep in sync with the source) ---- */

static uint32_t cidr_mask(int prefix_len) {
  if (prefix_len <= 0) return 0;
  if (prefix_len >= 32) return 0xFFFFFFFF;
  return ~((1u << (32 - prefix_len)) - 1);
}

static uint32_t ip_to_u32(const char *ip_str) {       /* from net_db.cc */
  unsigned int a, b, c, d;
  if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
  if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
  return (a << 24) | (b << 16) | (c << 8) | d;
}

/* FIXED parse_cidr (strict numeric prefix). */
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

struct ExcludeRange { uint32_t network, mask; };
static bool is_excluded(uint32_t ip, const std::vector<ExcludeRange> &ex) {
  for (auto &er : ex) if ((ip & er.mask) == er.network) return true;
  return false;
}

/* ---- independent oracle for whether a token is a valid prefix 0..32 ---- */
static bool valid_prefix_token(const std::string &t) {
  if (t.empty()) return false;
  for (char c : t) if (c < '0' || c > '9') return false;   /* digits only */
  errno = 0;
  long v = strtol(t.c_str(), nullptr, 10);
  return v >= 0 && v <= 32;
}

static uint64_t rng = 0xDEADBEEFCAFEBABEULL;
static uint32_t rnd() {
  rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
  return (uint32_t)(rng >> 32);
}

int main(int argc, char **argv) {
  if (argc > 1) rng = (uint64_t)atoll(argv[1]) * 2654435761ULL + 1;
  int passed = 0, failed = 0;

  /* ---- hand-verified cases ---- */
  struct C { const char *in; bool ok; uint32_t net; uint32_t mask; };
  std::vector<C> cases = {
    {"10.0.0.0/8",   true,  0x0A000000, 0xFF000000},
    {"172.16.0.0/12",true,  0xAC100000, 0xFFF00000},
    {"1.2.3.4",      true,  0x01020304, 0xFFFFFFFF},   /* bare -> /32 */
    {"0.0.0.0/0",    true,  0x00000000, 0x00000000},   /* explicit match-all: valid */
    {"1.2.3.4/abc",  false, 0, 0},                     /* THE BUG: now rejected */
    {"1.2.3.4/",     false, 0, 0},                     /* empty prefix */
    {"1.2.3.4/12x",  false, 0, 0},                     /* trailing junk */
    {"1.2.3.4/-1",   false, 0, 0},                     /* negative */
    {"1.2.3.4/33",   false, 0, 0},                     /* out of range */
    {"1.2.3.4/999",  false, 0, 0},                     /* out of range */
    {"abc/8",        false, 0, 0},                     /* bad ip */
    {"999.1.1.1/8",  false, 0, 0},                     /* octet > 255 */
    {"192.168.1.0/24", true, 0xC0A80100, 0xFFFFFF00},
  };
  for (auto &c : cases) {
    uint32_t net = 0xAAAA5555, mask = 0xAAAA5555;
    bool ok = parse_cidr(c.in, net, mask);
    bool good = (ok == c.ok) && (!ok || (net == c.net && mask == c.mask));
    if (good) passed++;
    else { failed++; printf("  FAIL [%s]: ok=%d(exp %d) net=%08X(exp %08X) mask=%08X(exp %08X)\n",
                            c.in, ok, c.ok, net, c.net, mask, c.mask); }
  }

  /* ---- END-TO-END: a list built only from MALFORMED lines must not
   *      exclude anything (the bug would have excluded all IPs). ---- */
  {
    const char *bad_lines[] = {"1.2.3.4/abc","10.0.0.0/","x.y.z/8","5.5.5.5/77", nullptr};
    std::vector<ExcludeRange> ex;
    for (const char **l = bad_lines; *l; ++l) {
      ExcludeRange er; if (parse_cidr(*l, er.network, er.mask)) ex.push_back(er);
    }
    bool any = false;
    for (int i = 0; i < 64; i++) if (is_excluded(rnd(), ex)) any = true;
    if (!any && ex.empty()) passed++;
    else { failed++; printf("  FAIL [end2end]: malformed-only list excluded traffic (size=%zu)\n", ex.size()); }
  }
  /* explicit /0 SHOULD still match everything (operator's choice) */
  {
    std::vector<ExcludeRange> ex; ExcludeRange er;
    parse_cidr("0.0.0.0/0", er.network, er.mask); ex.push_back(er);
    if (is_excluded(rnd(), ex) && is_excluded(0x08080808, ex)) passed++;
    else { failed++; printf("  FAIL [explicit-/0 should match all]\n"); }
  }

  /* ---- randomized fuzz: parse_cidr accept/reject vs independent oracle ---- */
  const int N = 2000000;
  for (int n = 0; n < N; n++) {
    /* random octets (often valid, sometimes >255) and a random prefix token */
    char buf[80];
    unsigned o0 = rnd()%300, o1 = rnd()%300, o2 = rnd()%300, o3 = rnd()%300;
    int mode = rnd()%5;
    std::string ptok;
    if (mode == 0) ptok = std::to_string(rnd()%40);          /* numeric, maybe >32 */
    else if (mode == 1) { ptok.clear(); }                    /* empty */
    else if (mode == 2) ptok = std::string(1, 'a'+(rnd()%26))+std::to_string(rnd()%99); /* alpha junk */
    else if (mode == 3) ptok = std::to_string(rnd()%32)+"x"; /* trailing junk */
    else ptok = std::to_string(rnd()%33);                    /* in-range numeric */

    snprintf(buf, sizeof(buf), "%u.%u.%u.%u/%s", o0,o1,o2,o3, ptok.c_str());

    uint32_t net=0, mask=0;
    bool ok = parse_cidr(buf, net, mask);

    /* Independent oracle. ip_to_u32 accepts iff all octets <= 255; the
       parse guard then rejects net==0 unless the text is exactly "0.0.0.0".
       So an IP is accepted iff octets are in range AND (it is non-zero OR it
       is literally 0.0.0.0 -- which it always is when all octets are 0). */
    bool octets_in_range = (o0<=255 && o1<=255 && o2<=255 && o3<=255);
    bool pfx_ok = valid_prefix_token(ptok);
    bool ip_accepted = octets_in_range;   /* zero-ip case is "0.0.0.0", allowed */
    bool expect = ip_accepted && pfx_ok;

    if (ok == expect) passed++;
    else { failed++; if (failed<=8) printf("  FAIL [rand '%s']: ok=%d expect=%d\n", buf, ok, expect); }

    /* hard invariant: a successful parse with mask==0 (matches every IP)
       must come from a genuine numeric /0 prefix -- never from a malformed
       token silently collapsing to 0 (the bug this test guards). */
    if (ok && mask == 0) {
      long pv = strtol(ptok.c_str(), nullptr, 10);
      if (!(pfx_ok && pv == 0)) {
        failed++;
        if (failed<=8) printf("  FAIL [match-all leak '%s']: accepted with mask=0\n", buf);
      }
    }
  }

  printf("\ncidr-parse test: %d passed, %d failed (%d random inputs)\n",
         passed, failed, N);
  return failed == 0 ? 0 : 1;
}
