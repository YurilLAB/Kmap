/*
 * test_cloud_match.cc -- pins cloud_map.cc: the offline cloud-range matcher
 * and the strict line parser.  Links the REAL cloud_map.cc.
 *
 * Build:
 *   g++ -O2 -g -std=gnu++17 -Wall -I.. fuzz/test_cloud_match.cc cloud_map.cc \
 *       -o fuzz/test_cloud_match.exe && fuzz/test_cloud_match.exe
 */

#include <cstdio>
#include <cstdint>
#include <string>
#include <fstream>

#include "../cloud_map.h"

static int g_fail = 0;

/* Local dotted-quad -> u32 (test convenience; cloud_map keeps its own). */
static uint32_t ip4(const char *s) {
  unsigned a, b, c, d;
  if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
  return (a << 24) | (b << 16) | (c << 8) | d;
}

static void want(const char *ip, const char *prov, const char *region,
                 const char *label) {
  CloudInfo ci = lookup_cloud(ip4(ip));
  if (ci.provider != prov || (region && ci.region != region)) {
    printf("  FAIL %-22s ip=%s\n    got    provider=[%s] region=[%s]\n"
           "    expect provider=[%s] region=[%s]\n",
           label, ip, ci.provider.c_str(), ci.region.c_str(),
           prov, region ? region : "");
    g_fail++;
  }
}

static void parse_ok(const char *line, const char *exp_prov, const char *label) {
  uint32_t net = 0, mask = 0; uint8_t pl = 0;
  std::string p, r, s;
  if (!cloud_parse_line(line, &net, &mask, &pl, &p, &r, &s) || p != exp_prov) {
    printf("  FAIL parse-ok %-14s line=[%s]\n", label, line);
    g_fail++;
  }
}

static void parse_bad(const char *line, const char *label) {
  uint32_t net = 0, mask = 0; uint8_t pl = 0;
  std::string p, r, s;
  if (cloud_parse_line(line, &net, &mask, &pl, &p, &r, &s)) {
    printf("  FAIL parse-bad %-14s accepted bad line=[%s]\n", label, line);
    g_fail++;
  }
}

int main(void) {
  /* ---- strict line parser ---- */
  parse_ok("1.2.3.0/24,aws,us-east-1,EC2", "aws", "full");
  parse_ok("1.2.3.0/24,gcp", "gcp", "no-region-service");
  parse_bad("1.2.3.0/abc,aws", "bad-prefix");      /* atoi-CIDR footgun guard */
  parse_bad("1.2.3.0/,aws",    "empty-prefix");
  parse_bad("1.2.3.0/33,aws",  "prefix-too-big");
  parse_bad("1.2.3.0/24",      "no-provider");
  parse_bad("1.2.3.0/24,",     "empty-provider");
  parse_bad("2001:db8::/32,aws", "ipv6");
  parse_bad("not-an-ip/24,aws", "bad-ip");

  /* host bits must be masked off: 1.2.3.4/24 -> network 1.2.3.0 */
  {
    uint32_t net = 0, mask = 0; uint8_t pl = 0;
    std::string p, r, s;
    cloud_parse_line("1.2.3.4/24,aws", &net, &mask, &pl, &p, &r, &s);
    if (net != ip4("1.2.3.0") || pl != 24) { printf("  FAIL host-bit mask\n"); g_fail++; }
  }

  /* ---- build a fixture and exercise the matcher ---- */
  const char *fix = "test_cloud_fixture.csv";
  {
    std::ofstream o(fix);
    o << "# cidr,provider,region,service\n"
         "3.5.140.0/22,aws,ap-northeast-2,S3\n"
         "13.104.0.0/14,azure,,AzureCloud\n"
         "34.80.0.0/15,gcp,asia-east1,\n"
         "104.16.0.0/13,cloudflare,,\n"
         "10.0.0.0/8,aws,outer,\n"
         "10.1.2.0/24,aws,inner,EC2\n"
         "2001:db8::/32,azure,,bad-ipv6-skipped\n"
         "garbage-line-no-cidr\n";
  }
  size_t n = cloud_ranges_load(fix);
  if (n != 6) { printf("  FAIL load count: got %zu expect 6 (v6 + garbage skipped)\n", n); g_fail++; }

  want("3.5.140.5",  "aws",        "ap-northeast-2", "aws-mid");
  want("13.105.0.1", "azure",      "",               "azure");
  want("34.80.5.5",  "gcp",        "asia-east1",     "gcp");
  want("104.20.0.1", "cloudflare", "",               "cloudflare");

  /* longest-prefix: nested /24 inside /8 wins; outside the /24 falls to /8 */
  want("10.1.2.5",   "aws", "inner", "nested-longest-prefix");
  want("10.9.9.9",   "aws", "outer", "nested-outer-fallback");

  /* no-false-positive: TEST-NET-3 is in no range */
  want("203.0.113.5", "", nullptr, "no-match");

  /* boundaries of 3.5.140.0/22 == 3.5.140.0 .. 3.5.143.255 */
  want("3.5.140.0",   "aws", "ap-northeast-2", "range-first");
  want("3.5.143.255", "aws", "ap-northeast-2", "range-last");
  want("3.5.144.0",   "",    nullptr,          "one-past-end");
  want("3.5.139.255", "",    nullptr,          "one-before-start");

  std::remove(fix);

  printf("\n%s\n", g_fail == 0 ? "cloud_match test: ALL PASS"
                               : "cloud_match test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
