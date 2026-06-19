/*
 * test_host_tags.cc -- known-answer test for derive_host_tags (host_tags.cc).
 *
 * Tags are an operator-facing faceting layer, so a wrong tag is a silent
 * mis-classification of someone's attack surface.  This pins every tag against
 * the field that produces it, the EOL version comparison (the one place with
 * real version math), and the determinism/dedup guarantees.
 *
 * Build (helper-linked, like test_mmh3 / test_hassh):
 *   g++ -O1 -g -std=gnu++17 -fsanitize=address,undefined \
 *       -fno-sanitize-recover=all fuzz/test_host_tags.cc host_tags.cc -o t && ./t
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>

#include "../host_tags.h"

static int g_fail = 0;

static bool has(const std::vector<std::string> &v, const std::string &s) {
  return std::find(v.begin(), v.end(), s) != v.end();
}

static void expect(bool cond, const char *label) {
  if (!cond) { printf("  FAIL %s\n", label); g_fail++; }
}

/* xorshift32 for the fuzz loop. */
static uint32_t g_rng = 1;
static uint32_t xr() { g_rng^=g_rng<<13; g_rng^=g_rng>>17; g_rng^=g_rng<<5; return g_rng; }

int main(int argc, char **argv) {
  if (argc > 1) g_rng = (uint32_t)strtoul(argv[1], nullptr, 0);
  if (!g_rng) g_rng = 1;

  printf("host_tags known-answer test\n===========================\n");

  /* self-signed only fires on the explicit tri-state 1. */
  { HostTagInput in; in.tls_self_signed = 1;
    expect(has(derive_host_tags(in), "self-signed"), "self-signed when tls=1"); }
  { HostTagInput in; in.tls_self_signed = 0;
    expect(!has(derive_host_tags(in), "self-signed"), "no self-signed when tls=0"); }
  { HostTagInput in; in.tls_self_signed = -1;
    expect(!has(derive_host_tags(in), "self-signed"), "no self-signed when unknown"); }

  /* cloud from any non-empty provider. */
  { HostTagInput in; in.cloud_provider = "aws";
    expect(has(derive_host_tags(in), "cloud"), "cloud when provider set"); }
  { HostTagInput in;
    expect(!has(derive_host_tags(in), "cloud"), "no cloud when provider empty"); }

  /* database from the service name. */
  { HostTagInput in; in.service = "mysql";
    expect(has(derive_host_tags(in), "database"), "database for mysql"); }
  { HostTagInput in; in.service = "MongoDB";  /* case-insensitive */
    expect(has(derive_host_tags(in), "database"), "database for MongoDB"); }
  { HostTagInput in; in.service = "http";
    expect(!has(derive_host_tags(in), "database"), "http is not a database"); }

  /* vuln / kev / ransomware from the cves JSON, exactly as cves_to_json emits. */
  { HostTagInput in; in.cves_json = "[]";
    expect(!has(derive_host_tags(in), "vuln"), "empty cve array -> no vuln"); }
  { HostTagInput in; in.cves_json = "[{\"id\":\"CVE-1\",\"cvss\":9.1}]";
    auto t = derive_host_tags(in);
    expect(has(t, "vuln"), "vuln when a CVE is present");
    expect(!has(t, "kev"), "no kev without the flag"); }
  { HostTagInput in;
    in.cves_json = "[{\"id\":\"CVE-2021-41773\",\"cvss\":9.8,\"epss\":0.9999,"
                   "\"kev\":1,\"ransomware\":1}]";
    auto t = derive_host_tags(in);
    expect(has(t, "vuln") && has(t, "kev") && has(t, "ransomware"),
           "vuln+kev+ransomware from a KEV+ransomware CVE"); }
  { HostTagInput in; in.cves_json = "[{\"id\":\"CVE-1\",\"kev\":0}]";
    expect(!has(derive_host_tags(in), "kev"), "kev:0 is not KEV"); }

  /* eol-product: CPE product/version vs the curated cutoffs. */
  auto eol = [](const char *cpe){ HostTagInput in; in.cpe = cpe;
                                  return has(derive_host_tags(in), "eol-product"); };
  expect( eol("cpe:2.3:a:apache:http_server:2.2.34:*:*:*:*:*:*:*"), "Apache 2.2 EOL");
  expect(!eol("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"), "Apache 2.4 not EOL");
  expect( eol("cpe:2.3:a:oracle:mysql:5.7.38:*:*:*:*:*:*:*"), "MySQL 5.7 EOL");
  expect(!eol("cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*"), "MySQL 8.0 not EOL");
  expect( eol("cpe:2.3:a:php_group:php:7.4.3:*:*:*:*:*:*:*"), "PHP 7.4 EOL");
  expect(!eol("cpe:2.3:a:php_group:php:8.3.0:*:*:*:*:*:*:*"), "PHP 8.3 not EOL");
  expect(!eol("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"), "nginx has no EOL rule");
  expect(!eol("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"), "version ANY -> no EOL");
  expect(!eol(""), "empty cpe -> no EOL");
  expect(!eol("not-a-cpe"), "garbage cpe -> no EOL");

  /* Determinism: sorted + de-duplicated, and stable across calls. */
  { HostTagInput in; in.service = "mysql"; in.cloud_provider = "gcp";
    in.tls_self_signed = 1;
    in.cves_json = "[{\"id\":\"CVE-1\",\"kev\":1}]";
    auto t1 = derive_host_tags(in);
    auto t2 = derive_host_tags(in);
    expect(t1 == t2, "deterministic across calls");
    expect(std::is_sorted(t1.begin(), t1.end()), "tags sorted");
    expect(std::unique(t1.begin(), t1.end()) == t1.end(), "tags de-duplicated");
    /* expected exact set */
    std::vector<std::string> want = {"cloud","database","kev","self-signed","vuln"};
    std::sort(want.begin(), want.end());
    expect(t1 == want, "exact multi-signal tag set"); }

  int kat_fail = g_fail;
  printf("known-answer: %s\n", kat_fail ? "FAIL" : "OK");

  /* Fuzz: random field values must never fault (ASan/UBSan) -- the EOL CPE
     parser and version math are the interesting targets. */
  const int ITERS = 200000;
  static const char *svcs[] = {"http","mysql","ssh","mongodb","",
                               "elasticsearch","ms-sql-s"};
  for (int i = 0; i < ITERS; i++) {
    HostTagInput in;
    in.service = svcs[xr() % 7];
    in.port = (int)(xr() % 70000) - 2000;
    in.tls_self_signed = (int)(xr() % 5) - 2;
    if (xr() & 1) in.cloud_provider = "aws";
    /* random-ish cpe + cves blobs */
    std::string cpe = "cpe:2.3:a:x:";
    int plen = xr() % 12;
    for (int k = 0; k < plen; k++) cpe += (char)(0x20 + (xr() % 0x5f));
    in.cpe = cpe;
    std::string c = "[{\"id\":\"CVE\",";
    int clen = xr() % 24;
    for (int k = 0; k < clen; k++) c += (char)(0x20 + (xr() % 0x5f));
    c += "}]";
    in.cves_json = c;
    volatile size_t n = derive_host_tags(in).size();
    (void)n;
  }
  printf("fuzz (%d iters): no fault\n", ITERS);

  printf("\n%s\n", g_fail == 0 ? "host_tags test: ALL PASS"
                               : "host_tags test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
