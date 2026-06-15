/*
 * test_cpe.cc -- pins net_hash_helpers.cc::derive_cpe (CPE 2.3 identity).
 *
 * Guards: the product->vendor/product map, the p-suffix-preserving version
 * field, the no-dotted-version -> "*" fallback, unknown-product -> "", and
 * case-insensitive product key lookup.
 *
 * Build:
 *   g++ -O2 -g -std=gnu++17 -Wall fuzz/test_cpe.cc net_hash_helpers.cc \
 *       -o fuzz/test_cpe.exe && fuzz/test_cpe.exe
 */

#include <cstdio>
#include <string>

#include "../net_hash_helpers.h"

static int g_fail = 0;

static void check(const std::string &product, const std::string &version,
                  const std::string &expect, const char *label) {
  std::string got = derive_cpe(product, version);
  if (got != expect) {
    printf("  FAIL %-20s\n    got    [%s]\n    expect [%s]\n",
           label, got.c_str(), expect.c_str());
    g_fail++;
  }
}

int main(void) {
  check("openssh", "OpenSSH 8.2p1",
        "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*", "openssh-p-suffix");
  check("http_server", "Apache/2.4.49",
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "apache");
  check("nginx", "nginx/1.18.0",
        "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", "nginx");
  check("iis", "Microsoft-IIS/10.0",
        "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*",
        "iis-nvd-token");
  check("mysql", "5.7.34-log",
        "cpe:2.3:a:oracle:mysql:5.7.34:*:*:*:*:*:*:*", "mysql");
  check("vsftpd", "2.3.4",
        "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*", "vsftpd");
  check("php", "7.4.3",
        "cpe:2.3:a:php_group:php:7.4.3:*:*:*:*:*:*:*", "php");

  /* Case-insensitive product key. */
  check("OPENSSH", "OpenSSH_9.6p1",
        "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*", "openssh-upper-key");

  /* No dotted version -> ANY wildcard in the version field. */
  check("nginx", "nginx",
        "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "nginx-no-version");
  check("redis", "",
        "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", "redis-empty-version");

  /* Unknown product / empty product -> no CPE. */
  check("definitely_not_a_product", "1.2.3", "", "unknown-product");
  check("", "1.2.3", "", "empty-product");

  /* A bare integer is not a version (needs a dot). */
  check("tomcat", "Tomcat 9",
        "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", "tomcat-bare-int");

  printf("\n%s\n", g_fail == 0 ? "cpe test: ALL PASS" : "cpe test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
