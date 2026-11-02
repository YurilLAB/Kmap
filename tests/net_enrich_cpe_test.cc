#include "../net_enrich.h"

#include <cstdio>
#include <string>

static int failures = 0;
static void expect(bool condition, const char *description) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", description);
    ++failures;
  }
}

static bool names(const std::string &cpe, const char *product) {
  return cpe.find(std::string(":") + product + ":") != std::string::npos;
}

/* Server headers map to the product the CVE matcher and CPE use. */
int main() {
  expect(names(net_enrich_cpe_for("http", "Apache Tomcat/9.0.83"), "tomcat"),
         "Apache Tomcat is Tomcat, not httpd");
  expect(net_enrich_cpe_for("http", "Apache-Coyote/1.1").empty(),
         "Coyote's connector version is not a Tomcat or httpd version");
  expect(names(net_enrich_cpe_for("http", "Apache/2.4.41 (Ubuntu)"), "http_server"),
         "Apache httpd still maps to http_server");
  if (failures) return 1;
  std::printf("net_enrich_cpe_test: product mapping PASS\n");
  return 0;
}
