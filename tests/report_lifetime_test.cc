// Production-linked presentation ownership regression. No feature engine or
// network code runs: all attached records below are artificial display values.
// Link with Kmap's OBJS/LIBS (OBJS excludes main.o), not the scanner entry point.
#ifdef WIN32
#include "kmap_winconfig.h"
#endif
#include "kmap.h"
#include "Target.h"
#include "output_json.h"
#include "default_creds.h"
#include "web_recon.h"
#include "cve_map.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
static int destroyed_attributes = 0;

static void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

struct Files {
  fs::path directory;
  std::vector<fs::path> files;
  bool preserve = true;
  Files() {
    std::random_device random;
    for (int i = 0; i < 20; ++i) {
      const auto candidate = fs::temp_directory_path() /
          ("kmap-report-lifetime-" + std::to_string(random()));
      if (fs::create_directory(candidate)) {
        directory = candidate;
        return;
      }
    }
    throw std::runtime_error("cannot create isolated report fixture");
  }
  fs::path file(const char *name) {
    files.push_back(directory / name);
    return files.back();
  }
  ~Files() {
    if (preserve) {
      std::cerr << "retained report fixture: " << directory.string() << '\n';
      return;
    }
    std::error_code error;
    // Delete only the known test files and the now-empty test-owned directory.
    for (const auto &path : files) fs::remove(path, error);
    fs::remove(directory, error);
  }
};

static std::string read(const fs::path &path) {
  std::ifstream input(path, std::ios::binary);
  require(input.is_open(), "report was not saved");
  return std::string(std::istreambuf_iterator<char>(input), {});
}

static void address(Target &target, uint32_t ip, int flags) {
  sockaddr_storage storage{};
  auto *ipv4 = reinterpret_cast<sockaddr_in *>(&storage);
  ipv4->sin_family = AF_INET;
  ipv4->sin_addr.s_addr = htonl(ip);
  target.setTargetSockAddr(&storage, sizeof(sockaddr_in));
  target.flags = flags;
}

static void snapshot(const fs::path &output) {
  report_initialize(output.string().c_str());
  const int before = destroyed_attributes;
  {
    Target target;
    address(target, 0x7f000001, HOST_UP);

    auto *creds = new TargetCredData();
    PortCredResults port_creds{};
    port_creds.portno = 12345;
    port_creds.proto = IPPROTO_TCP;
    CredResult inert{};
    inert.service = "fixture-service";
    inert.portno = 12345;
    inert.username = "snapshot-fixture-user";
    inert.password = "snapshot-fixture-value";
    inert.found = true;
    port_creds.hits.push_back(inert);
    creds->results.push_back(port_creds);
    target.attribute.set("kmap_default_creds", creds, [](void *p) {
      delete static_cast<TargetCredData *>(p);
      ++destroyed_attributes;
    });

    auto *web = new TargetWebData();
    WebReconResult observed{};
    observed.portno = 12345;
    observed.title = "snapshot-web-marker";
    observed.server = "owned-inert-fixture";
    web->results.push_back(observed);
    target.attribute.set("kmap_web_recon", web, [](void *p) {
      delete static_cast<TargetWebData *>(p);
      ++destroyed_attributes;
    });

    auto *cves = new TargetCveData();
    PortCveResults port{};
    port.portno = 12345;
    port.proto = "tcp";
    port.service = "fixture";
    CveEntry entry{};
    entry.cve_id = "CVE-2000-0001";
    entry.description = "Artificial presentation record; no vulnerability check";
    entry.cvss_score = 1.0f;
    entry.severity = "LOW";
    port.cves.push_back(entry);
    cves->port_results.push_back(port);
    target.attribute.set("kmap_cve_map", cves, [](void *p) {
      delete static_cast<TargetCveData *>(p);
      ++destroyed_attributes;
    });

    report_write_host(&target);
    // A report snapshot must remain independent even before destruction.
    creds->results[0].hits[0].username = "MUTATED-AFTER-SNAPSHOT";
    web->results[0].title = "MUTATED-AFTER-SNAPSHOT";
    cves->port_results[0].cves[0].cve_id = "MUTATED-AFTER-SNAPSHOT";

    Target no_attributes;
    address(no_attributes, 0x7f000002, HOST_DOWN);
    report_write_host(&no_attributes);
    report_write_host(nullptr);
  }
  require(destroyed_attributes - before == 3,
          "Target attributes must be released before report finalization");
  report_write_stats(1, 1, 2, 0.01f);
  require(report_finalize(), "report finalization failed");
  const std::string result = read(output);
  for (const char *marker : {"127.0.0.1", "127.0.0.2", "snapshot-fixture-user",
                             "snapshot-fixture-value", "snapshot-web-marker", "CVE-2000-0001"})
    require(result.find(marker) != std::string::npos, "report lost a retained presentation value");
  require(result.find("MUTATED-AFTER-SNAPSHOT") == std::string::npos,
          "report borrowed mutable Target attribute data");
  require(report_finalize(), "repeated empty finalization must be harmless");
  require(read(output) == result, "repeated finalization changed a saved report");
}

int main() {
  try {
    Files files;
    // Port maps intentionally remain empty. No port/network operation is used.
    snapshot(files.file("report.txt"));
    snapshot(files.file("report.MD"));
    require(destroyed_attributes == 6, "unexpected attribute lifetime count");

    const auto empty = files.file("empty.md");
    report_initialize(empty.string().c_str());
    report_write_stats(0, 0, 0, 0);
    require(report_finalize(), "empty report failed");
    require(read(empty).find("127.0.0.") == std::string::npos,
            "reinitialization retained earlier hosts");

    report_initialize(files.directory.string().c_str());
    require(!report_finalize(), "directory-as-file failure was hidden");
    require(report_finalize(), "failed finalization did not release state");
    const auto recovered = files.file("recovered.txt");
    report_initialize(recovered.string().c_str());
    report_write_stats(0, 0, 0, 0);
    require(report_finalize(), "report did not recover after output failure");
    require(read(recovered).find("127.0.0.") == std::string::npos,
            "failed output left stale host records");
    files.preserve = false;
    std::cout << "report ownership: two formats, six released attributes, reset/error recovery passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "report ownership: " << error.what() << '\n';
    return 1;
  }
}
