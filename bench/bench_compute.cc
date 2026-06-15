/*
 * bench_compute.cc -- CPU throughput of the per-host enrichment primitives and
 * the discovery IP-generation rate.  Links the REAL helpers.
 *
 * These are the CPU ceilings; real enrichment/discovery is network-bound and
 * far below these, which is the point: CPU is never the bottleneck.
 *
 * Build (cloud_map uses ifstream -> static libstdc++ on the dev box):
 *   g++ -O2 -std=gnu++17 -static-libstdc++ -static-libgcc -I. \
 *       bench/bench_compute.cc net_hash_helpers.cc cloud_map.cc -o bench/bench_compute.exe
 *   bench/bench_compute.exe
 */

#include <cstdio>
#include <cstdint>
#include <string>
#include <chrono>

#include "net_hash_helpers.h"
#include "sha256.h"
#include "cloud_map.h"

using clk = std::chrono::steady_clock;
static double since(clk::time_point t){ return std::chrono::duration<double>(clk::now()-t).count(); }

/* ---- copy of fast_syn's permutation + a representative exclude check, so the
   generation rate can be measured without linking the pcap-dependent TU. ---- */
static const uint32_t PERMUTE_PRIME = 3948573427u;
static inline uint32_t permute_ip(uint32_t index, uint32_t seed) {
  return (uint32_t)(((uint64_t)index * PERMUTE_PRIME) + seed);
}
struct ER { uint32_t net, mask; };
static const ER EXCLUDES[] = {  /* the ~30 builtin reserved/DoD ranges */
  {0x00000000,0xFF000000},{0x0A000000,0xFF000000},{0x64400000,0xFFC00000},
  {0x7F000000,0xFF000000},{0xA9FE0000,0xFFFF0000},{0xAC100000,0xFFF00000},
  {0xC0000000,0xFFFFFF00},{0xC0000200,0xFFFFFF00},{0xC0586300,0xFFFFFF00},
  {0xC0A80000,0xFFFF0000},{0xC6120000,0xFFFE0000},{0xC6336400,0xFFFFFF00},
  {0xCB007100,0xFFFFFF00},{0xE0000000,0xF0000000},{0xF0000000,0xF0000000},
  {0x06000000,0xFF000000},{0x07000000,0xFF000000},{0x0B000000,0xFF000000},
  {0x15000000,0xFF000000},{0x16000000,0xFF000000},{0x1A000000,0xFF000000},
  {0x1C000000,0xFF000000},{0x1D000000,0xFF000000},{0x1E000000,0xFF000000},
  {0x21000000,0xFF000000},{0x37000000,0xFF000000},{0xD6000000,0xFF000000},
  {0xD7000000,0xFF000000},
};
static inline bool excluded(uint32_t ip){
  for (const ER &e : EXCLUDES) if ((ip & e.mask) == e.net) return true;
  return false;
}

template<class F>
static double mbps(const char *label, size_t bytes_per_op, long ops, F f) {
  auto t = clk::now();
  volatile uint64_t sink = 0;
  for (long i = 0; i < ops; i++) sink ^= f(i);
  double s = since(t);
  double mb = (double)bytes_per_op * ops / 1048576.0;
  printf("  %-22s %8.1f MB/s   %10.0f ops/s\n", label, mb / s, ops / s);
  return s;
}

int main(void) {
  printf("=== enrichment CPU primitives (single-thread) ===\n");

  /* SHA-256 over a 16 KB body (a typical small HTTP root). */
  std::string body(16384, 'x');
  mbps("sha256 (16KB body)", body.size(), 200000,
       [&](long){ return (uint64_t)sha256_hex(body)[0]; });

  /* favicon hash = base64.encodebytes + mmh3 over a 4 KB favicon. */
  std::string fav(4096, '\1');
  mbps("favicon_mmh3 (4KB)", fav.size(), 300000,
       [&](long){ return (uint64_t)favicon_mmh3(fav).size(); });

  /* mmh3 alone over 4 KB. */
  mbps("mmh3_x86_32 (4KB)", fav.size(), 1000000,
       [&](long){ return (uint64_t)mmh3_x86_32(fav, 0); });

  /* CPE derivation (string map + version parse). */
  mbps("derive_cpe", 0, 5000000,
       [&](long){ return (uint64_t)derive_cpe("nginx", "nginx/1.18.0").size(); });

  /* Cloud longest-prefix lookup against the bundled seed. */
  size_t nr = cloud_ranges_load("kmap-cloud-ranges.csv");
  printf("  (cloud table: %zu ranges loaded)\n", nr);
  mbps("lookup_cloud", 0, 10000000,
       [&](long i){ return (uint64_t)lookup_cloud(0x68140000u + (uint32_t)i).provider.size(); });

  printf("\n=== discovery IP generation (single-thread, pre-network) ===\n");
  {
    long ops = 50000000;
    auto t = clk::now();
    volatile uint64_t live = 0;
    for (long i = 0; i < ops; i++) {
      uint32_t ip = permute_ip((uint32_t)i, 0xC0FFEEu);
      if (!excluded(ip)) live++;
    }
    double s = since(t);
    printf("  %-22s %10.0f IPs/s  (permute + exclude check; the rate the\n",
           "permute+exclude", ops / s);
    printf("  %-22s             send loop draws from -- orders above the\n", "");
    printf("  %-22s             25k pps network ceiling, so never the bottleneck)\n", "");
  }
  return 0;
}
