/* sys_resources.cc -- see sys_resources.h
 *
 * Cross-platform CPU / RAM detection and translation of the --efficient /
 * --fast performance modes into concrete worker-pool sizes and a memory
 * budget. The numbers scale with the detected hardware and, in fast mode,
 * stay within a tunable share of it instead of pegging the machine.
 */

#include "sys_resources.h"

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "KmapOps.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <thread>

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

extern KmapOps o;

/* ----------------------------------------------------------------------- */
/* Raw hardware detection                                                   */
/* ----------------------------------------------------------------------- */

int kmap_detect_cpu_count(void) {
  int n = 0;
#ifdef WIN32
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  n = static_cast<int>(si.dwNumberOfProcessors);
#elif defined(_SC_NPROCESSORS_ONLN)
  long sc = sysconf(_SC_NPROCESSORS_ONLN);
  if (sc > 0) n = static_cast<int>(sc);
#endif
  if (n <= 0) {
    unsigned hc = std::thread::hardware_concurrency();
    n = (hc > 0) ? static_cast<int>(hc) : 1;
  }
  if (n < 1) n = 1;
  return n;
}

uint64_t kmap_detect_total_ram(void) {
#ifdef WIN32
  MEMORYSTATUSEX ms;
  ms.dwLength = sizeof(ms);
  if (GlobalMemoryStatusEx(&ms))
    return static_cast<uint64_t>(ms.ullTotalPhys);
  return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__DragonFly__)
  /* HW_MEMSIZE (Apple) is 64-bit; HW_PHYSMEM (BSD) may be 32-bit. */
  uint64_t mem = 0;
  size_t len = sizeof(mem);
#if defined(HW_MEMSIZE)
  int mib[2] = { CTL_HW, HW_MEMSIZE };
  if (sysctl(mib, 2, &mem, &len, NULL, 0) == 0 && mem > 0) return mem;
#endif
#if defined(HW_PHYSMEM)
  {
    unsigned long pm = 0; len = sizeof(pm);
    int mib2[2] = { CTL_HW, HW_PHYSMEM };
    if (sysctl(mib2, 2, &pm, &len, NULL, 0) == 0 && pm > 0)
      return static_cast<uint64_t>(pm);
  }
#endif
  return 0;
#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGE_SIZE)
  long pages = sysconf(_SC_PHYS_PAGES);
  long psize = sysconf(_SC_PAGE_SIZE);
  if (pages > 0 && psize > 0)
    return static_cast<uint64_t>(pages) * static_cast<uint64_t>(psize);
  return 0;
#else
  return 0;
#endif
}

uint64_t kmap_detect_avail_ram(void) {
#ifdef WIN32
  MEMORYSTATUSEX ms;
  ms.dwLength = sizeof(ms);
  if (GlobalMemoryStatusEx(&ms))
    return static_cast<uint64_t>(ms.ullAvailPhys);
  return 0;
#else
  /* Linux exposes a far better "MemAvailable" (accounts for reclaimable
   * cache) than _SC_AVPHYS_PAGES, which only counts wholly-free pages. */
  FILE *f = fopen("/proc/meminfo", "r");
  if (f) {
    char line[256];
    uint64_t kb = 0;
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
      if (sscanf(line, "MemAvailable: %llu kB",
                 reinterpret_cast<unsigned long long *>(&kb)) == 1) {
        found = true;
        break;
      }
    }
    fclose(f);
    if (found && kb > 0) return kb * 1024ULL;
  }
#if defined(_SC_AVPHYS_PAGES) && defined(_SC_PAGE_SIZE)
  long pages = sysconf(_SC_AVPHYS_PAGES);
  long psize = sysconf(_SC_PAGE_SIZE);
  if (pages > 0 && psize > 0)
    return static_cast<uint64_t>(pages) * static_cast<uint64_t>(psize);
#endif
  /* Fall back to total physical RAM when "available" is undetectable. */
  return kmap_detect_total_ram();
#endif
}

/* ----------------------------------------------------------------------- */
/* Profile computation                                                      */
/* ----------------------------------------------------------------------- */

static int clampi(int v, int lo, int hi) {
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

/* Rough per-in-flight-host memory cost of the enrichment pipeline (banner
 * buffer + HTTP response cap + TLS + bookkeeping). Used only to keep the
 * worker pools from exceeding the memory budget on very large core counts;
 * deliberately conservative. */
static const uint64_t KMAP_MEM_PER_WORKER = 768ULL * 1024ULL; /* ~768 KB */

static KmapPerfProfile compute_profile(int mode, double cpu_pct,
                                       double mem_pct) {
  KmapPerfProfile p;
  std::memset(&p, 0, sizeof(p));
  p.mode            = mode;
  p.cpu_count       = kmap_detect_cpu_count();
  p.total_ram_bytes = kmap_detect_total_ram();
  p.avail_ram_bytes = kmap_detect_avail_ram();

  const int cores = p.cpu_count;

  if (mode == KMAP_PERF_EFFICIENT) {
    /* Low footprint: a small constant share of the cores, gentle pools.
     * Discovery is I/O-bound so it still benefits from more threads than
     * cores, but we keep the multiplier and the caps modest. */
    p.cpu_percent = 100.0 / 8.0;          /* ~1/8 of the machine */
    p.mem_percent = 5.0;
    int units = std::max(1, cores / 8);
    p.discovery_workers = clampi(units * 8,  8, 64);
    p.enrich_workers    = clampi(units * 4,  4, 24);
    /* Regular scans: keep host groups small, do not raise parallelism. */
    p.scan_max_hostgroup  = 16;
    p.scan_min_parallelism = 0;
    p.scan_min_hostgroup   = 0;
  } else if (mode == KMAP_PERF_FAST) {
    p.cpu_percent = cpu_pct;
    p.mem_percent = mem_pct;
    /* "CPU units" = the share of logical cores we are allowed to lean on. */
    double unitsf = static_cast<double>(cores) * (cpu_pct / 100.0);
    int units = std::max(1, static_cast<int>(unitsf + 0.5));
    /* Scanning is overwhelmingly I/O-bound (threads block in connect()/
     * select()), so each allowed core unit backs many concurrent sockets.
     * Enrichment does more per-connection work (TLS, parsing) so it gets a
     * smaller multiplier. */
    p.discovery_workers = clampi(units * 64, 50, 1024);
    p.enrich_workers    = clampi(units * 16, 20, 256);

    /* Memory budget = configured share of available RAM. */
    uint64_t base = p.avail_ram_bytes ? p.avail_ram_bytes : p.total_ram_bytes;
    if (base > 0) {
      p.mem_budget_bytes =
          static_cast<uint64_t>(static_cast<double>(base) * (mem_pct / 100.0));
      /* Do not let the pools' worst-case footprint exceed the budget. */
      uint64_t max_inflight = p.mem_budget_bytes / KMAP_MEM_PER_WORKER;
      if (max_inflight >= 20) {
        if (static_cast<uint64_t>(p.discovery_workers) > max_inflight)
          p.discovery_workers = static_cast<int>(max_inflight);
        if (static_cast<uint64_t>(p.enrich_workers) > max_inflight)
          p.enrich_workers = static_cast<int>(max_inflight);
      }
      p.discovery_workers = clampi(p.discovery_workers, 50, 1024);
      p.enrich_workers    = clampi(p.enrich_workers, 20, 256);
    }

    /* Regular scans: raise the host group and a parallelism floor so a -sV
     * sweep of a subnet keeps more probes in flight, scaled to the share. */
    p.scan_min_hostgroup   = clampi(units * 16, 16, 1024);
    p.scan_max_hostgroup   = 0; /* leave nmap's own ceiling */
    p.scan_min_parallelism = clampi(units * 8, 8, 256);
  }
  return p;
}

const KmapPerfProfile &kmap_perf_profile(void) {
  static bool computed = false;
  static KmapPerfProfile cached;
  if (!computed) {
    double cpu_pct = (o.fast_cpu_percent > 0.0) ? o.fast_cpu_percent : 50.0;
    double mem_pct = (o.fast_mem_percent > 0.0) ? o.fast_mem_percent : 25.0;
    cached = compute_profile(o.perf_mode, cpu_pct, mem_pct);
    computed = true;
  }
  return cached;
}

static void human_bytes(uint64_t b, char *out, size_t n) {
  if (b == 0) { snprintf(out, n, "unknown"); return; }
  double gb = static_cast<double>(b) / (1024.0 * 1024.0 * 1024.0);
  if (gb >= 1.0) { snprintf(out, n, "%.1f GB", gb); return; }
  double mb = static_cast<double>(b) / (1024.0 * 1024.0);
  snprintf(out, n, "%.0f MB", mb);
}

void kmap_perf_describe(char *buf, size_t buflen) {
  if (!buf || buflen == 0) return;
  const KmapPerfProfile &p = kmap_perf_profile();
  char ram[32];
  human_bytes(p.total_ram_bytes, ram, sizeof(ram));
  if (p.mode == KMAP_PERF_EFFICIENT) {
    snprintf(buf, buflen,
             "perf mode: efficient (low footprint) | %d CPU, %s RAM | "
             "discovery=%d enrich=%d workers",
             p.cpu_count, ram, p.discovery_workers, p.enrich_workers);
  } else if (p.mode == KMAP_PERF_FAST) {
    char budget[32];
    human_bytes(p.mem_budget_bytes, budget, sizeof(budget));
    snprintf(buf, buflen,
             "perf mode: fast (<=%.0f%% CPU, <=%.0f%% RAM) | %d CPU, %s RAM | "
             "discovery=%d enrich=%d workers, mem budget %s",
             p.cpu_percent, p.mem_percent, p.cpu_count, ram,
             p.discovery_workers, p.enrich_workers, budget);
  } else {
    snprintf(buf, buflen, "perf mode: normal | %d CPU, %s RAM",
             p.cpu_count, ram);
  }
  buf[buflen - 1] = '\0';
}

/* KmapOps::Initialize() defaults for the host-group sizes. We treat "still
 * at the default" as "user did not set it", so an explicit flag wins. */
static const unsigned int KMAP_DEFAULT_MIN_HOSTGROUP = 1;
static const unsigned int KMAP_DEFAULT_MAX_HOSTGROUP = 100000;

double kmap_perf_cpu_target_cores(void) {
  const KmapPerfProfile &p = kmap_perf_profile();
  if (p.mode == KMAP_PERF_NORMAL) return 0.0;
  double t = static_cast<double>(p.cpu_count) * (p.cpu_percent / 100.0);
  if (t < 0.1) t = 0.1; /* never throttle to a full stop */
  return t;
}

void kmap_perf_apply_to_scan(void) {
  const KmapPerfProfile &p = kmap_perf_profile();
  if (p.mode == KMAP_PERF_NORMAL) return;

  /* Only fill in values the user did not set explicitly, so an explicit
   * --min-parallelism / -T / --min-hostgroup flag always wins.
   * min_parallelism has a clean 0 = "unset" sentinel; the host-group sizes
   * do not, so we compare against their Initialize() defaults. */
  if (p.scan_min_parallelism > 0 && o.min_parallelism == 0)
    o.min_parallelism = p.scan_min_parallelism;

  if (p.scan_max_hostgroup > 0 &&
      o.maxHostGroupSz() == static_cast<int>(KMAP_DEFAULT_MAX_HOSTGROUP))
    o.setMaxHostGroupSz(static_cast<unsigned int>(p.scan_max_hostgroup));

  if (p.scan_min_hostgroup > 0 &&
      o.minHostGroupSz() == static_cast<int>(KMAP_DEFAULT_MIN_HOSTGROUP))
    o.setMinHostGroupSz(static_cast<unsigned int>(p.scan_min_hostgroup));
}
