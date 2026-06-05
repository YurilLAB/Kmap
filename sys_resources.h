/* sys_resources.h -- system resource detection and performance profiles
 *
 * Provides cross-platform detection of logical CPU count and physical /
 * available RAM, and turns the user-selected performance mode
 * (--efficient / --fast) into concrete, resource-aware concurrency knobs
 * for the scanning pipelines.
 *
 * Design goals:
 *   - "efficient": small footprint, background-friendly. Few workers, low
 *     memory, gentle on the host and the network.
 *   - "fast": smart, resource-aware speed-up. Scales worker pools with the
 *     detected hardware but stays within a configurable share of the
 *     machine (default ~50% of CPU, ~25% of available RAM) so it does not
 *     starve everything else on the box. Both shares are tunable and are
 *     derived from the actual hardware -- never hardcoded thread counts.
 */
#ifndef KMAP_SYS_RESOURCES_H
#define KMAP_SYS_RESOURCES_H

#include <stdint.h>
#include <stddef.h>

/* Performance modes -- mirrors KmapOps::perf_mode. */
enum {
  KMAP_PERF_NORMAL    = 0,  /* legacy fixed defaults (unless env overrides) */
  KMAP_PERF_EFFICIENT = 1,  /* low footprint */
  KMAP_PERF_FAST      = 2   /* resource-aware speed-up, capped share */
};

/* Resolved, resource-aware tuning for the current run. Computed once from
 * the detected hardware and the user-selected mode, then cached. */
struct KmapPerfProfile {
  int      mode;             /* KMAP_PERF_* */
  int      cpu_count;        /* detected logical CPUs (>= 1) */
  uint64_t total_ram_bytes;  /* physical RAM, 0 if undetectable */
  uint64_t avail_ram_bytes;  /* available RAM, 0 if undetectable */
  double   cpu_percent;      /* effective CPU share used (fast mode) */
  double   mem_percent;      /* effective RAM share used  (fast mode) */
  uint64_t mem_budget_bytes; /* memory budget for in-flight scan state */

  /* Custom internet-scan pipeline thread pools. */
  int discovery_workers;     /* SYN/connect discovery pool */
  int enrich_workers;        /* enrichment pool */

  /* Regular (per-host) nmap-style scan nudges. 0 means "leave the existing
   * default / user value untouched". */
  int scan_min_parallelism;
  int scan_min_hostgroup;
  int scan_max_hostgroup;
};

/* Raw hardware detection (cross-platform). */
int      kmap_detect_cpu_count(void);
uint64_t kmap_detect_total_ram(void);
uint64_t kmap_detect_avail_ram(void);

/* Returns the cached, resolved profile for this run. The first call reads
 * the global options object `o` (perf_mode, fast_cpu_percent,
 * fast_mem_percent) and computes the profile; later calls return the cache.
 */
const KmapPerfProfile &kmap_perf_profile(void);

/* Writes a one-line human-readable summary of the active profile into buf
 * (always NUL-terminated). Safe to call regardless of mode. */
void kmap_perf_describe(char *buf, size_t buflen);

/* Applies the regular-scan nudges (min parallelism / host group) to the
 * global options object, only where the user has not set them explicitly.
 * No-op in KMAP_PERF_NORMAL. Call once after option parsing. */
void kmap_perf_apply_to_scan(void);

/* CPU target for the live governor, in units of logical cores (e.g. 50% of
 * an 8-core box => 4.0). Returns 0.0 in KMAP_PERF_NORMAL, which disables the
 * governor. Feed this to kmap_cpu_governor_init() (see cpu_meter.h). */
double kmap_perf_cpu_target_cores(void);

#endif /* KMAP_SYS_RESOURCES_H */
