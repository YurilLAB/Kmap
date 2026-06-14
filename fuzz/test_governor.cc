/* test_governor.cc -- LIVE test of the real CPU governor (cpu_meter.cc).
 *
 * Links the actual shipping governor and drives it with N CPU-bound worker
 * threads that call kmap_cpu_governor_throttle() between work chunks -- the
 * same shape as the enrichment worker loop. Measures real process CPU over a
 * window and checks the governor holds sustained CPU near the target.
 *
 * Build: g++ -O2 -std=gnu++17 -pthread test_governor.cc ../cpu_meter.cc -o test_governor.exe
 */
#include "../cpu_meter.h"
#include <atomic>
#include <thread>
#include <vector>
#include <cstdio>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#ifdef _WIN32
#include <windows.h>
#pragma comment(lib, "winmm.lib")
#endif

static std::atomic<bool> g_stop{false};
static std::atomic<uint64_t> g_work{0};
static int g_chunk_iters = 20000;   /* tunable work-chunk size */

/* A chunk of real CPU work that the optimizer can't elide. */
static double burn(volatile double seed) {
  double x = seed;
  for (int i = 0; i < g_chunk_iters; i++) x = x * 1.0000001 + 1.0 - (x > 1e9 ? x : 0.0);
  return x;
}

static void worker() {
  volatile double acc = 1.0;
  while (!g_stop.load(std::memory_order_relaxed)) {
    acc = burn(acc);
    g_work.fetch_add(1, std::memory_order_relaxed);
    kmap_cpu_governor_throttle();   /* the real shipping throttle */
  }
}

/* Run nthreads workers for `secs`, return measured used-cores over the
 * steady-state window (skip a warmup so the controller can converge). */
static double measure(int nthreads, double target, double secs) {
  g_stop.store(false);
  g_work.store(0);
  kmap_cpu_governor_init(target);   /* target<=0 disables (full speed) */

  std::vector<std::thread> pool;
  for (int i = 0; i < nthreads; i++) pool.emplace_back(worker);

  /* warmup */
  double warm = 1.2;
  double t0 = kmap_monotonic_seconds();
  while (kmap_monotonic_seconds() - t0 < warm) std::this_thread::sleep_for(std::chrono::milliseconds(20));

  /* steady-state measurement window */
  double cpu0 = kmap_process_cpu_seconds();
  double w0   = kmap_monotonic_seconds();
  while (kmap_monotonic_seconds() - w0 < secs) std::this_thread::sleep_for(std::chrono::milliseconds(20));
  double cpu1 = kmap_process_cpu_seconds();
  double w1   = kmap_monotonic_seconds();

  g_stop.store(true);
  for (auto &t : pool) t.join();

  double used = (cpu1 - cpu0) / (w1 - w0);
  return used;
}

static void run_suite(const char *label, int nthreads, double base) {
  printf("\n--- %s (chunk_iters=%d) ---\n", label, g_chunk_iters);
  double targets[] = {1.0, 2.0, 3.0};
  for (double t : targets) {
    if (t > base + 0.5) { printf("  (skip target %.1f > baseline %.2f)\n", t, base); continue; }
    double used = measure(nthreads, t, 3.0);
    long settled = kmap_cpu_governor_sleep_us();
    double err = std::fabs(used - t);
    printf("  target %.1f -> used=%.2f cores  err=%.2f  settled_sleep=%ldus\n",
           t, used, err, settled);
  }
}

int main(int argc, char **argv) {
  int cores = (int)std::thread::hardware_concurrency();
  int nthreads = (argc > 1) ? atoi(argv[1]) : (cores > 0 ? cores : 8);
  bool use_hires = (argc > 2 && atoi(argv[2]) != 0);
  printf("hardware_concurrency=%d, workers=%d, hires_timer=%d\n",
         cores, nthreads, use_hires ? 1 : 0);

#ifdef _WIN32
  if (use_hires) { timeBeginPeriod(1); printf("[timeBeginPeriod(1) ACTIVE]\n"); }
#endif

  /* Fine-grained chunks (~tens of us) stress the sleep timer resolution. */
  g_chunk_iters = 20000;
  double base_fine = measure(nthreads, 0.0, 2.0);
  printf("governor OFF (fine chunks): baseline used=%.2f cores\n", base_fine);
  run_suite("FINE chunks", nthreads, base_fine);

  /* Coarse chunks (~ms) mimic a realistic per-work-item cost between throttle
     calls; this is closer to how enrichment actually calls the governor. */
  g_chunk_iters = 3000000;
  double base_coarse = measure(nthreads, 0.0, 2.0);
  printf("\ngovernor OFF (coarse chunks): baseline used=%.2f cores\n", base_coarse);
  run_suite("COARSE chunks", nthreads, base_coarse);

#ifdef _WIN32
  if (use_hires) timeEndPeriod(1);
#endif
  printf("\n(interpretation: if FINE fails but COARSE converges, the cause is\n"
         " sub-ms sleep_for resolution on Windows without timeBeginPeriod(1).)\n");
  return 0;
}
