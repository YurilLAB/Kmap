/* cpu_meter.cc -- see cpu_meter.h */

#include "cpu_meter.h"

#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <cmath>

#ifdef WIN32
#include <windows.h>
#else
#include <sys/resource.h>
#include <sys/time.h>
#endif

double kmap_process_cpu_seconds(void) {
#ifdef WIN32
  FILETIME creation, exit_t, kernel, user;
  if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit_t,
                       &kernel, &user))
    return -1.0;
  /* FILETIME is in 100-nanosecond ticks. */
  auto to_sec = [](const FILETIME &ft) -> double {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return static_cast<double>(u.QuadPart) * 1e-7;
  };
  return to_sec(kernel) + to_sec(user);
#else
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) != 0)
    return -1.0;
  double u = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6;
  double s = ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
  return u + s;
#endif
}

double kmap_monotonic_seconds(void) {
  using namespace std::chrono;
  return duration<double>(steady_clock::now().time_since_epoch()).count();
}

long kmap_cpu_throttle_step_us(double used_cores, double target_cores,
                               long cur_sleep_us) {
  if (target_cores <= 0.0) return 0;
  const long   MAX_SLEEP_US = 250000; /* 250 ms ceiling per call */
  const long   SEED_US      = 1500;   /* bootstrap when starting from ~0 */
  const double DAMP         = 0.7;    /* <1 damps oscillation */

  /* +-3% deadband around the target to avoid hunting once converged. */
  const double hi = target_cores * 1.03;
  const double lo = target_cores * 0.97;
  if (used_cores <= hi && used_cores >= lo)
    return cur_sleep_us; /* in band: hold */

  /* Multiplicative (damped) control: CPU utilisation falls roughly as the
   * duty cycle work/(work+sleep), so nudging the sleep by a damped power of
   * the error ratio converges geometrically instead of crawling linearly.
   * From a near-zero sleep we can't multiply up, so seed proportionally. */
  const double ratio = used_cores / target_cores; /* >1 too hot, <1 too cold */
  double next;
  if (cur_sleep_us < SEED_US) {
    next = (used_cores > target_cores)
             ? static_cast<double>(SEED_US) * ratio
             : 0.0;
  } else {
    double factor = std::pow(ratio, DAMP);
    next = static_cast<double>(cur_sleep_us) * factor;
  }
  if (next < 0.0) next = 0.0;
  if (next > MAX_SLEEP_US) next = MAX_SLEEP_US;
  return static_cast<long>(next);
}

namespace {
std::atomic<bool> g_active{false};
std::atomic<long> g_sleep_us{0};
std::mutex        g_mu;
double            g_target_cores = 0.0;
double            g_last_wall    = 0.0;
double            g_last_cpu     = 0.0;
const double      SAMPLE_INTERVAL_S = 0.1; /* re-sample at most every 100 ms */
}

void kmap_cpu_governor_init(double target_cores) {
  if (target_cores <= 0.0) { g_active.store(false); return; }
  if (getenv("KMAP_NO_CPU_GOVERNOR")) { g_active.store(false); return; }
  double cpu = kmap_process_cpu_seconds();
  if (cpu < 0.0) { g_active.store(false); return; } /* unmeasurable */

  std::lock_guard<std::mutex> lk(g_mu);
  g_target_cores = target_cores;
  g_last_wall = kmap_monotonic_seconds();
  g_last_cpu = cpu;
  g_sleep_us.store(0);
  g_active.store(true);
}

bool kmap_cpu_governor_active(void) { return g_active.load(); }

long kmap_cpu_governor_sleep_us(void) { return g_sleep_us.load(); }

void kmap_cpu_governor_throttle(void) {
  if (!g_active.load()) return;

  /* One thread at a time recomputes the sleep target; the rest just read
   * and honor the current value. try_lock keeps this off the hot path. */
  if (g_mu.try_lock()) {
    double now = kmap_monotonic_seconds();
    double dt = now - g_last_wall;
    if (dt >= SAMPLE_INTERVAL_S) {
      double cpu = kmap_process_cpu_seconds();
      if (cpu >= 0.0) {
        double used_cores = (cpu - g_last_cpu) / dt;
        long next = kmap_cpu_throttle_step_us(used_cores, g_target_cores,
                                              g_sleep_us.load());
        g_sleep_us.store(next);
        g_last_wall = now;
        g_last_cpu = cpu;
      }
    }
    g_mu.unlock();
  }

  long s = g_sleep_us.load();
  if (s > 0)
    std::this_thread::sleep_for(std::chrono::microseconds(s));
}
