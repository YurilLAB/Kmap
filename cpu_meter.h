/* cpu_meter.h -- process CPU measurement and a cooperative CPU governor.
 *
 * Deliberately free of any dependency on KmapOps / the rest of Kmap so the
 * control law can be unit-tested standalone. The --fast / --efficient modes
 * compute a target (in "cores" of allowed utilization) from the detected
 * hardware and feed it to kmap_cpu_governor_init(); CPU-heavy worker loops
 * then call kmap_cpu_governor_throttle() between work items, which injects
 * cooperative micro-sleeps to hold sustained CPU near the target.
 */
#ifndef KMAP_CPU_METER_H
#define KMAP_CPU_METER_H

/* Total CPU time (user+system, all threads) consumed by this process so
 * far, in seconds. Returns -1.0 if it cannot be measured. */
double kmap_process_cpu_seconds(void);

/* Monotonic wall-clock seconds (steady clock). */
double kmap_monotonic_seconds(void);

/* Pure control law for the governor: given the recently measured
 * utilization (in cores), the target (in cores), and the current per-call
 * sleep in microseconds, return the next sleep value. Exposed for testing.
 * target_cores <= 0 always returns 0 (governor disabled). */
long kmap_cpu_throttle_step_us(double used_cores, double target_cores,
                               long cur_sleep_us);

/* Governor lifecycle. target_cores is the allowed sustained CPU in units of
 * logical cores (e.g. 50% of an 8-core box => 4.0). target_cores <= 0, an
 * unmeasurable CPU clock, or the KMAP_NO_CPU_GOVERNOR env var all disable
 * it (throttle becomes a no-op). */
void kmap_cpu_governor_init(double target_cores);
bool kmap_cpu_governor_active(void);

/* Called by CPU-heavy worker loops between work items. Cheap when inactive
 * or when no throttling is currently required. */
void kmap_cpu_governor_throttle(void);

/* Current injected per-call sleep in microseconds (for diagnostics/tests). */
long kmap_cpu_governor_sleep_us(void);

#endif /* KMAP_CPU_METER_H */
