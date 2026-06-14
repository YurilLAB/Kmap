/*
 * test_lowwater.cc -- proves the EXACT resume low-water-mark in fast_syn.cc
 * never lets a crash-resume skip a claimed-but-unfinished IP index, and that
 * the OLD "cur_idx - total_workers" heuristic could.
 *
 * Background
 * ----------
 * fast_syn discovery runs a flat pool of total_workers threads. Each claims
 * one IP index via probe_idx.fetch_add(1), probes its ports, inserts opens,
 * then claims the next. All probes share ONE global rate limiter, so a worker
 * that stalls on a slow LIVE host (bail disabled -> every port probed at up to
 * probe_timeout_ms) can hold its claimed index K while the rest of the pool
 * races thousands of indices ahead. The periodic checkpoint must save a resume
 * position <= every claimed-but-unfinished index or a crash loses those hosts.
 *
 * The old heuristic saved cur_idx - total_workers, which under-rewinds when a
 * worker lags by more than total_workers. The fix tracks each worker's
 * in-flight index and saves min(exact_inflight_min, cur_idx - total_workers):
 *   (a) exact_inflight_min covers a slow PROCESSING worker (the real bug),
 *   (b) the cur_idx - total_workers floor covers the brief, non-blocking
 *       fetch_add->publish claim gap (indices always within total_workers of
 *       probe_idx there).
 *
 * Part 1 tests the pure low-water formula over millions of randomized states.
 * Part 2 runs a real threaded pool with planted laggards, "crashes" at random
 * points, and verifies no not-yet-completed index falls below the saved mark.
 *
 * Build (MinGW, here):
 *   g++ -O2 -g -std=gnu++17 -Wall -pthread fuzz/test_lowwater.cc \
 *       -o fuzz/test_lowwater.exe && fuzz/test_lowwater.exe
 */

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <atomic>
#include <thread>
#include <limits>

static const uint64_t NONE = std::numeric_limits<uint64_t>::max();

/* The fix, lifted verbatim from fast_syn.cc::compute_low_water. */
static uint64_t low_water_new(uint64_t probe_idx,
                              const std::vector<uint64_t> &inflight,
                              long total_workers) {
  uint64_t p = probe_idx, lw = p;
  for (long w = 0; w < (long)inflight.size(); w++) {
    uint64_t v = inflight[w];
    if (v != NONE && v < lw) lw = v;
  }
  uint64_t floor = (p > (uint64_t)total_workers) ? p - (uint64_t)total_workers : 0;
  if (floor < lw) lw = floor;
  return lw;
}

/* The old heuristic it replaced. */
static uint64_t resume_old(uint64_t cur_idx, long total_workers) {
  return (cur_idx > (uint64_t)total_workers) ? cur_idx - (uint64_t)total_workers : 0;
}

/* xorshift so runs are reproducible without Date/rand state. */
static uint64_t rs = 0x9e3779b97f4a7c15ULL;
static uint64_t rng() { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

/* ---------------------------------------------------------------------------
 * Part 1: pure-formula invariant over randomized states.
 * ------------------------------------------------------------------------- */
static int part1(uint64_t seed) {
  rs = seed ? seed : 1;
  const long ITERS = 3000000;
  long failed = 0, old_would_skip = 0;

  for (long it = 0; it < ITERS; it++) {
    long W = 1 + (long)(rng() % 256);                 /* total_workers */
    uint64_t p = rng() % 5000000ULL;                  /* probe_idx (next claim) */

    std::vector<uint64_t> inflight(W, NONE);
    /* Truth set of claimed-but-unfinished indices we must never skip. */
    std::vector<uint64_t> unfinished;

    /* (a) Some PROCESSING workers, each published at a random index < p.
           A fraction are "laggards" placed far below p - W to model a slow
           live host while the pool raced ahead. */
    long n_proc = (long)(rng() % (uint64_t)(W + 1));
    for (long k = 0; k < n_proc; k++) {
      long slot = (long)(rng() % (uint64_t)W);
      if (inflight[slot] != NONE) continue;            /* one claim per worker */
      uint64_t idx;
      if (p == 0) break;
      if (rng() % 4 == 0 && p > (uint64_t)W + 10) {
        /* laggard: somewhere in [0, p - W) -- the case the old code missed */
        idx = rng() % (p - (uint64_t)W);
      } else {
        idx = rng() % p;
      }
      inflight[slot] = idx;
      unfinished.push_back(idx);
    }

    /* (b) Claim-gap indices: claimed but not yet published, hence slot==NONE.
           They are always within total_workers of probe_idx (non-blocking
           gap), so model them in [p - W, p). */
    long n_gap = (long)(rng() % (uint64_t)(W + 1));
    for (long k = 0; k < n_gap && p > 0; k++) {
      uint64_t lo = (p > (uint64_t)W) ? p - (uint64_t)W : 0;
      uint64_t span = p - lo;
      uint64_t idx = lo + (span ? (rng() % span) : 0);
      unfinished.push_back(idx);
    }

    uint64_t lw  = low_water_new(p, inflight, W);
    uint64_t old = resume_old(p, W);

    for (uint64_t u : unfinished) {
      if (lw > u) {                       /* NEW skipped a real in-flight idx */
        failed++;
        if (failed <= 5)
          printf("  FAIL: new lw=%llu skips unfinished idx=%llu (p=%llu W=%ld)\n",
                 (unsigned long long)lw, (unsigned long long)u,
                 (unsigned long long)p, W);
      }
      if (old > u) old_would_skip++;      /* OLD heuristic would have skipped */
    }
  }

  printf("  part1: %ld randomized states, new-skips=%ld, old-would-skip=%ld\n",
         ITERS, failed, old_would_skip);
  if (failed)        printf("  part1 FAIL: new formula skipped an in-flight index\n");
  if (!old_would_skip)
    printf("  part1 WARN: old heuristic never skipped -- laggard model too weak\n");
  /* Pass requires: new never skips AND we actually demonstrated the old bug. */
  return (failed == 0 && old_would_skip > 0) ? 0 : 1;
}

/* ---------------------------------------------------------------------------
 * Part 2: real threaded pool with laggards + crash-snapshot check.
 * ------------------------------------------------------------------------- */
struct Pool {
  std::atomic<uint64_t> probe_idx{0};
  std::atomic<bool>     stop{false};
  uint64_t              scan_end;
  long                  total_workers;
  std::vector<std::atomic<uint64_t>> inflight;
  std::vector<std::atomic<uint8_t>>  completed;   /* per index: fully done */

  Pool(uint64_t end, long w)
    : scan_end(end), total_workers(w), inflight(w), completed(end) {
    for (long i = 0; i < w; i++) inflight[i].store(NONE, std::memory_order_relaxed);
    for (uint64_t i = 0; i < end; i++) completed[i].store(0, std::memory_order_relaxed);
  }
};

/* unsigned accumulator: defined modular wraparound, so a large spin count
   can't trip UBSan's signed-overflow check (the loop is only a time sink). */
static std::atomic<unsigned> g_busy_sink{0};
static void busy(int spins) { unsigned x = 0; for (int i = 0; i < spins; i++) x += (unsigned)i; g_busy_sink.store(x, std::memory_order_relaxed); }

static void worker_fn(Pool *pl, long w, uint64_t tseed) {
  uint64_t r = tseed | 1;
  auto nx = [&]() { r ^= r << 13; r ^= r >> 7; r ^= r << 17; return r; };
  while (!pl->stop.load(std::memory_order_relaxed)) {
    uint64_t my = pl->probe_idx.fetch_add(1, std::memory_order_relaxed);
    if (my >= pl->scan_end) { pl->inflight[w].store(NONE, std::memory_order_release); return; }
    pl->inflight[w].store(my, std::memory_order_release);      /* publish claim */

    /* Simulate work; ~1/64 indices are slow "live hosts" that stall this
       worker while the pool races ahead -- the exact bug scenario. */
    int spins = (nx() % 64 == 0) ? 20000 + (int)(nx() % 40000) : 50 + (int)(nx() % 200);
    busy(spins);

    if (pl->stop.load(std::memory_order_relaxed)) {
      /* Abandoned mid-process on crash: leave it PUBLISHED (not completed). */
      return;
    }
    pl->completed[my].store(1, std::memory_order_release);
    pl->inflight[w].store(NONE, std::memory_order_release);    /* release idx */
  }
}

static int part2(uint64_t seed) {
  rs = seed ? seed * 2654435761ULL + 1 : 7;
  const int ROUNDS = 40;
  long failed = 0;
  long total_inflight_observed = 0;

  for (int round = 0; round < ROUNDS; round++) {
    long W = 4 + (long)(rng() % 32);
    uint64_t END = 20000 + (rng() % 40000);
    Pool pl(END, W);

    std::vector<std::thread> th;
    for (long i = 0; i < W; i++)
      th.emplace_back(worker_fn, &pl, i, rng());

    /* Let it run a bit, then "crash": stop claiming and join (no thread is
       mid-claim-gap after join, so the snapshot is consistent). */
    busy(200000 + (int)(rng() % 800000));
    pl.stop.store(true, std::memory_order_relaxed);
    for (auto &t : th) t.join();

    /* Snapshot after join. */
    uint64_t p = pl.probe_idx.load();
    std::vector<uint64_t> snap(W);
    long live = 0;
    for (long i = 0; i < W; i++) {
      snap[i] = pl.inflight[i].load();
      if (snap[i] != NONE) live++;
    }
    total_inflight_observed += live;
    uint64_t lw = low_water_new(p, snap, W);

    /* Invariant: every claimed index that did NOT complete must be >= lw,
       otherwise resume would skip it = lost host data. Claimed indices are
       [0, min(p, END)). */
    uint64_t claimed_hi = p < END ? p : END;
    for (uint64_t i = 0; i < claimed_hi; i++) {
      if (!pl.completed[i].load(std::memory_order_acquire) && i < lw) {
        failed++;
        if (failed <= 5)
          printf("  FAIL round %d: idx=%llu not completed but < lw=%llu (p=%llu W=%ld)\n",
                 round, (unsigned long long)i, (unsigned long long)lw,
                 (unsigned long long)p, W);
      }
    }
  }
  printf("  part2: %d threaded crash rounds, in-flight-observed=%ld, skips=%ld\n",
         ROUNDS, total_inflight_observed, failed);
  return failed == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
  uint64_t seed = (argc > 1) ? strtoull(argv[1], nullptr, 10) : 1;
  printf("fast_syn resume low-water-mark test (seed=%llu)\n",
         (unsigned long long)seed);
  printf("==============================================\n");
  int rc = 0;
  printf("\nPart 1: pure-formula invariant + old-heuristic bug demo\n");
  rc |= part1(seed);
  printf("\nPart 2: threaded pool with laggards + crash snapshot\n");
  rc |= part2(seed);
  printf("\n%s\n", rc == 0 ? "low-water test: ALL PASS" : "low-water test: FAILURES");
  return rc;
}
