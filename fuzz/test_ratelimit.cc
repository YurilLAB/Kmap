/*
 * test_ratelimit.cc -- behavioral model test for fast_syn.cc's token-bucket
 * rate limiter (rate_init + the in-mutex refill/grant arithmetic of rate_wait).
 *
 * The Python suite checks the limiter's source STRUCTURE; this pins its
 * BEHAVIOR, which governs politeness: a sweep that exceeds --rate invites
 * upstream abuse blocks, and one that under-grants crawls. The arithmetic is
 * lifted verbatim and driven with INJECTED timestamps (no real clock/sleep) so
 * it is deterministic.
 *
 * Checks:
 *   - rate accuracy: over a simulated window, grants ~= pps * seconds (catches
 *     a refill_rate units error, e.g. pps/1000 instead of pps/1e6)
 *   - burst bound: after a long idle, a single instant cannot release more than
 *     max_tokens (the 20 ms ceiling that prevents the opening-spike IDS trip)
 *   - refill_rate == pps / 1e6; max_tokens == pps * 0.02 (floored at 4)
 *   - unlimited path: pps <= 0 sets the no-throttle flag and grants every call
 *     (the default now that the 25k pps ceiling has been removed)
 *
 * Build: g++ -O2 -g -std=gnu++17 -Wall fuzz/test_ratelimit.cc \
 *        -o fuzz/test_ratelimit.exe && fuzz/test_ratelimit.exe
 */
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <initializer_list>

/* ===== verbatim shape from fast_syn.cc ===== */
struct RateLimiter { double tokens; double max_tokens; double refill_rate; int64_t last_refill; bool unlimited; };

static void rate_init(RateLimiter &rl, int pps, int64_t now) {
  /* pps <= 0 -> no throttle (the default since the 25k ceiling was removed). */
  rl.unlimited = (pps <= 0);
  if (rl.unlimited) {
    rl.tokens = rl.max_tokens = rl.refill_rate = 0.0;
    rl.last_refill = now;
    return;
  }
  rl.max_tokens = (double)pps * 0.02;
  if (rl.max_tokens < 4.0) rl.max_tokens = 4.0;
  rl.tokens = 1.0;
  rl.refill_rate = (double)pps / 1000000.0;
  rl.last_refill = now;
}

/* The arithmetic rate_wait runs under the mutex, with `now` injected instead
   of now_usec(). Returns true if a token was granted. */
static bool rate_try(RateLimiter &rl, int64_t now) {
  if (rl.unlimited) return true;  /* unlimited: always grant, no throttle */
  double elapsed = (double)(now - rl.last_refill);
  rl.tokens += elapsed * rl.refill_rate;
  if (rl.tokens > rl.max_tokens) rl.tokens = rl.max_tokens;
  rl.last_refill = now;
  if (rl.tokens >= 1.0) { rl.tokens -= 1.0; return true; }
  return false;
}

static int g_fail = 0;
static void expect(bool c, const char *m) { if (!c) { printf("  FAIL: %s\n", m); g_fail++; } }

/* Drive the limiter as fast as possible across [0, window_us], advancing the
   injected clock by step_us each attempt; return how many tokens it granted. */
static long grants_over(int pps, int64_t window_us, int64_t step_us) {
  RateLimiter rl; rate_init(rl, pps, 0);
  long granted = 0;
  for (int64_t t = 0; t <= window_us; t += step_us)
    if (rate_try(rl, t)) granted++;
  return granted;
}

int main(void) {
  printf("rate-limiter behavioral model test\n==================================\n");

  /* ---- rate accuracy: grants ~= pps * seconds ----
     Driving at a fine step and consuming each token keeps the bucket low, so
     total grants ~= initial(1) + refill_rate*window = pps*sec + 1. Allow a
     small slack for the initial token + the burst ceiling. */
  struct { int pps; int64_t win_us; } cases[] = {
    {25000, 1000000}, {25000, 3000000}, {1000, 2000000}, {200, 5000000},
  };
  for (auto &c : cases) {
    double secs = (double)c.win_us / 1e6;
    long expect_tokens = (long)llround((double)c.pps * secs);
    long got = grants_over(c.pps, c.win_us, 10 /*us step*/);
    double err = expect_tokens ? fabs((double)(got - expect_tokens)) / expect_tokens : 0;
    char msg[128];
    snprintf(msg, sizeof(msg),
             "pps=%d over %.0fs: granted %ld, expected ~%ld (err %.2f%%, <2%%)",
             c.pps, secs, got, expect_tokens, err * 100.0);
    expect(err < 0.02, msg);
  }

  /* ---- burst bound: a single instant cannot release more than max_tokens ----
     Idle 10 s so the bucket would refill 10*pps tokens if uncapped, then drain
     at one fixed instant. Count <= ceil(max_tokens) grants. */
  for (int pps : {25000, 1000, 200}) {
    RateLimiter rl; rate_init(rl, pps, 0);
    int64_t t = 10000000; /* 10 s later */
    long burst = 0;
    while (rate_try(rl, t)) burst++;       /* same instant: no further refill */
    double cap = (double)pps * 0.02; if (cap < 4.0) cap = 4.0;
    char msg[128];
    snprintf(msg, sizeof(msg),
             "pps=%d burst after 10s idle = %ld, cap=%.0f (no opening spike)",
             pps, burst, cap);
    expect((double)burst <= cap + 1.0, msg);
  }

  /* ---- constants ---- */
  {
    RateLimiter rl; rate_init(rl, 25000, 0);
    expect(fabs(rl.refill_rate - 25000.0/1e6) < 1e-12, "refill_rate == pps/1e6");
    expect(fabs(rl.max_tokens - 25000.0*0.02) < 1e-9, "max_tokens == pps*0.02");
    RateLimiter lo; rate_init(lo, 50, 0);
    expect(lo.max_tokens == 4.0, "max_tokens floored at 4 for low pps");
  }

  /* ---- high-rate math stays finite + exact at the raised 1e9 cap ----
     The --rate ceiling was lifted from 10M to 1e9 pps; confirm the token-bucket
     arithmetic does not overflow or lose the values (all are exact in double). */
  for (long pps : {1000000L, 10000000L, 100000000L, 1000000000L}) {
    RateLimiter rl; rate_init(rl, (int)pps, 0);
    char m[128];
    snprintf(m, sizeof(m), "pps=%ld: refill_rate finite & == pps/1e6", pps);
    expect(std::isfinite(rl.refill_rate) &&
           fabs(rl.refill_rate - (double)pps / 1e6) < 1e-6, m);
    snprintf(m, sizeof(m), "pps=%ld: max_tokens finite & == pps*0.02", pps);
    expect(std::isfinite(rl.max_tokens) &&
           fabs(rl.max_tokens - (double)pps * 0.02) < 1.0, m);
    snprintf(m, sizeof(m), "pps=%ld: grants at least one token", pps);
    expect(rate_try(rl, 0), m);
  }

  /* ---- accuracy still holds at 1,000,000 pps (1 grant/call, 1 us step) ---- */
  {
    long got = grants_over(1000000, 1000000, 1);
    long exp = 1000000;
    double err = fabs((double)(got - exp)) / exp;
    char m[128];
    snprintf(m, sizeof(m), "pps=1e6 over 1s: granted %ld ~ %ld (err %.2f%%, <2%%)",
             got, exp, err * 100.0);
    expect(err < 0.02, m);
  }

  /* ---- unlimited path (pps <= 0): no throttle, every call grants ----
     This is the default now that the 25k ceiling is gone. Both pps=0 and a
     negative pps must set unlimited and grant on every attempt, including a
     burst of many calls at the SAME instant (which the token bucket would
     otherwise cap at max_tokens). */
  for (int pps : {0, -1, -25000}) {
    RateLimiter rl; rate_init(rl, pps, 0);
    char m[128];
    snprintf(m, sizeof(m), "pps=%d -> unlimited flag set", pps);
    expect(rl.unlimited, m);
    long burst = 0;
    for (int i = 0; i < 100000; i++) if (rate_try(rl, 0)) burst++;  /* same instant */
    snprintf(m, sizeof(m), "pps=%d: 100000/100000 grants at one instant (no cap), got %ld", pps, burst);
    expect(burst == 100000, m);
  }

  printf("\n%s\n", g_fail == 0 ? "rate-limiter test: ALL PASS" : "rate-limiter test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
