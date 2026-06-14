/*
 * test_discover_bail.cc -- live correctness test for the flat-pool
 * discovery worker's per-IP port loop + early-bail heuristic (fast_syn.cc).
 *
 * The refactor replaced a two-level (outer-IP x inner-port) thread design
 * with a single flat pool where each worker probes one IP's ports
 * SEQUENTIALLY with a thread-local bail counter. This test verifies that
 * sequential logic against an INDEPENDENT oracle, over millions of
 * randomized host profiles, so we are grounded in fact rather than
 * reasoning about thread behaviour.
 *
 * Contract (must hold for every host):
 *   - Ports are probed in order; the first non-timeout reply (CLOSED or
 *     OPEN) marks the host alive (sticky) and permanently disables bail.
 *   - A bail (skip remaining ports) happens IFF the host has >= BAIL_AFTER
 *     ports AND the first BAIL_AFTER probes are ALL timeouts -- because any
 *     non-timeout among them would have set alive and disabled the bail.
 *   - On bail: exactly BAIL_AFTER probes are issued, and no OPEN is found
 *     (the first BAIL_AFTER were all timeouts by definition).
 *   - Otherwise every port is probed and every OPEN is discovered.
 *
 * Build (MinGW, here):
 *   g++ -O2 -g -std=gnu++17 -Wall fuzz/test_discover_bail.cc \
 *       -o fuzz/test_discover_bail.exe && fuzz/test_discover_bail.exe
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <set>

enum class ProbeResult { OPEN, CLOSED, TIMEOUT };

static const int BAIL_AFTER = 8;

/* The exact loop logic from fast_syn.cc's flat worker, lifted verbatim so
 * the test exercises the same algorithm under test. */
static std::set<int> run_worker_logic(const std::vector<ProbeResult> &outcomes,
                                      int &probes_issued) {
  std::set<int> found;
  int timeout_streak = 0;
  bool any_response = false;
  probes_issued = 0;

  for (size_t i = 0; i < outcomes.size(); i++) {
    ProbeResult pr = outcomes[i];
    probes_issued++;
    if (pr == ProbeResult::TIMEOUT) {
      if (!any_response && ++timeout_streak >= BAIL_AFTER) break;
    } else {
      any_response = true;
      if (pr == ProbeResult::OPEN) found.insert((int)i);
    }
  }
  return found;
}

/* INDEPENDENT oracle -- derives the expected result from the contract via
 * a different formulation than the loop under test (no streak counter; it
 * decides bail by inspecting the leading window directly). */
static std::set<int> oracle_expected(const std::vector<ProbeResult> &outcomes,
                                     int &expected_probes) {
  int n = (int)outcomes.size();

  bool bail = false;
  if (n >= BAIL_AFTER) {
    bail = true;
    for (int i = 0; i < BAIL_AFTER; i++)
      if (outcomes[i] != ProbeResult::TIMEOUT) { bail = false; break; }
  }

  std::set<int> expected;
  if (bail) {
    expected_probes = BAIL_AFTER;     /* first 8 all timeout -> no opens */
  } else {
    expected_probes = n;
    for (int i = 0; i < n; i++)
      if (outcomes[i] == ProbeResult::OPEN) expected.insert(i);
  }
  return expected;
}

/* deterministic xorshift so the run is reproducible (no wall-clock seed). */
static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint32_t rnd() {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return (uint32_t)(rng_state >> 32);
}

int main(int argc, char **argv) {
  if (argc > 1) rng_state = (uint64_t)atoll(argv[1]) * 2654435761ULL + 1;

  int passed = 0, failed = 0;
  ProbeResult T = ProbeResult::TIMEOUT, C = ProbeResult::CLOSED,
              O = ProbeResult::OPEN;

  /* ---- Hand-built cases with LITERAL human-verified expectations. */
  struct Case {
    const char *name;
    std::vector<ProbeResult> o;
    std::set<int> expect_open;
    int expect_probes;
  };
  std::vector<Case> cases = {
    {"single-open",                {O},                       {0},   1},
    {"single-timeout",             {T},                       {},    1},
    {"all-timeout-dead-host",      {T,T,T,T,T,T,T,T,T,T,T,T},  {},    8},
    {"rst-then-late-open",         {C,T,T,T,T,T,T,T,T,O},      {9},  10},
    {"open-at-7-just-before-bail", {T,T,T,T,T,T,T,O},          {7},   8},
    {"open-after-8-timeouts-MISS", {T,T,T,T,T,T,T,T,O},        {},    8},
    {"alive-then-many-timeouts",   {O,T,T,T,T,T,T,T,T,T,T},    {0},  11},
    {"closed-disables-bail",       {T,T,C,T,T,T,T,T,T,T,T,O},  {11}, 12},
    {"seven-timeouts-no-bail",     {T,T,T,T,T,T,T},            {},    7},
  };
  for (auto &cs : cases) {
    int pi = 0;
    auto got = run_worker_logic(cs.o, pi);
    if (got == cs.expect_open && pi == cs.expect_probes) {
      passed++;
    } else {
      failed++;
      printf("  FAIL [%s]: opens=%zu (exp %zu) probes=%d (exp %d)\n",
             cs.name, got.size(), cs.expect_open.size(), pi, cs.expect_probes);
    }
    /* cross-check the oracle agrees with the literal expectation too */
    int oi = 0;
    auto orc = oracle_expected(cs.o, oi);
    if (!(orc == cs.expect_open && oi == cs.expect_probes)) {
      failed++;
      printf("  FAIL [%s/oracle-mismatch]: oracle disagrees with literal\n",
             cs.name);
    } else {
      passed++;
    }
  }

  /* ---- Randomized fuzz: code-under-test vs independent oracle. */
  const int N = 3000000;
  int rand_fail = 0;
  for (int n = 0; n < N; n++) {
    int nports = 1 + (rnd() % 130);             /* 1..130 ports */
    std::vector<ProbeResult> o(nports);
    for (int i = 0; i < nports; i++) {
      uint32_t r = rnd() % 100;                 /* timeout-heavy, like the net */
      if (r < 80)      o[i] = ProbeResult::TIMEOUT;
      else if (r < 95) o[i] = ProbeResult::CLOSED;
      else             o[i] = ProbeResult::OPEN;
    }
    int pi = 0, oi = 0;
    auto got = run_worker_logic(o, pi);
    auto exp = oracle_expected(o, oi);
    if (got == exp && pi == oi) {
      passed++;
    } else {
      failed++;
      if (++rand_fail <= 5)
        printf("  FAIL [rand n=%d nports=%d]: opens %zu vs %zu, probes %d vs %d\n",
               n, nports, got.size(), exp.size(), pi, oi);
    }
  }

  printf("\ndiscover-bail test: %d passed, %d failed (%d random hosts vs oracle)\n",
         passed, failed, N);
  return failed == 0 ? 0 : 1;
}
