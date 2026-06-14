/*
 * test_admit_reentry.cc -- proves the try_admit() re-entrancy guard in
 * net_enrich_async.cc converts unbounded recursion into iteration.
 *
 * The async enrich driver admits hosts up to max_in_flight, and each host
 * finalizes (frees its slot and admits the next pending host) from inside
 * a callback. When a host finalizes SYNCHRONOUSLY inside the admit loop --
 * which happens when submit_port_connect's nsock_iod_new() fails, e.g. once
 * max_in_flight * ports_per_host exceeds the process FD limit (default
 * ulimit -n = 1024 on Linux) -- finalize_host() calls try_admit() again
 * before the in-progress admit loop has returned. Without a guard that
 * nests one level deep per pending host: on a multi-thousand-host batch the
 * call stack blows up and the scanner crashes mid-sweep.
 *
 * This test models the admit/port_done/finalize_host/try_admit cycle
 * EXACTLY as written in net_enrich_async.cc, with every submit forced to
 * fail synchronously (the worst case), and measures peak recursion depth.
 *
 *   - WITH the guard: depth stays <= 2 regardless of batch size, and every
 *     host is admitted+finalized exactly once.
 *   - WITHOUT the guard: depth grows ~linearly with the batch (we cap it so
 *     the test itself can't stack-overflow, and assert the cap is hit) --
 *     demonstrating the bug the guard fixes.
 *
 * Build (MinGW, here):
 *   g++ -O2 -g -std=gnu++17 -Wall fuzz/test_admit_reentry.cc \
 *       -o fuzz/test_admit_reentry.exe && fuzz/test_admit_reentry.exe
 */

#include <cstdio>
#include <cstdint>
#include <deque>
#include <vector>

/* Hard cap so the UNGUARDED model can't actually overflow the real stack
   while we demonstrate that it recurses without bound. Comfortably above
   the guarded ceiling (2) and below anything that risks a crash. */
static const int DEPTH_CAP = 4096;

struct Model {
  bool   use_guard;
  size_t max_in_flight;
  size_t active_count;
  bool   in_try_admit;

  std::deque<size_t> pending;
  std::vector<int>   ports_remaining;   /* per host */
  std::vector<int>   admit_count;       /* per host: must end == 1 */
  std::vector<int>   finalize_count;    /* per host: must end == 1 */
  size_t hosts_completed;

  /* instrumentation */
  int cur_depth;
  int max_depth;
  bool cap_hit;
};

static void try_admit(Model &m);

/* finalize_host: free the slot and pull in the next pending host -- the
   recursive call back into try_admit is the whole point. */
static void finalize_host(Model &m, size_t h) {
  m.active_count--;
  m.finalize_count[h]++;
  m.hosts_completed++;
  try_admit(m);
}

/* port_done: decrement the host's outstanding-port counter; finalize on the
   last port. Mirrors net_enrich_async.cc::port_done. */
static void port_done(Model &m, size_t h) {
  if (--m.ports_remaining[h] > 0) return;
  finalize_host(m, h);
}

/* submit_port_connect, forced into its synchronous-failure branch (the
   nsock_iod_new()==NULL path) -- exactly what FD exhaustion triggers. */
static void submit_port_connect(Model &m, size_t h) {
  port_done(m, h);
}

/* try_admit, lifted from net_enrich_async.cc including the re-entrancy
   guard (toggled by use_guard so we can show both behaviours). */
static void try_admit(Model &m) {
  m.cur_depth++;
  if (m.cur_depth > m.max_depth) m.max_depth = m.cur_depth;
  if (m.cur_depth >= DEPTH_CAP) { m.cap_hit = true; m.cur_depth--; return; }

  if (m.use_guard && m.in_try_admit) { m.cur_depth--; return; }
  m.in_try_admit = true;

  while (m.active_count < m.max_in_flight && !m.pending.empty()) {
    size_t h = m.pending.front();
    m.pending.pop_front();

    int nports = m.ports_remaining[h];   /* preset by caller */
    m.admit_count[h]++;
    m.active_count++;

    for (int pi = 0; pi < nports; pi++)
      submit_port_connect(m, h);
  }

  m.in_try_admit = false;
  m.cur_depth--;
}

static int run_case(bool use_guard, size_t n_hosts, size_t max_in_flight,
                    int ports_per_host) {
  Model m{};
  m.use_guard     = use_guard;
  m.max_in_flight = max_in_flight;
  m.active_count  = 0;
  m.in_try_admit  = false;
  m.hosts_completed = 0;
  m.cur_depth = 0; m.max_depth = 0; m.cap_hit = false;

  m.ports_remaining.assign(n_hosts, ports_per_host);
  m.admit_count.assign(n_hosts, 0);
  m.finalize_count.assign(n_hosts, 0);
  for (size_t i = 0; i < n_hosts; i++) m.pending.push_back(i);

  try_admit(m);            /* initial kick, same as async_enrich_batch */

  int failed = 0;

  /* Whatever the depth behaviour, correctness must hold: every host
     admitted exactly once and finalized exactly once, and all completed. */
  for (size_t i = 0; i < n_hosts; i++) {
    if (m.admit_count[i] != 1)    { failed++; if (failed <= 3) printf("  host %zu admit_count=%d (want 1)\n", i, m.admit_count[i]); }
    if (m.finalize_count[i] != 1) { failed++; if (failed <= 3) printf("  host %zu finalize_count=%d (want 1)\n", i, m.finalize_count[i]); }
  }
  if (m.hosts_completed != n_hosts) { failed++; printf("  hosts_completed=%zu (want %zu)\n", m.hosts_completed, n_hosts); }
  if (m.active_count != 0)          { failed++; printf("  active_count=%zu (want 0)\n", m.active_count); }
  if (!m.pending.empty())           { failed++; printf("  pending not drained (%zu left)\n", m.pending.size()); }

  printf("  [%s] hosts=%zu inflight=%zu ports=%d -> max_depth=%d%s, completed=%zu, errors=%d\n",
         use_guard ? "guard" : "NOGRD", n_hosts, max_in_flight, ports_per_host,
         m.max_depth, m.cap_hit ? " (CAP HIT)" : "",
         m.hosts_completed, failed);
  return failed;
}

int main(void) {
  printf("try_admit re-entrancy guard test\n");
  printf("================================\n");

  int failed = 0;

  /* 1. The headline scenario: every submit fails synchronously (FD
        exhaustion). With the guard, depth must stay tiny no matter how
        many hosts; correctness must hold. */
  printf("\nGuarded (correctness + bounded depth under sync-fail storm):\n");
  {
    int f = 0;
    f += run_case(true,   100, 64, 1);
    f += run_case(true,  5000, 64, 1);
    f += run_case(true, 50000, 64, 1);
    f += run_case(true,  5000, 64, 17);   /* multi-port hosts */
    f += run_case(true,     1,  1, 1);    /* degenerate */
    f += run_case(true,     0,  1, 1);    /* empty batch */
    /* Guarded depth ceiling: outer call (1) + one bounced re-entrant
       probe (2). Anything above 2 means the guard regressed. */
    Model m{};
    m.use_guard=true; m.max_in_flight=64; m.in_try_admit=false;
    m.ports_remaining.assign(20000,1); m.admit_count.assign(20000,0);
    m.finalize_count.assign(20000,0);
    for (size_t i=0;i<20000;i++) m.pending.push_back(i);
    try_admit(m);
    if (m.max_depth > 2) { printf("  FAIL: guarded max_depth=%d > 2\n", m.max_depth); f++; }
    else printf("  guarded ceiling check: max_depth=%d (<=2) OK\n", m.max_depth);
    failed += f;
  }

  /* 2. Demonstrate the bug the guard prevents: WITHOUT the guard the same
        sync-fail storm recurses until it hits our safety cap. (Correctness
        of admit/finalize counts still holds -- the danger is purely the
        stack depth, which in the real binary is a crash.) */
  printf("\nUnguarded (shows unbounded recursion -- depth hits safety cap):\n");
  {
    int correctness = run_case(false, 5000, 64, 1);
    failed += correctness;
    /* The unguarded model MUST hit the cap, proving it recurses without
       bound (real code would stack-overflow here instead). */
    Model m{};
    m.use_guard=false; m.max_in_flight=64; m.in_try_admit=false;
    m.ports_remaining.assign(5000,1); m.admit_count.assign(5000,0);
    m.finalize_count.assign(5000,0);
    for (size_t i=0;i<5000;i++) m.pending.push_back(i);
    try_admit(m);
    if (!m.cap_hit) { printf("  FAIL: expected unguarded recursion to hit depth cap, max_depth=%d\n", m.max_depth); failed++; }
    else printf("  unguarded recursion hit cap at depth %d (this is the crash the guard prevents) OK\n", m.max_depth);
  }

  printf("\n%s\n", failed == 0 ? "admit-reentry test: ALL PASS" : "admit-reentry test: FAILURES");
  return failed == 0 ? 0 : 1;
}
