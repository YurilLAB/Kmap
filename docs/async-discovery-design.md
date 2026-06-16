# Async discovery engine — design

Implementation-ready design for the **#1 lever** in
[performance-roadmap.md](performance-roadmap.md): replacing the thread-per-probe
`connect()` discovery model with a single-threaded **async** engine that holds
tens of thousands of connects in flight, lifting dark-space discovery from
~200 IPs/sec (shipped default) toward the `--rate` ceiling (~100×).

> **Status: design, not yet implemented.** The engine is a rewrite of the most
> invariant-laden hot path (`fast_syn.cc`) and is async/stateful, so it must be
> **runtime-validated** before it ships — the analogous `net_enrich_async.cc`
> needed several bug-fix iterations (iod leaks, re-entrant `try_admit` stack
> overflow, FD exhaustion) that were only caught by running it. It will land
> **opt-in** (`KMAP_ASYNC_DISCOVERY=1`, default off) with the connect-thread
> pool preserved as the default until validated.

## Why nsock, not raw epoll/IOCP

The roadmap said "epoll/IOCP", but the in-tree **`nsock`** library already
abstracts epoll/kqueue/poll/IOCP cross-platform and is battle-tested.
`net_enrich_async.cc` already drives thousands of concurrent connects through one
`nsock_pool` on a single thread (callbacks run between `nsock_loop()` iterations,
never concurrently — `net_enrich_async.cc:99-100`). Reusing that pattern gives
all five target platforms (Linux/BSD/macOS/Solaris/Windows) for free and avoids
hand-rolling three readiness backends. **Decision: nsock.**

## Architecture (mirrors net_enrich_async, simpler)

Discovery is strictly simpler than enrichment: connect → classify → done. No
banner/HTTP/TLS stages.

```
struct AsyncDiscovery {
  nsock_pool pool;
  size_t     max_in_flight;     // admission cap (e.g. KMAP_NETSCAN_CONCURRENCY, but
                                //   async can go far higher — fd-bound, not thread-bound)
  size_t     active_count;      // connects currently outstanding
  bool       in_try_admit;      // re-entrancy guard (net_enrich_async.cc:801-809)
  uint64_t   next_index;        // permutation cursor (the IP source)
  uint64_t   total;             // 2^32 or the bounded count
  RateLimiter rate;             // the EXISTING token bucket, reused verbatim
  // ... seed, excludes, ports, shard write buffers, low-water tracking ...
};

struct AsyncProbe { uint32_t ip; int port; uint64_t index; nsock_iod iod; };
```

- **Admission** (`try_admit`): while `active_count < max_in_flight` and the
  permutation isn't exhausted and not interrupted: pull the next IP from
  `permute_ip(next_index++)`, skip `is_excluded`, gate on the token bucket
  (`rate_wait` — see *Rate pacing* below), then `nsock_iod_new` +
  `nsock_connect_tcp(on_connect, timeout, probe)`. Guard the whole loop with
  `in_try_admit` exactly as `net_enrich_async.cc:801-809` (a synchronous
  `nsock_iod_new` failure under FD exhaustion finalizes inline and re-enters).
- **Classification** (`on_connect`): mirror the status switch at
  `net_enrich_async.cc:904-919`.
  - `NSE_STATUS_SUCCESS` → port **OPEN**: record the alive host (sticky).
  - `NSE_STATUS_ERROR` with `ECONNREFUSED` → **CLOSED** (host alive).
  - `NSE_STATUS_TIMEOUT` / other → **filtered** (no host).
  - `NSE_STATUS_KILL` → `iod = NULL; return;` (shutdown path).
  Then `close_iod(probe)`, `active_count--`, and `try_admit` again
  (recursion → iteration via the guard).
- **`close_iod` discipline**: every terminal path closes the iod before
  re-admitting (the leak class fixed in `net_enrich_async.cc` — every dispatch
  entry preceded by `close_iod` or a still-NULL iod).
- **Loop**: `nsock_loop(pool, timeout)` in a drive loop until the permutation is
  exhausted **and** `active_count == 0` **and** the interrupt flag is clear.

## Preserving the fast_syn invariants (the hard part)

Each must be re-established in the async model (source: `fast_syn.cc`):

| Invariant | How async preserves it |
|---|---|
| **Token-bucket rate** (`rate_init`/`rate_wait`, unlimited by default) | Reuse verbatim (incl. the `unlimited` short-circuit). In a single-thread loop, call `rate_wait` in `try_admit` before each `nsock_connect_tcp`; when throttled and no token is available, schedule the next admission with an `nsock_timer` for the computed time-to-next-token instead of busy-waiting. |
| **Permutation** (`permute_ip`, affine bijection) | The IP source for `try_admit`. `next_index` is the cursor; O(1), no materialised list — unchanged. |
| **Exclusions** (`is_excluded`) | Checked per candidate IP in `try_admit` before connecting — unchanged. |
| **Checkpoint / resume** (the per-worker low-water-mark) | **The riskiest piece.** In flight, probes complete out of order, so the resume point is `min(index of every outstanding AsyncProbe, next_index − active_count)` — the async analogue of `compute_low_water()`. **v1 recommendation: do NOT support `--net-resume` in async mode** (warn + run without checkpoint). Resume is the one part whose correctness is data-loss-critical and unverifiable without a real crash-resume cycle; add it only with that validation. |
| **DB write** (per-shard, serial) | Buffer alive hosts in the single loop thread and flush per shard in batches (no worker→DB writes; the loop thread is the only writer — naturally serial). |
| **Signal handling** (SIGINT flag / `SetConsoleCtrlHandler`) | Reuse the existing flag; check it in the drive loop and stop admitting (let in-flight drain, then final flush). |
| **Windows `timeBeginPeriod`** | nsock owns its own timing; the manual `Sleep(1)` precision hack is not needed in the async path. |

## Rate pacing in a single-thread loop

The connect-thread model paces implicitly (N threads × 1/timeout). The async loop
must pace explicitly: in `try_admit`, consume a token per connect; when the bucket
is empty, arm one `nsock_timer` for the refill interval and return — the timer
callback calls `try_admit` again. This keeps the send rate at exactly `--rate`
without a busy loop, and is why the (now 1e9) `--rate` cap matters: async is the
first engine that can actually approach it.

## Expected throughput

- Connect-thread (today): `workers / timeout` ≈ 200 IPs/sec at defaults.
- Async: bound by `min(--rate, fd_limit / avg_connect_lifetime)`. With
  `max_in_flight` = 20–50k (raise `RLIMIT_NOFILE`, already done for the sync
  path) and a 1–3 s timeout, the engine sustains tens of thousands of pps on one
  thread — rate-bound, not thread-bound. ~100× on dark space.

## Opt-in gating

- `KMAP_ASYNC_DISCOVERY=1` (or `--async-discovery`) selects the engine; default
  is the proven connect-thread pool.
- On enable, print a loud `EXPERIMENTAL` warning to stderr + `kmap.log`.
- `--net-resume` with async mode → warn "resume not supported in async mode" and
  run a fresh sweep.

## Test plan

Unit-testable **without** a binary/network (add to `fuzz/`):
- The IP source: `permute_ip` + `is_excluded` iteration yields every non-excluded
  IP exactly once (already covered by `fuzz_core` / `test_excludes`).
- The admission accounting: `active_count` never exceeds `max_in_flight`; the
  loop terminates iff permutation exhausted and `active_count == 0`
  (model test with injected completions, like `test_admit_reentry.cc`).
- The classification map: status → OPEN/CLOSED/filtered (pure function test).
- The async low-water (if resume is implemented): the resume index never exceeds
  the lowest outstanding probe index (model test like `test_lowwater.cc`).

Needs a **live** binary + a safe target (loopback / TEST-NET-1 per
[`../bench/measure-live.sh`](../bench/measure-live.sh)):
- End-to-end: a localhost sweep finds the same OPEN/CLOSED set as the connect
  engine (correctness parity).
- A crash-resume cycle (only if resume is implemented).
- The sustained pps vs the connect engine on a controlled range (the ~100×).

## File plan

- New `async_discovery.{cc,h}` — the `AsyncDiscovery` engine, `nsock`-based,
  mirroring `net_enrich_async.cc`'s admission/`close_iod` discipline. Reuses
  `permute_ip` / `is_excluded` / `RateLimiter` / `raise_fd_limit` from
  `fast_syn.cc` (extract the shared ones to `fast_syn.h` if needed).
- `net_scan.cc` `run_net_scan`: when `KMAP_ASYNC_DISCOVERY=1`, call the async
  discovery instead of `run_fast_syn` for the discovery phase; enrichment phase
  unchanged.
- `Makefile.in` + `mswin32/kmap.vcxproj` parity for the new TU.
- `KmapOps` flag + the 3-place CLI wiring if a `--async-discovery` flag is added.

## Why this is design-first

Everything above is mechanical to write, but its correctness lives in runtime
behaviour the dev box cannot exercise (no built binary, no network): the loop
termination, the rate-timer pacing, the `close_iod` leak discipline at scale, and
(if added) the resume low-water. `net_enrich_async.cc`'s history shows these are
exactly the bugs that only surface under a real run. The engine should be
implemented against this design in an environment where the live tests above can
gate it before it goes anywhere near default-on.
