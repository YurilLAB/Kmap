# Performance roadmap

Where Kmap's throughput is bound today, and the changes that would lift it —
ranked by `(expected gain × likelihood it's the binding constraint) ÷ effort`.
Gains are stated against shipped defaults. Source anchors let each item be
picked up directly. See [`../bench/`](../bench/) for the measured baselines this
backlog is reasoned against, and [performance.md](performance.md) for tuning the
current build.

## The binding constraint

The discovery path is a **thread-per-probe `connect()` sweep**: a filtered IP
pins one OS thread for the whole probe timeout, so the sweep rate is
`workers / timeout` — about **200 IPs/sec at shipped defaults** (100 workers,
500 ms), ~125× below the 25,000-pps `--rate` ceiling, which therefore never
engages. Everything downstream (CPU primitives at 10⁷–10⁹ ops/sec, DB writes at
~7,900 hosts/sec) has ample headroom. **The connect model is the ceiling**, and
the top two discovery items below are about removing it.

## Backlog

| # | Subsystem | Change | Expected gain | Effort |
|---|---|---|---|---|
| 1 | Discovery (`fast_syn.cc`) | Replace thread-per-probe `connect()` with a single-threaded **async epoll/IOCP** engine (non-blocking connect + writability/timeout reaping, tens of thousands in flight per thread). Token bucket + shard writes already work per-event. | **~100×** on dark space (~200 → the 25k-pps ceiling) | High (~1 wk + epoll/IOCP split) |
| 2 | Screenshots (`web_recon.cc`) | Bounded **N-way browser process pool** for `spawn_browser` + a per-shot deadline. Removes the serial `waitpid`/`WaitForSingleObject(INFINITE)` and the one-hung-target-stalls-the-run failure mode. | **~N×** (near-linear) + robustness | Low–Med |
| 3 | Enrichment (`net_enrich_async.cc`) | Validate, then **promote `KMAP_ASYNC_ENRICH` to on-by-default** (A/B it). A single nsock loop holds 64 host×ports in flight, lifting the `concurrency/avg_host_time` blocking ceiling (sync floor ≈ 6 hps). | Largest enrichment-throughput lever | Low (flag) + Med (A/B) |
| 4 | Enrichment (`net_enrich.cc`) | **Batch the ASN lookup** out of the synchronous Stage-B worker (rDNS is already batched; ASN was left behind and blocks up to 2 s/host). | Removes up to 2 s worst-case blocking per host | Med |
| 5 | Enrichment RAM (`net_enrich.cc`) | **Per-shard flush / rolling window** instead of one global `results` vector across all 32 shards. | Up to **32× lower** enrichment peak RSS | Med |
| 6 | Enrichment (`net_enrich.cc`) | **Gate or pipeline the favicon GET** (an extra TCP connect per web host) behind a flag, or fold it onto a keep-alive socket. | ~15–30% fewer connects on web hosts | Low |
| 7 | Discovery (`fast_syn.cc`) | True **raw-SYN sender** (AF_PACKET/pcap, stateless source-port cookie, zmap-style) as an opt-in privileged fast path; `connect()` stays the unprivileged fallback. | **1000×+** over `connect()` (Mpps, link/`--rate` bound) | Highest (root + RX state machine; do after #1) |
| 8 | DB write (`net_db.cc`) | **Per-shard prepared statements** (`reset`+`bind`, `SQLITE_STATIC`, IP as int64) instead of `prepare_v2`+`finalize` per row, on both insert and Stage-C update paths. | 5–10× lower per-insert CPU, zero heap churn (matters once #1/#7 raise the probe rate) | Low |
| 9 | Enrichment CPU (`net_enrich.cc`) | **Cache the `os_profile`/HTTP-request string per host** (currently rebuilt up to 3× per port). | Small CPU; free hps at high concurrency | Low |
| 10 | Async path (`net_scan.cc`) | Give the async pre-pass **per-worker `cve_db` handles** rather than the shared handle. | Unblocks horizontal scaling of the async path | Low |
| 11 | DB IO (`net_db.cc`) | `PRAGMA page_size=8192` + `mmap_size` **before first write** (shrinks overflow-page chains for `cves`/`web_headers` blobs and the fingerprints B-tree). | Modest IO + tighter on-disk size at full-sweep scale | Low |
| 12 | Rate limiter (`fast_syn.cc`) | Sleep the **computed time-to-next-token** instead of a fixed 100 µs / 1 ms. | Small CPU + smoother pacing at ≥512 workers | Low |

The IPv4 permutation is already O(1) (affine multiplicative-inverse map, no
materialised address list — confirmed no RAM/alloc fix needed). Swapping it for
a keyed Feistel would improve dispersion at zero memory cost, but only if better
randomisation is ever wanted.

## Suggested sequence

1. **#8 + #11** (low-effort DB wins) — cheap, and they stop the write path from
   becoming the next bottleneck once discovery speeds up.
2. **#2** (screenshot pool) — self-contained, removes a real stall risk.
3. **#3 / #5 / #6** (enrichment throughput + RAM) — the enrichment phase is the
   second ceiling after discovery.
4. **#1** (async connect engine) — the headline discovery speedup; biggest
   single lever, biggest effort.
5. **#7** (raw-SYN) — only after #1, for the privileged Mpps tier.
