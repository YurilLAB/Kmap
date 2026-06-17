# Performance roadmap

Where Kmap's throughput is bound today, and the changes that would lift it —
ranked by `(expected gain × likelihood it's the binding constraint) ÷ effort`.
Gains are stated against shipped defaults. Source anchors let each item be
picked up directly. See [`../bench/`](../bench/) for the measured baselines this
backlog is reasoned against, and [performance.md](performance.md) for tuning the
current build.

## The binding constraint

Discovery now ships **two** engines. When raw packets are available it uses a
**stateless raw-SYN engine** (item #7, shipped) that is send-bound — on a 50k
random sample it ran **4.4× faster than `connect()`** (13.7 s vs 60.4 s) because
it never waits out a dark-IP timeout. Where raw packets are unavailable it falls
back to the **thread-per-probe `connect()` sweep**: a filtered IP pins one OS
thread for the whole probe timeout, so the fallback rate is `workers / timeout` —
about **200 IPs/sec at shipped defaults** (100 workers, 500 ms). The send rate is
now **unlimited by default** (the old 25k-pps `--rate` ceiling was removed; pass
`--rate` to throttle), so on the connect path `workers / timeout` is the only
ceiling and on the raw path it is now the **NIC/driver packet rate** — the
templated+batched TX sustains **~90k pps** (≈9× the old per-packet `send_tcp_raw`
loop), which is this adapter's Npcap per-send ceiling and crosses into
masscan/zmap territory on faster send paths. Everything downstream (CPU primitives
at 10⁷–10⁹ ops/sec, the bulk-insert DB flush) has ample headroom. **The connect fallback is still
the ceiling on dark space**, and item #1 (async connect) targets exactly that;
the raw engine already removes it where privileges allow.

## Backlog

| # | Subsystem | Change | Expected gain | Effort |
|---|---|---|---|---|
| 1 | Discovery (`fast_syn.cc`) | Replace thread-per-probe `connect()` with a single-threaded **async** engine (nsock, reusing the proven `net_enrich_async.cc` pattern — cross-platform for free) holding tens of thousands of connects in flight. **Implementation-ready design: [async-discovery-design.md](async-discovery-design.md).** Token bucket + shard writes reused per-event. | **~100×** on dark space (~200 IPs/sec → tens of thousands in flight) for the unprivileged path | High (needs live validation) |
| 2 | Screenshots (`web_recon.cc`) | Bounded **N-way browser process pool** for `spawn_browser` + a per-shot deadline. Removes the serial `waitpid`/`WaitForSingleObject(INFINITE)` and the one-hung-target-stalls-the-run failure mode. | **~N×** (near-linear) + robustness | Low–Med |
| 3 | Enrichment (`net_enrich_async.cc`) | Validate, then **promote `KMAP_ASYNC_ENRICH` to on-by-default** (A/B it). A single nsock loop holds 64 host×ports in flight, lifting the `concurrency/avg_host_time` blocking ceiling (sync floor ≈ 6 hps). | Largest enrichment-throughput lever | Low (flag) + Med (A/B) |
| 4 | Enrichment (`net_enrich.cc`) | **Batch the ASN lookup** out of the synchronous Stage-B worker (rDNS is already batched; ASN was left behind and blocks up to 2 s/host). | Removes up to 2 s worst-case blocking per host | Med |
| 5 | Enrichment RAM (`net_enrich.cc`) | **Per-shard flush / rolling window** instead of one global `results` vector across all 32 shards. | Up to **32× lower** enrichment peak RSS | Med |
| 6 | Enrichment (`net_enrich.cc`) | **Gate or pipeline the favicon GET** (an extra TCP connect per web host) behind a flag, or fold it onto a keep-alive socket. | ~15–30% fewer connects on web hosts | Low |
| 7 | Discovery (`fast_syn.cc`) | **SHIPPED + upgraded to masscan/zmap-class.** Stateless raw-SYN engine, now with a **54-byte packet template** patched per probe with an **incremental (RFC 1624) checksum** (no per-packet rebuild/malloc/re-sum); **batched transmit** (Npcap `pcap_sendqueue` on Windows, tight `netutil_eth_send` loop on POSIX); optional **multi-handle TX sharding** (`KMAP_RAWSYN_TX_THREADS`); **decoupled RX** — opens buffered in memory and **flushed after the sweep** (7a done), so discovery never blocks on SQLite; a **buffered `pcap_dispatch` RX** (bypasses the Windows nonblock-toggle in `readip_pcap`; reads the SYN-ACK burst in batches, zero drops); and a **time-based drain** (silence since last *new* open, immune to retransmit storms). **Measured ~10k->~90k pps TX (~9x)** and ~28-38k IPs/sec on a sparse real sample, ~90k being this adapter's Npcap ceiling. Dense-range note: on a dense `/20` the inbound rate is ~1.3k/s and **identical for Cloudflare and Fastly**, which pins the limit on the residential inbound path (router/ISP new-flow rate-limit), not on Kmap or the target. **(7b)** stateless per-pass `--retries` is still open — closes the ~0.2-0.4 % single-shot completeness gap at unlimited rate. | Shipped; 7b: Med | Done |
| 8 | DB write (`net_db.cc`) | **SHIPPED (insert path)** — `net_db_insert_opens_bulk()` prepares the UPSERT **once** and reuses it (reset+bind+step) for the whole post-discovery flush, grouped per shard, instead of `prepare_v2`+`finalize` per row. Removes the per-row SQL recompile from the decoupled flush. The Stage-C enrichment `UPDATE` path can still get the same treatment. | Insert done; update: Low | Mostly done |
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
4. **#1** (async connect engine) — the headline speedup for the *unprivileged*
   fallback; biggest single lever there, biggest effort.
5. **#7a/#7b** (raw-engine follow-ups) — move the RST/insert off the RX hot path
   so raw also wins on dense ranges, then add `--retries` for completeness. The
   raw engine itself is already shipped and default-on where privileges allow.
