# Performance & resource tuning

Kmap is built to run mass internet-scale reconnaissance from an ordinary
**gaming PC** — not server-grade hardware. The discovery path is dominated by
network round-trip time (RTT), not local CPU or RAM: an instrumented 150-IP
probe wave runs at roughly **1–2% CPU and ~23 MB RSS**, because workers spend
almost all their time blocked in `connect()`/`select()` waiting on the
network. That means the limiting factor is your link and the targets'
responsiveness, and a typical 8–16 core / 16–32 GB desktop has ample headroom
to keep thousands of probes in flight.

This page documents the knobs that control how hard Kmap leans on your machine
and how fast it scans. **Every default and bound below is taken directly from
the source** (`sys_resources.cc`, `cpu_meter.cc`, `fast_syn.cc`, `net_scan.cc`,
`net_enrich.cc`); when in doubt the code wins.

---

## Performance modes

Kmap has three resource profiles. Without a flag it uses the **normal**
profile (fixed legacy defaults, still env-tunable). Two flags opt into
resource-aware scaling that derives worker-pool sizes from your *detected*
hardware rather than hardcoded thread counts:

| Flag           | Profile    | CPU share | RAM share | Intent                                            |
|----------------|------------|-----------|-----------|---------------------------------------------------|
| *(none)*       | normal     | unbounded | unbounded | Fixed defaults; the env vars below still apply    |
| `--efficient`  | efficient  | ~12.5%    | ~5%       | Low footprint; run scans in the background        |
| `--fast`       | fast       | 50%       | 25%       | Resource-aware speed-up, capped so the box stays usable |

`--efficient` and `--fast` are **mutually exclusive** (passing both is a fatal
error). Both scale with the cores/RAM Kmap detects, so the same binary is
gentle on a laptop and aggressive on a 16-core desktop without a rebuild.

### Tuning the `--fast` share

The `--fast` caps are themselves adjustable, so a dedicated scan box can use
more of the machine while an everyday workstation stays responsive:

| Flag                          | Range   | Default | Effect                                   |
|-------------------------------|---------|---------|------------------------------------------|
| `--fast-cpu-percent <1-100>`  | 1–100   | 50      | Share of logical cores `--fast` may use  |
| `--fast-mem-percent <1-100>`  | 1–100   | 25      | Share of available RAM `--fast` may use  |

Passing either flag implies `--fast` (you don't also need to pass `--fast`).
Example — a dedicated scan on a gaming PC, using most of the machine:

```
kmap --net-scan --fast-cpu-percent 85 --fast-mem-percent 60 <targets>
```

### How the share becomes worker pools

In `--fast`, Kmap computes `units = round(cores × cpu_percent / 100)` and sizes
two pools from it (both then clamped, and further capped so their worst-case
in-flight memory footprint stays inside the RAM budget):

- **discovery** workers (connect probes): `clamp(units × 64, 50 … 1024)`
- **enrichment** workers (banner/CVE/HTTP/TLS): `clamp(units × 16, 20 … 256)`

`--efficient` uses much smaller multipliers (`units × 8` discovery,
`units × 4` enrichment) with low ceilings (64 / 24).

---

## The CPU governor

The CPU share is enforced by a **cooperative governor**, layered on top of the
two *hard* caps that do most of the work: the bounded worker pools (above) and
the memory budget. The governor only runs during the **enrichment** phase
(discovery is already ~1–2% CPU, RTT-bound, so it needs no throttling).
Enrichment workers call it between hosts; it injects small micro-sleeps when
sustained CPU runs hot, with a ±3% deadband so it doesn't hunt once converged
and a hard ceiling of 250 ms of sleep per call. It is a no-op in normal mode.

It is a **soft** target, not a hard real-time clamp: because enrichment is
I/O-bound (workers spend most of their time blocked on TLS/HTTP/banner RTTs),
actual CPU sits well under the share in practice and the governor rarely needs
to engage hard. Under an artificial sustained pure-CPU load it *reduces* CPU
rather than pinning it to the exact target — the firm guarantees are the
bounded thread count and the memory budget, with the governor smoothing the
CPU on top. (`fuzz/test_governor.cc` is a live harness that drives the real
governor and measures this behavior.)

Disable it entirely (let enrichment run unthrottled) with:

```
KMAP_NO_CPU_GOVERNOR=1
```

---

## Discovery rate

`--rate <pps>` sets the global packets-per-second target for discovery,
enforced by a shared token bucket across all discovery workers (**default
25000 pps**, range 1–10000000). The rate limiter is the *last* thing to
saturate: if you have CPU and bandwidth headroom and want a faster sweep,
raise the discovery concurrency first, then raise `--rate`.

The internet-scale SYN scanner (`fast_syn`) keeps a deliberate **25k pps
ceiling by default** to respect upstream/ISP limits and avoid abuse-report
blocks — raise it explicitly only when you own or are authorized to scan the
target range.

---

## Environment-variable reference

These override the per-phase concurrency and timing independently of the
performance mode. An explicit env var **always wins** over the mode-derived
value, so you can run `--fast` and still pin one phase by hand. All are read
with `atoi`; out-of-range values are ignored and the default is kept.

### Discovery (connect-probe sweep)

| Variable                          | Default | Range      | Controls                                              |
|-----------------------------------|---------|------------|-------------------------------------------------------|
| `KMAP_NETSCAN_CONCURRENCY`        | 100     | 1–1024     | Parallel IP workers in `--net-scan` discovery         |
| `KMAP_WATCHLIST_CONCURRENCY`      | 100     | 1–1024     | Parallel IP workers in `--watchlist` discovery        |
| `KMAP_DISCOVERY_PORT_PARALLELISM` | 8       | 1–32       | Ports probed concurrently within one IP               |
| `KMAP_PROBE_TIMEOUT_MS`           | 500     | 50–30000   | Per-probe TCP connect timeout (shared by both paths)  |
| `KMAP_BAIL_AFTER_TIMEOUTS`        | 8       | 1–100      | Consecutive timeouts (no opens) before skipping an IP |
| `KMAP_PROGRESS_INTERVAL_SECS`     | 30      | 1–3600     | How often the `\n` progress line is emitted           |

### Enrichment (banner / CVE / HTTP / TLS)

| Variable                            | Default | Range    | Controls                                                |
|-------------------------------------|---------|----------|---------------------------------------------------------|
| `KMAP_NETSCAN_ENRICH_CONCURRENCY`   | 40      | 1–256    | Parallel hosts enriched in `--net-scan`                 |
| `KMAP_WATCHLIST_ENRICH_CONCURRENCY` | 40      | 1–256    | Parallel hosts enriched in `--watchlist`                |
| `KMAP_HOST_PORT_PARALLELISM`        | 8       | 1–32     | Ports enriched concurrently within one host             |
| `KMAP_HOST_ENRICH_BUDGET_MS`        | 15000   | > 0      | Per-host wall-time budget; caps a slow host's worst case |
| `KMAP_ENRICH_CONNECT_TIMEOUT_MS`    | 3000    | > 0      | Per-port connect timeout during enrichment              |
| `KMAP_ENRICH_RETRIES`               | 0       | 0–10     | Extra attempts after a transient enrichment failure     |
| `KMAP_ASYNC_ENRICH_INFLIGHT`        | 64      | 1–99999  | Max concurrent connections in the async enrich pre-pass |
| `KMAP_NO_DNS`                       | off     | 0/1      | `1` disables reverse-DNS lookups during enrichment      |
| `KMAP_NO_CPU_GOVERNOR`              | off     | 0/1      | `1` disables the `--fast`/`--efficient` CPU governor    |

---

## Gaming-PC tuning recipes

**Stock fast sweep (8-core / 16 GB).** `--fast` detects 8 cores, takes 50% ≈ 4
"units", and sizes ~256 discovery / ~64 enrichment workers, capped to ~4 GB of
in-flight state and ~4 cores of sustained CPU. You can keep gaming while it
runs.

```
kmap --net-scan --fast <targets>
```

**Dedicated mass scan (machine is doing nothing else).** Lift the caps and the
rate; discovery is RTT-bound so the extra workers mostly buy you more
in-flight sockets, not more CPU load.

```
kmap --net-scan --fast-cpu-percent 85 --fast-mem-percent 60 --rate 50000 <targets>
KMAP_NETSCAN_CONCURRENCY=512 kmap --net-scan --fast --rate 50000 <targets>
```

**Background scan while you work.** Stay tiny and polite:

```
kmap --net-scan --efficient <targets>
```

**Slow or satellite link.** Give probes more time and bail later so real
services on high-RTT paths aren't dropped:

```
KMAP_PROBE_TIMEOUT_MS=1500 KMAP_BAIL_AFTER_TIMEOUTS=15 kmap --net-scan --fast <targets>
```

**LAN-only sweep.** Tighten the timeout for a much faster pass:

```
KMAP_PROBE_TIMEOUT_MS=120 kmap --net-scan <targets>
```

---

## Rule of thumb

1. Reach for `--fast` first — it scales to your hardware automatically.
2. If you want more, raise `--fast-cpu-percent` / `--fast-mem-percent` (or pin
   `KMAP_*_CONCURRENCY`) **before** raising `--rate`; the rate limiter
   saturates last.
3. The defaults assume a residential link and a shared desktop. A dedicated
   scan box with a fat pipe can push every number well past the defaults.
