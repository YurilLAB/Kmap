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

`--rate <pps>` sets the global packets-per-second send ceiling for discovery,
enforced by a shared token bucket across all discovery workers (**default
25000 pps**, range 1–1000000000). The default is deliberately polite; the cap
is effectively your hardware/link, not an artificial Kmap limit. The rate
limiter is the *last* thing to saturate: if you have CPU and bandwidth headroom
and want a faster sweep, raise the discovery concurrency first, then raise
`--rate`. A high `--rate` on its own changes nothing at default concurrency —
the connect()-model probe rate (≈`workers / timeout`) stays well below it.

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
| `KMAP_NETSCAN_CONCURRENCY`        | 100     | 1–1024     | Base discovery workers in `--net-scan` (see note)     |
| `KMAP_WATCHLIST_CONCURRENCY`      | 100     | 1–1024     | Parallel IP workers in `--watchlist` discovery        |
| `KMAP_DISCOVERY_PORT_PARALLELISM` | 8       | 1–32       | Discovery-worker multiplier (see note)                |
| `KMAP_PROBE_TIMEOUT_MS`           | 500     | 50–30000   | Per-probe TCP connect timeout (shared by both paths)  |
| `KMAP_BAIL_AFTER_TIMEOUTS`        | 8       | 1–100      | Consecutive timeouts (no opens) before skipping an IP |
| `KMAP_PROGRESS_INTERVAL_SECS`     | 30      | 1–3600     | How often the `\n` progress line is emitted           |

> **Discovery concurrency note.** `--net-scan` discovery uses one flat pool
> of persistent probe workers; the total number of concurrent `connect()`
> probes is `KMAP_NETSCAN_CONCURRENCY × KMAP_DISCOVERY_PORT_PARALLELISM`
> (default `100 × 8 = 800`, clamped at 4096). The multiplier is itself capped
> at the number of ports being scanned, so a single-port sweep — the canonical
> internet-scale workload — runs exactly `KMAP_NETSCAN_CONCURRENCY` workers.
> Each worker probes one IP's ports in sequence, so raising either knob adds
> more concurrent in-flight probes — the single biggest lever on discovery
> throughput when the scan is network-RTT bound (which it usually is) rather
> than rate-limited. The `--rate` ceiling still caps the aggregate send rate
> on top of this.

#### How fast can a sweep actually go?

Kmap's discovery probes with non-blocking `connect()`, not raw SYN. On
**unresponsive (filtered / dark) IP space** — most of the internet for any
given port — each probe runs to the full `KMAP_PROBE_TIMEOUT_MS` before its
worker is freed, so the pool's hard ceiling there is:

```
max_pps ≈ workers / (KMAP_PROBE_TIMEOUT_MS / 1000)
        = (KMAP_NETSCAN_CONCURRENCY × min(KMAP_DISCOVERY_PORT_PARALLELISM, #ports)) / timeout_s
```

This applies to the **`connect()` fallback** path (raw packets unavailable); the
raw-SYN engine is send-bound, not worker-bound, and sidesteps this ceiling
entirely. With the connect defaults (100 workers, 500 ms) a single-port sweep
tops out near **200 pps** — the send rate is unlimited by default, so this is
the worker/timeout floor, not a `--rate` cap. To push filtered-space throughput
on the connect path you must give it more concurrency or a shorter timeout:

| Goal (filtered space) | Example settings |
|-----------------------|------------------|
| ~2,000 pps            | `KMAP_NETSCAN_CONCURRENCY=1000` (500 ms timeout) |
| ~10,000 pps           | `KMAP_NETSCAN_CONCURRENCY=1000 KMAP_PROBE_TIMEOUT_MS=100` |

Lowering the timeout trades coverage for speed: a probe that would have
answered just after the cutoff is recorded as filtered. 500 ms suits
cross-continent paths; 100–200 ms is fine for nearby / well-connected
ranges. Responsive hosts answer in well under a millisecond, so real-world
throughput on live ranges is much higher than the dark-space floor above.
`kmap --net-scan` prints a one-line NOTE at start when the worker ceiling
sits well below the requested `--rate`, so you don't discover the gap only
by watching a slow progress bar.

> **Open-file limit.** Each worker holds a socket, so concurrency near 1000
> needs more file descriptors than the default POSIX limit (1024). Kmap raises
> the soft limit automatically before the pool starts and warns if the system
> *hard* limit is still too low — if you see that warning, raise it
> (`ulimit -Hn`) or lower the concurrency. See
> [troubleshooting.md](troubleshooting.md#scan-warns-about-the-open-file-limit).
> Windows is unaffected. The gaming-PC defaults stay under 1024 and never hit this.

### Enrichment (banner / CVE / HTTP / TLS)

| Variable                            | Default | Range    | Controls                                                |
|-------------------------------------|---------|----------|---------------------------------------------------------|
| `KMAP_NETSCAN_ENRICH_CONCURRENCY`   | 40      | 1–256    | Parallel hosts enriched in `--net-scan`                 |
| `KMAP_WATCHLIST_ENRICH_CONCURRENCY` | 40      | 1–256    | Parallel hosts enriched in `--watchlist`                |
| `KMAP_HOST_PORT_PARALLELISM`        | 8       | 1–32     | Ports enriched concurrently within one host             |
| `KMAP_HOST_ENRICH_BUDGET_MS`        | 15000   | > 0      | Per-host wall-time budget; caps a slow host's worst case |
| `KMAP_ENRICH_CONNECT_TIMEOUT_MS`    | 3000    | > 0      | Per-port connect timeout during enrichment              |
| `KMAP_ENRICH_RETRIES`               | 0       | 0–10     | Extra attempts after a transient enrichment failure     |
| `KMAP_ASYNC_ENRICH`                 | off     | 0/1      | `1` enables the experimental async enrich pre-pass (note below) |
| `KMAP_ASYNC_ENRICH_INFLIGHT`        | 64      | 1–99999  | Hosts the async pre-pass keeps in flight (needs `KMAP_ASYNC_ENRICH=1`) |
| `KMAP_NO_DNS`                       | off     | 0/1      | `1` disables reverse-DNS lookups during enrichment      |
| `KMAP_NO_CPU_GOVERNOR`              | off     | 0/1      | `1` disables the `--fast`/`--efficient` CPU governor    |

> **Async enrich pre-pass (experimental, opt-in).** `KMAP_ASYNC_ENRICH=1` runs
> the banner-grab + CVE + HTTP + TLS portion of enrichment through a single
> nsock event loop that holds many connections in flight at once, instead of
> one blocking host per worker thread. On large sweeps this lifts the per-host
> blocking ceiling that otherwise caps enrichment throughput;
> `KMAP_ASYNC_ENRICH_INFLIGHT` bounds how many hosts it drives concurrently.
> It is off by default while it is validated — the synchronous path stays the
> default and still fills any step the pre-pass leaves blank. Reverse-DNS and
> ASN lookups always run on the synchronous path.

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
