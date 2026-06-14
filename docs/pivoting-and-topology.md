# Pivoting & topology

Once a sweep has populated the scan store, the open ports are only the start.
Kmap ships three analysis features that turn that raw surface into *relationships*:

- **`--net-cluster`** — find every other host that shares a TLS certificate,
  hostname, or redirect target with a given IP (infrastructure correlation).
- **`--tracemap`** / **`--topo-export`** — map and export the network paths
  *between* you and your targets (router/ASN-level topology).
- **`--spoof-os`** — present a consistent OS/browser personality during
  enrichment so probed services see a plausible client, not a scanner.

All three read or write the same `kmap-data/` directory the
[internet-scale pipeline](internet-scale-scanning.md) produces, so they work
on data you already collected — no re-scan required for `--net-cluster` or
`--topo-export`.

---

## `--net-cluster` — infrastructure correlation by shared fingerprints

During enrichment, Kmap records *fingerprints* for each host — stable identifiers
that tend to be reused across a single operator's infrastructure:

| Kind | Source | Why it correlates |
|------|--------|-------------------|
| `tls_sha256` | SHA-256 of the peer's leaf certificate | The exact same cert deployed on many IPs is a strong same-owner signal |
| `tls_subject_cn` | Certificate Subject CN | Shared CN (e.g. a wildcard) ties hosts together |
| `tls_san` | Each Subject Alternative Name | Shared SANs link hosts behind one cert |
| `hostname` | Reverse-DNS / discovered hostname | Same name family |
| `redirect_host` | Host an HTTP probe was redirected to | Hosts funnelling to one front-end |

(IP-literal CNs/SANs are skipped — they carry no correlation value.)

`--net-cluster <ip>` pulls the target's own fingerprints, then walks all 32
shards collecting every *other* IP that carries at least one of them. The
target itself is excluded from its own cohort.

```bash
# Who shares TLS/host fingerprints with this IP?
kmap --net-cluster 203.0.113.10
```

The target must already be enriched — if it has no fingerprints, Kmap tells you
so (`Has it been enriched yet?`) and exits non-zero.

### Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--net-cluster <ip>` | — | The IP to build a cohort around (required) |
| `--nc-min-shared <n>` | `1` | Only include IPs sharing at least *n* distinct fingerprints (range 1–100) |
| `--nc-format <fmt>` | `text` | `text`, `dot`, or `json` |
| `--nc-output <file>` | stdout | Write results to a file |

Raise `--nc-min-shared` to cut noise: requiring 2+ shared fingerprints filters
out coincidental single-SAN overlaps and surfaces tightly-coupled hosts.

Results are sorted by shared-fingerprint count (descending), then by IP.

### Output formats

**`text`** (default) is pipeline-friendly — header lines start with `#`, then one
row per cohort IP as `IP<TAB>N shared<TAB>kind:value, kind:value …`:

```
# net-cluster cohort for 203.0.113.10 (min_shared=1)
# target carries 4 fingerprints; 2 IPs share >= 1
203.0.113.11    2 shared    tls_san:*.example.com, tls_sha256:ab12…
198.51.100.7    1 shared    tls_san:*.example.com
```

Chain it straight into another tool:

```bash
# Feed the cohort into a follow-up scan or tracemap
kmap --net-cluster 203.0.113.10 | grep -v '^#' | awk '{print $1}'
```

**`dot`** renders a Graphviz star — the target as a red hub, cohort IPs as teal
leaves, each edge labelled with the shared fingerprint *kinds* and the count:

```bash
kmap --net-cluster 203.0.113.10 --nc-format dot --nc-output cohort.dot
dot -Tsvg cohort.dot -o cohort.svg
```

**`json`** emits `{ target, min_shared, target_fingerprints, cohort: [ { ip,
shared, matches: [...] } ] }` with every fingerprint value RFC-8259 escaped (the
values come straight off the wire and can contain control bytes), ready for
downstream ingestion.

---

## `--tracemap` / `--topo-export` — path & ASN topology

`--tracemap` runs TTL-limited probes toward each target (traceroute-style),
records the routers in between, annotates them with ASN/geo, and — unless you
pass `--tm-no-persist` — writes the merged graph to `<data-dir>/topo.db`.
`--topo-export` then reads that persisted graph back out in a format you can
visualise or feed to a graph tool.

```bash
# Map paths to a set of targets, persisting the graph
kmap --tracemap targets.txt

# Later: export the neighborhood around one node as Graphviz
kmap --topo-export around.dot --topo-format dot \
     --topo-around 203.0.113.10 --topo-around-depth 2
```

### `--tracemap` options

| Flag | Default | Meaning |
|------|---------|---------|
| `--tracemap <targets>` | — | IPs, CIDRs, or a file of targets |
| `--tm-output <file>` | stdout | Live trace output destination |
| `--tm-format <fmt>` | `txt` | `txt`, `dot`, or `json` |
| `--tm-max-hops <n>` | `30` | Maximum TTL hops (range 1–255) |
| `--tm-no-persist` | off | Skip writing the graph to `<data-dir>/topo.db` |

### `--topo-export` options

`--topo-export` reads `<data-dir>/topo.db` (so run `--tracemap` first). The node
include-set is chosen by a single filter, with this precedence:
**`--topo-around` > `--topo-asn` > everything**.

| Flag | Default | Meaning |
|------|---------|---------|
| `--topo-export <file>` | — | Output path (required) |
| `--topo-format <fmt>` | `json` | `dot` or `json` |
| `--topo-around <ip>` | — | Limit to the neighborhood around an IP |
| `--topo-around-depth <n>` | `1` | BFS depth for `--topo-around` (range 1–6) |
| `--topo-asn <number>` | — | Limit to nodes in a single ASN |

With no filter, the export includes all nodes up to a 100,000-node cap (ordered
by path count, so the most-traversed routers are kept) — a guard so a huge graph
can't produce a multi-gigabyte file.

Each node carries `ip`, `hostname`, `asn`, `as_name`, `country`, `role`
(`target` / `hub` / `ixp` / other), `path_count`, and `avg_rtt_ms`. Edges carry
the average latency and whether they cross an ASN boundary (drawn dashed in DOT).

```bash
# Everything in one ASN, as JSON for d3/cytoscape/gephi
kmap --topo-export as13335.json --topo-asn 13335
```

---

## `--spoof-os` — OS/browser personality for enrichment

`--spoof-os <profile>` makes Kmap's enrichment probes present a coherent
operating-system + browser personality instead of a default scanner footprint.
Because the discovery layer is a `connect()` scan, the kernel owns the SYN
packet's low-level fields; `--spoof-os` deliberately stays inside the
cross-platform `setsockopt()` + HTTP surface so it behaves identically on Linux
and Windows with no extra dependencies. It adjusts:

- **IP layer** — IP TTL / IPv6 hop limit.
- **TCP layer** — `SO_RCVBUF`, `SO_SNDBUF`, and `TCP_MAXSEG` (MSS) hints
  (POSIX only).
- **HTTP layer** — request-line version, `User-Agent`, `Accept`,
  `Accept-Language`, `Accept-Encoding`, and (for browser-like profiles)
  `Sec-Fetch-*` + `Upgrade-Insecure-Requests`.

```bash
kmap --net-scan -p 443 --net-max-ips 100000 --spoof-os win11
```

Profiles (case-sensitive): `linux`, `win10`, `win11`, `macos`, `freebsd`,
`openbsd`, `android`, `ios`, and `random`. With `random`, each host gets a
*stable* personality (derived deterministically from its address), so every
probe to one host presents one coherent OS rather than flickering between them.
Unknown names fail fast at parse time rather than silently disabling spoofing.

---

## See also

- [Internet-scale scanning](internet-scale-scanning.md) — the pipeline that
  populates the data these features read.
- [Querying collected data](querying.md) — filter the same store by port,
  service, CVE, ASN, country, and more.
- [Data model](data-model.md) — the on-disk schema, including the `fingerprints`
  table `--net-cluster` walks.
