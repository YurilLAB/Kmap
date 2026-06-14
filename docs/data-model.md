# Data model — how kmap stores what it collects

`--net-scan` and `--watchlist` persist results to **SQLite** under the data
directory (default `kmap-data/`, override with `--data-dir`). This page
documents the on-disk layout so you can query it directly and understand the
rescan/history semantics. For the `--net-query` CLI see
[querying.md](querying.md); for the scan workflow see
[internet-scale-scanning.md](internet-scale-scanning.md).

## Sharding

Hosts are spread across **32 shard databases**, `shard_000.db` … `shard_031.db`,
keyed by the **top 5 bits of the IP** (`shard = ip >> 27`). Sharding keeps each
file small enough to stay fast on a desktop SSD and lets enrichment work shards
in parallel. `--net-query` reads across all shards transparently; to poke at one
directly:

```sh
sqlite3 kmap-data/shard_000.db ".schema hosts"
sqlite3 kmap-data/shard_000.db "SELECT ip, port, service, version FROM hosts LIMIT 10;"
```

Other files in the data dir: `.net-scan-checkpoint` (resume position + the
permutation seed) and `kmap.log` (the per-run event trail). Every shard holds
the same set of tables (`hosts`, `fingerprints`, topology, string interning).

## The `hosts` table

One row per **(ip, port)** — that pair is the primary key, so a host with three
open ports is three rows. Key columns:

| Column | Meaning |
|--------|---------|
| `ip`, `port`, `proto` | the open endpoint (the PK is `(ip, port)`) |
| `first_seen` | epoch seconds of the **earliest** discovery — never overwritten |
| `last_seen` | epoch seconds of the **most recent** discovery or enrichment |
| `scan_count` | bumped every time the endpoint is re-discovered |
| `service`, `version` | detected service + version string |
| `cves` | JSON array of matched CVEs (id, cvss, severity, vector, desc) |
| `web_title`, `web_server`, `web_headers`, `web_paths`, `powered_by`, `x_generator`, `redirect_target` | HTTP recon |
| `tls_subject_cn`, `tls_issuer`, `tls_san_json`, `tls_not_after`, `tls_self_signed`, `tls_protocol`, `tls_sha256` | TLS cert details |
| `asn`, `as_name`, `country`, `bgp_prefix`, `asn_registry`, `asn_region` | ASN / geo (Team Cymru) |
| `hostname` | reverse-DNS name |
| `enriched`, `enriched_at` | whether/when enrichment last ran |
| `enrichment_error`, `enrichment_error_at` | last enrichment error + a retry cool-down anchor |
| `prev_cves`, `prev_service`, `prev_version`, `prev_enriched_at` | snapshot of the previous enrichment, for diffing |

## Rescan / history semantics (the non-obvious part)

The store is **cumulative across scans**, not snapshot-per-run:

- **`first_seen` is permanent.** The discovery UPSERT updates `last_seen` and
  bumps `scan_count` but never touches `first_seen`, so you can always tell how
  long an endpoint has been observed.
- **Re-discovery triggers re-enrichment.** A host is eligible for enrichment
  when `enriched = 0` **OR** `last_seen > enriched_at` — i.e. it was seen again
  after it was last enriched. That's what populates the `prev_*` columns: when a
  row that was already enriched is enriched again, its current
  `cves`/`service`/`version`/`enriched_at` are snapshotted into `prev_*` first,
  so reports can show a **patch diff** (CVEs introduced vs. fixed between scans).
- **Partial results never wipe good data.** Enrichment, ASN, and TLS updates all
  `COALESCE` their fields, so a transient failure (HTTP timeout, a failed AS-name
  lookup, a half cert) leaves previously-captured values intact instead of
  blanking them on retry.
- **Errored hosts back off.** A host whose enrichment errored records
  `enrichment_error_at` and is skipped until a cool-down (default 1 hour)
  elapses, so a dead host isn't retried every pass.

Useful history queries:

```sh
# hosts seen on more than one scan, newest first
sqlite3 kmap-data/shard_000.db \
  "SELECT ip, port, scan_count, datetime(first_seen,'unixepoch'), datetime(last_seen,'unixepoch')
   FROM hosts WHERE scan_count > 1 ORDER BY last_seen DESC;"

# endpoints whose CVE set changed between the last two enrichments
sqlite3 kmap-data/shard_000.db \
  "SELECT ip, port, prev_cves, cves FROM hosts
   WHERE prev_cves IS NOT NULL AND prev_cves != '' AND prev_cves != cves;"
```

## The `fingerprints` table

A relationship index: each row is `(ip_u32, kind, value)`. The five `kind`s
are `tls_sha256` (leaf-cert hash), `tls_subject_cn`, `tls_san`, `hostname`
(reverse-DNS / discovered), and `redirect_host` (where an HTTP probe was
redirected) — e.g. `('…','tls_sha256','<hex>')`,
`('…','tls_san','*.example.com')`. The inverse index `(kind, value)` answers
"which **other** hosts carry this same cert / SAN / hostname?" in one indexed
lookup, even on a billions-of-rows table — this is exactly what
[`--net-cluster`](pivoting-and-topology.md#--net-cluster--infrastructure-correlation-by-shared-fingerprints)
walks. `ip_u32` is the 32-bit integer IP (compact, since this table outnumbers
`hosts` after a big sweep), and `port` is informational only (not part of the
PK — one cert served on 443 and 8443 is a single row, its port stamp tracking
the most recent sighting).

## Topology + string interning

`topo_nodes` / `topo_edges` hold the persistent traceroute graph (so successive
`--tracemap` runs refine one graph), and a string-interning table
(`AUTOINCREMENT` ids, `UNIQUE` values) deduplicates hostnames/AS-names referenced
by the topology rows.

## Schema migrations

`net_db_open` creates the tables `IF NOT EXISTS` and runs additive migrations
(new columns are added with defaults) so an older shard opened by a newer kmap
is upgraded in place without losing data.
