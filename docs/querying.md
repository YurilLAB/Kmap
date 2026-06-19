# Querying collected scan data

`--net-scan` and `--watchlist` persist everything they find into a sharded
SQLite store. `--net-query` searches that store after the fact — no re-scan
needed — so you can slice a large sweep by port, service, CVE, ASN, country,
web fingerprint, or device class.

All filters below are documented from the source and exercised by a live test
(`fuzz/test_netquery.cc`); the behavior notes (case-insensitivity, substring
matching, AND-combining, injection-safety) are verified, not assumed.

## Basic use

```
kmap --net-query                      # list everything collected
kmap --net-query --nq-service ssh     # only SSH services
kmap --net-query --nq-port 443 --nq-country US   # 443 in the US
```

`--net-query` (and every `--nq-*` flag) implies query mode, so you can omit the
bare `--net-query` when you pass any filter.

## Filters

| Flag                      | Argument           | Match behavior                                              |
|---------------------------|--------------------|------------------------------------------------------------|
| `--nq-port <1-65535>`     | port number        | exact                                                       |
| `--nq-service <name>`     | service name       | case-insensitive **substring** (`%name%`)                  |
| `--nq-cve <id>`           | CVE id fragment    | substring match against the stored `cves` JSON             |
| `--nq-min-cvss <0.0-10.0>`| minimum CVSS       | keeps rows whose highest CVE score ≥ the value             |
| `--nq-kev`                | CISA KEV only      | keeps rows with a Known-Exploited (in-the-wild) CVE        |
| `--nq-min-epss <0.0-1.0>` | minimum EPSS       | keeps rows whose highest EPSS exploitation probability ≥ the value |
| `--nq-web-title <text>`   | page title         | case-insensitive substring                                 |
| `--nq-web-server <text>`  | `Server:` header   | case-insensitive substring                                 |
| `--nq-asn <number>`       | ASN                | exact                                                       |
| `--nq-country <CC>`       | ISO 2-letter code  | exact, case-insensitive (`us` == `US`)                     |
| `--nq-ip-range <cidr>`    | e.g. `8.8.0.0/16`  | restricts the search to shards overlapping that CIDR       |
| `--nq-device <tag>`       | device class       | one of: web, ssh, ftp, telnet, smtp, mail, dns, db, rdp, vnc, snmp, smb, iot, router |

**Multiple filters combine with AND.** `--nq-service http --nq-country DE`
returns only German web hosts. A service substring of `http` matches both
`http` and `https` (it's a `%http%` `LIKE`).

Filter values are passed to SQLite as **bound parameters**, never concatenated
into the query — so a value like `' OR '1'='1` is treated as a literal search
string (and simply matches nothing), not as SQL. This is covered by the live
injection test.

## Output

| Flag                  | Effect                                                       |
|-----------------------|-------------------------------------------------------------|
| `--nq-count`          | print just the number of matching rows, not the rows        |
| `--nq-format <fmt>`   | `text` (default) or `json`                                  |
| `--nq-output <file>`  | write results to a file instead of stdout                   |

## Examples

```
# Count exposed RDP across the dataset
kmap --net-query --nq-device rdp --nq-count

# Critical-CVSS web servers in Germany, as JSON to a file
kmap --net-query --nq-device web --nq-country DE --nq-min-cvss 9.0 \
     --nq-format json --nq-output critical-de-web.json

# Everything in a /16 running nginx
kmap --net-query --nq-ip-range 203.0.113.0/16 --nq-web-server nginx

# Hosts tagged with a specific CVE
kmap --net-query --nq-cve CVE-2024-6387

# Actively-exploited exposure: hosts with a CISA-KEV CVE (count only)
kmap --net-query --nq-kev --nq-count

# High exploit-likelihood (EPSS ≥ 90%) web servers, as JSON
kmap --net-query --nq-min-epss 0.9 --nq-device web --nq-format json
```

> **EPSS** (0–1) is FIRST.org's predicted probability a CVE will be exploited
> in the next 30 days; **KEV** is CISA's catalog of CVEs confirmed exploited in
> the wild. Both are layered onto matched CVEs during enrichment and refreshed
> with [`scripts/update_epss_kev.py`](../scripts/update_epss_kev.py).

## How the data gets there

`--net-query` reads the same sharded store that the scanners write:

- `--net-scan <targets>` — discover + enrich + persist (see
  [`performance.md`](performance.md) for the resource modes).
- `--watchlist <file>` — bounded re-scan of a fixed IP list; the hosts table
  is **cumulative**, so re-runs update `last_seen`/`scan_count` and snapshot
  prior CVE/service state for diffing rather than overwriting history.

Because the store is cumulative, querying after several scans reflects the
union of everything seen, with first-seen/last-seen timestamps per host.
