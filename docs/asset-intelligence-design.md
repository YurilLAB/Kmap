# Full internet asset intelligence — design

The "full asset intelligence" roadmap item is the set of enrichments that turn a
host record into an attributable asset. Status:

| Capability | State |
|---|---|
| Cloud-provider identification | **Shipped** — `cloud_provider/region/service` columns, offline IP-range match (`cloud_map.cc`) |
| Hosting relationships | **Shipped** — `fingerprints` cohort (`--net-cluster`) + the asset graph (`--entity-graph`) |
| Certificate metadata | **Partly shipped** — subject CN / issuer CN / SAN / SHA-256 captured; subject **Organization (O=)** and Certificate Transparency cross-ref are not |
| WHOIS / RDAP (org, abuse, registrant) | **Designed below** |
| Subdomain discovery (via CT) | **Designed below** |
| Passive DNS (IP↔domain history) | **Designed below** |

The three remaining legs are all **online** (a runtime query to a third-party
service) and share one missing primitive, so they are specified together and
deferred for the same reason as the [async discovery
engine](async-discovery-design.md): they cannot be runtime-validated on a box
with no built binary and no network, and getting an online client right (TLS,
verification, rate-limit/backoff, response parsing) needs real runs.

## The shared prerequisite: a verifying HTTPS-by-hostname client

Every remaining leg fetches from an HTTPS API by **hostname** (rdap.org,
crt.sh, a passive-DNS endpoint). **No such client exists in the tree today** —
every TLS path is IP-literal, `SSL_VERIFY_NONE`, no SNI:

- `net_enrich.cc` `tls_capture_cert` connects to a numeric target and does **not**
  set SNI or verify the chain (it is fingerprinting an untrusted scan target).
- `web_recon.cc` `https_get` is IP-literal, SNI-by-IP, `VERIFY_NONE`.

A client that *trusts* a response (unlike scanning untrusted targets) needs the
opposite posture, so build it once as `net_http_client.{cc,h}`:

1. Resolve the API hostname (reuse `kmap_mass_dns` or `getaddrinfo`).
2. TLS with **real SNI** (`SSL_set_tlsext_host_name`) **and CA-chain
   verification** (`SSL_set_verify(SSL_VERIFY_PEER)`, default trust store).
3. HTTP/1.1 GET with `Host:`, follow ≤3 redirects, handle chunked + gzip, cap the
   response (e.g. 8 MB), with a hard timeout.
4. A minimal JSON reader for the responses (the tree has emitters, not a parser —
   the bundled `third-party/nlohmann/json.hpp` can be reused: it is already used
   by `output_json.cc` / `yuril_export.cc`).
5. Share one `SSL_CTX` via `std::call_once` (the `net_enrich.cc:1112` pattern).

This is ~150–250 lines, security-sensitive, and is the bulk of the work for all
three legs. Unit-testable parts (request building, redirect/chunk/JSON parsing)
can be pinned with fixtures; the live TLS fetch needs a real run.

## Leg 1 — Certificate Organization + Certificate Transparency

**Subject O= (small, no client needed — do this first):** `tls_capture_cert`
already pulls the subject **CN** via `X509_NAME_get_text_by_NID(...,
NID_commonName,...)` (`net_enrich.cc:1151`). Add a sibling call with
`NID_organizationName` → a new `tls_subject_org` column (mirror the cpe/cloud
column pattern: schema + migration + `NetHost` field + `get_host` index +
`net_db_update_tls` param + both Stage-C sites). This gives the
**`--entity-graph` a direct `cert --issued_to--> org` edge** (today the org node is
the AS owner) and is fully offline + locally verifiable — it should land as the
next concrete step, independent of the online client.

**CT cross-ref + subdomains (online):** key the lookup on domains already in the
store — `fingerprints` kinds `hostname` / `tls_subject_cn` / `tls_san`. Query
crt.sh JSON (`https://crt.sh/?q=%25.<domain>&output=json`, `certspotter` as a
documented fallback) via the shared client; `name_value` yields the cert history
**and** the subdomain list. Store discovered names as new `fingerprints` kinds
`ct_san` / `ct_issuer` (the table is free-text `kind` → **no schema change**; the
inverse index gives "who else shares subdomain X" for free). Domain-keyed cache +
backoff (crt.sh rate-limits hard) — mirror `asn_lookup.cc`'s `dns_cache`. Run as a
**post-enrichment phase** keyed by registered domain (not per-IP), gated
`KMAP_CT_LOOKUP=1` (default off). Future payoff: resolve discovered subdomains →
feed back as scan targets via `NewTargets.cc`.

## Leg 2 — WHOIS / RDAP

Today only ASN-level ownership is captured (`as_name`/`country` via Team Cymru).
RDAP adds registrant-level org/abuse:

- **IP RDAP** (`https://rdap.org/ip/<ip>` → RIR redirect): `name`, `handle`,
  `entities[].vcardArray` (org, abuse email), allocation dates. New columns
  `whois_org`, `whois_abuse`, `whois_registry` (mirror the asn column pattern;
  RDAP is per-netblock so cache by prefix, like `asn_lookup`).
- **Domain RDAP** (`https://rdap.org/domain/<domain>`): registrar, registrant,
  created/expires — attach to the domain nodes in `--entity-graph`.

RDAP returns structured JSON (far cleaner than legacy port-43 WHOIS) → use the
shared client + nlohmann reader. Cache + backoff like the ASN leg; gate
`KMAP_RDAP_LOOKUP=1` (default off — it is a per-host network round-trip).

## Leg 3 — Passive DNS

The longitudinal IP↔domain history (which names resolved to this IP over time —
the "all the time" dimension). Active PTR (`hostname`) is a point-in-time snapshot
only. Source: a passive-DNS provider, or the **YurilSecurity n8n pipeline** (the
project already runs it for threat-intel feeds) exposing a pDNS endpoint. Store in
a new `pdns(ip_u32, domain, first_seen, last_seen, source)` table (its own table,
not `fingerprints`, because the time range is load-bearing). Feeds the
`--entity-graph` IP→Domain edges with historical, not just current, links.

## Sequencing

1. **Cert subject O= column** — offline, small, locally verifiable, upgrades the
   entity graph. Do this next, independent of everything below.
2. **The shared `net_http_client`** — the prerequisite for 3–5; build + fixture-test.
3. **RDAP leg**, then **CT/subdomains leg**, then **passive DNS** — each on the
   shared client, each opt-in/default-off, each validated live before shipping.

## Why design-first (legs 2–5)

The online legs cannot be exercised here (no binary, no network, no reachable
crt.sh/rdap.org), and a trusting HTTPS client + rate-limited third-party APIs are
exactly where blind code breaks (verification bypass, redirect loops, parser
crashes on hostile JSON). They should be implemented against this design where
the live tests can gate them. The offline pieces of asset intelligence
(cloud-ID, the entity graph, and the cert-O column above) do not have this
constraint and are/should be shipped directly.
