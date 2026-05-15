/*
 * net_enrich_async.h -- Async (event-driven) enrichment for Kmap net-scan.
 *
 * Phase 1a: banner-grab + CVE lookup for many hosts in parallel inside a
 * single worker thread, using the vendored nsock event loop.
 * Phase 1b: async HTTP probe (GET /, parse Server/title/Location/X-*).
 * Phase 1c: async TLS handshake + X509 capture (subject CN, issuer,
 *           SAN list, notAfter, self-signed flag, protocol, SHA-256).
 *
 * After Phase 1c the async path is feature-complete with enrich_single_host
 * for banner+CVE+HTTP+TLS.  Reverse-DNS (PTR) and ASN lookup remain on the
 * synchronous path; both are CPU-bound / non-network bottlenecks on the
 * scale we care about (Phase 1d / 3 territory).
 *
 * The synchronous enrich_single_host (net_enrich.cc) is unchanged and still
 * the default; this async path is opt-in via a caller-side flag.  Both
 * implementations target the same per-port out_* vector contract so the
 * upper-level pipeline can pick either without restructuring.
 */

#ifndef NET_ENRICH_ASYNC_H
#define NET_ENRICH_ASYNC_H

#include "net_enrich.h"   /* TlsCapture struct */

#include <string>
#include <vector>

struct sqlite3;

/*
 * async_enrich_batch -- banner-grab + CVE + HTTP + TLS for a batch of hosts
 * driven by a single nsock event loop in the calling thread.
 *
 * Each host's port list is dispatched concurrently; for each port we issue
 * an async TCP connect followed by an async read (banner grab) and -- on
 * a non-empty classification -- a local SQLite CVE lookup against the
 * caller-supplied read-only handle.  HTTP-ish ports then drive an HTTP
 * GET / via async write + read; HTTPS-ish ports drive a TLS handshake
 * via nsock_connect_ssl with the pool's shared SSL_CTX, after which the
 * X509 cert is extracted synchronously inside the callback (microseconds
 * of CPU work).
 *
 * The function holds up to KMAP_ASYNC_ENRICH_INFLIGHT hosts in flight
 * concurrently (default 64) so the per-thread blocking ceiling of the
 * synchronous path goes away.  At KMAP_HOST_ENRICH_BUDGET_MS per host
 * (same env var the sync path reads) the host is finalized with whatever
 * partial data we collected.
 *
 * Parallel arrays (all of size N):
 *   ips                — dotted-quad IPv4 / numeric IPv6 strings
 *   ports_per_host     — open-port list for each host
 *
 * Outputs (pre-resized to N here; inner vectors resized to each host's
 * ports.size()):
 *   out_services_per_host      — service name (ssh/http/ftp/...) or empty
 *   out_versions_per_host      — version string lifted from the banner or empty
 *   out_cves_per_host          — JSON array string of matched CVE rows or empty
 *   out_web_titles_per_host    — HTML <title> for HTTP responses
 *   out_web_servers_per_host   — Server header
 *   out_web_headers_per_host   — JSON object of selected headers
 *   out_web_paths_per_host     — JSON array of probed paths (just "/")
 *   out_powered_by_per_host    — X-Powered-By header (broken-out)
 *   out_x_generator_per_host   — X-Generator header (broken-out)
 *   out_redirects_per_host     — Location header for 3xx responses
 *   out_tls_per_host           — (optional, pass NULL to skip) TLS cert capture
 *
 * timeout_ms — per-step (connect, read, send) timeout in milliseconds;
 *              nsock enforces it independently for each event.
 * cve_db     — caller-owned read-only sqlite3* used from this thread only.
 *              May be NULL: CVE lookup is then skipped, banner data still
 *              fills services/versions.
 *
 * Returns 0 on completion.  This function never propagates a fatal error
 * code; unreachable hosts simply finish with empty per-port entries.
 *
 * Thread-safety: this function must be called from one thread per nsock
 * pool; the caller may spin up many parallel invocations on disjoint
 * (ips, cve_db) inputs.  cve_db is read-only and safe under SQLite
 * default serialized mode, but each thread should pass its own handle to
 * sidestep mutex contention -- creating that handle is the integration
 * caller's responsibility.
 */
int async_enrich_batch(
    const std::vector<std::string> &ips,
    const std::vector<std::vector<int>> &ports_per_host,
    int timeout_ms,
    struct sqlite3 *cve_db,
    std::vector<std::vector<std::string>> &out_services_per_host,
    std::vector<std::vector<std::string>> &out_versions_per_host,
    std::vector<std::vector<std::string>> &out_cves_per_host,
    std::vector<std::vector<std::string>> &out_web_titles_per_host,
    std::vector<std::vector<std::string>> &out_web_servers_per_host,
    std::vector<std::vector<std::string>> &out_web_headers_per_host,
    std::vector<std::vector<std::string>> &out_web_paths_per_host,
    std::vector<std::vector<std::string>> &out_powered_by_per_host,
    std::vector<std::vector<std::string>> &out_x_generator_per_host,
    std::vector<std::vector<std::string>> &out_redirects_per_host,
    std::vector<std::vector<TlsCapture>> *out_tls_per_host);

#endif /* NET_ENRICH_ASYNC_H */
