/*
 * net_enrich_async.h -- Async (event-driven) enrichment for Kmap net-scan.
 *
 * Phase 1a: banner-grab + CVE lookup for many hosts in parallel inside a
 * single worker thread, using the vendored nsock event loop.  HTTP probe
 * and TLS handshake remain on the synchronous path in net_enrich.cc and
 * will be migrated in Phase 1b/1c.
 *
 * The synchronous enrich_single_host (net_enrich.cc) is unchanged and still
 * the default; this async path is opt-in via a caller-side flag.  Both
 * implementations target the same per-port out_* vector contract so the
 * upper-level pipeline can pick either without restructuring.
 */

#ifndef NET_ENRICH_ASYNC_H
#define NET_ENRICH_ASYNC_H

#include <string>
#include <vector>

struct sqlite3;

/*
 * async_enrich_batch -- banner-grab + CVE lookup for a batch of hosts
 * driven by a single nsock event loop in the calling thread.
 *
 * Each host's port list is walked in order; for each port we issue an
 * async TCP connect followed by an async read (banner grab), classify
 * the banner verbatim using the same patterns as the synchronous
 * grab_banner() (SSH/HTTP/FTP/SMTP/IMAP/POP3/MySQL/Redis/MongoDB/Postgres),
 * and -- on a non-empty classification -- run a local SQLite CVE lookup
 * against the caller-supplied read-only handle.
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
 *   out_services_per_host  — service name (ssh/http/ftp/...) or empty
 *   out_versions_per_host  — version string lifted from the banner or empty
 *   out_cves_per_host      — JSON array string of matched CVE rows or empty
 *
 * timeout_ms — per-step (connect, read) timeout in milliseconds; nsock
 *              enforces it independently for each event.
 * cve_db     — caller-owned read-only sqlite3* used from this thread only.
 *              May be NULL: CVE lookup is then skipped, banner data still
 *              fills services/versions.
 *
 * Returns 0 on completion.  Phase 1a never propagates a fatal error code;
 * unreachable hosts simply finish with empty per-port entries.
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
    std::vector<std::vector<std::string>> &out_cves_per_host);

#endif /* NET_ENRICH_ASYNC_H */
