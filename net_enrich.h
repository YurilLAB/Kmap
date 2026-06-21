/*
 * net_enrich.h -- Enrichment pipeline for Kmap net-scan.
 *
 * Pulls unenriched hosts from shard databases, runs simplified service
 * detection (banner grab + pattern match), CVE cross-referencing against
 * kmap-cve.db, and HTTP/S reconnaissance, then writes results back.
 */

#ifndef NET_ENRICH_H
#define NET_ENRICH_H

#include <string>
#include <vector>
#include <cstdint>

/* TLS handshake capture for a single (ip, port).  Populated by
 * enrich_single_host when the port is HTTPS-looking and the build has
 * OpenSSL; left at default-constructed state otherwise (self_signed=-1
 * meaning "unknown").  Mirrors the schema columns in net_db.h. */
struct TlsCapture {
  std::string subject_cn;
  std::string issuer;
  std::string san_json;   /* JSON array of DNS SANs, e.g. ["a.com","b.com"] */
  std::string not_after;
  int         self_signed; /* -1=unknown, 0=chain-validated, 1=self-signed */
  std::string protocol;    /* "TLSv1.2" / "TLSv1.3" */
  std::string sha256;      /* hex SHA-256 of DER cert (B-step pivot key) */
  TlsCapture() : self_signed(-1) {}
};

/* Active "fingerprints" captured per (ip, port) for cross-host clustering --
 * the same role the existing fingerprints table fills for tls_sha256 /
 * subject_cn / hostname, extended toward what the large internet-survey
 * platforms record.  Empty fields are skipped at persistence time.
 *   favicon_mmh3 -- Shodan http.favicon.hash (mmh3 of base64'd /favicon.ico).
 *   body_sha256  -- SHA-256 of the HTTP root ("/") response body.
 *   hassh        -- HASSH SSH-server fingerprint (Shodan ssh.hasshserver),
 *                   MD5 of the SSH_MSG_KEXINIT algorithm name-lists; survives
 *                   banner spoofing and clusters identical SSH builds.
 *   jarm         -- JARM active TLS-server fingerprint (Shodan ssl.jarm), the
 *                   62-char hash of ten crafted ClientHello probes; clusters
 *                   hosts running an indistinguishable TLS stack. Captured on
 *                   HTTPS-looking ports only (ten extra connects), so it is
 *                   gated on the fingerprint-capture path like favicon/body.
 * Only populated when enrich_single_host is given a non-null out_fp (the
 * net-scan path); the bounded watchlist path leaves it null and pays no
 * extra probe cost. */
struct HostFingerprints {
  std::string favicon_mmh3;
  std::string body_sha256;
  std::string hassh;
  std::string jarm;
};

/* Run the full enrichment pipeline across all shard databases.
 *   data_dir   — directory containing shard_NNN.db files
 *   batch_size — number of distinct IPs to process per batch (default 1000)
 * Returns 0 on success, 1 on error. */
int run_enrichment(const char *data_dir, int batch_size);

/* Derive a CPE 2.3 identifier from a detected (service, version).  Normalizes
 * the service/version to a canonical product key (same logic the CVE matcher
 * uses) and maps it to a CPE string, or "" when the product is unknown.
 * Exposed so both the net-scan and watchlist persistence phases can stamp the
 * hosts.cpe column from one implementation. */
std::string net_enrich_cpe_for(const std::string &service,
                               const std::string &version);

/* Enrich a single host: connect to each port, grab service banners,
 * look up CVEs, and probe HTTP ports.
 *   ip          — target IPv4 address (dotted-quad)
 *   ports       — list of open port numbers discovered for this host
 *   protos      — parallel list of protocol strings ("tcp"/"udp")
 *   cve_db_path — path to kmap-cve.db (or empty to skip CVE lookup)
 *   timeout_ms  — per-probe timeout in milliseconds
 *   out_services, out_versions, out_cves, out_web_titles, out_web_servers,
 *   out_web_headers, out_web_paths — parallel output vectors (one entry per port)
 *   out_powered_by, out_x_generator, out_redirects — broken-out HTTP headers,
 *     populated per port for HTTP responses; empty otherwise.
 * Returns 0 on success, -1 on error. */
int enrich_single_host(const char *ip,
                       const std::vector<int> &ports,
                       const std::vector<std::string> &protos,
                       struct sqlite3 *cve_db,
                       int timeout_ms,
                       std::vector<std::string> &out_services,
                       std::vector<std::string> &out_versions,
                       std::vector<std::string> &out_cves,
                       std::vector<std::string> &out_web_titles,
                       std::vector<std::string> &out_web_servers,
                       std::vector<std::string> &out_web_headers,
                       std::vector<std::string> &out_web_paths,
                       std::vector<std::string> &out_powered_by,
                       std::vector<std::string> &out_x_generator,
                       std::vector<std::string> &out_redirects,
                       std::vector<TlsCapture> *out_tls = nullptr,
                       std::vector<HostFingerprints> *out_fp = nullptr);

/* Per-host enrichment metrics exposed for scan-summary reporting.
   budget_bails: hosts whose total wall time exceeded
   KMAP_HOST_ENRICH_BUDGET_MS and were cut short. hosts_done: total
   enrich_single_host calls completed since the last reset. total_ms +
   max_ms: aggregate / worst per-host wall time, for average + worst-host
   computation. Reset at the start of each enrichment phase. */
struct EnrichMetrics {
  uint64_t budget_bails;
  uint64_t hosts_done;
  uint64_t total_ms;
  uint64_t max_ms;
};
void          enrich_reset_metrics();
EnrichMetrics enrich_get_metrics();

/* fp_* fingerprint-derivation helpers were moved into net_fp_helpers.h
   so the test harness can link them without dragging in this header's
   OpenSSL / sockets transitive dependencies. */

#endif /* NET_ENRICH_H */
