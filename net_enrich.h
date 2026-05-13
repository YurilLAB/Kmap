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

/* Run the full enrichment pipeline across all shard databases.
 *   data_dir   — directory containing shard_NNN.db files
 *   batch_size — number of distinct IPs to process per batch (default 1000)
 * Returns 0 on success, 1 on error. */
int run_enrichment(const char *data_dir, int batch_size);

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
                       const char *cve_db_path,
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
                       std::vector<TlsCapture> *out_tls = nullptr);

#endif /* NET_ENRICH_H */
