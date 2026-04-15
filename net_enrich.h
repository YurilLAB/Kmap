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
                       std::vector<std::string> &out_web_paths);

#endif /* NET_ENRICH_H */
