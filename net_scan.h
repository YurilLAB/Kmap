/*
 * net_scan.h -- Internet-scale scanning orchestrator for Kmap.
 *
 * Coordinates the full pipeline: discover (fast SYN scan) → enrich
 * (service detection, CVE map, web recon) → report (Findings/findings_NNN.txt).
 * Also supports watchlist mode for monitoring owned/client assets.
 */

#ifndef NET_SCAN_H
#define NET_SCAN_H

/* Run the --net-scan pipeline.  Reads options from the global KmapOps.
   Returns 0 on success, 1 on error.  Calls exit() when finished. */
int run_net_scan();

/* Run the --net-query search.  Returns 0 on success, 1 on error. */
int run_net_query_cli();

/* Run the --net-cluster relationship lookup.  Walks every shard,
   pulls the fingerprint set for the target IP, then inverse-resolves
   each (kind, value) across all shards to enumerate the cohort.
   Reads o.nc_ip / o.nc_min_shared / o.nc_output.
   Returns 0 on success, 1 on error. */
int run_net_cluster_cli();

/* Run the --entity-graph build.  Assembles the asset-attribution graph
   (IP -> Domain -> Certificate -> Organization -> ASN -> Country) around a seed
   IP on the fly from the fingerprints + hosts tables across all shards, then
   emits it in text / dot / json.  Reads o.eg_seed / o.eg_format / o.eg_output /
   o.eg_depth.  Returns 0 on success, 1 on error. */
int run_entity_graph_cli();

/* Run the --topo-export dump.  Reads the persistent topology graph
   from topo.db and emits in dot or json.  Honors o.topo_export_file,
   o.topo_format, and the optional filters o.topo_around_ip /
   o.topo_around_depth and o.topo_asn_filter.
   Returns 0 on success, 1 on error. */
int run_topo_export_cli();

/* Append one line to the open scan event log (<data-dir>/kmap.log) ONLY --
   no stderr/stdout echo. Lets callers in other translation units (e.g.
   enrichment, which already emits its own terminal output via log_write)
   mirror key events into the persistent triage log without double-printing
   to the terminal. No-op when the log isn't open. printf-style format. */
void net_event_log(const char *severity, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

#endif /* NET_SCAN_H */
