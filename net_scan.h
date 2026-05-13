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

#endif /* NET_SCAN_H */
