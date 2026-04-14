/*
 * net_scan.h -- Internet-scale scanning orchestrator for Kmap.
 *
 * Coordinates the full pipeline: discover (fast SYN scan) → enrich
 * (service detection, CVE map, web recon) → report (Findings/*.txt).
 * Also supports watchlist mode for monitoring owned/client assets.
 */

#ifndef NET_SCAN_H
#define NET_SCAN_H

/* Run the --net-scan pipeline.  Reads options from the global KmapOps.
   Returns 0 on success, 1 on error.  Calls exit() when finished. */
int run_net_scan();

/* Run the --net-query search.  Returns 0 on success, 1 on error. */
int run_net_query_cli();

#endif /* NET_SCAN_H */
