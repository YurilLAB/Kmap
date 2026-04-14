/*
 * net_query.h -- Query engine for Kmap net-scan data.
 *
 * Searches across all shard databases by port, service, CVE, CVSS score,
 * web title, web server, or IP range.  Supports count-only mode and
 * file export.
 */

#ifndef NET_QUERY_H
#define NET_QUERY_H

/* Run a query across net-scan shard databases.
 *   data_dir    — directory containing shard_NNN.db files
 *   port        — filter by port number (0 = no filter)
 *   service     — filter by service name substring (NULL = no filter)
 *   cve         — filter by CVE ID substring (NULL = no filter)
 *   min_cvss    — filter by minimum CVSS score (0.0 = no filter)
 *   web_title   — filter by web page title substring (NULL = no filter)
 *   web_server  — filter by server header substring (NULL = no filter)
 *   ip_range    — restrict to IP range CIDR (NULL = all shards)
 *   output_file — write results to file (NULL = stdout)
 *   count_only  — if true, only print total count of matching rows
 * Returns 0 on success, 1 on error. */
int run_net_query(const char *data_dir,
                  int port,
                  const char *service,
                  const char *cve,
                  float min_cvss,
                  const char *web_title,
                  const char *web_server,
                  const char *ip_range,
                  const char *output_file,
                  bool count_only);

#endif /* NET_QUERY_H */
