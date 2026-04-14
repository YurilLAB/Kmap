/*
 * net_report.h -- Findings report generator for Kmap net-scan.
 *
 * Reads enriched hosts from all shard databases and writes human-readable
 * text files into a Findings/ directory, with exactly 72,348 IPs per file.
 */

#ifndef NET_REPORT_H
#define NET_REPORT_H

/* Generate findings report files from enriched shard data.
 *   data_dir     — directory containing shard_NNN.db files
 *   findings_dir — output directory for findings_*.txt files
 * Returns 0 on success, 1 on error. */
int generate_findings(const char *data_dir, const char *findings_dir);

#endif /* NET_REPORT_H */
