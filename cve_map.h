/*
 * cve_map.h -- CVE cross-reference engine for Kmap (--cve-map).
 *
 * Queries a bundled SQLite database of CVEs (kmap-cve.db) by matching
 * detected service/product names to known vulnerable software, then
 * reports matching CVEs sorted by CVSS score descending.
 */

#ifndef CVE_MAP_H
#define CVE_MAP_H

#include <string>
#include <vector>
#include "Target.h"

struct CveEntry {
  std::string cve_id;
  std::string product;
  std::string vendor;
  std::string description;
  float cvss_score;
  std::string severity;
};

struct PortCveResults {
  int portno;
  std::string proto;     /* "tcp" or "udp" */
  std::string service;   /* detected service name */
  std::string version;   /* product + version string */
  std::vector<CveEntry> cves;
};

struct TargetCveData {
  std::vector<PortCveResults> port_results;
};

/* Run CVE lookup for all targets.  min_score filters out low-severity
   entries (default 7.0 = HIGH and above). */
void run_cve_map(std::vector<Target*>& Targets, float min_score);

/* Print CVE map output for a single host (called in the per-host loop). */
void print_cve_map_output(const Target *t);

#endif /* CVE_MAP_H */
