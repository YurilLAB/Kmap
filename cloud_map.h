/*
 * cloud_map.h -- passive cloud-provider identification for Kmap net-scan.
 *
 * Tags a host with its cloud provider / region / service by matching the IP
 * against a bundled table of published cloud IPv4 ranges (kmap-cloud-ranges.csv,
 * refreshed out-of-band by tools/refresh-cloud-ranges.py).  This is a PURE,
 * OFFLINE match -- no runtime network -- so it drops in beside the ASN leg in
 * the enrichment pipeline at near-zero cost.
 *
 * Self-contained TU (own strict CIDR parser, no net_db dependency) so the test
 * harness links the real matcher, mirroring net_hash_helpers / net_fp_helpers.
 */

#ifndef CLOUD_MAP_H
#define CLOUD_MAP_H

#include <cstdint>
#include <string>

/* Result of a cloud-range match for one IPv4 address.  An empty `provider`
   means "no match" (the host is not in any bundled cloud range). */
struct CloudInfo {
  std::string provider;   /* lowercased enum: "aws"/"gcp"/"azure"/"cloudflare"/... */
  std::string region;     /* provider region verbatim, e.g. "us-east-1" (may be "") */
  std::string service;    /* provider service, e.g. "EC2"/"S3" (may be "") */
};

/* Load + parse the cloud-range file at `path` into the in-memory match table,
   REPLACING any previously loaded table.  Call ONCE at pipeline start (before
   any worker thread runs lookup_cloud); lookups are then lock-free.  A NULL /
   empty / missing path loads nothing (every lookup_cloud returns no match).
   Returns the number of ranges loaded. */
size_t cloud_ranges_load(const char *path);

/* Longest-prefix match of a host IPv4 (host byte order) against the loaded
   table.  Lock-free; safe to call concurrently after the one-time load.
   Returns CloudInfo{} (empty provider) when the IP is in no cloud range. */
CloudInfo lookup_cloud(uint32_t ip);

/* Number of ranges currently loaded (for the startup log line / tests). */
size_t cloud_ranges_count();

/* Test seam: strictly parse one "cidr,provider,region,service" line.  Fills the
   out-params and returns true; returns false on any malformed field (bad CIDR,
   empty provider, IPv6).  region/service may be empty.  prefix_len is the CIDR
   prefix length.  net is the masked network base. */
bool cloud_parse_line(const char *line, uint32_t *net, uint32_t *mask,
                      uint8_t *prefix_len, std::string *provider,
                      std::string *region, std::string *service);

#endif /* CLOUD_MAP_H */
