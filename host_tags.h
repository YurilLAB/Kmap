/*
 * host_tags.h -- Shodan-style categorical tags derived from data Kmap already
 * collected during enrichment (no new probes).
 *
 * Tags are the faceting layer the big internet-survey platforms expose
 * (Shodan's `tags`, e.g. self-signed / cloud / vuln / eol-product): cheap,
 * high-signal labels an operator filters on to slice the catalogue.  They are
 * computed on the fly from the stored host columns -- the same precedent
 * net_query's classify_device() sets -- so there is no schema change and a
 * re-tag never needs a re-scan; refreshing the CVE DB (KEV/EPSS) or the EOL
 * table is enough.
 *
 * Pure: no sockets, no OpenSSL, no nbase, so the test/fuzz harnesses link it
 * directly (like net_hash_helpers.cc / ssh_hassh.cc).
 */

#ifndef KMAP_HOST_TAGS_H
#define KMAP_HOST_TAGS_H

#include <string>
#include <vector>

/* Already-collected fields a tag can be derived from.  All optional: an empty
 * / sentinel value simply means "that signal is unavailable", never an error. */
struct HostTagInput {
  std::string service;          /* detected service name ("http","mysql",...) */
  int         port = 0;
  std::string version;          /* detected version string (display form) */
  std::string cpe;              /* derived CPE 2.3 (may be empty/"*") */
  int         tls_self_signed = -1;  /* -1 unknown, 0 chain-valid, 1 self-signed */
  std::string cloud_provider;   /* "aws"/"gcp"/... or "" */
  std::string cves_json;        /* stored cves JSON array ("" / "[]" if none) */
};

/* Derive the sorted, de-duplicated tag set for one host.  Possible tags:
 *   self-signed  -- TLS leaf cert did not chain-validate
 *   cloud        -- IP fell in a known cloud provider range
 *   cdn          -- cloud provider is a known CDN (Cloudflare, Akamai, ...)
 *   database     -- service is a database engine
 *   ics          -- service port is a known ICS/SCADA protocol
 *   vuln         -- at least one CVE matched
 *   kev          -- a matched CVE is in the CISA KEV catalog
 *   ransomware   -- a matched KEV CVE is tied to a ransomware campaign
 *   eol-product  -- detected product/version is past end-of-life
 */
std::vector<std::string> derive_host_tags(const HostTagInput &in);

#endif /* KMAP_HOST_TAGS_H */
