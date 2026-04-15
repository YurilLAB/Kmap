/*
 * asn_lookup.h -- ASN / GeoIP enrichment for Kmap.
 *
 * Resolves an IPv4 address to its Autonomous System Number, owner name,
 * country code, and BGP prefix using DNS TXT queries against Team Cymru's
 * IP-to-ASN mapping service (origin.asn.cymru.com).
 *
 * All lookups use a lightweight built-in UDP DNS client — no external
 * libraries or bundled database files required.
 */

#ifndef ASN_LOOKUP_H
#define ASN_LOOKUP_H

#include <cstdint>
#include <string>

/* Result of an ASN lookup for a single IP address. */
struct AsnInfo {
  uint32_t    asn;         /* Autonomous System Number (0 = unknown) */
  std::string as_name;     /* AS owner name, e.g. "GOOGLE" */
  std::string country;     /* ISO 3166-1 alpha-2 country code, e.g. "US" */
  std::string bgp_prefix;  /* BGP prefix, e.g. "8.8.8.0/24" */
  std::string registry;    /* RIR name: arin, ripe, apnic, lacnic, afrinic */
  std::string region;      /* Human-readable region, e.g. "North America" */
};

/* Look up ASN information for an IPv4 address (dotted-quad string).
 * timeout_ms controls how long to wait for DNS responses.
 * Returns an AsnInfo with asn=0 on failure (timeout, parse error, etc.). */
AsnInfo lookup_asn(const char *ip, int timeout_ms = 3000);

/* Look up just the AS name for a given ASN number.
 * Uses AS<N>.peer.asn.cymru.com TXT query.
 * Returns empty string on failure. */
std::string lookup_as_name(uint32_t asn, int timeout_ms = 3000);

#endif /* ASN_LOOKUP_H */
