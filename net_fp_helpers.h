/*
 * net_fp_helpers.h -- Pure derivation helpers for the relationship-
 * matching fingerprint engine.  Extracted into their own translation
 * unit so the regression tests can link them without dragging in the
 * full net_enrich.cc (OpenSSL, sockets, the whole enrichment pipeline).
 *
 * All functions here are pure: no DB access, no networking, no globals.
 */

#ifndef NET_FP_HELPERS_H
#define NET_FP_HELPERS_H

#include <string>
#include <vector>

/* True if s parses as a bare IPv4 or IPv6 literal.  Used to skip
 * fingerprint emission for cert CNs and SANs that are just the server
 * IP — those have no clustering value (every kmap-scanned IP would
 * share with itself). */
bool fp_looks_like_ip(const std::string &s);

/* Extract the host component from an HTTP Location: header value.
 * Returns "" for relative redirects, scheme:opaque URIs like javascript:,
 * and single-label intranet names that cannot cluster across public-
 * internet scans.  Strips IPv6 brackets; lowercases for stable hashing. */
std::string fp_extract_redirect_host(const std::string &location);

/* Parse the JSON array written by tls_capture_cert into a flat list of
 * DNS SAN values.  Handles "[]", malformed input, and embedded escape
 * sequences; never throws. */
std::vector<std::string> fp_parse_san_json(const std::string &json);

#endif /* NET_FP_HELPERS_H */
