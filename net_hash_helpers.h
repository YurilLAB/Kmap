/*
 * net_hash_helpers.h -- Fingerprint + identity derivation helpers for the
 * Kmap net-scan catalog.
 *
 * Extracted into their own translation unit (mirroring net_fp_helpers.cc) so
 * the standalone test harnesses (fuzz/test_mmh3.cc, test_favicon.cc,
 * test_cpe.cc) can link the REAL implementation instead of a copy that can
 * silently drift.
 *
 * Covers two of the data-catalog upgrades that bring Kmap's collected data
 * closer to what the large internet-survey platforms record:
 *   - Shodan-style favicon hash (http.favicon.hash) for cross-host clustering.
 *   - CPE 2.3 canonical product identity for analytics + downstream tooling.
 */

#ifndef NET_HASH_HELPERS_H
#define NET_HASH_HELPERS_H

#include <string>
#include <cstdint>

/* MurmurHash3 x86_32 over `data` with `seed`, returned as a SIGNED 32-bit
   integer.  Signedness matters: Shodan/mmh3 report favicon hashes as signed
   int32 (values can be negative), and downstream consumers match on that
   exact decimal string. */
int32_t mmh3_x86_32(const std::string &data, uint32_t seed = 0);

/* Python base64.encodebytes() semantics: standard base64 alphabet, a '\n'
   inserted after every 76 output characters, AND a trailing '\n' on the whole
   string.  Empty input -> "" (no newline).  This exact framing is what makes
   the favicon hash below match the value the big scanners publish; plain
   base64 (no line wrapping) yields a different hash. */
std::string base64_encodebytes(const std::string &raw);

/* Shodan http.favicon.hash: mmh3_x86_32(base64_encodebytes(icon_bytes), 0)
   rendered as a decimal string (may carry a leading '-').  Empty input -> "".
   Result is ASCII-safe ([-0-9]); no JSON escaping needed at the storage layer. */
std::string favicon_mmh3(const std::string &icon_bytes);

/* Build a CPE 2.3 formatted-string identifier from a kmap product key (the
   output of net_enrich.cc::normalize_product, e.g. "openssh", "http_server")
   plus the raw banner version string.  Returns "" when the product is not in
   the known map.  Form:
       cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
   The version field keeps the dotted release (p-suffix preserved, so
   "OpenSSH 8.2p1" -> "8.2p1"); when no dotted version is present it is the
   ANY wildcard "*".  Vendor tokens are sourced from the bundled kmap-cve.db
   vendor column so they line up with the CVE taxonomy. */
std::string derive_cpe(const std::string &product, const std::string &version);

#endif /* NET_HASH_HELPERS_H */
