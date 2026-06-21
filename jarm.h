/*
 * jarm.h -- JARM active TLS server fingerprint (Salesforce JARM, John Althouse
 * et al., 2020).  Shodan exposes this as ssl.jarm; it was kmap's most notable
 * gap versus Shodan for TLS services.
 *
 * JARM sends ten specially-crafted TLS ClientHello probes (varying version,
 * cipher ordering, extension ordering, GREASE and ALPN) and hashes the servers'
 * ServerHello responses into a 62-character fingerprint: 30 chars of a fuzzy
 * cipher/version hash + 32 chars of a truncated SHA-256 over the ALPN/extension
 * data.  Two hosts with the same JARM are running an indistinguishable TLS stack
 * (same library/version/config), which is the pivot Shodan/Censys use.
 *
 * This is a faithful reimplementation of the reference jarm.py: the ClientHello
 * builders are byte-for-byte identical (verified against the reference packets
 * in fuzz/test_jarm.cc) and the hash is verified end-to-end against jarm.py run
 * against the same server.  The client random / session-id / key-share bytes do
 * not affect the result (the server echoes nothing JARM-relevant from them), so
 * production uses real random bytes while the byte-exact test injects zeros.
 */

#ifndef KMAP_JARM_H
#define KMAP_JARM_H

#include <cstdint>
#include <string>

/* Build the i-th (0..9) JARM ClientHello for `host`.  When `deterministic` is
 * true the random client-random / session-id / key-share bytes are zeroed and
 * GREASE is pinned to 0x0a0a, so the output is reproducible for known-answer
 * testing; production passes false for real entropy (JARM result is identical).
 * Returns the raw TLS record bytes, or "" if i is out of range. */
std::string jarm_build_client_hello(int i, const std::string &host,
                                    bool deterministic);

/* Parse a raw ServerHello record into the JARM per-probe string
 * "cipher|version|alpn|extensions" (mirrors jarm.py read_packet).  Returns
 * "|||" on an alert / non-ServerHello / malformed/truncated record. */
std::string jarm_parse_server_hello(const uint8_t *data, size_t n);

/* Assemble the final 62-char JARM hash from the ten comma-joined per-probe
 * strings (mirrors jarm.py jarm_hash).  All-failed input yields 62 zeros. */
std::string jarm_hash(const std::string &jarm_raw);

/* Full network fingerprint: probe ip:port ten times and return the 62-char
 * JARM.  Returns "" if not a single probe got a TCP connection (so callers can
 * distinguish "no TLS here" from a real all-failures "0"*62).  timeout_ms is
 * per-probe. */
std::string jarm_fingerprint(const char *ip, int port, int timeout_ms);

#endif /* KMAP_JARM_H */
