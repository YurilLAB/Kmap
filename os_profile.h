/*
 * os_profile.h -- OS fingerprint spoofing profiles for Kmap net-scan.
 *
 * Provides preset "personality" profiles that adjust the kernel-controlled
 * knobs we CAN influence on a connect()-scan path:
 *
 *   IP-layer:    IP TTL / IPv6 hop limit
 *   TCP-layer:   SO_RCVBUF, SO_SNDBUF, TCP_MAXSEG (POSIX only)
 *   HTTP-layer:  request line version, User-Agent, Accept, Accept-Language,
 *                Accept-Encoding, Sec-Fetch-* (browser_like), and
 *                Upgrade-Insecure-Requests (browser_like)
 *
 * Why not deeper TCP/IP stack spoofing?
 *   net-scan's discovery layer (fast_syn) currently runs as a connect()
 *   scan, so the SYN packet's window scale, option ordering, and the
 *   ephemeral source-port range are owned by the kernel and unreachable
 *   from userspace without raw sockets (Linux: libnet/raw, Windows:
 *   Npcap/WinDivert). This module deliberately stays inside the cross-
 *   platform setsockopt() surface so it works identically on both OSes
 *   with no extra dependencies. A future raw-mode path can layer on top
 *   of these profiles to spoof the full stack.
 *
 * Available profile names (case-sensitive):
 *   "linux"   -- modern glibc + curl
 *   "win10"   -- Windows 10 Edge/Chromium
 *   "win11"   -- Windows 11 Edge/Chromium with client hints
 *   "macos"   -- macOS Safari
 *   "freebsd" -- FreeBSD Firefox
 *   "openbsd" -- OpenBSD curl
 *   "android" -- Android Chrome
 *   "ios"     -- iOS Safari
 *   "random"  -- pick one of the above per target (stable per host)
 */

#ifndef OS_PROFILE_H
#define OS_PROFILE_H

#include <cstdint>
#include <string>

struct OsProfile {
  const char *name;             /* canonical name, e.g. "linux" */

  /* IP / TCP socket knobs */
  int      ttl;                 /* IP TTL / IPv6 hop limit (1-255). 0 = leave default */
  uint16_t source_port_min;     /* Informational only -- not bound. See os_profile.cc */
  uint16_t source_port_max;
  int      recv_buf_bytes;      /* SO_RCVBUF hint. 0 = leave default */
  int      send_buf_bytes;      /* SO_SNDBUF hint. 0 = leave default */
  int      mss_hint;            /* TCP_MAXSEG hint. 0 = leave default. POSIX only. */

  /* HTTP request shaping */
  const char *user_agent;       /* Required for real profiles */
  const char *accept;           /* Explicit Accept value. NULL = derive from browser_like */
  const char *accept_language;
  const char *accept_encoding;
  const char *extra_headers;    /* Raw extra header lines, "\r\n"-separated, no trailing CRLF */
  bool     http11;              /* true -> emit "HTTP/1.1" (still Connection: close) */
  bool     browser_like;        /* true -> emit Sec-Fetch-* and Upgrade-Insecure-Requests */
};

/* Look up a profile by name. Returns NULL if name doesn't match any preset.
 * For "random", returns a uniformly randomly selected concrete profile (a
 * different profile on each call). Most callers should prefer
 * os_profile_get_for_target() to get a stable per-host pick instead.
 * NULL profile_name returns NULL. */
const OsProfile *os_profile_get(const char *profile_name);

/* Like os_profile_get(), but for the "random" pseudo-profile uses `seed`
 * to deterministically pick a concrete profile, so repeated probes to the
 * same target get the same OS personality. For non-random profiles the
 * `seed` argument is ignored and behaviour is identical to os_profile_get().
 * Use os_profile_seed_from_ipv4 / os_profile_seed_from_text to compute a
 * seed appropriate to the caller's target representation. */
const OsProfile *os_profile_get_for_target(const char *profile_name,
                                           uint64_t seed);

/* Stable seed helpers for the per-target picker. Both produce the same
 * seed for the same input and spread small inputs (e.g. /24 ranges,
 * "10.x" prefixes) uniformly across the profile table. */
uint64_t os_profile_seed_from_ipv4(uint32_t ipv4_host_order);
uint64_t os_profile_seed_from_text(const char *text);

/* True if the name is a recognized profile. Use this for fail-fast CLI
 * validation before the scan starts, so typos surface immediately rather
 * than silently disabling spoofing later. */
bool os_profile_is_valid(const char *profile_name);

/* Comma-separated list of valid profile names -- for error messages. */
const char *os_profile_names(void);

/* Apply the profile's socket-level knobs to an already-created socket.
 * Safe to call with profile == NULL (no-op). Safe before connect() is
 * issued. The af argument must be AF_INET or AF_INET6 so we know whether
 * to set IP_TTL or IPV6_UNICAST_HOPS.
 *
 * On Windows, fd is a SOCKET cast to intptr_t; on POSIX it's an int fd.
 * The implementation casts back to the right platform type. setsockopt
 * failures are swallowed: the worst case is "the spoof doesn't take" and
 * the scan proceeds with the kernel default. */
void os_profile_apply_socket(intptr_t fd, int af, const OsProfile *profile);

/* Build an HTTP GET request that uses the profile's User-Agent, Accept-*
 * headers, and (when browser_like is set) Sec-Fetch-* + Upgrade-Insecure-
 * Requests. Bracketing of IPv6 hosts in the Host header is handled here
 * per RFC 7230 Section 5.4. profile == NULL falls back to a Kmap-branded
 * HTTP/1.0 request, preserving pre-spoofing behaviour. */
std::string os_profile_http_request(const char *path,
                                    const char *host,
                                    const OsProfile *profile);

/* Optional TLS knobs for callers that want to harmonise the JA3 fingerprint
 * with the spoofed OS. Returns the OpenSSL-style cipher list string for
 * TLS<=1.2, or NULL to leave the SSL_CTX default. Always safe to call;
 * profile == NULL returns NULL. */
const char *os_profile_tls_cipher_list(const OsProfile *profile);

#endif /* OS_PROFILE_H */
