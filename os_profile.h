/*
 * os_profile.h -- OS fingerprint spoofing profiles for Kmap net-scan.
 *
 * Provides preset "personality" profiles that adjust the kernel-controlled
 * knobs we CAN influence on a connect()-scan path: IP TTL / IPv6 hop limit,
 * SO_RCVBUF (advertised window hint), and the User-Agent / Accept-* headers
 * used by the HTTP and HTTPS probes in web_recon and net_enrich.
 *
 * Why not deeper TCP/IP stack spoofing?
 *   net-scan's discovery layer (fast_syn) currently runs as a connect()
 *   scan, so the SYN packet's window, MSS, and option ordering are owned
 *   by the kernel and unreachable from userspace without raw sockets
 *   (Linux: libnet/raw, Windows: Npcap/WinDivert). This module deliberately
 *   stays inside the cross-platform setsockopt() surface so it works
 *   identically on both OSes with no extra dependencies. A future raw-mode
 *   path can layer on top of these profiles to spoof the full stack.
 *
 * Available profile names (case-sensitive):
 *   "linux"   -- modern glibc + curl
 *   "win10"   -- Windows 10 Edge/Chromium
 *   "win11"   -- Windows 11 Edge/Chromium with client hints
 *   "macos"   -- macOS Safari
 *   "freebsd" -- FreeBSD Firefox
 *   "random"  -- pick one of the above per host
 */

#ifndef OS_PROFILE_H
#define OS_PROFILE_H

#include <cstdint>
#include <string>

struct OsProfile {
  const char *name;             /* canonical name, e.g. "linux" */

  /* Network-layer knobs */
  int      ttl;                 /* IP TTL / IPv6 hop limit (1-255). 0 = leave default */
  uint16_t source_port_min;     /* Inclusive. 0 = use kernel ephemeral */
  uint16_t source_port_max;     /* Inclusive. */
  int      recv_buf_bytes;      /* SO_RCVBUF hint. 0 = leave default */

  /* HTTP-layer knobs */
  const char *user_agent;       /* Required (never NULL for real profiles) */
  const char *accept_language;  /* Optional */
  const char *accept_encoding;  /* Optional */
  const char *extra_headers;    /* Raw extra header lines, "\r\n"-separated, no trailing CRLF */
};

/* Look up a profile by name. Returns NULL if name doesn't match any preset.
 * For "random", returns a randomly selected concrete profile (different
 * profile per call). NULL profile_name returns NULL. */
const OsProfile *os_profile_get(const char *profile_name);

/* True if the name is a recognized profile. Use this for fail-fast CLI
 * validation before the scan starts, so typos surface immediately rather
 * than silently disabling spoofing later. */
bool os_profile_is_valid(const char *profile_name);

/* Comma-separated list of valid profile names — for error messages. */
const char *os_profile_names(void);

/* Apply the profile's socket-level knobs to an already-created socket.
 * Safe to call with profile == NULL (no-op). Safe before connect() is
 * issued. The af argument must be AF_INET or AF_INET6 so we know whether
 * to set IP_TTL or IPV6_UNICAST_HOPS.
 *
 * On Windows, fd is a SOCKET cast to intptr_t; on POSIX it's an int fd.
 * The implementation casts back to the right platform type. */
void os_profile_apply_socket(intptr_t fd, int af, const OsProfile *profile);

/* Build a minimal HTTP/1.0 GET request that uses the profile's User-Agent
 * and Accept-* headers. Bracketing of IPv6 hosts is handled here per
 * RFC 7230 §5.4. profile == NULL falls back to a Kmap-branded request
 * (preserving pre-spoofing behavior). */
std::string os_profile_http_request(const char *path,
                                    const char *host,
                                    const OsProfile *profile);

#endif /* OS_PROFILE_H */
