/*
 * os_profile.cc -- OS fingerprint spoofing profiles for Kmap net-scan.
 * See os_profile.h for the rationale and API contract.
 */

#ifdef WIN32
/* kmap_winconfig.h MUST come first on Windows. It defines NOMINMAX before
 * <windows.h> can be pulled in transitively, and pre-includes the C++
 * stream headers ahead of nbase's close/write macro pollution. This file
 * itself doesn't use streams, but cross-TU compatibility benefits from the
 * same include shape we use everywhere else. */
#include "kmap_winconfig.h"
#endif

#include "os_profile.h"

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <random>
#include <string>

#ifdef WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

/* -----------------------------------------------------------------------
 * Profile presets
 *
 * UA strings track real-world current-generation defaults (Chrome 121,
 * Edge 121, Safari 17, Firefox 121). The point isn't to be perfectly
 * up-to-date — it's to look like *some* plausible recent browser instead
 * of "Kmap Web Recon", which is trivially fingerprinted by any WAF.
 * ----------------------------------------------------------------------- */

static const OsProfile g_profiles[] = {
  {
    "linux",
    64,                /* TTL — Linux default */
    32768, 60999,      /* /proc/sys/net/ipv4/ip_local_port_range default */
    131072,            /* recv_buf */
    /* curl is a much more believable Linux fingerprint than a browser UA
     * because it's what most Linux service-to-service traffic looks like. */
    "curl/8.5.0",
    "en-US,en;q=0.9",
    "gzip, deflate",
    NULL
  },
  {
    "win10",
    128,               /* TTL — Windows default */
    49152, 65535,      /* Windows ephemeral range (registry default) */
    65536,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "en-US,en;q=0.9",
    "gzip, deflate, br",
    "DNT: 1"
  },
  {
    "win11",
    128,
    49152, 65535,
    65536,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "en-US,en;q=0.9",
    "gzip, deflate, br",
    /* Client hints — appears on Chromium 89+; without them the UA looks
     * like a Chromium that has client hints disabled, which is unusual. */
    "Sec-Ch-Ua: \"Chromium\";v=\"121\", \"Not_A Brand\";v=\"24\", "
    "\"Microsoft Edge\";v=\"121\"\r\n"
    "Sec-Ch-Ua-Mobile: ?0\r\n"
    "Sec-Ch-Ua-Platform: \"Windows\"\r\n"
    "DNT: 1"
  },
  {
    "macos",
    64,
    49152, 65535,      /* macOS uses the IANA-recommended ephemeral range */
    131072,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "en-US,en;q=0.9",
    "gzip, deflate, br",
    NULL
  },
  {
    "freebsd",
    64,
    10000, 65535,      /* FreeBSD's net.inet.ip.portrange.first default */
    65536,
    "Mozilla/5.0 (X11; FreeBSD amd64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "en-US,en;q=0.5",
    "gzip, deflate, br",
    NULL
  }
};
static const size_t g_profile_count = sizeof(g_profiles) / sizeof(g_profiles[0]);

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

const char *os_profile_names(void) {
  /* Build once on first call; the comma-list itself is static and never
   * mutated, so this is safe without locks. */
  static std::string cached;
  if (!cached.empty()) return cached.c_str();
  for (size_t i = 0; i < g_profile_count; i++) {
    if (i) cached += ",";
    cached += g_profiles[i].name;
  }
  cached += ",random";
  return cached.c_str();
}

bool os_profile_is_valid(const char *profile_name) {
  if (!profile_name || !profile_name[0]) return false;
  if (strcmp(profile_name, "random") == 0) return true;
  for (size_t i = 0; i < g_profile_count; i++) {
    if (strcmp(profile_name, g_profiles[i].name) == 0) return true;
  }
  return false;
}

const OsProfile *os_profile_get(const char *profile_name) {
  if (!profile_name || !profile_name[0]) return NULL;

  if (strcmp(profile_name, "random") == 0) {
    /* Pick a uniformly-random concrete profile. We use std::random_device
     * (backed by /dev/urandom on POSIX, RtlGenRandom on Windows MSVC) so
     * an attacker observing a few requests can't predict the next one. */
    static std::random_device rd;
    return &g_profiles[rd() % g_profile_count];
  }

  for (size_t i = 0; i < g_profile_count; i++) {
    if (strcmp(profile_name, g_profiles[i].name) == 0)
      return &g_profiles[i];
  }
  return NULL;
}

void os_profile_apply_socket(intptr_t fd, int af, const OsProfile *profile) {
  if (!profile) return;

  /* TTL / hop limit. We deliberately don't fail the scan if setsockopt
   * returns an error — some BSD variants reject IP_TTL on TCP sockets,
   * and Solaris-style hosts may need a different option name. The
   * fallback is "scan succeeds with the kernel-default TTL" which is
   * exactly the pre-spoofing behavior. */
  if (profile->ttl > 0 && profile->ttl <= 255) {
    int ttl = profile->ttl;
#ifdef WIN32
    SOCKET s = static_cast<SOCKET>(fd);
    if (af == AF_INET6) {
      /* IPV6_UNICAST_HOPS is in <ws2tcpip.h> on Vista+ and is the right
       * option for IPv6 outbound hop count. */
      setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                 reinterpret_cast<const char *>(&ttl), sizeof(ttl));
    } else {
      setsockopt(s, IPPROTO_IP, IP_TTL,
                 reinterpret_cast<const char *>(&ttl), sizeof(ttl));
    }
#else
    int s = static_cast<int>(fd);
    if (af == AF_INET6) {
      setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
    } else {
      setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    }
#endif
  }

  /* SO_RCVBUF — only a hint to the kernel about advertised window size.
   * Linux doubles whatever you pass (sysctl net.core.rmem_max may cap
   * it), Windows takes it more literally. The point isn't to set a
   * specific window — it's to make the window NOT be the kernel default
   * so the SYN-ACK we eventually send back doesn't immediately scream
   * "default-tuned host of OS X". */
  if (profile->recv_buf_bytes > 0) {
    int bufsz = profile->recv_buf_bytes;
#ifdef WIN32
    SOCKET s = static_cast<SOCKET>(fd);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char *>(&bufsz), sizeof(bufsz));
#else
    int s = static_cast<int>(fd);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
#endif
  }

  /* Source port binding is intentionally NOT done here. Binding a fixed
   * port forces the kernel to track it and would refuse on EADDRINUSE
   * the moment two probes land on the same port. The valuable signal
   * (port range *distribution*) only matters across many connections
   * over time, which the kernel ephemeral allocator already produces in
   * a way roughly consistent with the host OS — meaning a Linux host
   * scanning with --spoof-os=win10 already shows a Linux-typical port
   * range to remote observers. Fixing this would need a per-scan port
   * allocator with retry-on-conflict; left as a TODO for the raw-mode
   * follow-up that wants full spoofing fidelity. */
}

/* Helper: detect IPv6 literal (presence of ':' indicates IPv6 since DNS
 * names and IPv4 dotted-quads never contain colons). RFC 7230 §5.4 requires
 * brackets in the Host header for IPv6 literals. */
static bool host_is_ipv6(const char *host) {
  return host && strchr(host, ':') != NULL;
}

std::string os_profile_http_request(const char *path,
                                    const char *host,
                                    const OsProfile *profile) {
  std::string host_hdr = host ? host : "";
  if (host_is_ipv6(host))
    host_hdr = "[" + std::string(host) + "]";

  std::string req;
  req.reserve(384);
  req += "GET ";
  req += (path && path[0]) ? path : "/";
  req += " HTTP/1.0\r\n";
  req += "Host: " + host_hdr + "\r\n";

  if (profile && profile->user_agent && profile->user_agent[0]) {
    req += "User-Agent: ";
    req += profile->user_agent;
    req += "\r\n";

    /* Accept: a believable browser request always sends Accept. We omit
     * it for the curl-style "linux" profile because curl by default
     * doesn't send one. */
    if (strcmp(profile->name, "linux") != 0) {
      req += "Accept: text/html,application/xhtml+xml,application/xml;"
             "q=0.9,image/avif,image/webp,*/*;q=0.8\r\n";
    }
    if (profile->accept_language && profile->accept_language[0]) {
      req += "Accept-Language: ";
      req += profile->accept_language;
      req += "\r\n";
    }
    if (profile->accept_encoding && profile->accept_encoding[0]) {
      req += "Accept-Encoding: ";
      req += profile->accept_encoding;
      req += "\r\n";
    }
    if (profile->extra_headers && profile->extra_headers[0]) {
      req += profile->extra_headers;
      req += "\r\n";
    }
  } else {
    /* No profile / unrecognized profile: keep the legacy Kmap-branded
     * request so existing behavior is preserved when --spoof-os is
     * absent. Web recon and net_enrich previously sent slightly
     * different banners; pick the more common one. */
    req += "User-Agent: Kmap\r\n";
  }

  req += "Connection: close\r\n\r\n";
  return req;
}
