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
#include <cstdio>
#include <ctime>
#include <random>
#include <string>

#ifdef WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>     /* TCP_MAXSEG */
#endif

/* -----------------------------------------------------------------------
 * Profile presets
 *
 * UA and TLS-cipher-order strings track real-world current-generation
 * defaults (Chrome 121, Edge 121, Safari 17, Firefox 121). The point isn't
 * to be perfectly up-to-date -- it's to look like *some* plausible recent
 * browser/OS instead of "Kmap Web Recon", which is trivially fingerprinted
 * by any WAF.
 *
 * Field order MUST match the OsProfile struct layout in os_profile.h.
 * Each entry is positionally-initialised in the same order as the struct
 * declaration to stay portable across compilers without depending on
 * C++20 designated-initialiser support.
 * ----------------------------------------------------------------------- */

static const OsProfile g_profiles[] = {
  /* ---- linux: glibc + curl ---- */
  {
    "linux",
    /* IP/TCP knobs */
    64,                /* TTL -- Linux default */
    32768, 60999,      /* /proc/sys/net/ipv4/ip_local_port_range default */
    131072,            /* recv_buf -- close to Linux 6.x autotune ceiling */
    16384,             /* send_buf */
    1460,              /* mss_hint -- standard Ethernet MSS */
    /* HTTP knobs.
     * curl is a much more believable Linux fingerprint than a browser UA
     * because it's what most Linux service-to-service traffic looks like.
     * Accept = "" -> omit (curl by default sends no Accept header). */
    "curl/8.5.0",
    "*/*",             /* curl 7.x+ default Accept */
    NULL,              /* accept_language: curl sends none */
    NULL,              /* accept_encoding: curl sends none unless --compressed */
    NULL,              /* extra_headers */
    false,             /* http11 -- keep HTTP/1.0 to match curl --http1.0 banner-grab style */
    false              /* browser_like */
  },
  /* ---- win10: Edge 120 on Windows 10 ---- */
  {
    "win10",
    128,               /* TTL -- Windows default */
    49152, 65535,      /* Windows ephemeral range (registry default) */
    65536,             /* recv_buf -- Windows TCP autotune typical */
    65536,
    1460,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    NULL,              /* accept: derive default browser Accept */
    "en-US,en;q=0.9",
    "gzip, deflate, br",
    "DNT: 1",
    true,              /* http11 */
    true               /* browser_like */
  },
  /* ---- win11: Edge 121 with full client hints ---- */
  {
    "win11",
    128,
    49152, 65535,
    65536,
    65536,
    1460,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    NULL,
    "en-US,en;q=0.9",
    "gzip, deflate, br",
    /* Client hints -- appears on Chromium 89+; without them the UA looks
     * like a Chromium that has client hints disabled, which is unusual
     * enough to flip many WAF heuristics. */
    "Sec-Ch-Ua: \"Chromium\";v=\"121\", \"Not_A Brand\";v=\"24\", "
    "\"Microsoft Edge\";v=\"121\"\r\n"
    "Sec-Ch-Ua-Mobile: ?0\r\n"
    "Sec-Ch-Ua-Platform: \"Windows\"\r\n"
    "DNT: 1",
    true,
    true
  },
  /* ---- macos: Safari 17 on Sonoma ---- */
  {
    "macos",
    64,
    49152, 65535,      /* macOS uses the IANA-recommended ephemeral range */
    131072,
    131072,
    1460,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    NULL,
    "en-US,en;q=0.9",
    "gzip, deflate, br",
    NULL,
    true,
    true
  },
  /* ---- freebsd: Firefox 121 ---- */
  {
    "freebsd",
    64,
    10000, 65535,      /* FreeBSD's net.inet.ip.portrange.first default */
    65536,
    32768,
    1460,
    "Mozilla/5.0 (X11; FreeBSD amd64; rv:121.0) Gecko/20100101 Firefox/121.0",
    NULL,
    "en-US,en;q=0.5",  /* Firefox default -- note the different q value */
    "gzip, deflate, br",
    NULL,
    true,
    true
  },
  /* ---- openbsd: curl/lynx-ish ---- */
  {
    "openbsd",
    64,
    1024, 49151,       /* OpenBSD inetbase + ipport_hifirstauto default */
    16384,             /* OpenBSD has conservative defaults */
    16384,
    1440,              /* OpenBSD pf often drops MSS to 1440 to avoid PMTUD */
    "curl/8.4.0",
    "*/*",
    NULL,
    NULL,
    NULL,
    false,             /* HTTP/1.0 like curl */
    false
  },
  /* ---- android: Chrome Mobile on Android 14 ---- */
  {
    "android",
    64,                /* Linux-derived TTL */
    32768, 60999,
    87380,             /* Android tcp_rmem default ceiling */
    16384,
    1460,
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
    NULL,
    "en-US,en;q=0.9",
    "gzip, deflate, br",
    "Sec-Ch-Ua: \"Chromium\";v=\"121\", \"Not_A Brand\";v=\"24\", "
    "\"Google Chrome\";v=\"121\"\r\n"
    "Sec-Ch-Ua-Mobile: ?1\r\n"
    "Sec-Ch-Ua-Platform: \"Android\"",
    true,
    true
  },
  /* ---- ios: Safari Mobile on iOS 17 ---- */
  {
    "ios",
    64,                /* Darwin-derived TTL */
    49152, 65535,
    131072,
    131072,
    1440,              /* iOS often advertises MSS=1440 over LTE/cellular */
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    NULL,
    "en-US,en;q=0.9",
    "gzip, deflate, br",
    NULL,
    true,
    true
  }
};
static const size_t g_profile_count = sizeof(g_profiles) / sizeof(g_profiles[0]);

/* -----------------------------------------------------------------------
 * Public API: lookup / validation
 * ----------------------------------------------------------------------- */

const char *os_profile_names(void) {
  /* Build once on first call; the comma-list itself is static and never
   * mutated, so this is safe without locks. (Multiple threads racing on
   * the first call is harmless: each writes the same bytes, and the
   * resulting std::string is internally consistent.) */
  static std::string cached;
  if (!cached.empty()) return cached.c_str();
  std::string s;
  for (size_t i = 0; i < g_profile_count; i++) {
    if (i) s += ",";
    s += g_profiles[i].name;
  }
  s += ",random";
  cached = s;
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
     * an attacker observing a few requests can't predict the next one.
     * Note: this picks a NEW profile on every call. Callers that need
     * stability per target should use os_profile_get_for_target(). */
    static std::random_device rd;
    return &g_profiles[rd() % g_profile_count];
  }

  for (size_t i = 0; i < g_profile_count; i++) {
    if (strcmp(profile_name, g_profiles[i].name) == 0)
      return &g_profiles[i];
  }
  return NULL;
}

/* splitmix64 -- small, fast, good distribution. The constants are the
 * usual ones from Steele/Lea splitmix; chosen because they pass BigCrush
 * for 64-bit avalanche. We only need the high-bit avalanche so that two
 * adjacent IPv4s (10.0.0.1 and 10.0.0.2) don't end up on the same
 * profile. */
static uint64_t splitmix64(uint64_t x) {
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

uint64_t os_profile_seed_from_ipv4(uint32_t ipv4_host_order) {
  return splitmix64(static_cast<uint64_t>(ipv4_host_order));
}

uint64_t os_profile_seed_from_text(const char *text) {
  if (!text) return 0;
  /* FNV-1a 64-bit, then splitmix to break low-bit clustering when two
   * inputs differ only in their final character. */
  uint64_t h = 0xcbf29ce484222325ULL;
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(text);
       *p; ++p) {
    h ^= *p;
    h *= 0x100000001b3ULL;
  }
  return splitmix64(h);
}

const OsProfile *os_profile_get_for_target(const char *profile_name,
                                           uint64_t seed) {
  if (!profile_name || !profile_name[0]) return NULL;

  if (strcmp(profile_name, "random") == 0) {
    /* Stable per-target pick: same seed -> same profile. The seed is
     * already mixed by the *_seed_from_* helpers, but we splitmix once
     * more here as a defence against callers that pass a raw, low-entropy
     * uint64_t (e.g. an interface index) and expect uniform distribution. */
    return &g_profiles[splitmix64(seed) % g_profile_count];
  }

  for (size_t i = 0; i < g_profile_count; i++) {
    if (strcmp(profile_name, g_profiles[i].name) == 0)
      return &g_profiles[i];
  }
  return NULL;
}

/* -----------------------------------------------------------------------
 * Public API: socket-level application
 * ----------------------------------------------------------------------- */

void os_profile_apply_socket(intptr_t fd, int af, const OsProfile *profile) {
  if (!profile) return;

  /* TTL / hop limit. We deliberately don't fail the scan if setsockopt
   * returns an error -- some BSD variants reject IP_TTL on TCP sockets,
   * and Solaris-style hosts may need a different option name. The
   * fallback is "scan succeeds with the kernel-default TTL" which is
   * exactly the pre-spoofing behaviour. */
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

  /* SO_RCVBUF / SO_SNDBUF -- hints to the kernel about advertised window
   * size. Linux doubles whatever you pass (sysctl net.core.rmem_max may
   * cap it), Windows takes it more literally. The point isn't to set a
   * specific window -- it's to make the window NOT be the kernel default
   * so the SYN-ACK we eventually send back doesn't immediately scream
   * "default-tuned host of OS X". Setting both directions matches what a
   * real OS's autotuner ends up doing on a fresh connection. */
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
  if (profile->send_buf_bytes > 0) {
    int bufsz = profile->send_buf_bytes;
#ifdef WIN32
    SOCKET s = static_cast<SOCKET>(fd);
    setsockopt(s, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char *>(&bufsz), sizeof(bufsz));
#else
    int s = static_cast<int>(fd);
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
#endif
  }

  /* MSS hint via TCP_MAXSEG. POSIX-only: Windows defines TCP_MAXSEG as
   * GET-only and setsockopt will return WSAEINVAL, so we skip it under
   * WIN32 entirely rather than producing scattered errors that mask real
   * failures in callers' getsockopt logging. The MSS hint must be set
   * BEFORE connect() for it to land in the SYN -- all current callers do
   * exactly that. */
#ifndef WIN32
  if (profile->mss_hint > 0 && profile->mss_hint <= 65535) {
    int mss = profile->mss_hint;
    int s = static_cast<int>(fd);
    /* IPv4 and IPv6 share the same TCP_MAXSEG semantics, so no af switch. */
    setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
  }
#endif

  /* Source port binding is intentionally NOT done here. Binding a fixed
   * port forces the kernel to track it and would refuse on EADDRINUSE
   * the moment two probes land on the same port. The valuable signal
   * (port range *distribution*) only matters across many connections
   * over time, which the kernel ephemeral allocator already produces in
   * a way roughly consistent with the host OS -- meaning a Linux host
   * scanning with --spoof-os=win10 already shows a Linux-typical port
   * range to remote observers. Fixing this without raw sockets would
   * need either Linux 6.3+'s IP_LOCAL_PORT_RANGE socket option or a
   * per-scan port allocator with retry-on-conflict; left as a TODO for
   * the raw-mode follow-up that wants full spoofing fidelity. The
   * source_port_min/max fields on the profile are kept for that future
   * code and for documentation. */
}

/* -----------------------------------------------------------------------
 * Public API: HTTP request shaping
 * ----------------------------------------------------------------------- */

/* Detect IPv6 literal (presence of ':' indicates IPv6 since DNS names
 * and IPv4 dotted-quads never contain colons). RFC 7230 Section 5.4 requires
 * brackets in the Host header for IPv6 literals. */
static bool host_is_ipv6(const char *host) {
  return host && strchr(host, ':') != NULL;
}

/* Default browser Accept value -- matches what current Chromium/Firefox/
 * Safari send when the user navigates directly to a URL. Identical
 * across the major browsers in 2024+, so a single default suffices for
 * all browser_like profiles that don't override it. */
static const char *kDefaultBrowserAccept =
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,*/*;q=0.8";

std::string os_profile_http_request(const char *path,
                                    const char *host,
                                    const OsProfile *profile) {
  std::string host_hdr = host ? host : "";
  if (host_is_ipv6(host))
    host_hdr = "[" + std::string(host) + "]";

  std::string req;
  req.reserve(512);

  /* Request line. HTTP/1.1 looks more browser-faithful than HTTP/1.0
   * but requires the Host header (which we always include) and breaks
   * if the server expects chunked-encoding aware clients -- so we still
   * send Connection: close at the end to force a clean response
   * termination regardless of version. */
  const bool use_http11 = profile && profile->http11;
  req += "GET ";
  req += (path && path[0]) ? path : "/";
  req += use_http11 ? " HTTP/1.1\r\n" : " HTTP/1.0\r\n";
  req += "Host: " + host_hdr + "\r\n";

  if (profile && profile->user_agent && profile->user_agent[0]) {
    req += "User-Agent: ";
    req += profile->user_agent;
    req += "\r\n";

    /* Accept: explicit per-profile, with NULL meaning "derive from
     * browser_like" and "" (empty string) meaning "omit". This three-way
     * encoding lets us model both "curl sends star-slash-star and no
     * Accept-Language" and "Edge sends a long browser Accept header". */
    if (profile->accept) {
      if (profile->accept[0]) {
        req += "Accept: ";
        req += profile->accept;
        req += "\r\n";
      }
      /* else explicit "" -> omit */
    } else if (profile->browser_like) {
      req += "Accept: ";
      req += kDefaultBrowserAccept;
      req += "\r\n";
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

    /* Browser-faithful headers. These are what real Chromium/Firefox/
     * Safari send on a top-level navigation; their absence is one of
     * the easiest WAF tells for "this isn't a real browser". They're
     * specifically NOT sent by curl/wget/lynx/etc., so we gate them on
     * the browser_like flag rather than on user_agent inspection. */
    if (profile->browser_like) {
      req += "Upgrade-Insecure-Requests: 1\r\n";
      req += "Sec-Fetch-Site: none\r\n";
      req += "Sec-Fetch-Mode: navigate\r\n";
      req += "Sec-Fetch-User: ?1\r\n";
      req += "Sec-Fetch-Dest: document\r\n";
    }

    if (profile->extra_headers && profile->extra_headers[0]) {
      req += profile->extra_headers;
      req += "\r\n";
    }
  } else {
    /* No profile / unrecognised profile: keep the legacy Kmap-branded
     * request so existing behaviour is preserved when --spoof-os is
     * absent. Web recon and net_enrich previously sent slightly
     * different banners; pick the more common one. */
    req += "User-Agent: Kmap\r\n";
  }

  req += "Connection: close\r\n\r\n";
  return req;
}

/* -----------------------------------------------------------------------
 * Public API: TLS knobs
 * ----------------------------------------------------------------------- */

const char *os_profile_tls_cipher_list(const OsProfile *profile) {
  if (!profile) return NULL;

  /* Per-profile cipher ordering for SSL_set_cipher_list (TLS<=1.2).
   * These are public, observed defaults of the corresponding clients
   * and produce JA3 hashes that match real traffic from those browsers.
   * For curl-like profiles we return NULL so OpenSSL uses its system
   * default -- that's exactly what a real curl build would do. */
  if (strcmp(profile->name, "linux") == 0 ||
      strcmp(profile->name, "openbsd") == 0)
    return NULL;

  if (strcmp(profile->name, "freebsd") == 0)
    /* Firefox 121 cipher order */
    return "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
           "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
           "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
           "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:"
           "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
           "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

  if (strcmp(profile->name, "macos") == 0 ||
      strcmp(profile->name, "ios") == 0)
    /* Safari 17 cipher order */
    return "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"
           "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:"
           "ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:"
           "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256";

  /* win10 / win11 / android -- Chromium 120/121 cipher order */
  return "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
         "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
         "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
         "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
         "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
}
