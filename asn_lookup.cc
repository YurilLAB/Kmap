/*
 * asn_lookup.cc -- ASN / GeoIP enrichment for Kmap.
 *
 * Uses Team Cymru's DNS-based IP-to-ASN service:
 *   - Query: <d>.<c>.<b>.<a>.origin.asn.cymru.com  TXT
 *     Response: "23456 | 1.2.3.0/24 | US | arin | 2001-02-01"
 *   - Query: AS23456.peer.asn.cymru.com  TXT
 *     Response: "23456 | US | arin | 2001-02-01 | GOOGLE"
 *
 * Implements a minimal raw UDP DNS client so we don't depend on
 * res_query (Linux-only) or DnsQuery (Windows-only).
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "asn_lookup.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <map>

#ifndef WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>  /* _getpid() on Windows */
#endif

/* -----------------------------------------------------------------------
 * Minimal DNS client — builds and parses raw UDP DNS packets
 * ----------------------------------------------------------------------- */

/* DNS header flags */
#define DNS_QR_QUERY   0x0000
#define DNS_OPCODE_STD 0x0000
#define DNS_RD         0x0100  /* Recursion Desired */
#define DNS_QTYPE_TXT  16
#define DNS_QCLASS_IN  1

/* Encode a DNS name: "4.3.2.1.origin.asn.cymru.com" → length-prefixed labels */
static size_t dns_encode_name(const char *name, uint8_t *buf, size_t buflen) {
  size_t pos = 0;
  const char *p = name;
  while (*p && pos < buflen - 2) {
    const char *dot = strchr(p, '.');
    size_t label_len = dot ? static_cast<size_t>(dot - p) : strlen(p);
    if (label_len > 63 || pos + 1 + label_len >= buflen) return 0;
    buf[pos++] = static_cast<uint8_t>(label_len);
    memcpy(buf + pos, p, label_len);
    pos += label_len;
    p += label_len;
    if (*p == '.') p++;
  }
  if (pos < buflen) buf[pos++] = 0; /* root label */
  return pos;
}

/* Build a DNS query packet for a TXT record.
 * Returns the total packet length, or 0 on error. */
static size_t dns_build_query(const char *name, uint16_t txid,
                              uint8_t *pkt, size_t pktlen) {
  if (pktlen < 12 + 256 + 4) return 0;

  /* Header: ID, Flags, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 */
  pkt[0] = static_cast<uint8_t>(txid >> 8);
  pkt[1] = static_cast<uint8_t>(txid & 0xFF);
  uint16_t flags = DNS_QR_QUERY | DNS_OPCODE_STD | DNS_RD;
  pkt[2] = static_cast<uint8_t>(flags >> 8);
  pkt[3] = static_cast<uint8_t>(flags & 0xFF);
  pkt[4] = 0; pkt[5] = 1;  /* QDCOUNT = 1 */
  pkt[6] = 0; pkt[7] = 0;  /* ANCOUNT */
  pkt[8] = 0; pkt[9] = 0;  /* NSCOUNT */
  pkt[10] = 0; pkt[11] = 0; /* ARCOUNT */

  /* Question section */
  size_t name_len = dns_encode_name(name, pkt + 12, pktlen - 12 - 4);
  if (name_len == 0) return 0;

  size_t off = 12 + name_len;
  /* QTYPE = TXT (16) */
  pkt[off++] = 0;
  pkt[off++] = DNS_QTYPE_TXT;
  /* QCLASS = IN (1) */
  pkt[off++] = 0;
  pkt[off++] = DNS_QCLASS_IN;

  return off;
}

/* Skip a DNS name in a packet (handles compression pointers).
 * Returns the number of bytes consumed from the current position.
 * Guards against infinite loops from malicious compression pointers
 * by limiting total label hops to 128. */
static size_t dns_skip_name(const uint8_t *pkt, size_t pktlen, size_t off) {
  size_t start = off;
  bool jumped = false;
  size_t first_jump = 0;
  int hops = 0;
  const int MAX_LABEL_HOPS = 128;

  while (off < pktlen) {
    if (++hops > MAX_LABEL_HOPS) return 0; /* prevent infinite loop */
    uint8_t len = pkt[off];
    if (len == 0) { off++; break; }
    if ((len & 0xC0) == 0xC0) {
      /* Compression pointer */
      if (!jumped) first_jump = off + 2;
      jumped = true;
      if (off + 1 >= pktlen) return 0;
      size_t target = ((len & 0x3F) << 8) | pkt[off + 1];
      if (target >= pktlen) return 0; /* pointer out of bounds */
      off = target;
      continue;
    }
    off += 1 + len;
  }

  return jumped ? (first_jump - start) : (off - start);
}

/* Extract the first TXT record from a DNS response.
 * Returns the concatenated text data, or empty string on failure. */
static std::string dns_extract_txt(const uint8_t *pkt, size_t pktlen) {
  if (pktlen < 12) return "";

  /* Check this is a response with at least one answer */
  uint16_t flags = (pkt[2] << 8) | pkt[3];
  if (!(flags & 0x8000)) return ""; /* Not a response */
  uint16_t ancount = (pkt[6] << 8) | pkt[7];
  if (ancount == 0) return "";

  /* Skip the question section */
  uint16_t qdcount = (pkt[4] << 8) | pkt[5];
  size_t off = 12;
  for (uint16_t i = 0; i < qdcount && off < pktlen; i++) {
    size_t skip = dns_skip_name(pkt, pktlen, off);
    if (skip == 0) return "";
    off += skip + 4; /* +4 for QTYPE + QCLASS */
  }

  /* Parse answer records looking for TXT */
  for (uint16_t i = 0; i < ancount && off < pktlen; i++) {
    size_t name_skip = dns_skip_name(pkt, pktlen, off);
    if (name_skip == 0) return "";
    off += name_skip;

    if (off + 10 > pktlen) return "";
    uint16_t rtype = (pkt[off] << 8) | pkt[off + 1];
    /* uint16_t rclass = (pkt[off+2] << 8) | pkt[off+3]; */
    /* uint32_t ttl = ...; */
    uint16_t rdlength = (pkt[off + 8] << 8) | pkt[off + 9];
    off += 10;

    if (off + rdlength > pktlen) return "";

    if (rtype == DNS_QTYPE_TXT) {
      /* TXT RDATA: one or more <length><text> chunks */
      std::string result;
      size_t roff = off;
      size_t rend = off + rdlength;
      while (roff < rend) {
        uint8_t tlen = pkt[roff++];
        if (roff + tlen > rend) break;
        result.append(reinterpret_cast<const char *>(pkt + roff), tlen);
        roff += tlen;
      }
      return result;
    }

    off += rdlength;
  }

  return "";
}

/* DNS result cache — avoids redundant queries for the same qname.
 * Critical for performance when enriching thousands of hosts that
 * share the same /24 prefix or ASN. */
struct DnsCacheEntry {
  std::string result;
  time_t      expires;
};
static std::map<std::string, DnsCacheEntry> dns_cache;
static const int DNS_CACHE_TTL_SECS = 300; /* 5-minute TTL */

/* Seed rand() once for DNS transaction ID generation.
 * Uses time + pid to avoid predictable txids (DNS cache poisoning risk). */
static void seed_rand_once() {
  static bool seeded = false;
  if (!seeded) {
#ifdef WIN32
    srand(static_cast<unsigned int>(time(nullptr)) ^ static_cast<unsigned int>(_getpid()));
#else
    srand(static_cast<unsigned int>(time(nullptr)) ^ static_cast<unsigned int>(getpid()));
#endif
    seeded = true;
  }
}

/* Send a DNS query and receive the response via raw UDP.
 * Returns the TXT record content, or empty string on failure.
 * Results are cached to avoid redundant queries. */
static std::string dns_txt_query(const char *qname, int timeout_ms) {
  /* Check the DNS cache first */
  std::string cache_key(qname);
  time_t now = time(nullptr);
  auto it = dns_cache.find(cache_key);
  if (it != dns_cache.end() && it->second.expires > now) {
    return it->second.result;
  }

  /* Seed rand() on first call */
  seed_rand_once();

  /* Build query packet */
  uint8_t query[512];
  uint16_t txid = static_cast<uint16_t>(rand() & 0xFFFF);
  size_t qlen = dns_build_query(qname, txid, query, sizeof(query));
  if (qlen == 0) return "";

  /* DNS server: use Google Public DNS (8.8.8.8) as a reliable default.
   * Team Cymru's service is publicly accessible via any recursive resolver. */
  struct sockaddr_in dns_addr{};
  dns_addr.sin_family = AF_INET;
  dns_addr.sin_port = htons(53);
  dns_addr.sin_addr.s_addr = htonl(0x08080808); /* 8.8.8.8 */

#ifdef WIN32
  SOCKET fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd == INVALID_SOCKET) return "";
#else
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) return "";
#endif

  /* Set receive timeout.
   * Windows: SO_RCVTIMEO takes a DWORD (milliseconds), not struct timeval.
   * Linux/Unix: SO_RCVTIMEO takes a struct timeval. */
#ifdef WIN32
  DWORD tv_win = static_cast<DWORD>(timeout_ms);
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
             reinterpret_cast<const char *>(&tv_win), sizeof(tv_win));
#else
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
             reinterpret_cast<const char *>(&tv), sizeof(tv));
#endif

  /* Send query */
  int sent = sendto(fd, reinterpret_cast<const char *>(query),
                    static_cast<int>(qlen), 0,
                    reinterpret_cast<struct sockaddr *>(&dns_addr),
                    sizeof(dns_addr));
  if (sent <= 0) {
#ifdef WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return "";
  }

  /* Receive response */
  uint8_t resp[512];
  int rlen = recvfrom(fd, reinterpret_cast<char *>(resp),
                      sizeof(resp), 0, nullptr, nullptr);

#ifdef WIN32
  closesocket(fd);
#else
  close(fd);
#endif

  if (rlen <= 0) return "";

  /* Verify transaction ID matches */
  if (static_cast<size_t>(rlen) < 12) return "";
  uint16_t resp_txid = (resp[0] << 8) | resp[1];
  if (resp_txid != txid) return "";

  std::string result = dns_extract_txt(resp, static_cast<size_t>(rlen));

  /* Store in cache with TTL */
  DnsCacheEntry entry;
  entry.result = result;
  entry.expires = now + DNS_CACHE_TTL_SECS;
  dns_cache[cache_key] = entry;

  return result;
}

/* -----------------------------------------------------------------------
 * ASN result parsing
 * ----------------------------------------------------------------------- */

/* Parse "23456 | 1.2.3.0/24 | US | arin | 2001-02-01" */
static void parse_origin_response(const std::string &txt, AsnInfo &info) {
  /* Split on " | " */
  std::vector<std::string> parts;
  size_t pos = 0;
  while (pos < txt.size()) {
    size_t sep = txt.find(" | ", pos);
    if (sep == std::string::npos) {
      parts.push_back(txt.substr(pos));
      break;
    }
    parts.push_back(txt.substr(pos, sep - pos));
    pos = sep + 3;
  }

  if (parts.size() >= 1) {
    /* ASN may have leading whitespace or "NA" */
    const std::string &asn_str = parts[0];
    char *end = nullptr;
    unsigned long val = strtoul(asn_str.c_str(), &end, 10);
    info.asn = (end != asn_str.c_str()) ? static_cast<uint32_t>(val) : 0;
  }
  if (parts.size() >= 2) info.bgp_prefix = parts[1];
  if (parts.size() >= 3) info.country = parts[2];
  if (parts.size() >= 4) info.registry = parts[3];
}

/* Parse "23456 | US | arin | 2001-02-01 | GOOGLE" */
static void parse_peer_response(const std::string &txt, AsnInfo &info) {
  std::vector<std::string> parts;
  size_t pos = 0;
  while (pos < txt.size()) {
    size_t sep = txt.find(" | ", pos);
    if (sep == std::string::npos) {
      parts.push_back(txt.substr(pos));
      break;
    }
    parts.push_back(txt.substr(pos, sep - pos));
    pos = sep + 3;
  }

  /* The AS name is the last field (index 4) */
  if (parts.size() >= 5) {
    info.as_name = parts[4];
    /* Trim trailing whitespace/newlines */
    while (!info.as_name.empty() &&
           (info.as_name.back() == ' ' || info.as_name.back() == '\r' ||
            info.as_name.back() == '\n'))
      info.as_name.pop_back();
  }
}

/* -----------------------------------------------------------------------
 * Geographic region mapping — maps country codes to human-readable regions
 * ----------------------------------------------------------------------- */

static const std::map<std::string, std::string> &get_region_map() {
  static const std::map<std::string, std::string> region_map = {
    /* North America */
    {"US", "North America"}, {"CA", "North America"}, {"MX", "North America"},
    /* Europe */
    {"GB", "Europe"}, {"DE", "Europe"}, {"FR", "Europe"}, {"NL", "Europe"},
    {"SE", "Europe"}, {"NO", "Europe"}, {"FI", "Europe"}, {"DK", "Europe"},
    {"IT", "Europe"}, {"ES", "Europe"}, {"PT", "Europe"}, {"PL", "Europe"},
    {"CZ", "Europe"}, {"AT", "Europe"}, {"CH", "Europe"}, {"BE", "Europe"},
    {"IE", "Europe"}, {"LU", "Europe"}, {"RO", "Europe"}, {"BG", "Europe"},
    {"HR", "Europe"}, {"SK", "Europe"}, {"SI", "Europe"}, {"HU", "Europe"},
    {"LT", "Europe"}, {"LV", "Europe"}, {"EE", "Europe"}, {"GR", "Europe"},
    {"UA", "Europe"}, {"RU", "Europe"},
    /* Asia Pacific */
    {"JP", "Asia Pacific"}, {"CN", "Asia Pacific"}, {"KR", "Asia Pacific"},
    {"TW", "Asia Pacific"}, {"HK", "Asia Pacific"}, {"SG", "Asia Pacific"},
    {"AU", "Asia Pacific"}, {"NZ", "Asia Pacific"}, {"IN", "Asia Pacific"},
    {"ID", "Asia Pacific"}, {"TH", "Asia Pacific"}, {"VN", "Asia Pacific"},
    {"MY", "Asia Pacific"}, {"PH", "Asia Pacific"}, {"PK", "Asia Pacific"},
    {"BD", "Asia Pacific"},
    /* Middle East */
    {"AE", "Middle East"}, {"SA", "Middle East"}, {"IL", "Middle East"},
    {"TR", "Middle East"}, {"QA", "Middle East"}, {"BH", "Middle East"},
    {"KW", "Middle East"}, {"OM", "Middle East"}, {"IR", "Middle East"},
    /* South America */
    {"BR", "South America"}, {"AR", "South America"}, {"CL", "South America"},
    {"CO", "South America"}, {"PE", "South America"}, {"VE", "South America"},
    {"EC", "South America"}, {"UY", "South America"},
    /* Africa */
    {"ZA", "Africa"}, {"NG", "Africa"}, {"KE", "Africa"}, {"EG", "Africa"},
    {"MA", "Africa"}, {"TN", "Africa"}, {"GH", "Africa"}, {"TZ", "Africa"},
  };
  return region_map;
}

static std::string country_to_region(const std::string &country) {
  const auto &rmap = get_region_map();
  auto it = rmap.find(country);
  if (it != rmap.end()) return it->second;
  return "Unknown";
}

/* -----------------------------------------------------------------------
 * ASN lookup cache — avoids redundant lookups for the same IP
 * ----------------------------------------------------------------------- */

static std::map<std::string, AsnInfo> asn_cache;

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

AsnInfo lookup_asn(const char *ip, int timeout_ms) {
  AsnInfo info{};
  info.asn = 0;

  if (!ip || !ip[0]) return info;

  /* Check the ASN cache first */
  std::string ip_str(ip);
  auto cache_it = asn_cache.find(ip_str);
  if (cache_it != asn_cache.end()) {
    return cache_it->second;
  }

  /* Parse the IP into octets for reversed query */
  unsigned int a, b, c, d;
  if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
    return info;
  if (a > 255 || b > 255 || c > 255 || d > 255)
    return info;

  /* Build the origin query: d.c.b.a.origin.asn.cymru.com */
  char qname[128];
  snprintf(qname, sizeof(qname), "%u.%u.%u.%u.origin.asn.cymru.com",
           d, c, b, a);

  std::string origin_txt = dns_txt_query(qname, timeout_ms);
  if (origin_txt.empty())
    return info;

  parse_origin_response(origin_txt, info);

  /* If we got an ASN, look up the AS name */
  if (info.asn > 0) {
    snprintf(qname, sizeof(qname), "AS%u.peer.asn.cymru.com", info.asn);
    std::string peer_txt = dns_txt_query(qname, timeout_ms);
    if (!peer_txt.empty())
      parse_peer_response(peer_txt, info);
  }

  /* Map country code to human-readable region */
  if (!info.country.empty()) {
    info.region = country_to_region(info.country);
  }

  /* Store in ASN cache */
  asn_cache[ip_str] = info;

  return info;
}

std::string lookup_as_name(uint32_t asn, int timeout_ms) {
  if (asn == 0) return "";

  char qname[64];
  snprintf(qname, sizeof(qname), "AS%u.peer.asn.cymru.com", asn);

  std::string txt = dns_txt_query(qname, timeout_ms);
  if (txt.empty()) return "";

  /* Parse — name is the last pipe-delimited field */
  size_t last_pipe = txt.rfind(" | ");
  if (last_pipe == std::string::npos) return "";

  std::string name = txt.substr(last_pipe + 3);
  while (!name.empty() &&
         (name.back() == ' ' || name.back() == '\r' || name.back() == '\n'))
    name.pop_back();

  return name;
}
