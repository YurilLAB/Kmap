/*
 * cloud_map.cc -- implementation of the offline cloud-provider matcher.
 *
 * The match table is loaded once at pipeline start and is immutable thereafter,
 * so per-host lookups are lock-free.  CIDR blocks are always disjoint-or-nested
 * (two prefixes never partially overlap), so among the ranges containing an IP
 * the one with the LARGEST network start is the longest-prefix (most specific)
 * match -- which a binary search + short backward scan finds directly.
 */

#ifdef WIN32
#include "kmap_winconfig.h"   /* NOMINMAX + <fstream>/<sstream> preload, FIRST */
#endif

#include "cloud_map.h"

#include <vector>
#include <algorithm>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cctype>

namespace {

struct CloudRange {
  uint32_t    range_start;   /* network base (masked) */
  uint32_t    range_end;     /* range_start | ~mask */
  uint8_t     prefix_len;    /* CIDR prefix length, for the longest-prefix order */
  std::string provider;
  std::string region;
  std::string service;
};

/* Sorted by (range_start asc, prefix_len asc) so that, among ranges sharing a
   start, the longest prefix has the highest index and is hit FIRST by the
   backward scan in lookup_cloud. */
std::vector<CloudRange> g_ranges;

uint32_t cloud_cidr_mask(int prefix_len) {
  if (prefix_len <= 0)  return 0;
  if (prefix_len >= 32) return 0xFFFFFFFFu;
  return ~((1u << (32 - prefix_len)) - 1);
}

/* Strict dotted-quad -> u32 (host order).  Returns false on anything that is
   not exactly four 0..255 octets separated by dots. */
bool cloud_ip_to_u32(const char *s, uint32_t *out) {
  uint32_t v = 0;
  int octets = 0;
  const char *p = s;
  while (octets < 4) {
    if (!isdigit(static_cast<unsigned char>(*p))) return false;
    char *endp = nullptr;
    long o = strtol(p, &endp, 10);
    if (endp == p || o < 0 || o > 255) return false;
    /* reject leading-zero ambiguity like "01" only loosely: strtol already
       handled the value; CIDR feeds never use leading zeros. */
    v = (v << 8) | static_cast<uint32_t>(o);
    octets++;
    p = endp;
    if (octets < 4) {
      if (*p != '.') return false;
      p++;
    }
  }
  if (*p != '\0') return false;   /* trailing junk after the 4th octet */
  *out = v;
  return true;
}

} /* namespace */

bool cloud_parse_line(const char *line, uint32_t *net, uint32_t *mask,
                      uint8_t *prefix_len, std::string *provider,
                      std::string *region, std::string *service) {
  if (!line) return false;
  /* Split into up to 4 comma fields: cidr,provider,region,service */
  std::string s(line);
  std::string fields[4];
  int nf = 0;
  size_t start = 0;
  for (int i = 0; i < 4 && start <= s.size(); i++) {
    size_t comma = s.find(',', start);
    if (comma == std::string::npos) {
      fields[nf++] = s.substr(start);
      break;
    }
    fields[nf++] = s.substr(start, comma - start);
    start = comma + 1;
  }
  if (nf < 2) return false;   /* need at least cidr + provider */

  const std::string &cidr = fields[0];
  if (cidr.find(':') != std::string::npos) return false;  /* IPv6: skip */

  /* Parse "a.b.c.d/p" strictly (mirrors fast_syn.cc parse_cidr: strtol prefix,
     never atoi -- a malformed "/abc" must NOT collapse to /0 and tag the whole
     internet as one provider). */
  int prefix = 32;
  std::string ip_part = cidr;
  size_t slash = cidr.find('/');
  if (slash != std::string::npos) {
    ip_part = cidr.substr(0, slash);
    const char *pp = cidr.c_str() + slash + 1;
    if (*pp == '\0') return false;
    char *endp = nullptr;
    long pv = strtol(pp, &endp, 10);
    if (endp == pp || *endp != '\0' || pv < 0 || pv > 32) return false;
    prefix = static_cast<int>(pv);
  }

  uint32_t base = 0;
  if (!cloud_ip_to_u32(ip_part.c_str(), &base)) return false;

  std::string prov = fields[1];
  if (prov.empty()) return false;

  uint32_t m = cloud_cidr_mask(prefix);
  *net = base & m;
  *mask = m;
  *prefix_len = static_cast<uint8_t>(prefix);
  *provider = prov;
  *region  = (nf > 2) ? fields[2] : std::string();
  *service = (nf > 3) ? fields[3] : std::string();
  return true;
}

size_t cloud_ranges_load(const char *path) {
  g_ranges.clear();
  if (!path || !path[0]) return 0;

  std::ifstream f(path);
  if (!f.is_open()) return 0;

  std::string line;
  while (std::getline(f, line)) {
    /* Trim leading/trailing whitespace (handles CRLF too). */
    size_t a = line.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) continue;
    size_t b = line.find_last_not_of(" \t\r\n");
    line = line.substr(a, b - a + 1);
    if (line.empty() || line[0] == '#') continue;

    uint32_t net = 0, mask = 0;
    uint8_t plen = 0;
    std::string prov, region, service;
    if (!cloud_parse_line(line.c_str(), &net, &mask, &plen,
                          &prov, &region, &service))
      continue;   /* skip malformed / IPv6 lines silently (refresh tool owns quality) */

    CloudRange r;
    r.range_start = net;
    r.range_end   = net | ~mask;
    r.prefix_len  = plen;
    r.provider    = std::move(prov);
    r.region      = std::move(region);
    r.service     = std::move(service);
    g_ranges.push_back(std::move(r));
  }

  std::sort(g_ranges.begin(), g_ranges.end(),
            [](const CloudRange &x, const CloudRange &y) {
              if (x.range_start != y.range_start)
                return x.range_start < y.range_start;
              return x.prefix_len < y.prefix_len;
            });
  return g_ranges.size();
}

size_t cloud_ranges_count() { return g_ranges.size(); }

CloudInfo lookup_cloud(uint32_t ip) {
  CloudInfo out;
  if (g_ranges.empty()) return out;

  /* Index of the first range whose start is > ip (upper_bound on range_start). */
  size_t lo = 0, hi = g_ranges.size();
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    if (g_ranges[mid].range_start <= ip) lo = mid + 1;
    else hi = mid;
  }
  /* Scan backward from the largest-start range whose start <= ip.  The first
     range that also contains ip (range_end >= ip) is, by the CIDR
     disjoint-or-nested property, the longest-prefix match.  Non-containing
     nested siblings are skipped; the scan is short in practice. */
  for (size_t k = lo; k-- > 0; ) {
    const CloudRange &r = g_ranges[k];
    if (ip <= r.range_end) {
      out.provider = r.provider;
      out.region   = r.region;
      out.service  = r.service;
      return out;
    }
  }
  return out;
}
