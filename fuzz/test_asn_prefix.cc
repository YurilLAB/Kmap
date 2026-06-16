// test_asn_prefix.cc -- pins the ASN prefix-cache key/containment logic added to
// asn_lookup.cc (lookup_asn). The cache is keyed by the IP's /24 base and a hit
// is GUARDED by a containment check against the announced BGP prefix Cymru
// returned, so a /24 that straddles two announcements can never mis-attribute.
// This is a copy-pin: keep asn_parse_prefix + the containment expression
// byte-identical to asn_lookup.cc.
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>

// --- verbatim copy of asn_lookup.cc::asn_parse_prefix ---
static bool asn_parse_prefix(const std::string &s, uint32_t &net, uint32_t &mask) {
  unsigned a, b, c, d, bits;
  if (sscanf(s.c_str(), "%u.%u.%u.%u/%u", &a, &b, &c, &d, &bits) != 5) return false;
  if (a > 255 || b > 255 || c > 255 || d > 255 || bits > 32) return false;
  mask = (bits == 0) ? 0u : (0xFFFFFFFFu << (32 - bits));
  net  = (((a << 24) | (b << 16) | (c << 8) | d) & mask);
  return true;
}

// The cache key + hit test exactly as lookup_asn uses them.
static bool prefix_hit(uint32_t ip, uint32_t entry_net, uint32_t entry_mask, uint32_t entry_ip24) {
  uint32_t ip24 = ip & 0xFFFFFF00u;
  if (ip24 != entry_ip24) return false;             // wrong /24 bucket
  return (ip & entry_mask) == entry_net;            // and contained in the announced prefix
}

static int fails = 0;
static void ck(bool ok, const char *m) { if (!ok) { printf("FAIL: %s\n", m); fails++; } }

// independent oracle: is ip inside a.b.c.d/bits ?
static bool in_cidr(uint32_t ip, unsigned a, unsigned b, unsigned c, unsigned d, unsigned bits) {
  uint64_t mask = bits == 0 ? 0 : (0xFFFFFFFFull << (32 - bits)) & 0xFFFFFFFFull;
  uint32_t net = ((a << 24) | (b << 16) | (c << 8) | d) & (uint32_t)mask;
  return (ip & (uint32_t)mask) == net;
}

int main(int argc, char **argv) {
  uint32_t net, mask;
  // 1. parse correctness
  ck(asn_parse_prefix("1.2.3.0/24", net, mask) && net == 0x01020300u && mask == 0xFFFFFF00u, "/24");
  ck(asn_parse_prefix("10.0.0.0/8", net, mask) && net == 0x0A000000u && mask == 0xFF000000u, "/8");
  ck(asn_parse_prefix("1.2.3.4/32", net, mask) && net == 0x01020304u && mask == 0xFFFFFFFFu, "/32");
  ck(asn_parse_prefix("0.0.0.0/0", net, mask) && net == 0u && mask == 0u, "/0");
  ck(asn_parse_prefix("203.0.113.128/25", net, mask) && net == 0xCB007180u && mask == 0xFFFFFF80u, "/25");
  // host bits in the string are masked off
  ck(asn_parse_prefix("1.2.3.55/24", net, mask) && net == 0x01020300u, "host bits cleared");

  // 2. malformed -> false
  ck(!asn_parse_prefix("1.2.3.0/33", net, mask), "bits>32 rejected");
  ck(!asn_parse_prefix("1.2.3.0", net, mask), "no slash rejected");
  ck(!asn_parse_prefix("256.0.0.0/24", net, mask), "octet>255 rejected");
  ck(!asn_parse_prefix("", net, mask), "empty rejected");
  ck(!asn_parse_prefix("1.2.3/24", net, mask), "too few octets rejected");

  // 3. containment / straddle safety: a /24 split into two /25 announcements.
  //    Cache holds 1.2.3.0/25 (low half). The high-half IPs MUST miss so they
  //    issue their own query -> never mis-attributed.
  asn_parse_prefix("1.2.3.0/25", net, mask);
  uint32_t k24 = 0x01020300u;
  ck(prefix_hit(0x01020305u, net, mask, k24), "1.2.3.5 in /25 -> hit");
  ck(prefix_hit(0x0102037Fu, net, mask, k24), "1.2.3.127 in /25 -> hit");
  ck(!prefix_hit(0x01020380u, net, mask, k24), "1.2.3.128 NOT in /25 -> miss (straddle-safe)");
  ck(!prefix_hit(0x010203C8u, net, mask, k24), "1.2.3.200 NOT in /25 -> miss");
  ck(!prefix_hit(0x01020405u, net, mask, k24), "different /24 -> miss");

  // common case: a /24 announcement, every host in it hits.
  asn_parse_prefix("8.8.8.0/24", net, mask);
  ck(prefix_hit(0x08080800u, net, mask, 0x08080800u), "8.8.8.0 -> hit");
  ck(prefix_hit(0x080808FFu, net, mask, 0x08080800u), "8.8.8.255 -> hit");

  // 4. randomized: the cache hit test agrees with the CIDR oracle whenever the
  //    /24 bucket matches; never claims a hit for an IP outside the prefix.
  unsigned seed = (argc > 1) ? (unsigned)strtoul(argv[1], nullptr, 10) : 1u;
  uint64_t st = seed ? seed : 1u;
  for (int i = 0; i < 3000000; i++) {
    st = st * 6364136223846793005ULL + 1442695040888963407ULL;
    unsigned a = (st >> 24) & 0xFF, b = (st >> 16) & 0xFF, c = (st >> 8) & 0xFF, d = st & 0xFF;
    unsigned bits = (st >> 40) % 33;
    char pfx[32];
    snprintf(pfx, sizeof(pfx), "%u.%u.%u.%u/%u", a, b, c, d, bits);
    uint32_t pn, pm;
    if (!asn_parse_prefix(pfx, pn, pm)) { printf("FAIL parse %s\n", pfx); fails++; break; }
    st = st * 6364136223846793005ULL + 1442695040888963407ULL;
    uint32_t ip = (uint32_t)(st >> 16);
    uint32_t entry24 = pn & 0xFFFFFF00u;  // bucket the announced prefix's network sits in
    bool hit = prefix_hit(ip, pn, pm, entry24);
    bool truly_in = in_cidr(ip, a, b, c, d, bits);
    // A hit REQUIRES true containment (never mis-attribute). The converse can
    // legitimately be false when the prefix is wider than /24 (different /24
    // bucket) -- that is a cache miss, not an error.
    if (hit && !truly_in) { printf("FAIL: claimed hit but ip 0x%08x NOT in %s\n", ip, pfx); fails++; break; }
    if (truly_in && (ip & 0xFFFFFF00u) == entry24 && !hit) {
      printf("FAIL: contained + same /24 bucket but no hit ip=0x%08x %s\n", ip, pfx); fails++; break;
    }
  }

  if (fails) { printf("asn-prefix test: %d FAILURE(S)\n", fails); return 1; }
  printf("asn-prefix test: PASS\n");
  return 0;
}
