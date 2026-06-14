/*
 * fuzz_dns.cc -- OSS-Fuzz / ClusterFuzzLite libFuzzer target for the DNS
 * response parser used by ASN enrichment (asn_lookup.cc).
 *
 * dns_skip_name() + dns_extract_txt() are copied VERBATIM from asn_lookup.cc
 * (kept byte-identical so the target exercises the shipping code path). They
 * parse raw, untrusted UDP DNS responses, including name-compression pointers
 * -- a classic OOB / infinite-loop surface, so a prime fuzz target.
 *
 * Built two ways:
 *   - OSS-Fuzz/ClusterFuzzLite: clang -fsanitize=fuzzer,address (libFuzzer main)
 *   - locally for verification: g++ with fuzz/ossfuzz/standalone_main.cc
 */
#include <cstdint>
#include <cstddef>
#include <string>

#define DNS_QTYPE_TXT 16

/* ===== VERBATIM from asn_lookup.cc ===== */
static size_t dns_skip_name(const uint8_t *pkt, size_t pktlen, size_t off) {
  size_t start = off;
  bool jumped = false;
  size_t first_jump = 0;
  int hops = 0;
  const int MAX_LABEL_HOPS = 128;
  while (off < pktlen) {
    if (++hops > MAX_LABEL_HOPS) return 0;
    uint8_t len = pkt[off];
    if (len == 0) { off++; break; }
    if ((len & 0xC0) == 0xC0) {
      if (!jumped) first_jump = off + 2;
      jumped = true;
      if (off + 1 >= pktlen) return 0;
      size_t target = ((len & 0x3F) << 8) | pkt[off + 1];
      if (target >= pktlen) return 0;
      off = target;
      continue;
    }
    off += 1 + len;
  }
  return jumped ? (first_jump - start) : (off - start);
}

static std::string dns_extract_txt(const uint8_t *pkt, size_t pktlen) {
  if (pktlen < 12) return "";
  uint16_t flags = (pkt[2] << 8) | pkt[3];
  if (!(flags & 0x8000)) return "";
  uint16_t ancount = (pkt[6] << 8) | pkt[7];
  if (ancount == 0) return "";
  uint16_t qdcount = (pkt[4] << 8) | pkt[5];
  size_t off = 12;
  for (uint16_t i = 0; i < qdcount && off < pktlen; i++) {
    size_t skip = dns_skip_name(pkt, pktlen, off);
    if (skip == 0) return "";
    off += skip + 4;
  }
  for (uint16_t i = 0; i < ancount && off < pktlen; i++) {
    size_t name_skip = dns_skip_name(pkt, pktlen, off);
    if (name_skip == 0) return "";
    off += name_skip;
    if (off + 10 > pktlen) return "";
    uint16_t rtype = (pkt[off] << 8) | pkt[off + 1];
    uint16_t rdlength = (pkt[off + 8] << 8) | pkt[off + 9];
    off += 10;
    if (off + rdlength > pktlen) return "";
    if (rtype == DNS_QTYPE_TXT) {
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  volatile std::string r = dns_extract_txt(data, size);
  (void)r;
  return 0;
}
