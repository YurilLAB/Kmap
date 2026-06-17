/* test_csum_patch.cc -- validate the raw-SYN engine's incremental-checksum
 * packet templating (fast_syn.cc) against a full from-scratch checksum, with no
 * kmap/network dependencies so it compiles and runs anywhere.
 *
 * The engine builds the SYN frame once with dst-IP / dst-port / seq = 0, caches
 * the IP and TCP checksums of that base, then per probe patches in the real
 * fields and updates the checksums incrementally (RFC 1624) instead of
 * re-summing the whole packet.  This test proves the incremental result is
 * BIT-IDENTICAL to a full recompute for random and edge-case fields -- if it
 * isn't, every SYN we send would carry a bad checksum and be dropped silently.
 *
 * Build:  cl /EHsc /O2 fuzz\test_csum_patch.cc   (MSVC)
 *         g++ -O2 -o test_csum_patch fuzz/test_csum_patch.cc
 *
 * Checks:
 *   1. csum_patch + base IP checksum  == full IP header checksum
 *   2. csum_patch + base TCP checksum == full TCP checksum (incl pseudo-header)
 *   3. holds over 2,000,000 pseudo-random (dst,port,seq) plus 0x0000/0xFFFF edges
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>

/* ---- the function under test (copied verbatim from fast_syn.cc) ---------- */
static inline uint16_t csum_patch(uint16_t hc, uint16_t old_word, uint16_t new_word) {
  uint32_t sum = (uint16_t)~hc;       /* ~HC  */
  sum += (uint16_t)~old_word;         /* + ~m */
  sum += new_word;                    /* + m' */
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)~sum;
}

/* ---- reference: full one's-complement checksum over a byte range ---------- */
static uint16_t ref_cksum_words(const uint16_t *words, int n, uint32_t init) {
  uint32_t sum = init;
  for (int i = 0; i < n; i++) sum += words[i];
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)~sum;
}

/* Full IP header checksum for a 20-byte IPv4 header carrying dst `dst`.
   Only dst varies in our use; everything else is fixed template content. */
static uint16_t full_ip_sum(uint32_t src, uint32_t dst) {
  uint16_t w[10];
  w[0] = 0x4500;          /* ver/ihl, tos */
  w[1] = 40;              /* total length */
  w[2] = 0x1234;          /* id (fixed) */
  w[3] = 0x4000;          /* flags=DF, frag=0 */
  w[4] = (64 << 8) | 6;   /* ttl, proto=TCP */
  /* w[5] = checksum, excluded (treated as 0) */
  w[5] = (uint16_t)(src >> 16); w[6] = (uint16_t)(src & 0xFFFF);
  w[7] = (uint16_t)(dst >> 16); w[8] = (uint16_t)(dst & 0xFFFF);
  return ref_cksum_words(w, 9, 0);
}

/* Full TCP checksum (pseudo-header + 20-byte TCP header) for the SYN. */
static uint16_t full_tcp_sum(uint32_t src, uint32_t dst, uint16_t sport,
                             uint16_t dport, uint32_t seq) {
  uint32_t init = 0;
  /* pseudo-header */
  init += (uint16_t)(src >> 16); init += (uint16_t)(src & 0xFFFF);
  init += (uint16_t)(dst >> 16); init += (uint16_t)(dst & 0xFFFF);
  init += 0x0006;   /* zero | proto */
  init += 20;       /* TCP length */
  uint16_t w[10];
  w[0] = sport;
  w[1] = dport;
  w[2] = (uint16_t)(seq >> 16); w[3] = (uint16_t)(seq & 0xFFFF);
  w[4] = 0; w[5] = 0;                 /* ack = 0 */
  w[6] = (5 << 12) | 0x002;           /* data offset=5, flags=SYN */
  w[7] = 1024;                        /* window */
  /* w[8] = checksum (0) */
  w[8] = 0;
  w[9] = 0;                           /* urgent ptr */
  return ref_cksum_words(w, 10, init);
}

/* ---- the engine's incremental path, mirrored ----------------------------- */
static uint16_t templ_ip_sum(uint32_t src, uint32_t dst) {
  uint16_t base = full_ip_sum(src, 0);          /* base: dst = 0 */
  uint16_t s = csum_patch(base, 0, (uint16_t)(dst >> 16));
  s = csum_patch(s, 0, (uint16_t)(dst & 0xFFFF));
  return s;
}
static uint16_t templ_tcp_sum(uint32_t src, uint32_t dst, uint16_t sport,
                              uint16_t dport, uint32_t seq) {
  uint16_t base = full_tcp_sum(src, 0, sport, 0, 0); /* base: dst/dport/seq = 0 */
  uint16_t s = csum_patch(base, 0, (uint16_t)(dst >> 16));
  s = csum_patch(s, 0, (uint16_t)(dst & 0xFFFF));
  s = csum_patch(s, 0, dport);
  s = csum_patch(s, 0, (uint16_t)(seq >> 16));
  s = csum_patch(s, 0, (uint16_t)(seq & 0xFFFF));
  return s;
}

int main(void) {
  const uint32_t SRC = 0xC0A80164u;  /* 192.168.1.100 */
  const uint16_t SPORT = 44321;
  uint64_t fails = 0, n = 0;

  /* deterministic LCG so the run is reproducible */
  uint64_t st = 0x9E3779B97F4A7C15ULL;
  auto next = [&]() -> uint32_t {
    st = st * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(st >> 32);
  };

  /* edge values that stress one's-complement carry / 0x0000-vs-0xFFFF */
  const uint32_t edges[] = {0u, 0xFFFFFFFFu, 0xFFFF0000u, 0x0000FFFFu,
                            0x00010000u, 0xFFFFFFFEu, 0x80000000u, 0x7FFFFFFFu};
  for (uint32_t d : edges)
    for (uint32_t s : edges)
      for (uint16_t p : {(uint16_t)0, (uint16_t)80, (uint16_t)0xFFFF, (uint16_t)443}) {
        n++;
        if (templ_ip_sum(SRC, d) != full_ip_sum(SRC, d)) fails++;
        if (templ_tcp_sum(SRC, d, SPORT, p, s) != full_tcp_sum(SRC, d, SPORT, p, s)) fails++;
      }

  /* bulk random */
  for (int i = 0; i < 2000000; i++) {
    uint32_t dst = next();
    uint16_t port = (uint16_t)next();
    uint32_t seq = next();
    n++;
    if (templ_ip_sum(SRC, dst) != full_ip_sum(SRC, dst)) {
      if (fails < 10) printf("IP  mismatch dst=%08x\n", dst);
      fails++;
    }
    if (templ_tcp_sum(SRC, dst, SPORT, port, seq) != full_tcp_sum(SRC, dst, SPORT, port, seq)) {
      if (fails < 10) printf("TCP mismatch dst=%08x port=%u seq=%08x\n", dst, port, seq);
      fails++;
    }
  }

  printf("csum_patch: %llu cases, %llu mismatches -> %s\n",
         (unsigned long long)n, (unsigned long long)fails,
         fails == 0 ? "PASS" : "FAIL");
  return fails == 0 ? 0 : 1;
}
