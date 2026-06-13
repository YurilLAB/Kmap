/* fuzz_dns.cc -- guard-page fuzzer for asn_lookup.cc DNS response parsing.
 *
 * Copies dns_skip_name() and dns_extract_txt() VERBATIM from asn_lookup.cc
 * (kept byte-identical so the fuzz exercises the shipping code path).
 * Each input is placed so its last byte abuts a PAGE_NOACCESS guard page;
 * any read past pktlen faults -> SIGSEGV handler dumps the input hex.
 * Build:  g++ -O1 -g -fsanitize=undefined -fsanitize-trap=all fuzz_dns.cc -o fuzz_dns.exe
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <csignal>
#include <windows.h>

#define DNS_QTYPE_TXT  16

/* ===== VERBATIM from asn_lookup.cc (lines 103-187) ===== */
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

static std::string dns_extract_txt(const uint8_t *pkt, size_t pktlen) {
  if (pktlen < 12) return "";

  uint16_t flags = (pkt[2] << 8) | pkt[3];
  if (!(flags & 0x8000)) return ""; /* Not a response */
  uint16_t ancount = (pkt[6] << 8) | pkt[7];
  if (ancount == 0) return "";

  uint16_t qdcount = (pkt[4] << 8) | pkt[5];
  size_t off = 12;
  for (uint16_t i = 0; i < qdcount && off < pktlen; i++) {
    size_t skip = dns_skip_name(pkt, pktlen, off);
    if (skip == 0) return "";
    off += skip + 4; /* +4 for QTYPE + QCLASS */
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
/* ===== end verbatim ===== */

/* Guard-page buffer: data sits flush against an inaccessible page so any
 * over-read of even one byte past `len` raises an access violation. */
static SIZE_T g_page;
static uint8_t *make_guarded(const uint8_t *data, size_t len, const uint8_t **out_ptr) {
  if (len == 0) len = 0; /* still place at page end */
  size_t npages = (len + g_page - 1) / g_page;
  if (npages == 0) npages = 1;
  size_t total = (npages + 1) * g_page;
  uint8_t *base = (uint8_t *)VirtualAlloc(NULL, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!base) { fprintf(stderr, "VirtualAlloc failed\n"); exit(2); }
  DWORD oldp;
  VirtualProtect(base + npages * g_page, g_page, PAGE_NOACCESS, &oldp);
  uint8_t *p = base + npages * g_page - len; /* flush against guard */
  if (len) memcpy(p, data, len);
  *out_ptr = p;
  return base;
}
static void free_guarded(uint8_t *base) { VirtualFree(base, 0, MEM_RELEASE); }

static const uint8_t *g_cur; static size_t g_curlen; static long long g_iter;
static void dump_and_die(int sig) {
  fprintf(stderr, "\n*** CRASH sig=%d at iter=%lld len=%zu input=", sig, g_iter, g_curlen);
  for (size_t i = 0; i < g_curlen && i < 600; i++) fprintf(stderr, "%02x", g_cur[i]);
  fprintf(stderr, "\n");
  _exit(99);
}

/* xorshift64 deterministic PRNG (Math.random-free, seed via argv) */
static uint64_t rng_s;
static uint64_t rng() { rng_s ^= rng_s << 13; rng_s ^= rng_s >> 7; rng_s ^= rng_s << 17; return rng_s; }

int main(int argc, char **argv) {
  SYSTEM_INFO si; GetSystemInfo(&si); g_page = si.dwPageSize;
  signal(SIGSEGV, dump_and_die);
  signal(SIGILL, dump_and_die);
  signal(SIGABRT, dump_and_die);

  rng_s = (argc > 1) ? strtoull(argv[1], NULL, 10) : 0x123456789abcdefULL;
  long long N = (argc > 2) ? atoll(argv[2]) : 20000000LL;

  uint8_t buf[600];
  for (g_iter = 0; g_iter < N; g_iter++) {
    int mode = rng() % 3;
    size_t len;
    if (mode == 0) {                 /* fully random, small */
      len = rng() % 80;
      for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rng();
    } else if (mode == 1) {          /* random up to 512 */
      len = rng() % 520;
      for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rng();
    } else {                         /* structured: valid-ish DNS header */
      len = 12 + (rng() % 200);
      for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rng();
      buf[2] = 0x80 | (buf[2] & 0x7f);      /* response bit */
      buf[6] = 0; buf[7] = (uint8_t)(1 + rng() % 8);  /* ancount 1..8 */
      buf[4] = 0; buf[5] = (uint8_t)(rng() % 3);      /* qdcount 0..2 */
      /* sprinkle compression pointers (0xC0xx) to stress jump logic */
      for (int k = 0; k < 6; k++) {
        size_t pos = 12 + (rng() % (len > 12 ? len - 12 : 1));
        if (pos + 1 < len) { buf[pos] = 0xC0; buf[pos + 1] = (uint8_t)rng(); }
      }
    }
    const uint8_t *p; uint8_t *base = make_guarded(buf, len, &p);
    g_cur = p; g_curlen = len;
    volatile std::string r = dns_extract_txt(p, len);  /* OOB read -> AV here */
    free_guarded(base);
    if ((g_iter & 0xFFFFF) == 0) { fprintf(stderr, "\r iter=%lld", g_iter); fflush(stderr); }
  }
  fprintf(stderr, "\nDNS fuzz OK: %lld iterations, no faults (seed=%s)\n",
          N, argc > 1 ? argv[1] : "default");
  return 0;
}
