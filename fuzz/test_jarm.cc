/*
 * test_jarm.cc -- known-answer + fuzz test for the JARM fingerprint (jarm.cc).
 *
 * (1) Byte-exact: each of the ten deterministic ClientHellos kmap builds must
 *     equal the packet the Salesforce reference jarm.py emits (dumped with the
 *     client-random / session-id / key-share zeroed and GREASE pinned, in
 *     fuzz/jarm_vectors.h). This proves the probe construction is correct down
 *     to the byte -- the half that cannot be checked end-to-end without a live
 *     server.
 * (2) Hash KAT: the documented all-failures input hashes to 62 zeros, and a
 *     hand-built jarm_raw hashes deterministically.
 * (3) Parser fuzz: random/truncated ServerHello bytes must never fault
 *     (ASan/UBSan) and the service label stays well-formed.
 *
 * Build: g++ -O2 -g -std=gnu++17 -fsanitize=address,undefined \
 *        fuzz/test_jarm.cc jarm.cc -lcrypto -o t && ./t
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../jarm.h"
#include "jarm_vectors.h"

static int g_fail = 0;

static std::string to_hex(const std::string &b) {
  static const char *h = "0123456789abcdef";
  std::string o;
  for (unsigned char c : b) { o.push_back(h[c >> 4]); o.push_back(h[c & 0xf]); }
  return o;
}

int main(int argc, char **argv) {
  uint32_t seed = argc > 1 ? (uint32_t)strtoul(argv[1], nullptr, 0) : 1;
  printf("JARM test\n=========\n");

  /* (1) Byte-exact ClientHello construction vs the reference packets. */
  for (int i = 0; i < 10; i++) {
    std::string got = to_hex(jarm_build_client_hello(i, "127.0.0.1", true));
    if (got != JARM_REF_HELLO[i]) {
      printf("  FAIL ClientHello[%d] mismatch vs reference\n", i);
      /* show first divergence to aid debugging */
      size_t m = 0, n = got.size() < strlen(JARM_REF_HELLO[i]) ? got.size()
                                                  : strlen(JARM_REF_HELLO[i]);
      while (m < n && got[m] == JARM_REF_HELLO[i][m]) m++;
      printf("       first diff at hex char %zu (got len %zu, ref len %zu)\n",
             m, got.size(), strlen(JARM_REF_HELLO[i]));
      g_fail++;
    }
  }
  printf("ClientHello byte-exact: %s\n", g_fail ? "FAIL" : "OK (10/10)");

  /* (2) Hash KATs. */
  if (jarm_hash("|||,|||,|||,|||,|||,|||,|||,|||,|||,|||") != std::string(62, '0')) {
    printf("  FAIL all-failures hash != 62 zeros\n"); g_fail++;
  }
  {
    /* Deterministic non-trivial input -> stable 62-char hex. */
    std::string raw =
      "c030|0303|h2|002b-0033,c030|0303|h2|002b-0033,|||,|||,|||,|||,"
      "1302|0304||002b-0033,1302|0304||002b-0033,|||,1302|0304||002b-0033";
    std::string h = jarm_hash(raw);
    if (h.size() != 62) { printf("  FAIL hash length %zu != 62\n", h.size()); g_fail++; }
    if (jarm_hash(raw) != h) { printf("  FAIL hash nondeterministic\n"); g_fail++; }
  }
  printf("hash KATs: %s\n", g_fail ? "CHECK" : "OK");

  /* (3) Parser fuzz: never fault on random/truncated ServerHellos, and the
     ten-probe hash stays well-formed (62 chars). */
  uint32_t r = seed ? seed : 1;
  auto xr = [&](){ r ^= r << 13; r ^= r >> 17; r ^= r << 5; return r; };
  for (int it = 0; it < 200000; it++) {
    std::string raw;
    for (int probe = 0; probe < 10; probe++) {
      int len = xr() % 200;
      std::string s; s.resize(len);
      for (int i = 0; i < len; i++) s[i] = (char)(xr() & 0xff);
      raw += jarm_parse_server_hello(
          reinterpret_cast<const uint8_t *>(s.data()), s.size());
      if (probe != 9) raw += ",";
    }
    std::string hv = jarm_hash(raw);     /* exercises split/cipher_bytes/version_byte */
    if (hv.size() != 62) { printf("  FAIL fuzz hash len %zu != 62\n", hv.size()); g_fail++; break; }
  }
  printf("parser+hash fuzz (200000 x10 probes): no fault\n");

  printf("\n%s\n", g_fail == 0 ? "JARM test: ALL PASS" : "JARM test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
