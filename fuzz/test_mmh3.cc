/*
 * test_mmh3.cc -- pins net_hash_helpers.cc::mmh3_x86_32 against values from
 * the reference `mmh3` Python library (the de-facto Shodan-compatible
 * implementation).  A wrong MurmurHash3 silently produces favicon hashes that
 * never match the big-scanner corpus, so these vectors are load-bearing.
 *
 * Build (links the REAL helper, not a copy):
 *   g++ -O2 -g -std=gnu++17 -Wall fuzz/test_mmh3.cc net_hash_helpers.cc \
 *       -o fuzz/test_mmh3.exe && fuzz/test_mmh3.exe
 */

#include <cstdio>
#include <cstdint>
#include <string>

#include "../net_hash_helpers.h"

static int g_fail = 0;

static void check(const std::string &in, uint32_t seed, int32_t expect,
                  const char *label) {
  int32_t got = mmh3_x86_32(in, seed);
  if (got != expect) {
    printf("  FAIL %-22s seed=%u len=%zu\n    got    %d\n    expect %d\n",
           label, seed, in.size(), got, expect);
    g_fail++;
  }
}

int main(int argc, char ** /*argv*/) {
  (void)argc;
  /* Seed-0 vectors (verified against mmh3 4.x). */
  check("",            0, 0,           "empty");
  check("a",           0, 1009084850,  "a");
  check("ab",          0, -1681926305, "ab");
  check("abc",         0, -1277324294, "abc");
  check("test",        0, -1167338989, "test");
  check("hello world", 0, 1586663183,  "hello world");

  /* Binary payload with NUL and high bytes -- exercises the unsigned-byte
     block read and the 2-byte tail. */
  const unsigned char bin[] = {0x00, 0x01, 0x02, 0x03, 0xff, 0xfe};
  check(std::string(reinterpret_cast<const char *>(bin), sizeof(bin)),
        0, -2128357829, "binary6");

  /* Non-zero seed path. */
  check("",     1, 1364076727,  "empty/seed1");
  check("test", 1, -1715459358, "test/seed1");

  printf("\n%s\n", g_fail == 0 ? "mmh3 test: ALL PASS" : "mmh3 test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
