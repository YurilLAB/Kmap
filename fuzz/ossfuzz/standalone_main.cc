/*
 * standalone_main.cc -- a minimal libFuzzer-compatible driver.
 *
 * OSS-Fuzz / ClusterFuzzLite build the LLVMFuzzerTestOneInput targets with
 * clang's -fsanitize=fuzzer (which supplies its own main). This driver lets the
 * SAME harness sources be compiled and exercised locally with plain g++ (which
 * has no libFuzzer), so the harness bodies can be verified without clang:
 *
 *   g++ -O1 -g -std=gnu++17 fuzz/ossfuzz/fuzz_dns.cc \
 *       fuzz/ossfuzz/standalone_main.cc -o /tmp/fdns && /tmp/fdns [seed] [iters]
 *
 * With no file arguments it drives the target with deterministic pseudo-random
 * inputs (seedable, reproducible). With file arguments it replays each file
 * through the target (handy for reproducing an OSS-Fuzz crash artifact).
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Optional one-time init some targets define; weak so it's not required. */
extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(int *, char ***);

static uint64_t rs = 0xD1CE5EEDULL;
static uint32_t rng() { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)(rs >> 32); }

int main(int argc, char **argv) {
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);

  /* If any argument is a readable file, replay those files (crash repro). */
  bool replayed = false;
  for (int i = 1; i < argc; i++) {
    FILE *f = fopen(argv[i], "rb");
    if (!f) continue;
    replayed = true;
    std::vector<uint8_t> buf;
    int c;
    while ((c = fgetc(f)) != EOF) buf.push_back((uint8_t)c);
    fclose(f);
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
  }
  if (replayed) { printf("standalone: replayed %d file arg(s)\n", argc - 1); return 0; }

  /* Otherwise drive with pseudo-random inputs: argv[1]=seed, argv[2]=iters. */
  if (argc > 1) rs = (uint64_t)strtoull(argv[1], nullptr, 10) * 2654435761ULL + 1;
  long long iters = (argc > 2) ? atoll(argv[2]) : 2000000LL;

  for (long long n = 0; n < iters; n++) {
    int len = (int)(rng() % ((rng() & 7) ? 64 : 600));
    std::vector<uint8_t> buf((size_t)len);
    for (int i = 0; i < len; i++) buf[i] = (uint8_t)rng();
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
  }
  printf("standalone: %lld iterations, no fault (seed=%s)\n",
         iters, argc > 1 ? argv[1] : "default");
  return 0;
}
