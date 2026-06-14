/*
 * test_checkpoint.cc -- live test for the fast_syn.cc net-scan checkpoint
 * serialization (the resume data-handling path).
 *
 * A corrupt or mis-parsed checkpoint at internet scale means re-scanning from
 * zero (lost progress) or -- worse, if the seed were dropped -- walking a
 * different permutation so some IPs are never scanned and others twice. The
 * real code defends against this with: an atomic .tmp+rename write, a .tmp
 * fallback on load, a strict 5-field fscanf check, and a seed==0 resume guard.
 * This test exercises those behaviours against the REAL filesystem.
 *
 * The save/load logic is mirrored verbatim from fast_syn.cc (the functions are
 * static there, so they cannot be linked). This pins the on-disk format
 * contract: 5 newline-separated fields in the order
 * next_index, packets_sent, hosts_found, seed, last_save. If fast_syn.cc's
 * format changes, update this copy in lockstep.
 *
 * Build (Win):  g++ -O2 -std=gnu++17 test_checkpoint.cc -o test_checkpoint.exe
 * Build (CI):   g++ $CXXFLAGS fuzz/test_checkpoint.cc -o test_checkpoint
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <string>

static int g_fail = 0;
static void chk(bool c, const char *m) { if (!c) { printf("  FAIL: %s\n", m); g_fail++; } }

/* ---- mirror of fast_syn.cc ScanCheckpoint + save/load (verbatim logic) ---- */
struct ScanCheckpoint {
  uint64_t next_index;
  uint64_t packets_sent;
  uint64_t hosts_found;
  uint64_t seed;
  time_t   last_save;
};

static std::string checkpoint_path(const char *data_dir) {
  return std::string(data_dir) + "/.net-scan-checkpoint";
}

static bool save_checkpoint(const char *data_dir, const ScanCheckpoint &cp) {
  std::string path = checkpoint_path(data_dir);
  std::string tmp_path = path + ".tmp";
  FILE *f = fopen(tmp_path.c_str(), "w");
  if (!f) return false;
  int n = fprintf(f, "%llu\n%llu\n%llu\n%llu\n%lld\n",
                  (unsigned long long)cp.next_index,
                  (unsigned long long)cp.packets_sent,
                  (unsigned long long)cp.hosts_found,
                  (unsigned long long)cp.seed,
                  (long long)cp.last_save);
  if (n < 0 || fflush(f) != 0) { fclose(f); remove(tmp_path.c_str()); return false; }
  if (fclose(f) != 0) { remove(tmp_path.c_str()); return false; }
#ifdef WIN32
  remove(path.c_str());
#endif
  if (rename(tmp_path.c_str(), path.c_str()) != 0) {
    remove(tmp_path.c_str());
    return false;
  }
  return true;
}

static bool load_checkpoint(const char *data_dir, ScanCheckpoint &cp) {
  std::string path = checkpoint_path(data_dir);
  FILE *f = fopen(path.c_str(), "r");
  if (!f) {
    std::string tmp_path = path + ".tmp";
    f = fopen(tmp_path.c_str(), "r");
    if (!f) return false;
  }
  unsigned long long ni, ps, hf, sd;
  long long ls;
  if (fscanf(f, "%llu\n%llu\n%llu\n%llu\n%lld", &ni, &ps, &hf, &sd, &ls) != 5) {
    fclose(f);
    return false;
  }
  cp.next_index = ni; cp.packets_sent = ps; cp.hosts_found = hf;
  cp.seed = sd; cp.last_save = static_cast<time_t>(ls);
  fclose(f);
  return true;
}

/* ---- the seed-safety resume gate from run_fast_syn (the decision, not I/O) ---- */
static bool can_resume(const ScanCheckpoint &cp) {
  /* mirrors: if (cp.seed == 0 && cp.next_index > 0) -> refuse */
  return !(cp.seed == 0 && cp.next_index > 0);
}

/* ---- test helpers ---- */
static void rm(const char *dir) {
  std::string p = checkpoint_path(dir);
  remove(p.c_str());
  remove((p + ".tmp").c_str());
}
static void write_raw(const std::string &path, const char *content) {
  FILE *f = fopen(path.c_str(), "w");
  if (f) { fputs(content, f); fclose(f); }
}

int main(int argc, char **argv) {
  (void)argc; (void)argv;
  printf("checkpoint serialization test\n=============================\n");
  const char *dir = ".";  /* writes ./.net-scan-checkpoint(.tmp) */
  rm(dir);

  /* 1. Round-trip preserves every field. */
  ScanCheckpoint a{};
  a.next_index = 123456789ULL;
  a.packets_sent = 987654321ULL;
  a.hosts_found = 42;
  a.seed = 0xDEADBEEFCAFEULL;
  a.last_save = 1700000000;
  chk(save_checkpoint(dir, a), "save_checkpoint succeeds");
  ScanCheckpoint b{};
  chk(load_checkpoint(dir, b), "load_checkpoint succeeds");
  chk(b.next_index == a.next_index, "next_index round-trips");
  chk(b.packets_sent == a.packets_sent, "packets_sent round-trips");
  chk(b.hosts_found == a.hosts_found, "hosts_found round-trips");
  chk(b.seed == a.seed, "seed round-trips");
  chk(b.last_save == a.last_save, "last_save round-trips");

  /* 2. After a successful save the .tmp must be gone (renamed, not left). */
  {
    std::string tmp = checkpoint_path(dir) + ".tmp";
    FILE *t = fopen(tmp.c_str(), "r");
    chk(t == nullptr, "no stray .tmp after successful save");
    if (t) fclose(t);
  }

  /* 3. Full uint64 range survives (top half of IPv4 index space, big counters). */
  rm(dir);
  ScanCheckpoint big{};
  big.next_index = UINT64_MAX;
  big.packets_sent = UINT64_MAX - 1;
  big.hosts_found = 0;
  big.seed = UINT64_MAX / 2;
  big.last_save = 0;
  chk(save_checkpoint(dir, big), "save large values");
  ScanCheckpoint big2{};
  chk(load_checkpoint(dir, big2), "load large values");
  chk(big2.next_index == UINT64_MAX, "UINT64_MAX next_index round-trips");
  chk(big2.packets_sent == UINT64_MAX - 1, "near-max packets_sent round-trips");
  chk(big2.seed == UINT64_MAX / 2, "large seed round-trips");

  /* 4. .tmp fallback: main file absent but a good .tmp present -> load uses it. */
  rm(dir);
  write_raw(checkpoint_path(dir) + ".tmp",
            "555\n666\n777\n888\n1699999999\n");
  ScanCheckpoint fb{};
  chk(load_checkpoint(dir, fb), "load falls back to .tmp when main is missing");
  chk(fb.next_index == 555 && fb.seed == 888, ".tmp fallback parses fields");

  /* 5. Corrupt / truncated checkpoint (fewer than 5 fields) is rejected,
        not partially accepted with garbage. */
  rm(dir);
  write_raw(checkpoint_path(dir), "123\n456\n");   /* only 2 fields */
  ScanCheckpoint c{};
  chk(!load_checkpoint(dir, c), "truncated checkpoint (<5 fields) rejected");

  /* 6. Empty file rejected. */
  rm(dir);
  write_raw(checkpoint_path(dir), "");
  ScanCheckpoint e{};
  chk(!load_checkpoint(dir, e), "empty checkpoint rejected");

  /* 7. Missing checkpoint entirely -> load returns false (start fresh). */
  rm(dir);
  ScanCheckpoint m{};
  chk(!load_checkpoint(dir, m), "absent checkpoint -> load false");

  /* 8. Seed-safety resume gate: progress with seed==0 must be refused;
        a fresh (index 0) or seeded checkpoint is resumable. */
  ScanCheckpoint noseed{}; noseed.seed = 0; noseed.next_index = 1000;
  chk(!can_resume(noseed), "seed==0 with progress is NOT resumable");
  ScanCheckpoint seeded{}; seeded.seed = 12345; seeded.next_index = 1000;
  chk(can_resume(seeded), "seeded checkpoint IS resumable");
  ScanCheckpoint fresh{}; fresh.seed = 0; fresh.next_index = 0;
  chk(can_resume(fresh), "fresh checkpoint (index 0) is resumable");

  rm(dir);
  printf("\n%s\n", g_fail == 0 ? "checkpoint test: ALL PASS"
                               : "checkpoint test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
