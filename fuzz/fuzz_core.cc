/* fuzz_core.cc -- resource-control + addressing core.
 * VERBATIM copies of:
 *   fast_syn.cc : cidr_mask, parse_cidr, permute_ip (+ IP_SPACE/PRIME)
 *   net_db.cc   : ip_to_u32, u32_to_ip
 *   cpu_meter.cc: kmap_cpu_throttle_step_us (the governor control law)
 *
 * Checks:
 *  - permute_ip is a bijection over contiguous windows (no dup / no skip)
 *  - ip_to_u32 / cidr_mask shift safety (UBSan trap on bad shift)
 *  - parse_cidr memcpy guard holds for overlong inputs (guard-page string)
 *  - governor control law: result always in [0, MAX_SLEEP_US], never NaN-cast
 *  Build: g++ -O1 -g -std=gnu++17 -D_GLIBCXX_ASSERTIONS \
 *         -fsanitize=undefined -fsanitize-trap=all fuzz_core.cc -o fuzz_core.exe
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <csignal>
#include <windows.h>

/* ===== fast_syn.cc verbatim ===== */
static uint32_t cidr_mask(int prefix_len) {
  if (prefix_len <= 0) return 0;
  if (prefix_len >= 32) return 0xFFFFFFFF;
  return ~((1u << (32 - prefix_len)) - 1);
}
static const uint64_t IP_SPACE = 0x100000000ULL;
static const uint64_t PERMUTE_PRIME = 3948573427ULL;
static uint32_t permute_ip(uint64_t index, uint64_t seed) {
  return static_cast<uint32_t>(((index * PERMUTE_PRIME) + seed) & 0xFFFFFFFF);
}
/* ===== net_db.cc verbatim ===== */
static uint32_t ip_to_u32(const char *ip_str) {
  unsigned int a, b, c, d;
  if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
  if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
  return (a << 24) | (b << 16) | (c << 8) | d;
}
static std::string u32_to_ip(uint32_t ip) {
  char buf[16];
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
  return buf;
}
/* parse_cidr verbatim (needs ip_to_u32) */
static bool parse_cidr(const char *line, uint32_t &net, uint32_t &mask) {
  char ip_buf[64];
  int prefix = 32;
  const char *slash = strchr(line, '/');
  if (slash) {
    size_t ip_len = static_cast<size_t>(slash - line);
    if (ip_len >= sizeof(ip_buf)) return false;
    memcpy(ip_buf, line, ip_len);
    ip_buf[ip_len] = '\0';
    prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return false;
  } else {
    strncpy(ip_buf, line, sizeof(ip_buf) - 1);
    ip_buf[sizeof(ip_buf) - 1] = '\0';
  }
  net = ip_to_u32(ip_buf);
  if (net == 0 && strcmp(ip_buf, "0.0.0.0") != 0) return false;
  mask = cidr_mask(prefix);
  net &= mask;
  return true;
}
/* ===== cpu_meter.cc verbatim ===== */
static long kmap_cpu_throttle_step_us(double used_cores, double target_cores,
                                      long cur_sleep_us) {
  if (target_cores <= 0.0) return 0;
  const long   MAX_SLEEP_US = 250000;
  const long   SEED_US      = 1500;
  const double DAMP         = 0.7;
  const double hi = target_cores * 1.03;
  const double lo = target_cores * 0.97;
  if (used_cores <= hi && used_cores >= lo) {
    if (cur_sleep_us < 0) return 0;
    if (cur_sleep_us > MAX_SLEEP_US) return MAX_SLEEP_US;
    return cur_sleep_us;
  }
  const double ratio = used_cores / target_cores;
  double next;
  if (cur_sleep_us < SEED_US) {
    next = (used_cores > target_cores) ? static_cast<double>(SEED_US) * ratio : 0.0;
  } else {
    double factor = std::pow(ratio, DAMP);
    next = static_cast<double>(cur_sleep_us) * factor;
  }
  if (next < 0.0) next = 0.0;
  if (next > MAX_SLEEP_US) next = MAX_SLEEP_US;
  return static_cast<long>(next);
}

/* ===== guard-page C-string for parse_cidr over-read detection ===== */
static SIZE_T g_page;
static char *make_guarded_str(const char *s, size_t len, char **out) {
  size_t need = len + 1; /* include NUL */
  size_t npages = (need + g_page - 1) / g_page; if (!npages) npages = 1;
  size_t total = (npages + 1) * g_page;
  char *base = (char *)VirtualAlloc(NULL, total, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  DWORD o; VirtualProtect(base + npages*g_page, g_page, PAGE_NOACCESS, &o);
  char *p = base + npages*g_page - need;
  memcpy(p, s, len); p[len] = '\0';
  *out = p; return base;
}

static long long g_iter; static const char *g_fn = "?";
static void onfail(int sig){ fprintf(stderr,"\n*** FAULT sig=%d fn=%s iter=%lld\n",sig,g_fn,g_iter); _exit(99); }
static uint64_t rs; static uint64_t rng(){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }

int main(int argc, char **argv) {
  SYSTEM_INFO si; GetSystemInfo(&si); g_page = si.dwPageSize;
  signal(SIGSEGV,onfail); signal(SIGILL,onfail); signal(SIGABRT,onfail);
  rs = (argc>1)? strtoull(argv[1],NULL,10) : 0xBEEFULL;

  /* --- 1. permute_ip bijection over contiguous windows (no dup/skip) --- */
  /* A linear map with odd multiplier is a bijection mod 2^32; verify the
     implementation by checking every output in a window is distinct AND the
     window's outputs form a permutation of themselves (popcount == size). */
  {
    const uint64_t WIN = 1ULL << 28; /* 256M indices, 32MB bitset */
    std::vector<uint64_t> seen(WIN/64, 0);
    uint64_t seed = rng();
    uint64_t base = (rng() % (IP_SPACE - WIN));
    g_fn = "permute_ip:distinct";
    uint64_t dup = 0;
    /* outputs over the window are distinct as 32-bit values only if WIN<=2^32;
       to test distinctness we map output->index-within-window is not possible,
       so instead verify distinctness of outputs by hashing into the bitset on
       the low 28 bits is insufficient. Proper test: the inverse. PRIME is
       invertible mod 2^32; recompute index from output and confirm round-trip. */
    /* modular inverse of PRIME mod 2^32 (odd => invertible) */
    auto modinv32 = [](uint64_t a)->uint64_t{ uint64_t x=1; for(int i=0;i<5;i++) x*= (2 - a*x); return x & 0xFFFFFFFFULL; };
    uint64_t inv = modinv32(PERMUTE_PRIME);
    for (uint64_t i = 0; i < WIN; i++) {
      uint32_t out = permute_ip(base + i, seed);
      /* invert: idx = (out - seed) * inv mod 2^32 */
      uint64_t idx = (((uint64_t)out - seed) * inv) & 0xFFFFFFFFULL;
      if (idx != ((base + i) & 0xFFFFFFFFULL)) {
        fprintf(stderr,"\n*** permute_ip not invertible at i=%llu out=%u idx=%llu\n",
                (unsigned long long)i, out, (unsigned long long)idx); _exit(97);
      }
      uint64_t off = i; /* distinctness via bitset on window offset of inverse */
      uint64_t b = ((idx - base) & 0xFFFFFFFFULL);
      if (b < WIN) { if (seen[b>>6] & (1ULL<<(b&63))) dup++; else seen[b>>6]|=(1ULL<<(b&63)); }
      (void)off;
    }
    fprintf(stderr,"permute_ip: %llu indices round-trip OK, dup=%llu (seed=%llu base=%llu)\n",
            (unsigned long long)WIN,(unsigned long long)dup,
            (unsigned long long)seed,(unsigned long long)base);
    if (dup) { fprintf(stderr,"*** DUPLICATE outputs!\n"); _exit(96); }
  }

  /* --- 2. ip_to_u32 / u32_to_ip / cidr_mask shift safety --- */
  g_fn = "cidr_mask";
  for (int p = -2; p <= 34; p++) { volatile uint32_t m = cidr_mask(p); (void)m; }
  g_fn = "ip_to_u32";
  for (long long k = 0; k < 3000000; k++) {
    g_iter = k;
    unsigned a=rng()%300,b=rng()%300,c=rng()%300,d=rng()%300;
    char s[64]; snprintf(s,sizeof(s),"%u.%u.%u.%u",a,b,c,d);
    uint32_t v = ip_to_u32(s);
    if (v) { std::string back = u32_to_ip(v); volatile uint32_t v2 = ip_to_u32(back.c_str());
             if (v2 != v) { fprintf(stderr,"\n*** ip roundtrip fail %s -> %u -> %s\n",s,v,back.c_str()); _exit(95);} }
    /* random u32 -> string -> u32 roundtrip */
    uint32_t ru = (uint32_t)rng(); std::string rb = u32_to_ip(ru);
    if (ip_to_u32(rb.c_str()) != ru) { fprintf(stderr,"\n*** u32->ip->u32 fail %u -> %s\n",ru,rb.c_str()); _exit(95);}
  }

  /* --- 3. parse_cidr with guard-page strings (overlong / weird) --- */
  g_fn = "parse_cidr";
  const char *al = "0123456789./ \t-ABCxyz";
  for (long long k = 0; k < 2000000; k++) {
    g_iter = k;
    size_t len = rng() % 200; /* deliberately exceed ip_buf[64] sometimes */
    std::string s; for (size_t i=0;i<len;i++) s += al[rng()%strlen(al)];
    if ((rng()&3)==0) { /* force a slash to hit the memcpy(ip_len) path */
      size_t at = len? rng()%len : 0; if (at<s.size()) s[at]='/';
    }
    char *gp; char *base = make_guarded_str(s.c_str(), s.size(), &gp);
    uint32_t net, mask; volatile bool ok = parse_cidr(gp, net, mask); (void)ok;
    VirtualFree(base,0,MEM_RELEASE);
  }

  /* --- 4. governor control law: bounded output, no NaN-cast on finite input --- */
  g_fn = "governor";
  const long MAXS = 250000;
  for (long long k = 0; k < 5000000; k++) {
    g_iter = k;
    /* realistic finite domain: used 0..64 cores, target 0..32 cores, sleep 0..1e6us */
    double used   = (double)(rng()%6400)/100.0;
    double target = (double)(rng()%3200)/100.0;
    long   cur    = (long)(rng()%1000001);
    long out = kmap_cpu_throttle_step_us(used, target, cur);
    if (out < 0 || out > MAXS) {
      if (!(target<=0.0 && out==0)) {
        fprintf(stderr,"\n*** governor out of range: used=%.3f target=%.3f cur=%ld -> %ld\n",
                used,target,cur,out); _exit(94);
      }
    }
    /* in-band must hold current, clamped to [0, MAXS] (hardened postcondition) */
    if (target>0.0) { double hi=target*1.03, lo=target*0.97;
      long expect = cur < 0 ? 0 : (cur > MAXS ? MAXS : cur);
      if (used<=hi && used>=lo && out!=expect) {
        fprintf(stderr,"\n*** governor deadband violated used=%.3f target=%.3f cur=%ld -> %ld (expect %ld)\n",
                used,target,cur,out,expect); _exit(93);
      }
    }
  }

  fprintf(stderr,"\nCORE fuzz OK (seed=%s)\n", argc>1?argv[1]:"default");
  return 0;
}
