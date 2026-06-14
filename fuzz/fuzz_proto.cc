/* fuzz_proto.cc -- guard-page fuzzer for the fixed-buffer BINARY protocol
 * parsers that index hostile server bytes with non-trivial pointer math.
 *
 * VERBATIM extraction of the parse-after-recv logic from default_creds.cc:
 *   - probe_mysql   HandshakeV10 -> 20-byte scramble extraction (lines 862-886)
 *   - probe_postgresql auth-challenge salt extraction (lines 972-985)
 * and net_enrich.cc grab_banner's raw-buffer MySQL detection (lines 473-479).
 *
 * Each input `buf` of length `n` sits flush against a PAGE_NOACCESS guard
 * page, so ANY read at buf[n] or beyond faults -> SIGSEGV -> dump input.
 * The fixed destination arrays (scramble[20], salt[4]) are likewise placed
 * before guard pages so an over-WRITE faults too.
 *
 *  Build: g++ -O1 -g -std=gnu++17 -fsanitize=undefined -fsanitize-trap=all \
 *         fuzz_proto.cc -o fuzz_proto.exe
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <string>
#include <csignal>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

/* Guard page via VirtualAlloc/VirtualProtect on Windows, mmap/mprotect
   (PROT_NONE) on POSIX -- so this harness runs in the Linux ASan/UBSan CI
   loop, not only on Windows. */
static size_t g_page;
static uint8_t *guard_map(size_t total, size_t guard_off) {
#ifdef _WIN32
  uint8_t *base = (uint8_t *)VirtualAlloc(NULL, total, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  if (!base) { fprintf(stderr,"VirtualAlloc failed\n"); exit(2); }
  DWORD o; VirtualProtect(base + guard_off, g_page, PAGE_NOACCESS, &o);
#else
  uint8_t *base = (uint8_t *)mmap(NULL, total, PROT_READ|PROT_WRITE,
                                  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED) { fprintf(stderr,"mmap failed\n"); exit(2); }
  mprotect(base + guard_off, g_page, PROT_NONE);
#endif
  return base;
}
/* `sz` must match the make call so POSIX munmap gets the mapping size. */
static void free_guarded(uint8_t *base, size_t sz) {
#ifdef _WIN32
  (void)sz; VirtualFree(base, 0, MEM_RELEASE);
#else
  size_t need = sz ? sz : 1;
  size_t npages = (need + g_page - 1) / g_page; if (!npages) npages = 1;
  munmap(base, (npages + 1) * g_page);
#endif
}
/* Place `len` bytes flush against a trailing guard page; returns base to free. */
static uint8_t *guard_before(const void *data, size_t len, uint8_t **out) {
  size_t need = len ? len : 1;
  size_t npages = (need + g_page - 1) / g_page; if (!npages) npages = 1;
  size_t total = (npages + 1) * g_page;
  uint8_t *base = guard_map(total, npages*g_page);
  uint8_t *p = base + npages*g_page - len;
  if (len) memcpy(p, data, len);
  *out = p; return base;
}
/* A guard-protected fixed array of exactly `sz` bytes (over-write faults). */
static uint8_t *guard_arr(size_t sz, uint8_t **out) {
  size_t npages = (sz + g_page - 1)/g_page; if(!npages) npages=1;
  size_t total=(npages+1)*g_page;
  uint8_t *base = guard_map(total, npages*g_page);
  *out = base+npages*g_page - sz;
  return base;
}

static long long g_iter; static const uint8_t *g_cur; static size_t g_len; static const char*g_fn="?";
static void onfail(int s){
  fprintf(stderr,"\n*** FAULT sig=%d fn=%s iter=%lld n=%zu buf=",s,g_fn,g_iter,g_len);
  for(size_t i=0;i<g_len&&i<300;i++) fprintf(stderr,"%02x",g_cur[i]);
  fprintf(stderr,"\n"); _exit(99);
}
static uint64_t rs; static uint64_t rng(){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }

/* === VERBATIM: MySQL HandshakeV10 scramble extraction (default_creds.cc) === */
static void mysql_parse(const uint8_t *buf, int n, uint8_t *scramble /*[20]*/) {
  /* protocol byte must be 0x0a (caller guards n<5); replicate guard here */
  if (n < 5) return;
  if (buf[4] != 0x0a) return;
  int pos = 5;
  while (pos < n && buf[pos] != '\0') pos++;
  pos++;        /* skip null terminator of server version */
  if (pos + 13 <= n) {
    pos += 4;   /* skip connection ID */
    memcpy(scramble, buf + pos, 8);  /* scramble part 1 */
    pos += 9;   /* skip 8-byte scramble + 1-byte filler */
    if (pos + 8 + 10 <= n) {
      pos += 7;
      int pdata_len = static_cast<int>(static_cast<unsigned char>(buf[pos])); pos++;
      pos += 10;  /* skip reserved */
      int part2_len = (std::max)(13, pdata_len - 8);
      if (pos + part2_len <= n)
        memcpy(scramble + 8, buf + pos, (std::min)(12, part2_len));
    }
  }
}

/* === VERBATIM: PostgreSQL auth-challenge salt extraction (default_creds.cc) === */
static void pg_parse(const uint8_t *buf, int n, uint8_t *salt /*[4]*/) {
  if (n < 9 || buf[0] != 'R') return;
  uint32_t auth_type = (static_cast<uint8_t>(buf[5]) << 24) |
                       (static_cast<uint8_t>(buf[6]) << 16) |
                       (static_cast<uint8_t>(buf[7]) <<  8) |
                        static_cast<uint8_t>(buf[8]);
  if (auth_type == 0) return;
  if (auth_type == 5 && n >= 13) {
    memcpy(salt, buf + 9, 4);
  }
}

/* === VERBATIM: grab_banner raw MySQL detection (net_enrich.cc 473-479) === */
static std::string banner_mysql(const char *buf, int n) {
  std::string version;
  if (n >= 5 && static_cast<unsigned char>(buf[4]) == 0x0a) {
    const char *verp = buf + 5;
    size_t vlen = strnlen(verp, static_cast<size_t>(n) > 5 ? static_cast<size_t>(n) - 5 : 0);
    if (vlen > 0) version = std::string(verp, vlen);
  }
  return version;
}

/* === VERBATIM: grab_banner full binary service detection (net_enrich.cc) ===
   The complete branch sequence: MySQL (buf[4]==0x0a + version string),
   MongoDB OP_REPLY (buf[12]==0x01, n>=16 -- the read fuzz_proto did NOT
   previously exercise), and PostgreSQL auth ('R' at buf[0], n>=9). */
static const char *banner_classify_bin(const char *buf, int n,
                                       std::string &version) {
  if (n >= 5 && static_cast<unsigned char>(buf[4]) == 0x0a) {
    const char *verp = buf + 5;
    size_t vlen = strnlen(verp, static_cast<size_t>(n) > 5
                                  ? static_cast<size_t>(n) - 5 : 0);
    if (vlen > 0) version = std::string(verp, vlen);
    return "mysql";
  }
  if (n >= 16 && static_cast<unsigned char>(buf[12]) == 0x01) return "mongodb";
  if (n >= 9 && buf[0] == 'R') return "postgresql";
  return "unknown";
}

int main(int argc, char **argv) {
#ifdef _WIN32
  SYSTEM_INFO si; GetSystemInfo(&si); g_page=(size_t)si.dwPageSize;
#else
  g_page=(size_t)sysconf(_SC_PAGESIZE);
#endif
  signal(SIGSEGV,onfail); signal(SIGILL,onfail); signal(SIGABRT,onfail);
  rs=(argc>1)?strtoull(argv[1],NULL,10):0x5151ULL;
  long long N=(argc>2)?atoll(argv[2]):20000000LL;

  for (g_iter=0; g_iter<N; g_iter++) {
    /* small n stresses the boundary guards; occasionally larger */
    int n = (int)(rng()% ((rng()&7)?40:520));
    uint8_t tmp[520];
    for (int i=0;i<n;i++) tmp[i]=(uint8_t)rng();
    /* bias byte[4] toward 0x0a and byte[0] toward 'R' to enter parse paths */
    if (n>4 && (rng()&1)) tmp[4]=0x0a;
    if (n>0 && (rng()&1)) tmp[0]='R';
    if (n>8 && (rng()&3)==0) { tmp[5]=0;tmp[6]=0;tmp[7]=0;tmp[8]=5; } /* pg auth_type 5 */
    if (n>12 && (rng()&3)==0) tmp[12]=0x01;  /* bias into the mongodb buf[12] path */
    /* sprinkle nulls to vary the server-version scan length */
    if (n>6 && (rng()&3)==0) tmp[5 + rng()%((n>6)?(n-6):1)]=0;

    uint8_t *ib, *inp; ib=guard_before(tmp,(size_t)n,&inp);
    g_cur=inp; g_len=(size_t)n;

    uint8_t *sb, *scr; sb=guard_arr(20,&scr); memset(scr,0,20);
    g_fn="mysql_parse"; mysql_parse(inp,n,scr);
    free_guarded(sb,20);

    uint8_t *pb, *salt; pb=guard_arr(4,&salt);
    g_fn="pg_parse"; pg_parse(inp,n,salt);
    free_guarded(pb,4);

    g_fn="banner_mysql"; volatile auto v=banner_mysql((const char*)inp,n); (void)v;

    g_fn="banner_classify_bin";
    { std::string bv; volatile auto cls=banner_classify_bin((const char*)inp,n,bv);
      (void)cls; (void)bv; }

    free_guarded(ib,(size_t)n);
    if ((g_iter&0xFFFFF)==0){ fprintf(stderr,"\r iter=%lld",g_iter); fflush(stderr); }
  }
  fprintf(stderr,"\nPROTO fuzz OK: %lld iterations, no faults (seed=%s)\n",
          N, argc>1?argv[1]:"default");
  return 0;
}
