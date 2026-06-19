/*
 * test_vercmp.cc -- audit of the CVE version-comparison logic that backs the
 * "version-precise" guarantee of --cve-map (per-host) and --net-scan (enrich).
 *
 * Two INDEPENDENT implementations of the same comparison ship today:
 *   cve_map.cc   : str_split + parse_ver + ver_cmp + extract_ver
 *   net_enrich.cc: parse_ver_enrich + ver_cmp_parsed + ver_cmp_enrich
 * If they ever disagree, the per-host scan and the internet-scan enrich path
 * would flag DIFFERENT CVEs for the identical detected version. Nothing pinned
 * that invariant -- this harness does, with all six functions copied VERBATIM
 * (keep in sync) and cross-checked over a fuzz corpus.
 *
 * It also KATs the behaviors the README promises: numeric (not lexical)
 * ordering (8.2 < 8.10), and the NVD versionEndExcluding rule -- a release that
 * equals an *exclusive* upper bound is the FIXED version and must NOT be
 * flagged (Apache 2.4.52 is never reported for a bug fixed in 2.4.52).
 *
 * Build (helper-style, no deps):
 *   g++ -O1 -g -std=gnu++17 -fsanitize=address,undefined \
 *       -fno-sanitize-recover=all fuzz/test_vercmp.cc -o t && ./t
 */

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>

/* ===== VERBATIM from cve_map.cc ===== */
static std::vector<std::string> str_split(const std::string &s, char delim) {
  std::vector<std::string> parts;
  std::istringstream ss(s);
  std::string part;
  while (std::getline(ss, part, delim))
    if (!part.empty()) parts.push_back(part);
  return parts;
}
static std::vector<int> parse_ver(const std::string &ver) {
  std::vector<int> parts;
  auto tokens = str_split(ver, '.');
  for (auto &t : tokens) {
    std::string digits;
    for (char c : t) {
      if (isdigit((unsigned char)c)) digits += c;
      else break;
    }
    if (!digits.empty()) {
      try { parts.push_back(std::stoi(digits)); }
      catch (...) {}
    }
  }
  return parts;
}
static int ver_cmp(const std::string &a, const std::string &b) {
  auto va = parse_ver(a);
  auto vb = parse_ver(b);
  size_t n = std::max(va.size(), vb.size());
  for (size_t i = 0; i < n; i++) {
    int ai = (i < va.size()) ? va[i] : 0;
    int bi = (i < vb.size()) ? vb[i] : 0;
    if (ai < bi) return -1;
    if (ai > bi) return  1;
  }
  return 0;
}
static std::string extract_ver(const std::string &s) {
  size_t i = 0;
  while (i < s.size()) {
    if (isdigit((unsigned char)s[i])) {
      size_t start = i;
      while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '.' || s[i] == 'p'))
        i++;
      std::string candidate = s.substr(start, i - start);
      if (candidate.find('.') != std::string::npos)
        return candidate;
    } else {
      i++;
    }
  }
  return "";
}
/* ===== VERBATIM from net_enrich.cc ===== */
static std::vector<int> parse_ver_enrich(const std::string &s) {
  std::vector<int> parts;
  std::istringstream ss(s);
  std::string tok;
  while (std::getline(ss, tok, '.')) {
    std::string digits;
    for (char c : tok) {
      if (isdigit(static_cast<unsigned char>(c))) digits += c;
      else break;
    }
    if (!digits.empty()) {
      try { parts.push_back(std::stoi(digits)); }
      catch (...) {}
    }
  }
  return parts;
}
static int ver_cmp_parsed(const std::vector<int> &va, const std::vector<int> &vb) {
  size_t n = std::max(va.size(), vb.size());
  for (size_t i = 0; i < n; i++) {
    int ai = (i < va.size()) ? va[i] : 0;
    int bi = (i < vb.size()) ? vb[i] : 0;
    if (ai < bi) return -1;
    if (ai > bi) return  1;
  }
  return 0;
}
static int ver_cmp_enrich(const std::string &a, const std::string &b) {
  return ver_cmp_parsed(parse_ver_enrich(a), parse_ver_enrich(b));
}
/* ===== end verbatim ===== */

/* The applicability decision both paths run, distilled (inclusive/exclusive
   bounds).  affected == "detected version falls in the CVE's affected range". */
static bool affected(const std::string &dver, const std::string &vmin,
                     const std::string &vmax, bool vmin_excl, bool vmax_excl) {
  if (!vmin.empty()) {
    int c = ver_cmp(dver, vmin);
    if (c < 0 || (vmin_excl && c == 0)) return false;
  }
  if (!vmax.empty()) {
    int c = ver_cmp(dver, vmax);
    if (c > 0 || (vmax_excl && c == 0)) return false;
  }
  return true;
}

static int g_fail = 0;
static void eq(int got, int want, const char *label) {
  if (got != want) { printf("  FAIL %s: got %d want %d\n", label, got, want); g_fail++; }
}
static void tt(bool cond, const char *label) {
  if (!cond) { printf("  FAIL %s\n", label); g_fail++; }
}
static int sgn(int x){ return x<0?-1:(x>0?1:0); }

static uint32_t g_rng = 1;
static uint32_t xr(){ g_rng^=g_rng<<13; g_rng^=g_rng>>17; g_rng^=g_rng<<5; return g_rng; }

int main(int argc, char **argv) {
  if (argc > 1) g_rng = (uint32_t)strtoul(argv[1], nullptr, 0);
  if (!g_rng) g_rng = 1;
  printf("CVE version-comparison audit\n============================\n");

  /* 1. numeric, not lexical -- the classic bug this must never have. */
  eq(ver_cmp("8.2", "8.10"), -1, "8.2 < 8.10 (numeric)");
  eq(ver_cmp("1.18.0", "1.9"), 1, "1.18.0 > 1.9");
  eq(ver_cmp("2.4.49", "2.4.49"), 0, "equal");
  eq(ver_cmp("2.4.50", "2.4.49"), 1, "2.4.50 > 2.4.49");
  eq(ver_cmp("8.2p1", "8.2"), 0, "p-suffix drops to base (== )");
  eq(ver_cmp("8.2", "8.2.0"), 0, "missing trailing component == .0");

  /* 2. extract_ver -- document the REAL return (keeps the 'p', has a dot). */
  tt(extract_ver("OpenSSH 8.2p1 Ubuntu 4") == "8.2p1", "extract_ver OpenSSH");
  tt(extract_ver("nginx 1.18.0") == "1.18.0", "extract_ver nginx");
  tt(extract_ver("Apache/2.4.49 (Ubuntu)") == "2.4.49", "extract_ver Apache");
  tt(extract_ver("10").empty(), "extract_ver no-dot -> empty");
  tt(extract_ver("Server").empty(), "extract_ver no-digit -> empty");

  /* 3. NVD versionEndExcluding: the FIXED release must not be flagged. */
  tt(!affected("2.4.52", "", "2.4.52", false, true),  "patched (==exclusive max) not flagged");
  tt( affected("2.4.51", "", "2.4.52", false, true),  "pre-fix version flagged");
  tt( affected("2.4.52", "", "2.4.52", false, false), "inclusive max includes the bound");
  tt(!affected("2.4.40", "2.4.41", "", true, false),  "below exclusive min not flagged");
  tt( affected("2.4.41", "2.4.41", "", false, false), "inclusive min includes the bound");
  int kat = g_fail;
  printf("KATs: %s (%d failed)\n", kat ? "FAIL" : "OK", kat);

  /* 4. cross-implementation equivalence + ordering invariants, fuzzed.
        cve_map's ver_cmp and net_enrich's ver_cmp_enrich must agree in sign,
        and the comparator must be antisymmetric and reflexive. */
  int eqfail = 0, invfail = 0;
  const char *frag[] = {"0","1","9","10","18","49","2p1","8","255",
                        "4294967296","99999999999999999",".","p","x",""};
  for (int it = 0; it < 1000000; it++) {
    auto mk = [&](){ std::string s; int n = xr()%8;
      for (int k=0;k<n;k++){ if (xr()&1) s+=frag[xr()%15];
        else { s+='.'; s+=std::to_string(xr()%200);} } return s; };
    std::string a = mk(), b = mk();
    if (sgn(ver_cmp(a,b)) != sgn(ver_cmp_enrich(a,b))) {
      if (eqfail<5) printf("  DIVERGE a=%s b=%s cve=%d enrich=%d\n",
                           a.c_str(), b.c_str(), ver_cmp(a,b), ver_cmp_enrich(a,b));
      eqfail++;
    }
    if (ver_cmp(a,b) != -ver_cmp(b,a)) invfail++;
    if (ver_cmp(a,a) != 0) invfail++;
  }
  printf("equivalence (cve_map==net_enrich): %s (%d diverge)\n", eqfail?"FAIL":"OK", eqfail);
  printf("antisymmetry+reflexivity: %s (%d violations)\n", invfail?"FAIL":"OK", invfail);
  g_fail += eqfail + invfail;

  /* 5. crash fuzz: hostile version strings (huge digit runs -> stoi overflow
        must stay caught; arbitrary bytes) must never fault. */
  for (int it = 0; it < 300000; it++) {
    std::string s; int n = xr()%32;
    for (int k=0;k<n;k++) s += (char)(xr()&0xff);
    volatile int x = ver_cmp(s, "2.4.49"); (void)x;
    volatile int y = ver_cmp_enrich("2.4.49", s); (void)y;
    volatile size_t z = extract_ver(s).size(); (void)z;
  }
  printf("crash fuzz (300000 iters): no fault\n");

  printf("\n%s\n", g_fail==0 ? "vercmp test: ALL PASS" : "vercmp test: FAILURES");
  return g_fail==0 ? 0 : 1;
}
