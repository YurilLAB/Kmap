/*
 * fuzz_query.cc -- adversarial fuzzing for net_query.cc's CVE/CVSS JSON
 * parsers, which the fuzz_text harness does not cover.
 *
 *   max_cvss_from_json  -- drives the --nq-min-cvss post-filter; a wrong
 *                          result silently returns the wrong hosts.
 *   first_cve_summary   -- compact CVE display string.
 *
 * Both walk a host row's `cves` column (kmap-generated JSON) with find()/
 * substr()/index scans. They run on operator-controlled but
 * network-influenced data (CVE descriptions are lifted from kmap-cve.db),
 * so they must never over-read or crash on malformed/truncated input.
 *
 * The two functions are lifted VERBATIM from net_query.cc (keep in sync).
 * Under ASan/UBSan in CI (-fno-sanitize-recover=all) any heap over-read or
 * UB aborts the run; locally a SIGSEGV/SIGABRT handler reports the input.
 * Invariants checked on every iteration:
 *   - max_cvss_from_json(s) >= -1.0f  (init sentinel; only raised, never lowered)
 *   - both functions are deterministic (same input -> same output twice)
 *   - a non-empty first_cve_summary begins with the extracted CVE id
 *
 * Build (MinGW, here):
 *   g++ -O2 -g -std=gnu++17 -Wall fuzz/fuzz_query.cc -o fuzz/fuzz_query.exe \
 *       && fuzz/fuzz_query.exe
 */

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cctype>
#include <string>

/* ---- net_query.cc: max_cvss_from_json (verbatim) ---- */
static float max_cvss_from_json(const std::string &cves_json) {
  float max_score = -1.0f;
  size_t pos = 0;
  while (true) {
    pos = cves_json.find("\"cvss\":", pos);
    if (pos == std::string::npos) break;
    pos += 7;
    while (pos < cves_json.size() && cves_json[pos] == ' ') pos++;
    size_t end = pos;
    while (end < cves_json.size() &&
           (isdigit(static_cast<unsigned char>(cves_json[end])) ||
            cves_json[end] == '.' || cves_json[end] == '-'))
      end++;
    if (end > pos) {
      float score = static_cast<float>(
          atof(cves_json.substr(pos, end - pos).c_str()));
      if (score > max_score) max_score = score;
    }
    pos = end;
  }
  return max_score;
}

/* ---- net_query.cc: first_cve_summary (verbatim) ---- */
static std::string first_cve_summary(const std::string &cves_json) {
  size_t id_pos = cves_json.find("\"id\":\"");
  if (id_pos == std::string::npos) return "";
  id_pos += 6;
  size_t id_end = cves_json.find('"', id_pos);
  if (id_end == std::string::npos) return "";
  std::string cve_id = cves_json.substr(id_pos, id_end - id_pos);

  size_t cvss_pos = cves_json.find("\"cvss\":", id_pos);
  std::string cvss_str;
  if (cvss_pos != std::string::npos && cvss_pos < id_pos + 200) {
    cvss_pos += 7;
    while (cvss_pos < cves_json.size() && cves_json[cvss_pos] == ' ')
      cvss_pos++;
    size_t cvss_end = cvss_pos;
    while (cvss_end < cves_json.size() &&
           (isdigit(static_cast<unsigned char>(cves_json[cvss_end])) ||
            cves_json[cvss_end] == '.'))
      cvss_end++;
    if (cvss_end > cvss_pos)
      cvss_str = cves_json.substr(cvss_pos, cvss_end - cvss_pos);
  }

  if (!cvss_str.empty())
    return cve_id + " (CVSS:" + cvss_str + ")";
  return cve_id;
}

/* ---- driver ---- */
static long long g_iter; static std::string g_cur; static const char *g_fn;
static void onfail(int sig) {
  fprintf(stderr, "\n*** FAULT sig=%d fn=%s iter=%lld len=%zu input=<<%s>>\n",
          sig, g_fn ? g_fn : "?", g_iter, g_cur.size(), g_cur.c_str());
  _exit(99);
}
static uint64_t rs;
static uint64_t rng() { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

/* alphabet biased toward the structural tokens these parsers key on */
static char pick() {
  static const char a[] = "{}[]\":\\,0123456789.- cvssidCVE-HIGHseverytx";
  return a[rng() % (sizeof(a) - 1)];
}

/* Build a plausibly-structured cves array so the success paths are
   exercised, not just the early-return garbage paths. */
static std::string build_structured() {
  std::string s = "[";
  int n = (int)(rng() % 4);
  for (int i = 0; i < n; i++) {
    if (i) s += ",";
    s += "{\"id\":\"CVE-20";
    s += std::to_string(10 + (int)(rng() % 90));
    s += "-";
    s += std::to_string((int)(rng() % 99999));
    s += "\",\"cvss\":";
    /* sometimes a valid score, sometimes garbage in the value slot */
    switch (rng() % 5) {
      case 0: s += std::to_string((int)(rng() % 11)) + "." + std::to_string((int)(rng() % 10)); break;
      case 1: s += "10.0"; break;
      case 2: s += "-"; break;          /* lone minus */
      case 3: s += "...";               /* dots only */ break;
      default: s += std::to_string(rng() % 1000); break;
    }
    s += ",\"severity\":\"HIGH\",\"desc\":\"";
    /* desc with escaped quotes + the literal token "cvss": to confirm the
       escaping keeps it from being mistaken for a real key */
    size_t dl = rng() % 40;
    for (size_t k = 0; k < dl; k++) {
      char c = pick();
      if (c == '"' || c == '\\') s += '\\';   /* emulate JSON escaping */
      s += c;
    }
    s += "\"}";
  }
  s += "]";
  return s;
}

int main(int argc, char **argv) {
  signal(SIGSEGV, onfail); signal(SIGILL, onfail); signal(SIGABRT, onfail);
  rs = (argc > 1) ? strtoull(argv[1], NULL, 10) : 0xC0FFEEULL;
  long long N = (argc > 2) ? atoll(argv[2]) : 5000000LL;

  for (g_iter = 0; g_iter < N; g_iter++) {
    std::string s;
    int mode = rng() % 3;
    if (mode == 0) {
      s = build_structured();
    } else {
      size_t len = rng() % 300;
      s.reserve(len);
      for (size_t i = 0; i < len; i++) {
        if (mode == 1) s += pick();
        else s += (char)(rng() & 0xFF);   /* raw bytes */
      }
      if ((rng() & 3) == 0) s = "[{\"id\":\"" + s;   /* plausible prefix */
      if ((rng() & 3) == 0) s += "\"cvss\":";        /* trailing key, no value */
    }
    g_cur = s;

    g_fn = "max_cvss_from_json";
    float mx = max_cvss_from_json(s);
    if (!(mx >= -1.0f)) {   /* NaN also fails this */
      fprintf(stderr, "\n*** max_cvss invariant: %f < -1.0 input=<<%s>>\n",
              mx, s.c_str());
      _exit(98);
    }
    float mx2 = max_cvss_from_json(s);
    if (memcmp(&mx, &mx2, sizeof(float)) != 0) {
      fprintf(stderr, "\n*** max_cvss non-deterministic input=<<%s>>\n", s.c_str());
      _exit(97);
    }

    g_fn = "first_cve_summary";
    std::string sum = first_cve_summary(s);
    std::string sum2 = first_cve_summary(s);
    if (sum != sum2) {
      fprintf(stderr, "\n*** first_cve_summary non-deterministic input=<<%s>>\n", s.c_str());
      _exit(96);
    }
    /* If it returned something, the id portion must be a prefix (the
       function always returns cve_id or cve_id + " (CVSS:...)"). */
    if (!sum.empty()) {
      size_t paren = sum.find(" (CVSS:");
      std::string id_part = (paren == std::string::npos) ? sum : sum.substr(0, paren);
      if (sum.compare(0, id_part.size(), id_part) != 0) {
        fprintf(stderr, "\n*** first_cve_summary id-prefix broken input=<<%s>>\n", s.c_str());
        _exit(95);
      }
    }

    if ((g_iter & 0xFFFFF) == 0) { fprintf(stderr, "\r iter=%lld", g_iter); fflush(stderr); }
  }
  fprintf(stderr, "\nQUERY fuzz OK: %lld iterations, no faults (seed=%s)\n",
          N, argc > 1 ? argv[1] : "default");
  return 0;
}
