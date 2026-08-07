/* fuzz_text.cc -- fuzzer for the std::string text/JSON/HTTP parsers that
 * chew on hostile scan-target input. Functions copied VERBATIM from
 * net_db.cc, net_report.cc, cve_map.cc, net_enrich.cc.
 *
 * Build with _GLIBCXX_ASSERTIONS so any operator[]/substr overrun aborts,
 * plus UBSan trap for signed-overflow / shift UB:
 *   g++ -O1 -g -std=gnu++17 -D_GLIBCXX_ASSERTIONS \
 *       -fsanitize=undefined -fsanitize-trap=all fuzz_text.cc -o fuzz_text.exe
 */
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <csignal>

/* ---- helpers (verbatim) ---- */
static std::vector<std::string> str_split(const std::string &s, char delim) {
  std::vector<std::string> parts;
  std::istringstream ss(s);
  std::string part;
  while (std::getline(ss, part, delim))
    if (!part.empty()) parts.push_back(part);
  return parts;
}
static std::string str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}

/* ---- cve_map.cc: VerPart / ver_suffix_rank / ver_part_cmp / parse_ver /
       ver_cmp / extract_ver (verbatim) ---- */
struct VerPart { int num = 0; std::string suf; };
static int ver_suffix_rank(const std::string &s) {
  if (s.empty()) return 0;
  static const char *const kPre[] = { "alpha", "beta", "rc", "dev",
                                      "pre", "snapshot" };
  std::string l = str_lower(s);
  for (const char *p : kPre)
    if (l.compare(0, strlen(p), p) == 0) return -1;
  return 1;
}
static int ver_part_cmp(const VerPart &a, const VerPart &b) {
  if (a.num != b.num) return (a.num < b.num) ? -1 : 1;
  int ra = ver_suffix_rank(a.suf), rb = ver_suffix_rank(b.suf);
  if (ra != rb) return (ra < rb) ? -1 : 1;
  if (a.suf == b.suf) return 0;
  return (a.suf < b.suf) ? -1 : 1;
}
static std::vector<VerPart> parse_ver(const std::string &ver) {
  std::vector<VerPart> parts;
  auto tokens = str_split(ver, '.');
  for (auto &t : tokens) {
    size_t i = 0;
    std::string digits;
    while (i < t.size() && isdigit((unsigned char)t[i])) digits += t[i++];
    if (digits.empty()) continue;
    VerPart vp;
    try { vp.num = std::stoi(digits); } catch (...) { continue; }
    vp.suf = t.substr(i);
    parts.push_back(vp);
  }
  return parts;
}
static int ver_cmp(const std::string &a, const std::string &b) {
  auto va = parse_ver(a); auto vb = parse_ver(b);
  size_t n = std::max(va.size(), vb.size());
  for (size_t i = 0; i < n; i++) {
    VerPart pa = (i < va.size()) ? va[i] : VerPart();
    VerPart pb = (i < vb.size()) ? vb[i] : VerPart();
    int c = ver_part_cmp(pa, pb);
    if (c != 0) return c;
  }
  return 0;
}
static std::string extract_ver(const std::string &s) {
  size_t i = 0;
  while (i < s.size()) {
    if (isdigit((unsigned char)s[i])) {
      size_t start = i;
      while (i < s.size() && (isalnum((unsigned char)s[i]) || s[i] == '.')) i++;
      std::string candidate = s.substr(start, i - start);
      if (candidate.find('.') != std::string::npos) return candidate;
    } else i++;
  }
  return "";
}

/* ---- net_enrich.cc: parse_ver_enrich / ver_cmp_parsed / extract_status /
       extract_header_val / extract_html_title (verbatim) ---- */
static std::vector<VerPart> parse_ver_enrich(const std::string &s) {
  std::vector<VerPart> parts; std::istringstream ss(s); std::string tok;
  while (std::getline(ss, tok, '.')) {
    size_t i = 0;
    std::string digits;
    while (i < tok.size() && isdigit((unsigned char)tok[i])) digits += tok[i++];
    if (digits.empty()) continue;
    VerPart vp;
    try { vp.num = std::stoi(digits); } catch (...) { continue; }
    vp.suf = tok.substr(i);
    parts.push_back(vp);
  }
  return parts;
}
static int ver_cmp_parsed(const std::vector<VerPart> &va,
                          const std::vector<VerPart> &vb) {
  size_t n = std::max(va.size(), vb.size());
  for (size_t i = 0; i < n; i++) {
    VerPart pa = (i < va.size()) ? va[i] : VerPart();
    VerPart pb = (i < vb.size()) ? vb[i] : VerPart();
    int c = ver_part_cmp(pa, pb);
    if (c != 0) return c;
  }
  return 0;
}
static int extract_status(const std::string &resp) {
  if (resp.size() < 12) return 0;
  if (resp.substr(0, 4) != "HTTP") return 0;
  size_t sp = resp.find(' ');
  if (sp == std::string::npos || sp + 3 >= resp.size()) return 0;
  char c1 = resp[sp + 1], c2 = resp[sp + 2], c3 = resp[sp + 3];
  if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9' || c3 < '0' || c3 > '9') return 0;
  return (c1 - '0') * 100 + (c2 - '0') * 10 + (c3 - '0');
}
static std::string extract_header_val(const std::string &resp, const char *name) {
  std::string lower_resp = str_lower(resp);
  std::string lower_name = str_lower(std::string(name));
  std::string needle = "\n" + lower_name + ":";
  size_t pos = lower_resp.find(needle);
  if (pos == std::string::npos) return "";
  size_t start = pos + needle.size();
  while (start < resp.size() && resp[start] == ' ') start++;
  size_t end = resp.find('\r', start);
  if (end == std::string::npos) end = resp.find('\n', start);
  if (end == std::string::npos) end = resp.size();
  return resp.substr(start, end - start);
}
static std::string extract_html_title(const std::string &body) {
  std::string lower = str_lower(body);
  size_t ts = lower.find("<title>");
  if (ts == std::string::npos) return "";
  ts += 7;
  size_t te = lower.find("</title>", ts);
  if (te == std::string::npos) te = std::min(ts + 200, body.size());
  std::string t = body.substr(ts, te - ts);
  size_t a = t.find_first_not_of(" \t\r\n");
  size_t b = t.find_last_not_of(" \t\r\n");
  return (a == std::string::npos) ? "" : t.substr(a, b - a + 1);
}

/* ---- net_db.cc: db_json_find_object_end / net_db_parse_cve_ids (verbatim) ---- */
static size_t db_json_find_object_end(const std::string &json, size_t start) {
  if (start >= json.size() || json[start] != '{') return std::string::npos;
  int depth = 0; bool in_string = false; bool escape_next = false;
  for (size_t i = start; i < json.size(); i++) {
    char c = json[i];
    if (escape_next) { escape_next = false; continue; }
    if (in_string) { if (c == '\\') escape_next = true; else if (c == '"') in_string = false; continue; }
    if (c == '"') in_string = true;
    else if (c == '{') depth++;
    else if (c == '}') { depth--; if (depth == 0) return i; }
  }
  return std::string::npos;
}
static std::vector<std::string> net_db_parse_cve_ids(const std::string &cves_json) {
  std::vector<std::string> ids;
  if (cves_json.empty() || cves_json == "[]") return ids;
  size_t pos = 0;
  while (pos < cves_json.size()) {
    size_t obj_start = cves_json.find('{', pos);
    if (obj_start == std::string::npos) break;
    size_t obj_end = db_json_find_object_end(cves_json, obj_start);
    if (obj_end == std::string::npos) break;
    static const char id_key[] = "\"id\":\"";
    size_t key = cves_json.find(id_key, obj_start);
    if (key == std::string::npos || key > obj_end) { pos = obj_end + 1; continue; }
    size_t id_start = key + sizeof(id_key) - 1;
    size_t id_end = id_start;
    while (id_end < obj_end) {
      id_end = cves_json.find('"', id_end);
      if (id_end == std::string::npos || id_end > obj_end) break;
      size_t bs = 0; size_t k = id_end;
      while (k > id_start && cves_json[k - 1] == '\\') { bs++; k--; }
      if ((bs % 2) == 0) break;
      id_end++;
    }
    if (id_end != std::string::npos && id_end > id_start && id_end <= obj_end)
      ids.emplace_back(cves_json.substr(id_start, id_end - id_start));
    pos = obj_end + 1;
  }
  return ids;
}

/* ---- net_report.cc: json_extract_string / json_find_object_end (verbatim) ---- */
static std::string json_extract_string(const std::string &json, const char *key) {
  std::string search = std::string("\"") + key + "\":\"";
  size_t pos = json.find(search);
  if (pos == std::string::npos) return "";
  pos += search.size();
  size_t end = pos;
  while (end < json.size()) {
    end = json.find('"', end);
    if (end == std::string::npos) return "";
    size_t bs_count = 0; size_t i = end;
    while (i > pos && json[i - 1] == '\\') { bs_count++; i--; }
    if ((bs_count & 1u) == 0) break;
    end++;
  }
  if (end >= json.size() || end == std::string::npos) return "";
  return json.substr(pos, end - pos);
}
static size_t json_find_object_end(const std::string &json, size_t start) {
  if (start >= json.size() || json[start] != '{') return std::string::npos;
  int depth = 0; bool in_string = false; bool escape_next = false;
  for (size_t i = start; i < json.size(); i++) {
    char c = json[i];
    if (escape_next) { escape_next = false; continue; }
    if (in_string) { if (c == '\\') escape_next = true; else if (c == '"') in_string = false; continue; }
    if (c == '"') in_string = true;
    else if (c == '{') depth++;
    else if (c == '}') { depth--; if (depth == 0) return i; }
  }
  return std::string::npos;
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

/* alphabet biased toward JSON / HTTP / version metacharacters */
static char pick() {
  static const char a[] = "{}[]\":\\,0123456789.pHTPveri/ \r\n\tid<>title</>x-ServerLocation";
  return a[rng() % (sizeof(a) - 1)];
}

int main(int argc, char **argv) {
  signal(SIGSEGV, onfail); signal(SIGILL, onfail); signal(SIGABRT, onfail);
  rs = (argc > 1) ? strtoull(argv[1], NULL, 10) : 0xC0FFEEULL;
  long long N = (argc > 2) ? atoll(argv[2]) : 5000000LL;

  for (g_iter = 0; g_iter < N; g_iter++) {
    size_t len = rng() % 300;
    std::string s; s.reserve(len);
    int m = rng() % 4;
    for (size_t i = 0; i < len; i++) {
      if (m == 0) s += pick();                       /* metachar soup */
      else if (m == 1) s += (char)(rng() & 0xFF);    /* raw bytes */
      else if (m == 2) s += (char)(0x20 + rng() % 95); /* printable */
      else s += pick();
    }
    /* occasionally prefix a plausible structure */
    if ((rng() & 3) == 0) s = "[{\"id\":\"" + s;
    if ((rng() & 7) == 0) s = "HTTP/1.1 " + s;
    g_cur = s;

    g_fn = "parse_ver";          volatile auto v1 = parse_ver(s);
    g_fn = "extract_ver";        volatile auto v2 = extract_ver(s);
    g_fn = "parse_ver_enrich";   volatile auto v3 = parse_ver_enrich(s);
    g_fn = "extract_status";     volatile int  v4 = extract_status(s);
    g_fn = "extract_header_val"; volatile auto v5 = extract_header_val(s, "Server");
    (void)extract_header_val(s, "Location");
    g_fn = "extract_html_title"; volatile auto v6 = extract_html_title(s);
    g_fn = "net_db_parse_cve_ids"; volatile auto v7 = net_db_parse_cve_ids(s);
    g_fn = "json_extract_string";  volatile auto v8 = json_extract_string(s, "id");
    (void)json_extract_string(s, "desc");
    g_fn = "json_find_object_end"; volatile auto v9 = json_find_object_end(s, 0);
    (void)v1;(void)v2;(void)v3;(void)v4;(void)v5;(void)v6;(void)v7;(void)v8;(void)v9;

    /* ver_cmp antisymmetry: cmp(a,b) == -cmp(b,a) */
    if ((rng() & 1) == 0) {
      std::string t; size_t tl = rng() % 20;
      for (size_t i = 0; i < tl; i++) t += pick();
      g_fn = "ver_cmp"; int ab = ver_cmp(s, t), ba = ver_cmp(t, s);
      if (ab != -ba) { fprintf(stderr, "\n*** ver_cmp asymmetry a=<<%s>> b=<<%s>> ab=%d ba=%d\n",
                               s.c_str(), t.c_str(), ab, ba); _exit(98); }
    }
    if ((g_iter & 0xFFFFF) == 0) { fprintf(stderr, "\r iter=%lld", g_iter); fflush(stderr); }
  }

  /* ------------------------------------------------------------------
     Deterministic regression pins for the SUFFIX-AWARE comparator.

     The comparator used to keep only the leading digit run of each dotted
     token, so every member of a letter-suffixed release family collapsed to
     one integer vector: parse_ver("1.1.1w") == parse_ver("1.1.1k"). Since
     all 42 alpha-suffixed bounds in kmap-cve.db are INCLUSIVE, the matcher's
     "skip only if cmp > 0" test then reported the CVE against the very
     release that fixed it (OpenSSL 1.1.1w flagged for CVE-2021-3450, bound
     1.1.1k; ProFTPD 1.3.8b flagged for CVE-2023-51713, bound 1.3.8a).
     These cases pin both directions: patched hosts must compare GREATER
     than the bound, and still-vulnerable hosts must stay LESS-or-equal.
     ------------------------------------------------------------------ */
  {
    struct VC { const char *a, *b; int want; const char *why; };
    static const VC kCases[] = {
      /* patched release must sort ABOVE the CVE's inclusive upper bound */
      { "1.3.8b",    "1.3.8a",    1, "ProFTPD CVE-2023-51713 bound" },
      { "1.3.7d",    "1.3.7c",    1, "ProFTPD CVE-2021-46854 bound" },
      { "1.1.1w",    "1.1.1k",    1, "OpenSSL CVE-2021-3450 bound" },
      { "1.1.1w",    "1.1.1t",    1, "OpenSSL CVE-2022-4450 bound" },
      { "1.0.2zn",   "1.0.2zd",   1, "OpenSSL CVE-2022-0778 bound" },
      { "1.0.2zn",   "1.0.2zh",   1, "OpenSSL CVE-2023-0464 bound" },
      { "16.12.10b", "16.12.10a", 1, "IOS-XE CVE-2023-20198 bound" },
      /* genuinely affected releases must NOT be excluded (no new FNs) */
      { "1.1.1i",    "1.1.1k",   -1, "affected, below bound" },
      { "1.0.2zb",   "1.0.2zd",  -1, "affected, below bound" },
      { "1.3.8",     "1.3.8a",   -1, "bare release precedes its patch letter" },
      /* OpenSSL a..z,za..zz ordering */
      { "1.0.2z",    "1.0.2za",  -1, "z precedes za" },
      { "1.0.2za",   "1.0.2zn",  -1, "za precedes zn" },
      /* OpenSSH portable patch level */
      { "7.4",       "7.4p1",    -1, "bare release precedes pN" },
      { "7.4p1",     "7.4p2",    -1, "p1 precedes p2" },
      { "9.8p1",     "9.7",       1, "numeric wins over suffix" },
      /* pre-release markers sort BEFORE the bare release (semver) */
      { "1.3.8rc1",  "1.3.8",    -1, "rc precedes release" },
      { "2.4.41beta","2.4.41",   -1, "beta precedes release" },
      /* unchanged legacy behaviour */
      { "1.3",       "1.3.0",     0, "missing component == 0" },
      { "1.1.1w",    "1.1.1w",    0, "identity" },
      { "1.3.8",     "1.3.9",    -1, "plain numeric ordering" },
    };
    int bad = 0;
    for (const VC &c : kCases) {
      int got = ver_cmp(c.a, c.b);
      if (got != c.want) {
        fprintf(stderr, "\n*** ver_cmp(\"%s\",\"%s\") = %d, want %d  (%s)\n",
                c.a, c.b, got, c.want, c.why);
        bad++;
      }
      /* the net_enrich copy must agree with the cve_map copy -- the two
         matchers are required to tag the exact same CVEs */
      int got_e = ver_cmp_parsed(parse_ver_enrich(c.a), parse_ver_enrich(c.b));
      if (got_e != c.want) {
        fprintf(stderr, "\n*** ver_cmp_parsed(\"%s\",\"%s\") = %d, want %d  (%s)\n",
                c.a, c.b, got_e, c.want, c.why);
        bad++;
      }
    }
    /* extract_ver must not amputate the suffix before the comparator sees it */
    struct EV { const char *in, *want; };
    static const EV kEv[] = {
      { "ProFTPD 1.3.8b Server", "1.3.8b" },
      { "OpenSSH 8.2p1 Ubuntu 4", "8.2p1" },
      { "nginx/1.18.0",          "1.18.0" },
      { "1.0.2k-fips",           "1.0.2k" },
      { "Apache/2.4.41 (Ubuntu)", "2.4.41" },
    };
    for (const EV &e : kEv) {
      std::string got = extract_ver(e.in);
      if (got != e.want) {
        fprintf(stderr, "\n*** extract_ver(\"%s\") = \"%s\", want \"%s\"\n",
                e.in, got.c_str(), e.want);
        bad++;
      }
    }
    if (bad) { fprintf(stderr, "\n*** %d version-comparator regression(s)\n", bad); _exit(97); }
    fprintf(stderr, "version-comparator regressions: %d checks OK\n",
            (int)(sizeof(kCases)/sizeof(kCases[0])) * 2 +
            (int)(sizeof(kEv)/sizeof(kEv[0])));
  }

  fprintf(stderr, "\nTEXT fuzz OK: %lld iterations, no faults (seed=%s)\n",
          N, argc > 1 ? argv[1] : "default");
  return 0;
}
