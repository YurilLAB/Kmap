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

/* ---- cve_map.cc: parse_ver / ver_cmp / extract_ver (verbatim) ---- */
static std::vector<int> parse_ver(const std::string &ver) {
  std::vector<int> parts;
  auto tokens = str_split(ver, '.');
  for (auto &t : tokens) {
    std::string digits;
    for (char c : t) { if (isdigit((unsigned char)c)) digits += c; else break; }
    if (!digits.empty()) { try { parts.push_back(std::stoi(digits)); } catch (...) {} }
  }
  return parts;
}
static int ver_cmp(const std::string &a, const std::string &b) {
  auto va = parse_ver(a); auto vb = parse_ver(b);
  size_t n = std::max(va.size(), vb.size());
  for (size_t i = 0; i < n; i++) {
    int ai = (i < va.size()) ? va[i] : 0;
    int bi = (i < vb.size()) ? vb[i] : 0;
    if (ai < bi) return -1; if (ai > bi) return 1;
  }
  return 0;
}
static std::string extract_ver(const std::string &s) {
  size_t i = 0;
  while (i < s.size()) {
    if (isdigit((unsigned char)s[i])) {
      size_t start = i;
      while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '.' || s[i] == 'p')) i++;
      std::string candidate = s.substr(start, i - start);
      if (candidate.find('.') != std::string::npos) return candidate;
    } else i++;
  }
  return "";
}

/* ---- net_enrich.cc: parse_ver_enrich / ver_cmp_parsed / extract_status /
       extract_header_val / extract_html_title (verbatim) ---- */
static std::vector<int> parse_ver_enrich(const std::string &s) {
  std::vector<int> parts; std::istringstream ss(s); std::string tok;
  while (std::getline(ss, tok, '.')) {
    std::string digits;
    for (char c : tok) { if (isdigit((unsigned char)c)) digits += c; else break; }
    if (!digits.empty()) { try { parts.push_back(std::stoi(digits)); } catch (...) {} }
  }
  return parts;
}
static int ver_cmp_parsed(const std::vector<int> &va, const std::vector<int> &vb) {
  size_t n = std::max(va.size(), vb.size());
  for (size_t i = 0; i < n; i++) {
    int ai = (i < va.size()) ? va[i] : 0;
    int bi = (i < vb.size()) ? vb[i] : 0;
    if (ai < bi) return -1; if (ai > bi) return 1;
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
  fprintf(stderr, "\nTEXT fuzz OK: %lld iterations, no faults (seed=%s)\n",
          N, argc > 1 ? argv[1] : "default");
  return 0;
}
