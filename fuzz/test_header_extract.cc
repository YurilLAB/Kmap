/*
 * test_header_extract.cc -- pins net_enrich.cc::extract_header_val after the
 * "lowercase the response once" refactor.
 *
 * The hot HTTP enrichment path used to call extract_header_val once per header,
 * and each call did str_lower() over the whole (up to 64 KB) response. The
 * refactor lowercases ONCE in probe_http and passes that lower copy in. This
 * test proves the refactor is BEHAVIOR-PRESERVING: for every input, the new
 * signature (resp, str_lower(resp), name) returns exactly what the old
 * self-lowercasing implementation returned -- and pins the parser's contract
 * (line anchoring, case-insensitive name match, leading-space trim, CR-or-LF
 * termination, original-case value) against regressions.
 *
 * Build (Win):  g++ -O2 -std=gnu++17 test_header_extract.cc -o test_header_extract.exe
 * Build (CI):   g++ $CXXFLAGS fuzz/test_header_extract.cc -o test_header_extract
 */
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <string>

static int g_fail = 0;
static void chk(bool c, const char *m) { if (!c) { printf("  FAIL: %s\n", m); g_fail++; } }

/* Verbatim copy of net_enrich.cc::str_lower. */
static std::string str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}

/* OLD behavior reference: lowercases resp internally on every call. */
static std::string extract_old(const std::string &resp, const char *name) {
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

/* NEW implementation: verbatim copy of the refactored net_enrich.cc version,
   which takes the precomputed lower_resp. */
static std::string extract_new(const std::string &resp,
                               const std::string &lower_resp,
                               const char *name) {
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

/* Equivalence wrapper matching how probe_http now calls it. */
static std::string extract_via_new(const std::string &resp, const char *name) {
  return extract_new(resp, str_lower(resp), name);
}

/* xorshift32 so the random pass is deterministic across runs/platforms. */
static uint32_t rng(uint32_t &s) { s^=s<<13; s^=s>>17; s^=s<<5; return s; }

int main(int argc, char **argv) {
  printf("header-extract refactor test\n============================\n");
  uint32_t seed = (argc > 1) ? static_cast<uint32_t>(atoi(argv[1])) : 1u;
  if (seed == 0) seed = 1;

  /* ---- Contract checks (the value of the parser, pinned) ---- */
  std::string resp =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.18.0\r\n"
    "X-Powered-By: PHP/8.1.2\r\n"
    "X-Server: should-not-match\r\n"     /* anchoring: must not match "Server" */
    "Content-Type:   text/html\r\n"      /* leading spaces trimmed */
    "Location: https://example.com/x\r\n"
    "\r\n<html><title>Hi</title>";
  std::string lr = str_lower(resp);

  chk(extract_new(resp, lr, "Server") == "nginx/1.18.0", "Server value");
  chk(extract_new(resp, lr, "server") == "nginx/1.18.0", "case-insensitive name");
  chk(extract_new(resp, lr, "X-Powered-By") == "PHP/8.1.2", "X-Powered-By value");
  chk(extract_new(resp, lr, "Content-Type") == "text/html", "leading spaces trimmed");
  chk(extract_new(resp, lr, "Location") == "https://example.com/x", "Location value");
  chk(extract_new(resp, lr, "Nonexistent") == "", "absent header -> empty");
  /* "Server" must anchor at line start: it must NOT pick up "X-Server:". The
     real Server header here IS present, so to test pure anchoring use a resp
     where only X-Server exists. */
  {
    std::string only_x = "HTTP/1.1 200 OK\r\nX-Server: nope\r\n\r\n";
    chk(extract_via_new(only_x, "Server") == "", "anchoring: X-Server != Server");
  }
  /* Value terminated by LF when no CR present. */
  {
    std::string lf = "HTTP/1.0 200 OK\nServer: lighttpd\n\n";
    chk(extract_via_new(lf, "Server") == "lighttpd", "LF-terminated value");
  }
  /* Value original case preserved even though match is case-insensitive. */
  {
    std::string mixed = "HTTP/1.1 200 OK\r\nsErVeR: MixedCaseValue\r\n\r\n";
    chk(extract_via_new(mixed, "Server") == "MixedCaseValue", "value keeps original case");
  }
  /* Header value at very end with no trailing CRLF. */
  {
    std::string tail = "HTTP/1.1 200 OK\r\nServer: tail-no-crlf";
    chk(extract_via_new(tail, "Server") == "tail-no-crlf", "value runs to EOF");
  }

  /* ---- Equivalence: new == old for crafted inputs ---- */
  const char *names[] = {"Server","X-Powered-By","X-Generator","Location",
                         "Content-Type","Set-Cookie","X-Frame-Options",
                         "x-server","NOPE",""};
  std::string crafted[] = {
    resp, "", "no headers at all", "\n", "\r\n\r\n",
    "HTTP/1.1 200 OK\r\nServer:\r\n\r\n",            /* empty value */
    "HTTP/1.1 200 OK\r\nServer:    \r\n\r\n",        /* spaces only */
    "Server: leading-line\r\n",                      /* no \n before -> no match */
    "\nServer: matches-with-leading-newline\r\n",
  };
  for (const std::string &c : crafted)
    for (const char *nm : names) {
      if (extract_old(c, nm) != extract_via_new(c, nm)) {
        printf("  FAIL: mismatch name='%s'\n", nm);
        g_fail++;
      }
    }

  /* ---- Equivalence: new == old over random fuzzed responses ---- */
  const char *alpha = "ABCDEfghij:-\r\n   Sserver0123./";
  size_t alen = 0; while (alpha[alen]) alen++;
  int iters = 200000;
  for (int it = 0; it < iters; it++) {
    size_t len = rng(seed) % 400;
    std::string s; s.reserve(len);
    for (size_t i = 0; i < len; i++) s += alpha[rng(seed) % alen];
    for (const char *nm : names) {
      if (extract_old(s, nm) != extract_via_new(s, nm)) {
        printf("  FAIL: random mismatch at iter=%d name='%s'\n", it, nm);
        g_fail++;
        if (g_fail > 5) { printf("aborting after too many failures\n"); return 1; }
      }
    }
  }
  printf("  checked %d random responses x %zu names\n", iters,
         sizeof(names)/sizeof(names[0]));

  printf("\n%s\n", g_fail == 0 ? "header-extract test: ALL PASS"
                               : "header-extract test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
