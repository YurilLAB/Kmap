/*
 * jarm.cc -- JARM active TLS fingerprint (see jarm.h).
 *
 * Faithful C++ port of Salesforce's reference jarm.py (Apache-2.0): the ten
 * ClientHello builders are byte-for-byte identical to the reference (proven in
 * fuzz/test_jarm.cc against packets dumped from jarm.py) and the hash matches
 * jarm.py run against the same server.  Pure builders/parser/hash do no I/O so
 * they unit-test standalone; only jarm_fingerprint() touches sockets.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "jarm.h"

#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

#ifdef HAVE_CONFIG_H
#include "nbase.h"
#endif

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#endif

#include <openssl/sha.h>

/* --------------------------------------------------------------------------
 * Probe table -- the ten JARM specs (mirrors jarm.py main()'s queue).
 * ------------------------------------------------------------------------ */
namespace {

struct JarmSpec {
  const char *version;      /* TLS_1.1 / TLS_1.2 / TLS_1.3 */
  const char *cipher_list;  /* ALL / NO1.3 */
  const char *cipher_order; /* FORWARD / REVERSE / TOP_HALF / BOTTOM_HALF / MIDDLE_OUT */
  bool        grease;
  const char *alpn;         /* APLN / RARE_APLN */
  const char *support;      /* 1.2_SUPPORT / 1.3_SUPPORT / NO_SUPPORT */
  const char *ext_order;    /* FORWARD / REVERSE */
};

static const JarmSpec SPECS[10] = {
  {"TLS_1.2","ALL",  "FORWARD",    false,"APLN",     "1.2_SUPPORT","REVERSE"},
  {"TLS_1.2","ALL",  "REVERSE",    false,"APLN",     "1.2_SUPPORT","FORWARD"},
  {"TLS_1.2","ALL",  "TOP_HALF",   false,"APLN",     "NO_SUPPORT", "FORWARD"},
  {"TLS_1.2","ALL",  "BOTTOM_HALF",false,"RARE_APLN","NO_SUPPORT", "FORWARD"},
  {"TLS_1.2","ALL",  "MIDDLE_OUT", true, "RARE_APLN","NO_SUPPORT", "REVERSE"},
  {"TLS_1.1","ALL",  "FORWARD",    false,"APLN",     "NO_SUPPORT", "FORWARD"},
  {"TLS_1.3","ALL",  "FORWARD",    false,"APLN",     "1.3_SUPPORT","REVERSE"},
  {"TLS_1.3","ALL",  "REVERSE",    false,"APLN",     "1.3_SUPPORT","FORWARD"},
  {"TLS_1.3","NO1.3","FORWARD",    false,"APLN",     "1.3_SUPPORT","FORWARD"},
  {"TLS_1.3","ALL",  "MIDDLE_OUT", true, "APLN",     "1.3_SUPPORT","REVERSE"},
};

/* GREASE byte pinned in deterministic mode (any GREASE value yields the same
   JARM since the server ignores it). 0x0a0a is the first of jarm.py's list. */
const uint16_t GREASE_FIXED = 0x0a0a;

/* The "ALL" cipher suite list, in jarm.py order. */
static const uint16_t CIPHERS_ALL[] = {
  0x0016,0x0033,0x0067,0xc09e,0xc0a2,0x009e,0x0039,0x006b,0xc09f,0xc0a3,
  0x009f,0x0045,0x00be,0x0088,0x00c4,0x009a,0xc008,0xc009,0xc023,0xc0ac,
  0xc0ae,0xc02b,0xc00a,0xc024,0xc0ad,0xc0af,0xc02c,0xc072,0xc073,0xcca9,
  0x1302,0x1301,0xcc14,0xc007,0xc012,0xc013,0xc027,0xc02f,0xc014,0xc028,
  0xc030,0xc060,0xc061,0xc076,0xc077,0xcca8,0x1305,0x1304,0x1303,0xcc13,
  0xc011,0x000a,0x002f,0x003c,0xc09c,0xc0a0,0x009c,0x0035,0x003d,0xc09d,
  0xc0a1,0x009d,0x0041,0x00ba,0x0084,0x00c0,0x0007,0x0004,0x0005,
};

/* The "NO1.3" list: ALL with the five TLS 1.3 suites (1301-1305) removed. */
static const uint16_t CIPHERS_NO13[] = {
  0x0016,0x0033,0x0067,0xc09e,0xc0a2,0x009e,0x0039,0x006b,0xc09f,0xc0a3,
  0x009f,0x0045,0x00be,0x0088,0x00c4,0x009a,0xc008,0xc009,0xc023,0xc0ac,
  0xc0ae,0xc02b,0xc00a,0xc024,0xc0ad,0xc0af,0xc02c,0xc072,0xc073,0xcca9,
  0xcc14,0xc007,0xc012,0xc013,0xc027,0xc02f,0xc014,0xc028,0xc030,0xc060,
  0xc061,0xc076,0xc077,0xcca8,0xcc13,0xc011,0x000a,0x002f,0x003c,0xc09c,
  0xc0a0,0x009c,0x0035,0x003d,0xc09d,0xc0a1,0x009d,0x0041,0x00ba,0x0084,
  0x00c0,0x0007,0x0004,0x0005,
};

/* cipher_bytes() index reference list (sorted), jarm.py line 437. */
static const uint16_t CIPHER_INDEX[] = {
  0x0004,0x0005,0x0007,0x000a,0x0016,0x002f,0x0033,0x0035,0x0039,0x003c,
  0x003d,0x0041,0x0045,0x0067,0x006b,0x0084,0x0088,0x009a,0x009c,0x009d,
  0x009e,0x009f,0x00ba,0x00be,0x00c0,0x00c4,0xc007,0xc008,0xc009,0xc00a,
  0xc011,0xc012,0xc013,0xc014,0xc023,0xc024,0xc027,0xc028,0xc02b,0xc02c,
  0xc02f,0xc030,0xc060,0xc061,0xc072,0xc073,0xc076,0xc077,0xc09c,0xc09d,
  0xc09e,0xc09f,0xc0a0,0xc0a1,0xc0a2,0xc0a3,0xc0ac,0xc0ad,0xc0ae,0xc0af,
  0xcc13,0xcc14,0xcca8,0xcca9,0x1301,0x1302,0x1303,0x1304,0x1305,
};

/* --- byte helpers ------------------------------------------------------- */

static inline std::string be16(unsigned v) {
  std::string s; s.push_back(char((v >> 8) & 0xff)); s.push_back(char(v & 0xff));
  return s;
}
static inline std::string two(uint16_t v) { return be16(v); }

static std::string to_hex(const std::string &b) {
  static const char *h = "0123456789abcdef";
  std::string o; o.reserve(b.size() * 2);
  for (unsigned char c : b) { o.push_back(h[c >> 4]); o.push_back(h[c & 0xf]); }
  return o;
}

/* cipher_mung -- the FORWARD/REVERSE/TOP_HALF/BOTTOM_HALF/MIDDLE_OUT reordering
   (jarm.py cipher_mung), generic over any element list (ciphers, ALPN, versions). */
static std::vector<std::string> mung(const std::vector<std::string> &c,
                                     const std::string &req) {
  std::vector<std::string> out;
  size_t n = c.size();
  if (req == "REVERSE") {
    for (size_t i = n; i-- > 0; ) out.push_back(c[i]);
  } else if (req == "BOTTOM_HALF") {
    size_t start = (n % 2 == 1) ? n / 2 + 1 : n / 2;
    for (size_t i = start; i < n; i++) out.push_back(c[i]);
  } else if (req == "TOP_HALF") {
    if (n % 2 == 1) out.push_back(c[n / 2]);
    std::vector<std::string> bh = mung(mung(c, "REVERSE"), "BOTTOM_HALF");
    for (auto &x : bh) out.push_back(x);
  } else if (req == "MIDDLE_OUT") {
    size_t middle = n / 2;
    if (n % 2 == 1) {
      out.push_back(c[middle]);
      for (size_t i = 1; i <= middle; i++) {
        out.push_back(c[middle + i]);
        out.push_back(c[middle - i]);
      }
    } else {
      for (size_t i = 1; i <= middle; i++) {
        out.push_back(c[middle - 1 + i]);
        out.push_back(c[middle - i]);
      }
    }
  } else {
    out = c;
  }
  return out;
}

static std::string get_ciphers(const JarmSpec &s) {
  std::vector<std::string> list;
  if (std::strcmp(s.cipher_list, "ALL") == 0) {
    for (uint16_t v : CIPHERS_ALL) list.push_back(two(v));
  } else {
    for (uint16_t v : CIPHERS_NO13) list.push_back(two(v));
  }
  if (std::strcmp(s.cipher_order, "FORWARD") != 0) list = mung(list, s.cipher_order);
  if (s.grease) list.insert(list.begin(), two(GREASE_FIXED));
  std::string out;
  for (auto &c : list) out += c;
  return out;
}

static std::string ext_server_name(const std::string &host) {
  std::string e = std::string("\x00\x00", 2);
  e += be16((unsigned)host.size() + 5);
  e += be16((unsigned)host.size() + 3);
  e += '\x00';
  e += be16((unsigned)host.size());
  e += host;
  return e;
}

static std::string ext_alpn(const JarmSpec &s) {
  std::string e = std::string("\x00\x10", 2);
  std::vector<std::string> alpns;
  auto P = [&](const char *p, size_t n){ alpns.push_back(std::string(p, n)); };
  if (std::strcmp(s.alpn, "RARE_APLN") == 0) {
    P("\x08http/0.9",9); P("\x08http/1.0",9); P("\x06spdy/1",7);
    P("\x06spdy/2",7); P("\x06spdy/3",7); P("\x03h2c",4); P("\x02hq",3);
  } else {
    P("\x08http/0.9",9); P("\x08http/1.0",9); P("\x08http/1.1",9);
    P("\x06spdy/1",7); P("\x06spdy/2",7); P("\x06spdy/3",7);
    P("\x02h2",3); P("\x03h2c",4); P("\x02hq",3);
  }
  if (std::strcmp(s.ext_order, "FORWARD") != 0) alpns = mung(alpns, s.ext_order);
  std::string all; for (auto &a : alpns) all += a;
  e += be16((unsigned)all.size() + 2);
  e += be16((unsigned)all.size());
  e += all;
  return e;
}

static std::string ext_key_share(bool grease, bool deterministic) {
  std::string e = std::string("\x00\x33", 2);
  std::string share;
  if (grease) { share += two(GREASE_FIXED); share += std::string("\x00\x01\x00", 3); }
  share += std::string("\x00\x1d", 2);   /* group x25519 */
  share += std::string("\x00\x20", 2);   /* key exchange length 32 */
  if (deterministic) share += std::string(32, '\x00');
  else { unsigned char r[32]; for (int i = 0; i < 32; i++) r[i] = (unsigned char)(rand() & 0xff);
         share.append(reinterpret_cast<char *>(r), 32); }
  e += be16((unsigned)share.size() + 2);
  e += be16((unsigned)share.size());
  e += share;
  return e;
}

static std::string ext_supported_versions(const JarmSpec &s, bool grease) {
  std::vector<std::string> tls;
  tls.push_back(two(0x0301)); tls.push_back(two(0x0302)); tls.push_back(two(0x0303));
  if (std::strcmp(s.support, "1.2_SUPPORT") != 0) tls.push_back(two(0x0304));
  if (std::strcmp(s.ext_order, "FORWARD") != 0) tls = mung(tls, s.ext_order);
  std::string e = std::string("\x00\x2b", 2);
  std::string versions;
  if (grease) versions += two(GREASE_FIXED);
  for (auto &v : tls) versions += v;
  e += be16((unsigned)versions.size() + 1);
  e.push_back(char(versions.size() & 0xff));
  e += versions;
  return e;
}

static std::string build_extensions(const JarmSpec &s, const std::string &host,
                                    bool deterministic) {
  std::string all;
  if (s.grease) { all += two(GREASE_FIXED); all += std::string("\x00\x00", 2); }
  all += ext_server_name(host);
  all += std::string("\x00\x17\x00\x00", 4);                 /* extended_master_secret */
  all += std::string("\x00\x01\x00\x01\x01", 5);             /* max_fragment_length */
  all += std::string("\xff\x01\x00\x01\x00", 5);             /* renegotiation_info */
  all += std::string("\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19", 14); /* supported_groups */
  all += std::string("\x00\x0b\x00\x02\x01\x00", 6);         /* ec_point_formats */
  all += std::string("\x00\x23\x00\x00", 4);                 /* session_ticket */
  all += ext_alpn(s);
  all += std::string("\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01"
                     "\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01", 24); /* signature_algorithms */
  all += ext_key_share(s.grease, deterministic);
  all += std::string("\x00\x2d\x00\x02\x01\x01", 6);         /* psk_key_exchange_modes */
  if (std::strcmp(s.version, "TLS_1.3") == 0 ||
      std::strcmp(s.support, "1.2_SUPPORT") == 0)
    all += ext_supported_versions(s, s.grease);
  std::string out = be16((unsigned)all.size());
  out += all;
  return out;
}

} /* namespace */

std::string jarm_build_client_hello(int i, const std::string &host,
                                    bool deterministic) {
  if (i < 0 || i >= 10) return "";
  const JarmSpec &s = SPECS[i];

  std::string rec_ver, cli_ver;
  if (std::strcmp(s.version, "TLS_1.3") == 0) { rec_ver = two(0x0301); cli_ver = two(0x0303); }
  else if (std::strcmp(s.version, "TLS_1.1") == 0) { rec_ver = two(0x0302); cli_ver = two(0x0302); }
  else { rec_ver = two(0x0303); cli_ver = two(0x0303); }  /* TLS_1.2 */

  std::string ch = cli_ver;
  if (deterministic) ch += std::string(32, '\x00');
  else { for (int k = 0; k < 32; k++) ch.push_back(char(rand() & 0xff)); }
  std::string sid = deterministic ? std::string(32, '\x00') : std::string();
  if (!deterministic) for (int k = 0; k < 32; k++) sid.push_back(char(rand() & 0xff));
  ch.push_back(char(sid.size() & 0xff));
  ch += sid;
  std::string ciphers = get_ciphers(s);
  ch += be16((unsigned)ciphers.size());
  ch += ciphers;
  ch += '\x01';   /* compression methods length */
  ch += '\x00';   /* compression: null */
  ch += build_extensions(s, host, deterministic);

  std::string hs = "\x01";                 /* handshake type: client_hello */
  hs += '\x00';                            /* 24-bit length, high byte */
  hs += be16((unsigned)ch.size());
  hs += ch;

  std::string payload = "\x16";            /* record: handshake */
  payload += rec_ver;
  payload += be16((unsigned)hs.size());
  payload += hs;
  return payload;
}

/* --------------------------------------------------------------------------
 * ServerHello parsing (jarm.py read_packet / extract_extension_info).
 * All accesses bounds-checked: a short/garbage record yields the same "|||"
 * (whole-packet) or "|" (extension) sentinel jarm.py produces on its
 * IndexError, and never reads out of bounds.
 * ------------------------------------------------------------------------ */
namespace {

/* Python-style slice [a,b): clamps to [0,n], may return fewer bytes. */
static std::string slice(const uint8_t *d, size_t n, size_t a, size_t b) {
  if (a > n) a = n;
  if (b > n) b = n;
  if (b < a) b = a;
  return std::string(reinterpret_cast<const char *>(d + a), b - a);
}

static std::string extract_ext_info(const uint8_t *d, size_t n,
                                    size_t counter, size_t sh_len) {
  /* data[counter+47] index access -> IndexError -> "|" if OOB */
  if (counter + 47 >= n) return "|";
  if (d[counter + 47] == 11) return "|";
  if (slice(d, n, counter + 50, counter + 53) == std::string("\x0e\xac\x0b", 3) ||
      slice(d, n, 82, 85) == std::string("\x0f\xf0\x0b", 3))
    return "|";
  if (counter + 42 >= sh_len) return "|";

  size_t count = 49 + counter;
  std::string lh = slice(d, n, counter + 47, counter + 49);
  if (lh.size() < 2) return "|";                 /* int("",16) path -> treat as error */
  unsigned length = ((unsigned char)lh[0] << 8) | (unsigned char)lh[1];
  size_t maximum = length + (count - 1);

  std::vector<std::string> types, values;
  while (count < maximum) {
    std::string t = slice(d, n, count, count + 2);
    types.push_back(t);
    std::string el = slice(d, n, count + 2, count + 4);
    unsigned ext_length = el.size() < 2 ? 0
                          : (((unsigned char)el[0] << 8) | (unsigned char)el[1]);
    if (ext_length == 0) { count += 4; values.push_back(""); }
    else { values.push_back(slice(d, n, count + 4, count + 4 + ext_length));
           count += ext_length + 4; }
  }

  /* ALPN value (type 00 10): bytes after the 3-byte length prefix, as ASCII. */
  std::string alpn;
  for (size_t i = 0; i < types.size(); i++) {
    if (types[i] == std::string("\x00\x10", 2)) {
      alpn = values[i].size() > 3 ? values[i].substr(3) : std::string();
      break;
    }
  }
  std::string result = alpn;
  result += "|";
  for (size_t i = 0; i < types.size(); i++) {
    result += to_hex(types[i]);
    if (i + 1 != types.size()) result += "-";
  }
  return result;
}

} /* namespace */

std::string jarm_parse_server_hello(const uint8_t *d, size_t n) {
  if (n == 0 || d == nullptr) return "|||";
  if (d[0] == 21) return "|||";                       /* alert */
  if (!(d[0] == 22 && n > 5 && d[5] == 2)) return "|||"; /* not a ServerHello */
  if (n < 44) return "|||";                           /* data[43] index access */
  size_t sh_len = ((unsigned)d[3] << 8) | d[4];
  size_t counter = d[43];
  std::string cipher = slice(d, n, counter + 44, counter + 46);
  std::string version = slice(d, n, 9, 11);
  std::string jarm = to_hex(cipher);
  jarm += "|";
  jarm += to_hex(version);
  jarm += "|";
  jarm += extract_ext_info(d, n, counter, sh_len);
  return jarm;
}

/* --------------------------------------------------------------------------
 * Fuzzy hash (jarm.py jarm_hash / cipher_bytes / version_byte).
 * ------------------------------------------------------------------------ */
namespace {

static std::vector<std::string> split_keep(const std::string &s, char sep) {
  std::vector<std::string> out;
  size_t start = 0;
  for (size_t i = 0; i <= s.size(); i++) {
    if (i == s.size() || s[i] == sep) { out.push_back(s.substr(start, i - start)); start = i + 1; }
  }
  return out;
}

static std::string cipher_bytes(const std::string &cipher_hex) {
  if (cipher_hex.empty()) return "00";
  int count = 1;
  for (uint16_t v : CIPHER_INDEX) {
    if (cipher_hex == to_hex(two(v))) break;
    count++;
  }
  char buf[8];
  std::snprintf(buf, sizeof(buf), "%x", count);
  std::string h = buf;
  if (h.size() < 2) h = "0" + h;
  return h;
}

static std::string version_byte(const std::string &version_hex) {
  if (version_hex.empty()) return "0";
  if (version_hex.size() < 4) return "0";
  static const char *options = "abcdef";
  int c = version_hex[3] - '0';
  if (c < 0 || c > 5) return "0";
  return std::string(1, options[c]);
}

} /* namespace */

std::string jarm_hash(const std::string &jarm_raw) {
  if (jarm_raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||")
    return std::string(62, '0');
  std::string fuzzy, alpns_ext;
  std::vector<std::string> handshakes = split_keep(jarm_raw, ',');
  for (auto &hsk : handshakes) {
    std::vector<std::string> comp = split_keep(hsk, '|');
    while (comp.size() < 4) comp.push_back("");
    fuzzy += cipher_bytes(comp[0]);
    fuzzy += version_byte(comp[1]);
    alpns_ext += comp[2];
    alpns_ext += comp[3];
  }
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char *>(alpns_ext.data()),
         alpns_ext.size(), digest);
  std::string sh(reinterpret_cast<char *>(digest), SHA256_DIGEST_LENGTH);
  fuzzy += to_hex(sh).substr(0, 32);
  return fuzzy;
}

/* --------------------------------------------------------------------------
 * Network leg: probe ip:port ten times, parse, hash.
 * ------------------------------------------------------------------------ */
#ifndef WIN32
namespace {

/* Blocking connect + send + single recv (up to 1484 bytes, like jarm.py),
   bounded by `timeout_ms`. Returns the bytes read, or "" on any failure. */
static std::string jarm_probe_once(const char *ip, int port, int timeout_ms,
                                   const std::string &hello, bool &connected) {
  connected = false;
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return "";
  struct sockaddr_in sa; std::memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { ::close(fd); return ""; }

  int fl = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  int rc = ::connect(fd, (struct sockaddr *)&sa, sizeof(sa));
  if (rc < 0 && errno != EINPROGRESS) { ::close(fd); return ""; }
  if (rc < 0) {
    fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
    struct timeval tv; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(fd + 1, nullptr, &wf, nullptr, &tv) <= 0) { ::close(fd); return ""; }
    int err = 0; socklen_t el = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err != 0) { ::close(fd); return ""; }
  }
  connected = true;

  size_t sent = 0;
  while (sent < hello.size()) {
    ssize_t w = ::send(fd, hello.data() + sent, hello.size() - sent, 0);
    if (w > 0) { sent += (size_t)w; continue; }
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
      struct timeval tv; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
      if (select(fd + 1, nullptr, &wf, nullptr, &tv) <= 0) { ::close(fd); return ""; }
      continue;
    }
    ::close(fd); return "";
  }

  std::string resp;
  char buf[1484];
  for (;;) {
    fd_set rf; FD_ZERO(&rf); FD_SET(fd, &rf);
    struct timeval tv; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(fd + 1, &rf, nullptr, nullptr, &tv) <= 0) break;
    ssize_t r = ::recv(fd, buf, sizeof(buf) - resp.size() > 0
                                 ? sizeof(buf) : 0, 0);
    if (r > 0) { resp.append(buf, (size_t)r); if (resp.size() >= 1484) break; }
    else break;
  }
  ::close(fd);
  return resp;
}

} /* namespace */

std::string jarm_fingerprint(const char *ip, int port, int timeout_ms) {
  if (!ip) return "";
  std::string raw;
  int connected_any = 0;
  for (int i = 0; i < 10; i++) {
    std::string hello = jarm_build_client_hello(i, ip, /*deterministic=*/false);
    bool connected = false;
    std::string resp = jarm_probe_once(ip, port, timeout_ms, hello, connected);
    if (connected) connected_any++;
    if (resp.empty())
      raw += "|||";
    else
      raw += jarm_parse_server_hello(
          reinterpret_cast<const uint8_t *>(resp.data()), resp.size());
    if (i != 9) raw += ",";
  }
  if (connected_any == 0) return "";   /* nothing listening: no JARM, not "0"*62 */
  return jarm_hash(raw);
}
#else  /* WIN32: network leg omitted (pure builders/parser/hash still available) */
std::string jarm_fingerprint(const char *, int, int) { return ""; }
#endif
