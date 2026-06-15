/*
 * net_hash_helpers.cc -- implementations for net_hash_helpers.h.
 *
 * Pure byte/string math: no sockets, no OpenSSL, no nbase.  Kept dependency-
 * light so the test harnesses link it directly.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_hash_helpers.h"

#include <cctype>
#include <cstring>
#include <sstream>

/* ---------------------------------------------------------------------------
 * MurmurHash3 x86_32 (Austin Appleby, public domain reference algorithm).
 *
 * Bytes are read one at a time into each 4-byte little-endian block rather
 * than reinterpret_cast'ing a uint32_t* so the result is identical on
 * big-endian targets and never trips an unaligned-access trap.
 * ------------------------------------------------------------------------- */
static inline uint32_t mmh3_rotl32(uint32_t x, int8_t r) {
  return (x << r) | (x >> (32 - r));
}

int32_t mmh3_x86_32(const std::string &data, uint32_t seed) {
  const uint8_t *d = reinterpret_cast<const uint8_t *>(data.data());
  const size_t len = data.size();
  const size_t nblocks = len / 4;

  uint32_t h1 = seed;
  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;

  for (size_t i = 0; i < nblocks; i++) {
    const uint8_t *p = d + i * 4;
    uint32_t k1 = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                  ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    k1 *= c1;
    k1 = mmh3_rotl32(k1, 15);
    k1 *= c2;
    h1 ^= k1;
    h1 = mmh3_rotl32(h1, 13);
    h1 = h1 * 5 + 0xe6546b64;
  }

  const uint8_t *tail = d + nblocks * 4;
  uint32_t k1 = 0;
  switch (len & 3) {
    case 3: k1 ^= (uint32_t)tail[2] << 16; /* fallthrough */
    case 2: k1 ^= (uint32_t)tail[1] << 8;  /* fallthrough */
    case 1: k1 ^= (uint32_t)tail[0];
            k1 *= c1; k1 = mmh3_rotl32(k1, 15); k1 *= c2; h1 ^= k1;
  }

  h1 ^= (uint32_t)len;
  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return (int32_t)h1;
}

/* ---------------------------------------------------------------------------
 * base64.encodebytes() — standard alphabet, '\n' every 76 chars + trailing.
 * ------------------------------------------------------------------------- */
std::string base64_encodebytes(const std::string &raw) {
  if (raw.empty()) return "";

  static const char tbl[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string b64;
  b64.reserve(((raw.size() + 2) / 3) * 4);
  const uint8_t *p = reinterpret_cast<const uint8_t *>(raw.data());
  size_t n = raw.size();
  size_t i = 0;
  while (i + 3 <= n) {
    uint32_t v = (p[i] << 16) | (p[i + 1] << 8) | p[i + 2];
    b64 += tbl[(v >> 18) & 0x3f];
    b64 += tbl[(v >> 12) & 0x3f];
    b64 += tbl[(v >> 6) & 0x3f];
    b64 += tbl[v & 0x3f];
    i += 3;
  }
  if (n - i == 1) {
    uint32_t v = p[i] << 16;
    b64 += tbl[(v >> 18) & 0x3f];
    b64 += tbl[(v >> 12) & 0x3f];
    b64 += '=';
    b64 += '=';
  } else if (n - i == 2) {
    uint32_t v = (p[i] << 16) | (p[i + 1] << 8);
    b64 += tbl[(v >> 18) & 0x3f];
    b64 += tbl[(v >> 12) & 0x3f];
    b64 += tbl[(v >> 6) & 0x3f];
    b64 += '=';
  }

  /* Re-wrap to match Python's base64.encodebytes: a newline after every 76
     output characters, and a trailing newline at the very end. */
  std::string out;
  out.reserve(b64.size() + b64.size() / 76 + 1);
  for (size_t j = 0; j < b64.size(); j += 76) {
    out += b64.substr(j, 76);
    out += '\n';
  }
  return out;
}

std::string favicon_mmh3(const std::string &icon_bytes) {
  if (icon_bytes.empty()) return "";
  int32_t h = mmh3_x86_32(base64_encodebytes(icon_bytes), 0);
  return std::to_string(h);
}

/* ---------------------------------------------------------------------------
 * CPE 2.3 derivation.
 * ------------------------------------------------------------------------- */

/* Map kmap product keys -> (CPE vendor, CPE product).  Vendor tokens taken
   from the bundled kmap-cve.db `vendor` column (dominant non-NULL value) so a
   stored CPE lines up with the CVE taxonomy this build matches against.
   All current entries are application components (part 'a'). */
struct CpeMap {
  const char *key;     /* normalize_product() output */
  const char *vendor;  /* CPE 2.3 vendor field */
  const char *product; /* CPE 2.3 product field (NVD token; may differ from key) */
};

static const CpeMap CPE_TABLE[] = {
  {"openssh",       "openbsd",        "openssh"},
  {"http_server",   "apache",         "http_server"},
  {"nginx",         "f5",             "nginx"},
  {"lighttpd",      "lighttpd",       "lighttpd"},
  {"iis",           "microsoft",      "internet_information_services"},
  {"tomcat",        "apache",         "tomcat"},
  {"mysql",         "oracle",         "mysql"},
  {"mariadb",       "mariadb",        "mariadb"},
  {"postgresql",    "postgresql",     "postgresql"},
  {"redis",         "redis",          "redis"},
  {"mongodb",       "mongodb",        "mongodb"},
  {"vsftpd",        "vsftpd_project", "vsftpd"},
  {"proftpd",       "proftpd",        "proftpd"},
  {"samba",         "samba",          "samba"},
  {"elasticsearch", "elastic",        "elasticsearch"},
  {"jenkins",       "jenkins",        "jenkins"},
  {"php",           "php_group",      "php"},
  {"wordpress",     "wordpress",      "wordpress"},
};

/* Extract the CPE version field from a raw banner/version string.
   Keeps the first digit-led run consisting of [0-9.p] -- preserving the
   OpenSSH-style "p" patch suffix that the CVE version comparator also keeps --
   but only if it contains a '.' (so a lone "10" or a bare word is rejected as
   not-a-version).  Returns "*" (CPE ANY) when no dotted version is found.
   Any literal ':' is backslash-escaped per CPE 2.3 formatted-string rules. */
static std::string cpe_version_field(const std::string &version) {
  size_t i = 0;
  const size_t n = version.size();
  while (i < n) {
    if (isdigit(static_cast<unsigned char>(version[i]))) {
      size_t j = i;
      bool has_dot = false;
      while (j < n) {
        char c = version[j];
        if (c == '.') { has_dot = true; j++; }
        else if (isdigit(static_cast<unsigned char>(c)) || c == 'p' || c == 'P') j++;
        else break;
      }
      if (has_dot) {
        std::string v = version.substr(i, j - i);
        std::string out;
        out.reserve(v.size());
        for (char c : v) {
          char lc = static_cast<char>(tolower(static_cast<unsigned char>(c)));
          if (lc == ':') out += '\\';
          out += lc;
        }
        return out;
      }
      i = j;
    } else {
      i++;
    }
  }
  return "*";
}

std::string derive_cpe(const std::string &product, const std::string &version) {
  if (product.empty()) return "";
  std::string key;
  key.reserve(product.size());
  for (char c : product)
    key += static_cast<char>(tolower(static_cast<unsigned char>(c)));

  const CpeMap *m = nullptr;
  for (const CpeMap &e : CPE_TABLE) {
    if (key == e.key) { m = &e; break; }
  }
  if (!m) return "";

  std::string ver = cpe_version_field(version);
  std::ostringstream cpe;
  cpe << "cpe:2.3:a:" << m->vendor << ':' << m->product << ':' << ver
      << ":*:*:*:*:*:*:*";
  return cpe.str();
}
