/*
 * fuzz_proto.cc -- OSS-Fuzz / ClusterFuzzLite libFuzzer target for the binary
 * protocol parsers that index untrusted server bytes with non-trivial pointer
 * math: the MySQL HandshakeV10 scramble extraction and PostgreSQL auth-salt
 * extraction (default_creds.cc), plus the grab_banner binary service
 * classifier (net_enrich.cc: MySQL / MongoDB OP_REPLY / PostgreSQL).
 *
 * Functions copied VERBATIM from the shipping code (and kept in sync with the
 * Windows guard-page harness fuzz/fuzz_proto.cc). The fixed destination arrays
 * (scramble[20], salt[4]) get ASan stack red-zones in the clang build, so any
 * over-write is caught; reads past the input are caught by ASan heap red-zones
 * (libFuzzer passes a heap buffer of exactly `size`).
 */
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <algorithm>

/* === VERBATIM: MySQL HandshakeV10 scramble extraction (default_creds.cc) === */
static void mysql_parse(const uint8_t *buf, int n, uint8_t *scramble /*[20]*/) {
  if (n < 5) return;
  if (buf[4] != 0x0a) return;
  int pos = 5;
  while (pos < n && buf[pos] != '\0') pos++;
  pos++;
  if (pos + 13 <= n) {
    pos += 4;
    memcpy(scramble, buf + pos, 8);
    pos += 9;
    if (pos + 8 + 10 <= n) {
      pos += 7;
      int pdata_len = static_cast<int>(static_cast<unsigned char>(buf[pos])); pos++;
      pos += 10;
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

/* === VERBATIM: grab_banner binary service classifier (net_enrich.cc) === */
static const char *banner_classify_bin(const char *buf, int n, std::string &version) {
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* The parsers take an int length; cap sanely (they only touch small
     offsets, and real banners are tiny). */
  int n = (size > 65535) ? 65535 : static_cast<int>(size);
  uint8_t scramble[20];
  uint8_t salt[4];
  std::string ver;
  mysql_parse(data, n, scramble);
  pg_parse(data, n, salt);
  banner_classify_bin(reinterpret_cast<const char *>(data), n, ver);
  return 0;
}
