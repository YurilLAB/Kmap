/*
 * test_hassh.cc -- known-answer + robustness test for the HASSH SSH
 * fingerprint (md5.h + ssh_hassh.cc).
 *
 * Three things must hold:
 *   1. md5.h reproduces the RFC 1321 known-answer suite bit-for-bit -- HASSH is
 *      *defined* as an MD5, so a wrong MD5 means a value that never pivots
 *      against Shodan/Censys `ssh.hassh`.
 *   2. The KEXINIT parser extracts the ten name-lists from a real-shaped SSH
 *      server packet, and ssh_hassh_server() reproduces the reference hash
 *      computed independently by Python hashlib (the ground truth pinned
 *      below) -- both from a bare packet and from a full "SSH-2.0-...\r\n"+
 *      packet server-initial buffer.
 *   3. The parser never reads out of bounds.  Real SSH reads are capped, so the
 *      KEXINIT arrives truncated constantly; we sweep every truncation of the
 *      reference buffer and hammer random bytes, all under ASan/UBSan, and
 *      require a clean false/"" -- never a fault.
 *
 * Build (matches .github/workflows/fuzz.yml helper-linked harnesses):
 *   g++ -O1 -g -std=gnu++17 -fsanitize=address,undefined \
 *       -fno-sanitize-recover=all fuzz/test_hassh.cc ssh_hassh.cc -o test_hassh
 *   ./test_hassh [seed]
 */

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../md5.h"
#include "../ssh_hassh.h"

static int g_fail = 0;

static void check_md5(const std::string &in, const char *expect, const char *label) {
  std::string got = md5_hex(in);
  if (got != expect) {
    printf("  FAIL md5 %-12s len=%zu\n    got    %s\n    expect %s\n",
           label, in.size(), got.c_str(), expect);
    g_fail++;
  }
}

/* SSH name-list = uint32 big-endian length + raw bytes. */
static void put_namelist(std::string &p, const std::string &s) {
  uint32_t n = static_cast<uint32_t>(s.size());
  p.push_back((char)((n >> 24) & 0xff));
  p.push_back((char)((n >> 16) & 0xff));
  p.push_back((char)((n >> 8) & 0xff));
  p.push_back((char)(n & 0xff));
  p += s;
}

/* Build an RFC 4253 binary packet wrapping an SSH_MSG_KEXINIT with the ten
   supplied name-lists, exactly as a server sends it. */
static std::string build_kexinit(const std::string nl[10]) {
  std::string payload;
  payload.push_back((char)20);                 /* SSH_MSG_KEXINIT */
  for (int i = 0; i < 16; i++) payload.push_back((char)i);  /* cookie 0..15 */
  for (int i = 0; i < 10; i++) put_namelist(payload, nl[i]);
  payload.push_back((char)0);                  /* first_kex_packet_follows */
  for (int i = 0; i < 4; i++) payload.push_back((char)0);   /* reserved */

  /* (padding_length byte + payload + padding) must be a multiple of 8, with at
     least 4 bytes of padding. */
  size_t need = (8 - ((1 + payload.size()) % 8)) % 8;
  size_t padlen = need >= 4 ? need : need + 8;
  uint32_t packet_length = (uint32_t)(1 + payload.size() + padlen);

  std::string packet;
  packet.push_back((char)((packet_length >> 24) & 0xff));
  packet.push_back((char)((packet_length >> 16) & 0xff));
  packet.push_back((char)((packet_length >> 8) & 0xff));
  packet.push_back((char)(packet_length & 0xff));
  packet.push_back((char)padlen);
  packet += payload;
  for (size_t i = 0; i < padlen; i++) packet.push_back((char)0);
  return packet;
}

/* xorshift32 -- deterministic, seedable; same idiom as the other harnesses. */
static uint32_t g_rng = 1;
static uint32_t xr(void) {
  g_rng ^= g_rng << 13; g_rng ^= g_rng >> 17; g_rng ^= g_rng << 5;
  return g_rng;
}

int main(int argc, char **argv) {
  if (argc > 1) g_rng = (uint32_t)strtoul(argv[1], nullptr, 0);
  if (!g_rng) g_rng = 1;

  printf("HASSH (md5.h + ssh_hassh.cc) known-answer + robustness test\n");
  printf("==========================================================\n");

  /* 1. MD5 against the RFC 1321 appendix A.5 vector suite. */
  check_md5("", "d41d8cd98f00b204e9800998ecf8427e", "empty");
  check_md5("a", "0cc175b9c0f1b6a831c399e269772661", "a");
  check_md5("abc", "900150983cd24fb0d6963f7d28e17f72", "abc");
  check_md5("message digest", "f96b697d7cb7938d525a2f31aaf161d0", "msgdigest");
  check_md5("abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b", "alpha");
  check_md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f", "alnum");
  check_md5("123456789012345678901234567890123456789012345678901234567890"
            "12345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a", "80digits");
  int md5_fail = g_fail;
  printf("MD5 RFC 1321 KATs: %s (%d/7 failed)\n",
         md5_fail ? "FAIL" : "OK", md5_fail);

  /* 2. HASSH against a Python-hashlib reference (OpenSSH_8.9p1 server). */
  std::string nl[10] = {
    /* kex */
    "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
    "ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
    "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
    "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
    /* host_key */
    "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519",
    /* enc c2s / s2c */
    "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,"
    "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,"
    "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    /* mac c2s / s2c */
    "umac-64-etm@openssh.com,umac-128-etm@openssh.com,"
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
    "hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,"
    "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    "umac-64-etm@openssh.com,umac-128-etm@openssh.com,"
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
    "hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,"
    "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    /* comp c2s / s2c */
    "none,zlib@openssh.com",
    "none,zlib@openssh.com",
    /* lang c2s / s2c */
    "", ""
  };
  const char *EXPECT_SERVER = "3ccd1778a76049721c71ad7d2bf62bbc";

  std::string packet = build_kexinit(nl);
  SshKexInit k;
  int hassh_fail = 0;
  if (!ssh_parse_kexinit(packet, k)) {
    printf("  FAIL ssh_parse_kexinit on well-formed packet\n");
    hassh_fail++;
  } else {
    if (k.kex != nl[0])      { printf("  FAIL kex name-list mismatch\n");      hassh_fail++; }
    if (k.comp_s2c != nl[7]) { printf("  FAIL comp_s2c name-list mismatch\n"); hassh_fail++; }
    std::string hs = ssh_hassh_server(k);
    if (hs != EXPECT_SERVER) {
      printf("  FAIL hasshServer\n    got    %s\n    expect %s\n",
             hs.c_str(), EXPECT_SERVER);
      hassh_fail++;
    }
  }

  /* Same value via the full server-initial buffer (id line + CRLF + packet). */
  std::string server_buf = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n" + packet;
  if (ssh_hassh_server_from_buffer(server_buf) != EXPECT_SERVER) {
    printf("  FAIL ssh_hassh_server_from_buffer\n");
    hassh_fail++;
  }
  /* Tolerate a pre-banner informational line before the SSH- id. */
  std::string pre_buf = "Welcome to the jungle\r\n" + server_buf;
  if (ssh_hassh_server_from_buffer(pre_buf) != EXPECT_SERVER) {
    printf("  FAIL ssh_hassh_server_from_buffer (pre-banner line)\n");
    hassh_fail++;
  }
  printf("HASSH reference vector: %s (%d failed)\n",
         hassh_fail ? "FAIL" : "OK", hassh_fail);
  g_fail += hassh_fail;

  /* 3a. Truncation sweep: every prefix of the reference buffer must parse to a
     clean true/false with no fault, and any success must match the reference
     (a partial KEXINIT can only ever parse once it is whole). */
  int trunc_fail = 0;
  for (size_t len = 0; len <= server_buf.size(); len++) {
    std::string pre = server_buf.substr(0, len);
    std::string h = ssh_hassh_server_from_buffer(pre);
    if (!h.empty() && h != EXPECT_SERVER) {
      if (trunc_fail < 5)
        printf("  FAIL truncation len=%zu produced wrong hash %s\n",
               len, h.c_str());
      trunc_fail++;
    }
  }
  printf("Truncation sweep (%zu prefixes): %s (%d wrong)\n",
         server_buf.size() + 1, trunc_fail ? "FAIL" : "OK", trunc_fail);
  g_fail += trunc_fail;

  /* 3b. Random-byte fuzz: the parser must never fault on hostile input.  Mix
     pure noise with mutated copies of the real packet so length fields point
     just past the end -- the classic over-read trigger. */
  const int ITERS = 500000;
  for (int it = 0; it < ITERS; it++) {
    std::string s;
    if (it & 1) {
      s = packet;                         /* mutate the real packet */
      int muts = 1 + (xr() % 8);
      for (int m = 0; m < muts && !s.empty(); m++)
        s[xr() % s.size()] = (char)(xr() & 0xff);
      if ((xr() & 3) == 0 && !s.empty())  /* random truncation */
        s.resize(xr() % s.size());
    } else {
      size_t len = xr() % 2048;           /* pure noise */
      s.resize(len);
      for (size_t i = 0; i < len; i++) s[i] = (char)(xr() & 0xff);
    }
    SshKexInit kk;
    volatile bool ok = ssh_parse_kexinit(s, kk);   /* must not fault */
    (void)ok;
    volatile bool ok2 = ssh_kexinit_from_server_buffer(s, kk);
    (void)ok2;
  }
  printf("Random fuzz (%d iters, seed-derived): no fault\n", ITERS);

  printf("\n%s\n", g_fail == 0 ? "hassh test: ALL PASS" : "hassh test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
