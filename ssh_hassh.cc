/*
 * ssh_hassh.cc -- implementation of the HASSH SSH fingerprint (see header).
 *
 * Pure byte parsing + MD5: no sockets, no OpenSSL, no nbase, so the test and
 * fuzz harnesses link it on its own.  The wire format is RFC 4253 section 6
 * (binary packet) carrying an SSH_MSG_KEXINIT (RFC 4253 section 7.1).  Every
 * field read goes through bounded helpers; a malformed or truncated buffer
 * yields a clean `false`, never an out-of-bounds read.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "ssh_hassh.h"
#include "md5.h"

#include <cstdint>

#define SSH_MSG_KEXINIT 20

/* Read a big-endian uint32 at offset `pos` in `s`, advancing `pos`.  Returns
   false (leaving pos untouched) if fewer than 4 bytes remain. */
static bool read_u32(const std::string &s, size_t &pos, uint32_t &out) {
  if (pos + 4 > s.size()) return false;
  const uint8_t *p = reinterpret_cast<const uint8_t *>(s.data()) + pos;
  out = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
        (uint32_t)p[2] << 8  | (uint32_t)p[3];
  pos += 4;
  return true;
}

/* Read an SSH "name-list": a uint32 length followed by that many bytes.
   Bounds-checked against the buffer end.  `out` gets the raw bytes verbatim. */
static bool read_namelist(const std::string &s, size_t &pos, std::string &out) {
  uint32_t len;
  size_t save = pos;
  if (!read_u32(s, pos, len)) return false;
  /* A single name-list cannot be larger than the buffer that holds it; the
     explicit cap also stops a bogus 4 GB length from wrapping the addition. */
  if (len > s.size() || pos + len > s.size()) { pos = save; return false; }
  out.assign(s, pos, len);
  pos += len;
  return true;
}

bool ssh_parse_kexinit(const std::string &packet, SshKexInit &out) {
  size_t pos = 0;
  uint32_t packet_length;
  if (!read_u32(packet, pos, packet_length)) return false;
  if (packet_length < 1) return false;                 /* must hold padding_len */
  if (pos >= packet.size()) return false;
  uint8_t padding_length = static_cast<uint8_t>(packet[pos]);
  pos += 1;

  /* payload_length = packet_length - padding_length - 1(the padding_len byte).
     Guard the subtraction so a padding_length >= packet_length can't wrap. */
  if ((uint32_t)padding_length + 1u > packet_length) return false;
  uint32_t payload_length = packet_length - padding_length - 1u;
  if (payload_length < 1 + 16) return false;           /* msg id + cookie */
  if (pos + payload_length > packet.size()) return false;

  /* The payload region is [pos, pos+payload_length); confine all further
     reads to it by slicing so a lying name-list length can't reach into the
     padding or beyond. */
  std::string payload(packet, pos, payload_length);
  size_t pp = 0;
  if (static_cast<uint8_t>(payload[pp]) != SSH_MSG_KEXINIT) return false;
  pp += 1;
  pp += 16;                                            /* skip the cookie */

  std::string *fields[10] = {
    &out.kex, &out.host_key, &out.enc_c2s, &out.enc_s2c,
    &out.mac_c2s, &out.mac_s2c, &out.comp_c2s, &out.comp_s2c,
    &out.lang_c2s, &out.lang_s2c
  };
  for (int i = 0; i < 10; i++) {
    if (!read_namelist(payload, pp, *fields[i])) return false;
  }
  return true;
}

bool ssh_kexinit_from_server_buffer(const std::string &buf, SshKexInit &out) {
  /* Walk past any CRLF/LF-terminated text lines (the "SSH-2.0-..." id line and
     any pre-banner informational lines RFC 4253 permits before it).  The
     binary KEXINIT packet begins at the first byte after the last such line.
     We stop at the first line that does not begin with text we expect, which
     in practice is the KEXINIT whose first 4 bytes are a big-endian length. */
  size_t pos = 0;
  const size_t n = buf.size();
  while (pos < n) {
    /* Only treat a line as "banner text" if it starts with 'S' (SSH-) or is a
       pre-banner line of printable text ending in LF.  The KEXINIT packet's
       first byte is the high byte of packet_length, which for any real packet
       (<16 MB) is 0x00 -- never a printable line start -- so this terminates. */
    unsigned char c = static_cast<unsigned char>(buf[pos]);
    if (c == 0x00) break;                  /* start of the binary packet */
    size_t nl = buf.find('\n', pos);
    if (nl == std::string::npos) return false;  /* no complete line / no packet */
    pos = nl + 1;
  }
  if (pos >= n) return false;
  std::string packet(buf, pos, n - pos);
  return ssh_parse_kexinit(packet, out);
}

std::string ssh_hassh_server(const SshKexInit &k) {
  std::string s = k.kex + ';' + k.enc_s2c + ';' + k.mac_s2c + ';' + k.comp_s2c;
  return md5_hex(s);
}

std::string ssh_hassh_client(const SshKexInit &k) {
  std::string s = k.kex + ';' + k.enc_c2s + ';' + k.mac_c2s + ';' + k.comp_c2s;
  return md5_hex(s);
}

std::string ssh_hassh_server_from_buffer(const std::string &buf) {
  SshKexInit k;
  if (!ssh_kexinit_from_server_buffer(buf, k)) return "";
  return ssh_hassh_server(k);
}
