/*
 * ssh_hassh.h -- HASSH SSH fingerprinting (Salesforce HASSH standard).
 *
 * HASSH summarises an SSH endpoint's negotiated algorithm preferences into a
 * single MD5 hash, the same value Shodan publishes as `ssh.hassh` /
 * `ssh.hasshserver` and Censys exposes on SSH services.  Because it is derived
 * from the SSH_MSG_KEXINIT name-lists -- not the banner string -- it survives
 * banner spoofing and clusters hosts that share an SSH build/config (fleets,
 * managed appliances, honeypots).  It slots into Kmap's existing per-host
 * `fingerprints` table next to tls_sha256 / favicon_mmh3 as another pivot key
 * for --net-cluster and --search.
 *
 *   hasshServer = md5( kex ; enc_s2c ; mac_s2c ; comp_s2c )
 *   hasshClient = md5( kex ; enc_c2s ; mac_c2s ; comp_c2s )
 *
 * where each field is the raw comma-separated name-list exactly as it appeared
 * on the wire (empty fields contribute an empty string between the ';'s).
 *
 * This TU is deliberately dependency-light (no sockets, no OpenSSL, no nbase),
 * like net_hash_helpers.cc, so the test/fuzz harnesses link it directly.  Every
 * parse step is bounds-checked against hostile/truncated input -- a server can
 * send fewer than 10 name-lists, lie about a length, or cut the packet short
 * (Kmap caps the SSH read), and the parser must return false, never over-read.
 */

#ifndef KMAP_SSH_HASSH_H
#define KMAP_SSH_HASSH_H

#include <string>

/* The ten name-lists carried in an SSH_MSG_KEXINIT, in wire order. */
struct SshKexInit {
  std::string kex;        /* kex_algorithms */
  std::string host_key;   /* server_host_key_algorithms */
  std::string enc_c2s;    /* encryption_algorithms_client_to_server */
  std::string enc_s2c;    /* encryption_algorithms_server_to_client */
  std::string mac_c2s;    /* mac_algorithms_client_to_server */
  std::string mac_s2c;    /* mac_algorithms_server_to_client */
  std::string comp_c2s;   /* compression_algorithms_client_to_server */
  std::string comp_s2c;   /* compression_algorithms_server_to_client */
  std::string lang_c2s;   /* languages_client_to_server */
  std::string lang_s2c;   /* languages_server_to_client */
};

/* Parse a single SSH binary packet that begins at the front of `packet`:
 *   uint32 packet_length | byte padding_length | payload | padding
 * The payload must be an SSH_MSG_KEXINIT (msg id 20) followed by a 16-byte
 * cookie and the ten name-lists.  Returns true and fills `out` only when the
 * full structure is present and in bounds; returns false on any truncation,
 * wrong message id, or inconsistent length.  Never reads past `packet`.
 */
bool ssh_parse_kexinit(const std::string &packet, SshKexInit &out);

/* Locate the SSH_MSG_KEXINIT inside a raw server-initial buffer (the bytes a
 * server sends right after connect: the "SSH-2.0-..." identification line,
 * CRLF, then the KEXINIT packet -- often in the same TCP flight) and parse it.
 * Tolerates an arbitrary number of CRLF-terminated pre-banner lines (some
 * servers emit informational lines before the SSH- id).  Returns true on a
 * complete parse.
 */
bool ssh_kexinit_from_server_buffer(const std::string &buf, SshKexInit &out);

/* hasshServer / hasshClient MD5 hex (32 lowercase hex chars). */
std::string ssh_hassh_server(const SshKexInit &k);
std::string ssh_hassh_client(const SshKexInit &k);

/* Convenience: parse a raw server-initial buffer and return the hasshServer
 * hex, or "" if no complete KEXINIT could be parsed.  This is what the
 * enrichment SSH leg calls on bytes it already read. */
std::string ssh_hassh_server_from_buffer(const std::string &buf);

#endif /* KMAP_SSH_HASSH_H */
