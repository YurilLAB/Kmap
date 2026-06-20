/*
 * fuzz_hassh.cc -- OSS-Fuzz / ClusterFuzzLite libFuzzer target for the SSH
 * HASSH parser (ssh_hassh.cc): the SSH_MSG_KEXINIT binary-packet parser that
 * runs over hostile bytes a server sends right after connect.
 *
 * Includes the REAL shipping translation unit (ssh_hassh.cc, which pulls in
 * ssh_hassh.h + md5.h) so this fuzzes production code, not a copy. The parser
 * is all bounded index math over attacker-controlled length fields -- exactly
 * the over-read class libFuzzer+ASan is built to find.
 */
#include <cstdint>
#include <cstddef>
#include <string>

#include "../../ssh_hassh.cc"   /* real parser (single-TU, no kmap linkage) */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string in(reinterpret_cast<const char *>(data), size);

  /* 1. Server-buffer entry point (ident line + KEXINIT). Must never fault. */
  std::string h = ssh_hassh_server_from_buffer(in);
  /* Invariant: a returned HASSH is always 32 lowercase hex chars (MD5). */
  if (!h.empty()) {
    if (h.size() != 32) __builtin_trap();
    for (char c : h)
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) __builtin_trap();
  }

  /* 2. Raw packet parser directly. If it accepts the input, the hashes must
        also be well-formed and deterministic. */
  SshKexInit k;
  if (ssh_parse_kexinit(in, k)) {
    std::string s1 = ssh_hassh_server(k);
    std::string s2 = ssh_hassh_server(k);
    if (s1 != s2 || s1.size() != 32) __builtin_trap();  /* nondeterminism/format */
    std::string c1 = ssh_hassh_client(k);
    if (c1.size() != 32) __builtin_trap();
  }
  return 0;
}
