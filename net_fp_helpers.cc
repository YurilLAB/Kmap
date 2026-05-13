/*
 * net_fp_helpers.cc -- Pure derivation helpers for the fingerprint
 * relationship engine.  See net_fp_helpers.h for the contract.
 *
 * Lives in its own translation unit so tests can link it without
 * dragging in OpenSSL / sockets / the rest of net_enrich.cc.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_fp_helpers.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

bool fp_looks_like_ip(const std::string &s) {
  if (s.empty()) return false;
  struct in_addr  v4;
  struct in6_addr v6;
  if (inet_pton(AF_INET,  s.c_str(), &v4) == 1) return true;
  if (inet_pton(AF_INET6, s.c_str(), &v6) == 1) return true;
  return false;
}

std::vector<std::string>
fp_parse_san_json(const std::string &json) {
  std::vector<std::string> out;
  if (json.size() < 2) return out;
  size_t i = 0;
  while (i < json.size()) {
    if (json[i] != '"') { i++; continue; }
    size_t start = ++i;
    std::string val;
    while (i < json.size() && json[i] != '"') {
      if (json[i] == '\\' && i + 1 < json.size()) {
        char esc = json[i + 1];
        val += (esc == 'n')  ? '\n'
             : (esc == 'r')  ? '\r'
             : (esc == 't')  ? '\t'
             : esc;
        i += 2;
      } else {
        val += json[i++];
      }
    }
    if (i >= json.size()) break;  /* unterminated string — bail */
    i++;  /* consume the closing quote */
    if (!val.empty()) out.push_back(std::move(val));
    (void)start;
  }
  return out;
}

std::string fp_extract_redirect_host(const std::string &loc) {
  if (loc.empty()) return "";
  std::string s = loc;
  /* Strip a scheme prefix if present. */
  size_t scheme_end = s.find("://");
  if (scheme_end != std::string::npos) {
    s = s.substr(scheme_end + 3);
  } else if (s.size() >= 2 && s[0] == '/' && s[1] == '/') {
    s = s.substr(2);
  } else if (!s.empty() && s[0] == '/') {
    return "";
  }
  /* IPv6-literal hosts arrive bracketed per RFC 3986 ("[::1]:8080/x").
     The brackets must be processed BEFORE the port-delimiter scan, or
     the first ':' inside the address gets mistaken for the port colon
     and the host comes out as "[:" instead of "::1". */
  if (!s.empty() && s.front() == '[') {
    size_t close = s.find(']');
    if (close == std::string::npos) return "";  /* malformed */
    s = s.substr(1, close - 1);
  } else {
    size_t end = s.find_first_of("/?#:");
    if (end != std::string::npos) s = s.substr(0, end);
  }
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                        s.back() == '\r' || s.back() == '\n'))
    s.pop_back();
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  /* Dot-gate: must contain '.' or ':' (IPv6) — rejects scheme names
     and single-label intranet names that pollute the cluster table. */
  if (s.find('.') == std::string::npos && s.find(':') == std::string::npos)
    return "";
  return s;
}
