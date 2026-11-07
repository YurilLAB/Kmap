#ifndef KMAP_HTTP_HEADERS_H
#define KMAP_HTTP_HEADERS_H

#include <string>
#include <vector>

/* HTTP metadata must come from the header block, never from a line in the
 * response body. Accept LF-only responses as well as CRLF and preserve partial
 * header blocks, which are common when a bounded probe stops reading early. */
namespace kmap_http {

inline std::string ascii_lower(std::string text) {
  for (char &c : text)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
  return text;
}

inline std::string trim_ows(const std::string &text) {
  const size_t start = text.find_first_not_of(" \t");
  if (start == std::string::npos) return "";
  return text.substr(start, text.find_last_not_of(" \t") - start + 1);
}

inline int response_status(const std::string &response, size_t start, size_t end) {
  if (end == std::string::npos || response.compare(start, 5, "HTTP/") != 0) return 0;
  const size_t space = response.find(' ', start + 5);
  if (space == std::string::npos || space >= end) return 0;
  size_t code_start = response.find_first_not_of(" \t", space);
  if (code_start == std::string::npos || code_start + 3 > end) return 0;
  int code = 0;
  for (size_t i = code_start; i < code_start + 3; ++i) {
    if (response[i] < '0' || response[i] > '9') return 0;
    code = code * 10 + (response[i] - '0');
  }
  const size_t after = code_start + 3;
  if (after < end && response[after] != ' ' && response[after] != '\t' && response[after] != '\r')
    return 0;
  return code;
}

struct HeaderBlock {
  size_t begin, end;
  size_t body_begin;
  int status;
};

inline HeaderBlock header_block(const std::string &response) {
  size_t block_start = 0;
  for (;;) {
    const size_t status_end = response.find('\n', block_start);
    if (status_end == std::string::npos)
      return {block_start, response.size(), std::string::npos,
              response_status(response, block_start, response.size())};
    const int code = response_status(response, block_start, status_end);
    size_t start = status_end + 1;
    while (start < response.size()) {
      size_t end = response.find('\n', start);
      if (end == std::string::npos) end = response.size();
      size_t content_end = end;
      if (content_end > start && response[content_end - 1] == '\r') --content_end;
      if (content_end == start) {
        const size_t next = end < response.size() ? end + 1 : response.size();
        // Informational responses have no body. Advance only when another
        // complete status line follows; bounded reads may end in this block.
        // A 101 response instead switches protocols, so its payload is opaque.
        if (code >= 100 && code < 200 && code != 101 && next < response.size() &&
            response_status(response, next, response.find('\n', next)) != 0) {
          block_start = next;
          break;
        }
        return {status_end, start, next, code};
      }
      if (end == response.size())
        return {status_end, response.size(), std::string::npos, code};
      start = end + 1;
    }
    if (start >= response.size())
      return {status_end, response.size(), std::string::npos, code};
  }
}

inline int status_code(const std::string &response) {
  return header_block(response).status;
}

inline std::string response_body(const std::string &response) {
  const HeaderBlock block = header_block(response);
  // Informational/upgrade and no-content responses do not carry an HTTP body.
  if (block.body_begin == std::string::npos || block.status < 200 ||
      block.status == 204 || block.status == 304)
    return "";
  return response.substr(block.body_begin);
}

/* lower_response is a precomputed ASCII-lowercase copy of response. Retaining
 * it lets enrichment look up several fields without copying the whole response
 * once per field. cursor supports repeated fields such as Set-Cookie. */
inline bool next_header_value(const std::string &response,
                              const std::string &lower_response,
                              const char *name, size_t &cursor,
                              std::string &value) {
  const HeaderBlock block = header_block(response);
  const size_t limit = block.end;
  const std::string needle = "\n" + ascii_lower(name) + ":";
  const size_t pos = lower_response.find(needle, cursor < block.begin ? block.begin : cursor);
  if (pos == std::string::npos || pos + 1 >= limit) return false;
  const size_t start = pos + needle.size();
  size_t end = response.find_first_of("\r\n", start);
  if (end == std::string::npos || end > limit) end = limit;
  cursor = end;
  value = trim_ows(response.substr(start, end - start));
  return true;
}

inline std::string header_value(const std::string &response,
                                const std::string &lower_response,
                                const char *name) {
  size_t cursor = 0;
  std::string value;
  next_header_value(response, lower_response, name, cursor, value);
  return value;
}

/* Cookie attributes are semicolon-delimited tokens. Searching arbitrary
 * substrings would mistake a cookie value for SameSite, or a similarly named
 * attribute for Secure/HttpOnly. Cookie values are deliberately not returned. */
inline std::vector<std::string> cookie_flag_summary(const std::string &response) {
  std::vector<std::string> result;
  const std::string lower_response = ascii_lower(response);
  size_t cursor = 0;
  std::string cookie;
  while (next_header_value(response, lower_response, "Set-Cookie", cursor, cookie)) {
    const size_t first_end = cookie.find(';');
    const std::string pair = cookie.substr(0, first_end);
    const size_t equals = pair.find('=');
    if (equals == std::string::npos) continue;
    const std::string name = trim_ows(pair.substr(0, equals));
    if (name.empty()) continue;
    bool secure = false, httponly = false;
    std::string samesite;
    size_t start = first_end;
    while (start != std::string::npos) {
      ++start;
      const size_t end = cookie.find(';', start);
      const std::string attribute = trim_ows(cookie.substr(start, end - start));
      const size_t eq = attribute.find('=');
      const std::string key = ascii_lower(trim_ows(attribute.substr(0, eq)));
      if (key == "secure") secure = true;
      else if (key == "httponly") httponly = true;
      else if (key == "samesite" && eq != std::string::npos)
        samesite = trim_ows(attribute.substr(eq + 1));
      start = end;
    }
    std::vector<std::string> flags;
    if (secure) flags.push_back("Secure");
    if (httponly) flags.push_back("HttpOnly");
    if (!samesite.empty()) flags.push_back("SameSite=" + samesite);
    std::string summary = name;
    if (!flags.empty()) {
      summary += " (";
      for (size_t i = 0; i < flags.size(); ++i) {
        if (i) summary += ", ";
        summary += flags[i];
      }
      summary += ")";
    }
    result.push_back(summary);
  }
  return result;
}

} // namespace kmap_http
#endif
