/*
 * json_escape.h -- single-source JSON string escaper, header-only.
 *
 * Escapes a byte string for use as a JSON string value AND guarantees the
 * result is valid UTF-8 (RFC 8259 requires UTF-8 text):
 *   - the seven short escapes (" \ \b \f \n \r \t) and every other control
 *     byte U+0000..U+001F as \uXXXX;
 *   - any byte >= 0x80 is validated as part of a well-formed UTF-8 sequence
 *     (RFC 3629); a malformed / overlong / surrogate / truncated / out-of-range
 *     sequence is replaced with U+FFFD. Scan targets routinely return banners,
 *     HTTP headers and TLS fields that are raw Latin-1 or truncated multi-byte
 *     data, so without this the emitted document is rejected by jq / Python
 *     json / the ypanel ingester.
 *
 * This used to be copy-pasted into four TUs (net_enrich.cc, net_enrich_async.cc,
 * net_query.cc, net_scan.cc) and the copies drifted -- three kept the old
 * passthrough-high-bytes behaviour while net_query gained UTF-8 validation, so
 * the same host could serialise to valid JSON via --net-query and invalid JSON
 * in the findings report. Header-only `static inline` gives every TU one
 * internal-linkage copy of the SAME code -- no new .cc, no link step, the same
 * pattern sha256.h / md5.h use -- and fuzz/test_json_escape.cc tests this exact
 * function rather than a hand-kept duplicate.
 */

#ifndef KMAP_JSON_ESCAPE_H
#define KMAP_JSON_ESCAPE_H

#include <cstdio>
#include <cstdint>
#include <string>

static inline std::string kmap_json_escape(const std::string &in) {
  std::string out;
  out.reserve(in.size() + 8);
  size_t i = 0, n = in.size();
  while (i < n) {
    unsigned char c = static_cast<unsigned char>(in[i]);
    if (c < 0x80) {                         /* ASCII: escape JSON metachars/ctrl */
      switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
          if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
          else          out += static_cast<char>(c);
      }
      i++;
      continue;
    }
    /* Validate a multi-byte UTF-8 sequence (RFC 3629); emit U+FFFD on any
       malformed / overlong / surrogate / truncated sequence. */
    int len = (c >= 0xF0 && c <= 0xF4) ? 4
            : (c >= 0xE0 && c <= 0xEF) ? 3
            : (c >= 0xC2 && c <= 0xDF) ? 2 : 0;   /* 0xC0/0xC1 = overlong */
    bool ok = (len != 0) && (i + static_cast<size_t>(len) <= n);
    for (int k = 1; ok && k < len; k++) {
      unsigned char cc = static_cast<unsigned char>(in[i + k]);
      if (cc < 0x80 || cc > 0xBF) ok = false;     /* not a continuation byte */
    }
    if (ok) {
      unsigned char c1 = (len > 1) ? static_cast<unsigned char>(in[i + 1]) : 0;
      if (len == 3 && c == 0xE0 && c1 < 0xA0) ok = false;      /* overlong */
      else if (len == 3 && c == 0xED && c1 > 0x9F) ok = false; /* surrogate */
      else if (len == 4 && c == 0xF0 && c1 < 0x90) ok = false; /* overlong */
      else if (len == 4 && c == 0xF4 && c1 > 0x8F) ok = false; /* > U+10FFFF */
    }
    if (ok) {
      out.append(in, i, static_cast<size_t>(len));
      i += static_cast<size_t>(len);
    } else {
      out += "\xEF\xBF\xBD";                 /* U+FFFD REPLACEMENT CHARACTER */
      i++;
    }
  }
  return out;
}

#endif /* KMAP_JSON_ESCAPE_H */
