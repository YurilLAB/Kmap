/*
 * banner_classify.h -- single-source service/version classifier for a raw
 * connect-banner, header-only.
 *
 * Maps the first bytes a server sends (or its reply to a probe) to a service
 * name + version string, the way the net-scan enrichment identifies a port.
 * This logic used to be duplicated in net_enrich.cc::grab_banner and
 * net_enrich_async.cc::classify_banner with a "MUST stay in sync" comment --
 * and they HAD drifted (grab_banner grew MariaDB detection and the tightened
 * PostgreSQL length check, the async copy had neither). Both now call this one
 * function, so they cannot diverge, and fuzz/test_banner_classify.cc tests this
 * exact code rather than a hand-kept duplicate (same pattern as json_escape.h).
 *
 * Pure: no sockets, no OpenSSL. The SSH branch sets service/version only; the
 * HASSH fingerprint is layered on by grab_banner (it needs the drained KEXINIT
 * bytes), so it is deliberately NOT computed here.
 */

#ifndef KMAP_BANNER_CLASSIFY_H
#define KMAP_BANNER_CLASSIFY_H

#include <string>
#include <algorithm>
#include <cstring>
#include <cctype>

struct BannerClass {
  std::string service;        /* "http","https","ssh","vnc","telnet","rsync",... */
  std::string version;        /* product/version string, may be empty */
  std::string http_response;  /* full response when the banner was HTTP */
};

static inline std::string bc_str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}

/* Classify `buf` (length `n`, observed on `port`). Returns an empty service on
 * no data. Keep in lockstep with the protocol notes in net_enrich.cc. */
static inline BannerClass kmap_classify_banner(const char *buf, int n, int port) {
  BannerClass result;
  if (n <= 0 || !buf) return result;

  std::string banner(buf, static_cast<size_t>(n));
  std::string banner_lower = bc_str_lower(banner);

  std::string first_line = banner;
  size_t nl = first_line.find('\n');
  if (nl != std::string::npos) first_line = first_line.substr(0, nl);
  while (!first_line.empty() &&
         (first_line.back() == '\r' || first_line.back() == '\n'))
    first_line.pop_back();

  /* HTTP */
  if (banner.size() >= 8 && banner.substr(0, 4) == "HTTP") {
    result.service = "http";
    result.http_response = banner;
    size_t spos = banner_lower.find("\nserver:");
    if (spos != std::string::npos) {
      spos += 8;
      while (spos < banner.size() && banner[spos] == ' ') spos++;
      size_t epos = banner.find('\r', spos);
      if (epos == std::string::npos) epos = banner.find('\n', spos);
      if (epos == std::string::npos) epos = banner.size();
      result.version = banner.substr(spos, epos - spos);
    }
    if (port == 443 || port == 8443 || port == 4443)
      result.service = "https";
    /* Elasticsearch serves its cluster info as the HTTP root JSON; the tagline
       is unmistakable. Reclassify (with the real version) so CVE/EOL matching
       uses the elasticsearch product instead of generic http. */
    if (banner.find("You Know, for Search") != std::string::npos ||
        (banner.find("\"cluster_name\"") != std::string::npos &&
         banner.find("\"lucene_version\"") != std::string::npos)) {
      result.service = "elasticsearch";
      size_t vp = banner.find("\"number\"");          /* version.number */
      if (vp != std::string::npos) {
        vp = banner.find('"', vp + 8);                /* opening quote of value */
        if (vp != std::string::npos) {
          size_t ve = banner.find('"', vp + 1);
          if (ve != std::string::npos)
            result.version = banner.substr(vp + 1, ve - vp - 1);
        }
      }
    }
    /* Jenkins advertises its version in the X-Jenkins response header. */
    {
      size_t jp = banner_lower.find("\nx-jenkins:");
      if (jp != std::string::npos) {
        result.service = "jenkins";
        size_t vs = jp + 11;                       /* past "\nx-jenkins:" */
        while (vs < banner.size() && banner[vs] == ' ') vs++;
        size_t ve = banner.find_first_of("\r\n", vs);
        if (ve == std::string::npos) ve = banner.size();
        result.version = banner.substr(vs, ve - vs);
      }
    }
    /* SharePoint stamps its build in the MicrosoftSharePointTeamServices
       header (always in the headers, so the version is reliably captured). */
    {
      size_t sp = banner_lower.find("\nmicrosoftsharepointteamservices:");
      if (sp != std::string::npos) {
        result.service = "sharepoint";
        size_t vs = sp + 33;   /* past "\nmicrosoftsharepointteamservices:" */
        while (vs < banner.size() && banner[vs] == ' ') vs++;
        size_t ve = banner.find_first_of("\r\n", vs);
        if (ve == std::string::npos) ve = banner.size();
        result.version = banner.substr(vs, ve - vs);
      }
    }
    return result;
  }

  /* SSH (service/version only; HASSH added by grab_banner) */
  if (banner.size() >= 4 && banner.substr(0, 4) == "SSH-") {
    result.service = "ssh";
    size_t dash3 = banner.find('-', 4);
    if (dash3 != std::string::npos && dash3 + 1 < first_line.size()) {
      result.version = first_line.substr(dash3 + 1);
      std::replace(result.version.begin(), result.version.end(), '_', ' ');
    }
    return result;
  }

  /* VNC / RFB (RFC 6143): "RFB <major>.<minor>\n", e.g. "RFB 003.008". */
  if (banner.size() >= 8 && banner.compare(0, 4, "RFB ") == 0 &&
      isdigit(static_cast<unsigned char>(banner[4]))) {
    result.service = "vnc";
    result.version = first_line;
    return result;
  }

  /* Telnet: IAC (0xFF) + WILL/WONT/DO/DONT (0xFB-0xFE). */
  if (n >= 2 && static_cast<unsigned char>(buf[0]) == 0xFF &&
      static_cast<unsigned char>(buf[1]) >= 0xFB &&
      static_cast<unsigned char>(buf[1]) <= 0xFE) {
    result.service = "telnet";
    return result;
  }

  /* rsync daemon greeting. */
  if (banner.compare(0, 8, "@RSYNCD:") == 0) {
    result.service = "rsync";
    result.version = first_line;
    return result;
  }

  /* FTP / SMTP 220 greeting */
  if (banner.size() >= 4 &&
      (banner.substr(0, 4) == "220 " || banner.substr(0, 4) == "220-")) {
    if (banner_lower.find("ftp") != std::string::npos) {
      result.service = "ftp";
    } else if (banner_lower.find("smtp") != std::string::npos ||
               banner_lower.find("mail") != std::string::npos ||
               banner_lower.find("esmtp") != std::string::npos) {
      result.service = "smtp";
    } else {
      if (port == 21) result.service = "ftp";
      else if (port == 25 || port == 587 || port == 465) result.service = "smtp";
      else result.service = "ftp";
    }
    result.version = first_line.substr(4);
    return result;
  }

  /* IMAP */
  if (banner.size() >= 4 && banner.substr(0, 4) == "* OK") {
    result.service = "imap";
    result.version = first_line.size() > 5 ? first_line.substr(5) : "";
    return result;
  }

  /* POP3 */
  if (banner.size() >= 3 && banner.substr(0, 3) == "+OK") {
    result.service = "pop3";
    result.version = first_line.size() > 4 ? first_line.substr(4) : "";
    return result;
  }

  /* MySQL / MariaDB handshake: pkt-len then protocol version 0x0a at byte 4. */
  if (n >= 5 && static_cast<unsigned char>(buf[4]) == 0x0a) {
    result.service = "mysql";
    const char *verp = buf + 5;
    size_t vlen = strnlen(verp,
                          static_cast<size_t>(n) > 5 ? static_cast<size_t>(n) - 5 : 0);
    if (vlen > 0) result.version = std::string(verp, vlen);
    /* MariaDB speaks the MySQL wire protocol; it advertises a legacy compat
       greeting "5.5.5-<real-version>-MariaDB-...". Route to mariadb with the
       real version so CVE matching hits MariaDB, not Oracle MySQL. */
    if (bc_str_lower(result.version).find("mariadb") != std::string::npos) {
      result.service = "mariadb";
      if (result.version.rfind("5.5.5-", 0) == 0)
        result.version = result.version.substr(6);
    }
    return result;
  }

  /* Redis: -ERR / +PONG / $... */
  if (banner_lower.find("-err") == 0 || banner_lower.find("+pong") == 0 ||
      banner_lower.find("$") == 0) {
    result.service = "redis";
    return result;
  }

  /* MongoDB wire protocol OP_REPLY */
  if (n >= 16 && static_cast<unsigned char>(buf[12]) == 0x01) {
    result.service = "mongodb";
    return result;
  }

  /* PostgreSQL 'R' AuthenticationRequest with a bounded length field. */
  if (n >= 9 && buf[0] == 'R') {
    uint32_t pg_len = (static_cast<uint32_t>(static_cast<unsigned char>(buf[1])) << 24) |
                      (static_cast<uint32_t>(static_cast<unsigned char>(buf[2])) << 16) |
                      (static_cast<uint32_t>(static_cast<unsigned char>(buf[3])) << 8)  |
                       static_cast<uint32_t>(static_cast<unsigned char>(buf[4]));
    if (pg_len >= 8 && pg_len <= 64) {
      result.service = "postgresql";
      return result;
    }
  }

  /* Unknown: keep a trimmed first line as the version. */
  if (!first_line.empty()) {
    result.service = "unknown";
    result.version = first_line.size() > 64 ? first_line.substr(0, 64) : first_line;
  }
  return result;
}

#endif /* KMAP_BANNER_CLASSIFY_H */
