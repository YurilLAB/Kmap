#ifndef KMAP_WEB_RECON_H
#define KMAP_WEB_RECON_H

/*
 * web_recon.h -- HTTP/HTTPS reconnaissance for Kmap.
 * Activated via --web-recon on any port detected as http/https.
 *
 * Probes: page title, server headers, robots.txt, TLS info, common paths.
 */

#include <string>
#include <vector>
#include "Target.h"

struct WebPath {
  std::string path;
  int         status_code = 0;   // HTTP status (200, 301, etc.), 0 = error/timeout
  std::string redirect_to;   // non-empty if 3xx
  std::string title;         // page title if HTML
};

struct TlsInfo {
  std::string subject_cn;
  std::string issuer;
  std::string not_before;    // validity start (ASN1_TIME printed)
  std::string not_after;     // expiry date string
  bool        self_signed = false;
  std::string protocol;      // "TLSv1.2", "TLSv1.3"
  std::string cipher;        // negotiated cipher suite, e.g. "ECDHE-RSA-AES128-GCM-SHA256"
  std::vector<std::string> san; // Subject Alternative Names (DNS + IP)
  std::string fingerprint_sha256; // colon-separated lowercase hex of DER cert
  std::string pubkey_algo;   // "RSA", "EC", "DSA", "Ed25519", ... or "id=N"
  int         pubkey_bits = 0; // key size in bits
  std::string sig_algo;      // certificate signature algorithm OID short name
};

struct WebReconResult {
  uint16_t    portno;
  bool        is_https;
  std::string title;         // from GET /
  std::string server;        // Server: header
  std::string powered_by;    // X-Powered-By: header
  std::string generator;     // X-Generator: header
  std::vector<std::string> robots_disallowed; // from robots.txt
  TlsInfo     tls;           // only if is_https
  std::vector<WebPath> paths; // probed path results (non-404 only)

  // Security-posture response headers (empty string = header absent).
  // Long values (CSP, Permissions-Policy) are truncated to 200 chars + "..."
  // so the text output stays scannable; the JSON output preserves the same
  // value for downstream tooling that wants the truncated form.
  std::string hsts;          // Strict-Transport-Security
  std::string csp;           // Content-Security-Policy
  std::string xframe_options;// X-Frame-Options
  std::string xcontent_type; // X-Content-Type-Options
  std::string referrer_policy;   // Referrer-Policy
  std::string permissions_policy;// Permissions-Policy

  // Allowed HTTP methods from an OPTIONS / probe (Allow: header). Empty
  // when the server didn't respond, returned no Allow header, or 4xx'd.
  std::vector<std::string> allowed_methods;

  // Per-cookie security-flag summary parsed from Set-Cookie response
  // headers: "name (Secure, HttpOnly, SameSite=Strict)". A cookie with
  // no flags is rendered as just "name" so missing flags are easy to spot.
  std::vector<std::string> cookie_flags;
};

/* Per-target web recon storage (attached to Target via attribute map) */
struct TargetWebData {
  std::vector<WebReconResult> results;
};

/*
 * Run web recon against all HTTP/HTTPS ports on all targets.
 * extra_paths_file: optional file with additional paths to probe (one per line).
 */
void run_web_recon(std::vector<Target *> &targets,
                   const char *extra_paths_file);

/* Print web recon results for a single host to normal output. */
void print_web_recon_output(const Target *t);

/*
 * Capture screenshots of HTTP/HTTPS ports on all targets.
 * Uses a headless browser (Chrome, Chromium, Edge, or Firefox).
 * out_dir: directory to save PNGs (default: "kmap-screenshots").
 */
void run_screenshot_capture(std::vector<Target *> &targets,
                            const char *out_dir);

#endif /* KMAP_WEB_RECON_H */
