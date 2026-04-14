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
  int         status_code;   // HTTP status (200, 301, etc.), 0 = error/timeout
  std::string redirect_to;   // non-empty if 3xx
  std::string title;         // page title if HTML
};

struct TlsInfo {
  std::string subject_cn;
  std::string issuer;
  std::string not_after;     // expiry date string
  bool        self_signed;
  std::string protocol;      // "TLSv1.2", "TLSv1.3"
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
