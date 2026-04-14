#ifndef KMAP_DEFAULT_CREDS_H
#define KMAP_DEFAULT_CREDS_H

/*
 * default_creds.h -- Post-scan phase that probes detected services for
 * default/common credentials. Activated via --default-creds.
 *
 * Supported services: SSH, FTP, Telnet, HTTP Basic Auth,
 *                     MySQL, PostgreSQL, MSSQL, MongoDB
 */

#include <string>
#include <vector>
#include "Target.h"

/* Result of a single credential probe */
struct CredResult {
  std::string service;   // "ssh", "ftp", etc.
  uint16_t    portno;
  std::string username;
  std::string password;
  bool        found;
};

/* Per-port credential findings attached to a Target */
struct PortCredResults {
  uint16_t portno;
  uint8_t  proto;
  std::vector<CredResult> hits; // usually 0 or 1 entry
};

/* Per-target credential storage (attached to Target via attribute map) */
struct TargetCredData {
  std::vector<PortCredResults> results;
};

/*
 * Run default credential checks against all open ports on all targets.
 * Modifies each Target's userdata to attach PortCredResults.
 * creds_file: path to custom wordlist, or nullptr to use built-in data file.
 * timeout_ms: per-attempt timeout in milliseconds.
 */
void run_default_creds(std::vector<Target *> &targets,
                       const char *creds_file,
                       int timeout_ms);

/*
 * Print credential results for a single host to normal/machine output.
 * Called from the per-host output phase alongside printportoutput().
 */
void print_default_creds_output(const Target *t);

#endif /* KMAP_DEFAULT_CREDS_H */
