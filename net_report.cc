/*
 * net_report.cc -- Findings report generator for Kmap net-scan.
 *
 * Reads enriched host records from all shard databases (ordered by IP),
 * and writes human-readable text files into a Findings/ directory.
 * Each file contains exactly 72,348 IPs with their complete scan results,
 * formatted in Kmap's --report text style.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_report.h"
#include "net_db.h"
#include "KmapOps.h"
#include "kmap.h"
#include "output.h"

#include "sqlite/sqlite3.h"

#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <sstream>

#ifdef WIN32
#include <direct.h>
#define report_mkdir(d) _mkdir(d)
#else
#include <sys/stat.h>
#define report_mkdir(d) mkdir(d, 0755)
#endif

extern KmapOps o;

/* -----------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------- */

#define HOSTS_PER_FILE  72348
#define SEPARATOR_WIDTH 80

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static std::string separator_line() {
  return std::string(SEPARATOR_WIDTH, '=');
}

static std::string dash_line() {
  return std::string(74, '-');
}

/* Format a number with thousand separators */
static std::string format_count(int64_t n) {
  if (n < 0) return "-" + format_count(-n);
  std::string raw = std::to_string(n);
  std::string out;
  int len = static_cast<int>(raw.size());
  for (int i = 0; i < len; i++) {
    if (i > 0 && (len - i) % 3 == 0) out += ',';
    out += raw[i];
  }
  return out;
}

/* Format a Unix timestamp to a date string (thread-safe). */
static std::string format_date(int64_t ts) {
  if (ts <= 0) return "unknown";
  time_t t = static_cast<time_t>(ts);
  struct tm tm_buf{};
#ifdef WIN32
  if (localtime_s(&tm_buf, &t) != 0) return "unknown";
#else
  if (!localtime_r(&t, &tm_buf)) return "unknown";
#endif
  char buf[16];
  strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_buf);
  return buf;
}

/* Minimal JSON string value extraction:
 * find "key":"value" and return value. */
static std::string json_extract_string(const std::string &json,
                                       const char *key) {
  std::string search = std::string("\"") + key + "\":\"";
  size_t pos = json.find(search);
  if (pos == std::string::npos) return "";
  pos += search.size();
  /* Find the unescaped closing quote. A quote is escaped only when preceded
   * by an ODD number of consecutive backslashes; an even count means each
   * pair is itself an escaped backslash (\\) and the quote terminates the
   * string. The previous "json[end-1] == '\\\\'" check got this wrong and
   * skipped past valid string ends in CVE descriptions containing literal
   * backslashes. */
  size_t end = pos;
  while (end < json.size()) {
    end = json.find('"', end);
    if (end == std::string::npos) return "";
    size_t bs_count = 0;
    size_t i = end;
    while (i > pos && json[i - 1] == '\\') { bs_count++; i--; }
    if ((bs_count & 1u) == 0) break; /* unescaped quote */
    end++; /* escaped — keep looking */
  }
  if (end >= json.size() || end == std::string::npos) return "";
  return json.substr(pos, end - pos);
}

/* Find the end of a JSON object that starts at `start` (which must point
 * at '{').  Returns the position of the matching '}', or npos if the
 * input is malformed.
 *
 * Needed because CVE / web-path JSON values often contain literal '{' or
 * '}' inside string values (CVE descriptions in particular -- prose with
 * code snippets, regex examples, set-builder notation).  A naive
 * find('}', start) lands on the first '}' it sees, which may be inside
 * a description string instead of the actual object terminator, and
 * truncates the parse so the entry's id / cvss / desc come out wrong or
 * the entry is silently dropped from the report.
 *
 * State machine: track brace depth while skipping over JSON string
 * literals.  Backslash escapes inside strings are honored so a \" does
 * not prematurely close the string. */
static size_t json_find_object_end(const std::string &json, size_t start) {
  if (start >= json.size() || json[start] != '{') return std::string::npos;
  int  depth        = 0;
  bool in_string    = false;
  bool escape_next  = false;
  for (size_t i = start; i < json.size(); i++) {
    char c = json[i];
    if (escape_next) { escape_next = false; continue; }
    if (in_string) {
      if (c == '\\')      escape_next = true;
      else if (c == '"')  in_string = false;
      continue;
    }
    if (c == '"')       in_string = true;
    else if (c == '{')  depth++;
    else if (c == '}') {
      depth--;
      if (depth == 0) return i;
    }
  }
  return std::string::npos;
}

/* Extract a numeric value from JSON: "key":NNN */
static std::string json_extract_number(const std::string &json,
                                       const char *key) {
  std::string search = std::string("\"") + key + "\":";
  size_t pos = json.find(search);
  if (pos == std::string::npos) return "";
  pos += search.size();
  /* Skip whitespace */
  while (pos < json.size() && json[pos] == ' ') pos++;
  size_t end = pos;
  while (end < json.size() &&
         (isdigit(static_cast<unsigned char>(json[end])) ||
          json[end] == '.' || json[end] == '-'))
    end++;
  if (end == pos) return "";
  return json.substr(pos, end - pos);
}

/* -----------------------------------------------------------------------
 * File summary tracking
 * ----------------------------------------------------------------------- */

struct FileSummary {
  int64_t hosts_in_file;
  int64_t with_open_ports;
  int64_t total_ports;
  int64_t cves_found;
  int64_t earliest_seen;  /* Unix epoch */
  int64_t latest_seen;    /* Unix epoch */

  /* Patch-status counters. Populated as write_host_section walks each
     host and computes net_db_cve_diff(prev_cves, cves) per port. The
     "rescanned_hosts" counter is the number of hosts whose port rows
     have scan_count >= 2, i.e. ones we have data from more than one
     scan for and therefore have meaningful patch deltas to report. */
  int64_t patched_cves;     /* gone since prior scan */
  int64_t persisting_cves;  /* still present across scans */
  int64_t introduced_cves;  /* new this scan */
  int64_t rescanned_hosts;  /* hosts seen in >= 2 scans */
};

/* -----------------------------------------------------------------------
 * Write one host's report section to a file
 * ----------------------------------------------------------------------- */

static void write_host_section(FILE *fp, const std::string &ip,
                               const std::vector<NetHost> &ports,
                               FileSummary &summary) {
  summary.hosts_in_file++;

  fprintf(fp, "%s\n", separator_line().c_str());
  fprintf(fp, "  TARGET: %s\n", ip.c_str());
  fprintf(fp, "%s\n", separator_line().c_str());

  if (ports.empty()) {
    fprintf(fp, "  (no open ports found)\n\n");
    return;
  }

  summary.with_open_ports++;

  /* Track timestamps */
  for (const auto &p : ports) {
    if (p.first_seen > 0 &&
        (summary.earliest_seen == 0 || p.first_seen < summary.earliest_seen))
      summary.earliest_seen = p.first_seen;
    if (p.last_seen > summary.latest_seen)
      summary.latest_seen = p.last_seen;
  }

  /* PORT TABLE */
  fprintf(fp, "\n  PORT TABLE\n");
  fprintf(fp, "  %s\n", dash_line().c_str());
  fprintf(fp, "  %-14s%-10s%-16s%s\n", "PORT", "STATE", "SERVICE", "VERSION");

  bool has_cves = false;
  bool has_web  = false;

  for (const auto &p : ports) {
    summary.total_ports++;

    char port_str[32];
    snprintf(port_str, sizeof(port_str), "%d/%s",
             p.port, p.proto.c_str());

    fprintf(fp, "  %-14s%-10s%-16s%s\n",
            port_str,
            "open",
            p.service.empty() ? "unknown" : p.service.c_str(),
            p.version.c_str());
    if (!p.cpe.empty())
      fprintf(fp, "    CPE:     %s\n", p.cpe.c_str());
    if (!p.cloud_provider.empty())
      fprintf(fp, "    CLOUD:   %s%s%s\n", p.cloud_provider.c_str(),
              p.cloud_region.empty() ? "" : " / ", p.cloud_region.c_str());

    if (!p.cves.empty() && p.cves != "[]") has_cves = true;
    if (!p.web_title.empty() || !p.web_server.empty() ||
        (!p.web_paths.empty() && p.web_paths != "[]"))
      has_web = true;
  }

  /* CVE MAP section */
  if (has_cves) {
    fprintf(fp, "\n  CVE MAP\n");
    fprintf(fp, "  %s\n", dash_line().c_str());

    for (const auto &p : ports) {
      if (p.cves.empty() || p.cves == "[]") continue;

      char port_str[32];
      snprintf(port_str, sizeof(port_str), "%d/%s",
               p.port, p.proto.c_str());

      std::string header = std::string(port_str) + " " + p.service;
      if (!p.version.empty())
        header += " (" + p.version + ")";
      fprintf(fp, "  %s:\n", header.c_str());

      /* Parse CVE JSON array — iterate over entries.
       * Format: [{"id":"CVE-...","cvss":8.1,"severity":"HIGH","desc":"..."}] */
      std::string cves_str = p.cves;
      size_t search_pos = 0;
      while (true) {
        size_t obj_start = cves_str.find('{', search_pos);
        if (obj_start == std::string::npos) break;
        size_t obj_end = json_find_object_end(cves_str, obj_start);
        if (obj_end == std::string::npos) break;

        std::string obj = cves_str.substr(obj_start,
                                          obj_end - obj_start + 1);
        search_pos = obj_end + 1;

        std::string cve_id   = json_extract_string(obj, "id");
        std::string cvss_str = json_extract_number(obj, "cvss");
        std::string severity = json_extract_string(obj, "severity");
        std::string desc     = json_extract_string(obj, "desc");
        std::string remote   = json_extract_number(obj, "remote");
        std::string epss     = json_extract_number(obj, "epss");
        std::string kev      = json_extract_number(obj, "kev");
        std::string ransom   = json_extract_number(obj, "ransomware");

        if (cve_id.empty()) continue;
        summary.cves_found++;

        /* Tier-1 confidence tag: REMOTE = network/no-auth/no-UI;
           needs-auth/other = anything that requires auth or local access;
           unknown = legacy CVE row not yet backfilled with a v3 vector. */
        const char *conf_tag = "[unknown]";
        if (remote == "1")      conf_tag = "[REMOTE]";
        else if (remote == "0") conf_tag = "[needs-auth/other]";

        /* Exploit-triage tail: EPSS percentage + KEV / ransomware flags. */
        std::string triage;
        if (!epss.empty()) {
          char b[24];
          snprintf(b, sizeof(b), " EPSS:%.1f%%", atof(epss.c_str()) * 100.0);
          triage += b;
        }
        if (kev == "1") triage += (ransom == "1") ? " [KEV+RANSOMWARE]" : " [KEV]";

        fprintf(fp, "    %-18sCVSS:%-6s%-9s %s%s\n",
                cve_id.c_str(),
                cvss_str.empty() ? "N/A" : cvss_str.c_str(),
                severity.c_str(),
                conf_tag,
                triage.c_str());

        if (!desc.empty()) {
          if (desc.size() > 70) desc = desc.substr(0, 67) + "...";
          fprintf(fp, "      %s\n", desc.c_str());
        }
      }
    }
  }

  /* PATCH STATUS section
     ---------------------
     Emitted only for hosts that have been enriched at least twice
     (any port row has prev_cves non-empty OR a previous enriched_at).
     Lists the per-port diff between prev_cves and cves so a re-scan
     surfaces "what was patched" (CVE was on this host last scan, gone
     now), "still vulnerable", and "newly introduced since last scan".

     This is the headline value of keeping prev_* columns: an operator
     scanning the same range a year apart immediately sees what the
     defenders fixed and what regressed. */
  bool host_was_rescanned = false;
  for (const auto &p : ports) {
    if (!p.prev_cves.empty() || p.prev_enriched_at > 0 || p.scan_count >= 2) {
      host_was_rescanned = true;
      break;
    }
  }
  if (host_was_rescanned) {
    summary.rescanned_hosts++;
    fprintf(fp, "\n  PATCH STATUS\n");
    fprintf(fp, "  %s\n", dash_line().c_str());

    for (const auto &p : ports) {
      /* Skip ports that have no prior state to compare against. We
         still want to render rescanned hosts even when one of their
         ports is brand new -- that fact itself is interesting -- so
         the per-port skip is independent of host_was_rescanned. */
      if (p.prev_cves.empty() && p.prev_enriched_at == 0 && p.scan_count < 2)
        continue;

      char port_str[32];
      snprintf(port_str, sizeof(port_str), "%d/%s",
               p.port, p.proto.c_str());

      /* Header line shows port + scan-count and the time since the
         previous enrichment so the reader knows the baseline date. The
         service-prefix string is hoisted to a named std::string variable
         instead of being computed inline as ("" or " " + service).c_str()
         in the fprintf args -- that inline form relies on full-expression
         temporary lifetime extension, which MSVC has historically been
         flaky about across the conditional operator. Hoisting removes
         the question entirely. */
      std::string svc_part;
      if (!p.service.empty()) svc_part = " " + p.service;

      std::string when;
      if (p.prev_enriched_at > 0) {
        when = " (prev scan ";
        when += format_date(p.prev_enriched_at);
        when += ")";
      } else if (p.scan_count >= 2) {
        when = " (rediscovered, no prior enrichment)";
      }
      fprintf(fp, "  %s%s [scans=%d]%s\n",
              port_str, svc_part.c_str(),
              p.scan_count, when.c_str());

      /* Service / version drift -- a port flipping from OpenSSH to
         nginx is itself a finding (port reassigned), and a version
         bump even with the same CVEs implies a partial patch. */
      if (!p.prev_service.empty() && p.prev_service != p.service) {
        fprintf(fp, "    SERVICE:   %s -> %s\n",
                p.prev_service.c_str(),
                p.service.empty() ? "(none)" : p.service.c_str());
      }
      if (!p.prev_version.empty() && p.prev_version != p.version) {
        fprintf(fp, "    VERSION:   %s -> %s\n",
                p.prev_version.c_str(),
                p.version.empty() ? "(none)" : p.version.c_str());
      }

      NetDbCveDiff d = net_db_cve_diff(p.prev_cves, p.cves);
      summary.patched_cves    += static_cast<int64_t>(d.patched.size());
      summary.persisting_cves += static_cast<int64_t>(d.persisting.size());
      summary.introduced_cves += static_cast<int64_t>(d.introduced.size());

      auto print_list = [&](const char *label,
                            const std::vector<std::string> &v) {
        if (v.empty()) return;
        fprintf(fp, "    %-10s ", label);
        /* Wrap at ~6 IDs per line so the report stays readable when
           a host has dozens of CVEs (legacy appliances commonly do). */
        const size_t per_line = 6;
        for (size_t k = 0; k < v.size(); k++) {
          fprintf(fp, "%s%s", v[k].c_str(),
                  (k + 1 < v.size()) ? ", " : "\n");
          if ((k + 1) % per_line == 0 && k + 1 < v.size())
            fprintf(fp, "\n               ");
        }
      };
      print_list("PATCHED:",    d.patched);
      print_list("PERSISTING:", d.persisting);
      print_list("NEW:",        d.introduced);

      /* All-clear case: a host whose prev had CVEs and current has
         none is the cleanest possible "good news" signal -- call it
         out explicitly so it does not get lost in the file. */
      if (!d.patched.empty() && d.persisting.empty() && d.introduced.empty())
        fprintf(fp, "    STATUS:    fully patched since last scan\n");
    }
  }

  /* WEB RECON section */
  if (has_web) {
    fprintf(fp, "\n  WEB RECON\n");
    fprintf(fp, "  %s\n", dash_line().c_str());

    for (const auto &p : ports) {
      if (p.web_title.empty() && p.web_server.empty() &&
          p.web_paths.empty())
        continue;

      /* Determine protocol label */
      std::string proto = "http";
      if (p.port == 443 || p.port == 8443 || p.port == 4443)
        proto = "https";
      if (!p.service.empty() &&
          p.service.find("https") != std::string::npos)
        proto = "https";

      fprintf(fp, "  Port %d/%s:\n", p.port, proto.c_str());

      if (!p.web_title.empty())
        fprintf(fp, "    Title:   %s\n", p.web_title.c_str());
      if (!p.web_server.empty())
        fprintf(fp, "    Server:  %s\n", p.web_server.c_str());

      /* Parse web_paths JSON for path results */
      if (!p.web_paths.empty() && p.web_paths != "[]") {
        std::string paths = p.web_paths;
        size_t spos = 0;
        while (true) {
          size_t ostart = paths.find('{', spos);
          if (ostart == std::string::npos) break;
          size_t oend = json_find_object_end(paths, ostart);
          if (oend == std::string::npos) break;

          std::string obj = paths.substr(ostart, oend - ostart + 1);
          spos = oend + 1;

          std::string path   = json_extract_string(obj, "path");
          std::string status = json_extract_number(obj, "status");
          std::string title  = json_extract_string(obj, "title");
          std::string redir  = json_extract_string(obj, "redirect_to");

          if (path.empty() || status.empty()) continue;

          if (!redir.empty())
            fprintf(fp, "    [%s] %s -> %s\n",
                    status.c_str(), path.c_str(), redir.c_str());
          else if (!title.empty())
            fprintf(fp, "    [%s] %s  \"%s\"\n",
                    status.c_str(), path.c_str(), title.c_str());
          else
            fprintf(fp, "    [%s] %s\n", status.c_str(), path.c_str());
        }
      }
    }
  }

  fprintf(fp, "\n");
}

/* -----------------------------------------------------------------------
 * Write file header
 * ----------------------------------------------------------------------- */

static void write_file_header(FILE *fp, const std::string &first_ip,
                              const std::string &last_ip,
                              int64_t host_count) {
  /* Use the reentrant variant to match format_date() at the top of this
   * file -- mixing localtime() (returns a shared static buffer) with
   * localtime_r/localtime_s elsewhere means any future concurrent
   * report-generation path would silently corrupt one of the two. */
  time_t now = time(nullptr);
  struct tm tm_buf{};
#ifdef WIN32
  if (localtime_s(&tm_buf, &now) != 0) tm_buf = {};
#else
  if (!localtime_r(&now, &tm_buf)) tm_buf = {};
#endif
  char timebuf[64];
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_buf);

  fprintf(fp, "%s\n", separator_line().c_str());
  /* Center the title within 80 chars */
  const char *title = "KMAP NET SCAN FINDINGS";
  int title_len = static_cast<int>(strlen(title));
  int pad = (SEPARATOR_WIDTH - title_len) / 2;
  fprintf(fp, "%*s%s\n", pad, "", title);
  fprintf(fp, "%s\n", separator_line().c_str());
  fprintf(fp, "  Generated: %s\n", timebuf);
  fprintf(fp, "  IP Range:  %s - %s\n", first_ip.c_str(), last_ip.c_str());
  fprintf(fp, "  Hosts:     %s\n", format_count(host_count).c_str());
  fprintf(fp, "%s\n\n", separator_line().c_str());
}

/* -----------------------------------------------------------------------
 * Write file summary footer
 * ----------------------------------------------------------------------- */

static void write_file_summary(FILE *fp, const FileSummary &summary) {
  fprintf(fp, "%s\n", separator_line().c_str());
  fprintf(fp, "  FILE SUMMARY\n");
  fprintf(fp, "%s\n", separator_line().c_str());
  fprintf(fp, "  Hosts in file:   %s\n",
          format_count(summary.hosts_in_file).c_str());
  fprintf(fp, "  With open ports:  %s\n",
          format_count(summary.with_open_ports).c_str());
  fprintf(fp, "  Total ports:      %s\n",
          format_count(summary.total_ports).c_str());
  fprintf(fp, "  CVEs found:       %s\n",
          format_count(summary.cves_found).c_str());

  /* Patch-status summary -- only meaningful when at least one host in
     the file was rescanned. Suppress the lines on first-ever scans so
     the footer does not show four "0" lines that mean nothing. */
  if (summary.rescanned_hosts > 0) {
    fprintf(fp, "  Rescanned hosts:  %s\n",
            format_count(summary.rescanned_hosts).c_str());
    fprintf(fp, "  Patched CVEs:     %s\n",
            format_count(summary.patched_cves).c_str());
    fprintf(fp, "  Persisting CVEs:  %s\n",
            format_count(summary.persisting_cves).c_str());
    fprintf(fp, "  New CVEs:         %s\n",
            format_count(summary.introduced_cves).c_str());
  }

  std::string period;
  if (summary.earliest_seen > 0 && summary.latest_seen > 0)
    period = format_date(summary.earliest_seen) + " to "
           + format_date(summary.latest_seen);
  else
    period = "unknown";
  fprintf(fp, "  Scan period:      %s\n", period.c_str());
  fprintf(fp, "%s\n", separator_line().c_str());
}

/* -----------------------------------------------------------------------
 * generate_findings — main entry point
 * ----------------------------------------------------------------------- */

int generate_findings(const char *data_dir, const char *findings_dir) {
  if (!data_dir || !findings_dir) return 1;

  report_mkdir(findings_dir);

  /* Shards are partitioned by the top 5 bits of the IP (see
     net_shard_index in net_db.cc), so iterating shards 0..31 in order
     already gives globally IP-prefix-ordered output. Within each shard
     we still need a numeric sort because lexicographic ordering of dotted
     strings ("1.x" < "10." < "2.x") puts hosts in the wrong order.

     The previous implementation loaded every host from every shard into
     one std::vector before sorting -- O(total hosts) memory, fine for the
     150-IP watchlist case but a non-starter for the full-IPv4 sweep this
     tool is designed for. The streaming form below caps peak memory at
     one shard's IP list plus a single HOSTS_PER_FILE-bounded batch
     buffer that carries forward across shard boundaries so output files
     keep the original even-sized batching. */

  struct IpEntry {
    std::string ip;
    int shard_idx;
  };

  sqlite3 *shard_dbs[NET_SHARD_COUNT] = {};
  int64_t total_hosts = 0;

  log_write(LOG_STDOUT,
    "net-scan: collecting hosts from shard databases...\n");

  for (int shard = 0; shard < NET_SHARD_COUNT; shard++) {
    std::string db_path = net_shard_path(data_dir, shard);

    FILE *test = fopen(db_path.c_str(), "r");
    if (!test) continue;
    fclose(test);

    sqlite3 *db = net_db_open(db_path);
    if (!db) {
      log_write(LOG_STDOUT,
        "net-scan: WARNING: cannot open %s -- skipping.\n",
        db_path.c_str());
      continue;
    }
    shard_dbs[shard] = db;

    /* Count without materializing -- needed up front so progress
       percentages and the trailing filename range (last batch may be
       short) are correct as we stream. */
    sqlite3_stmt *cnt = nullptr;
    if (sqlite3_prepare_v2(db,
          "SELECT COUNT(DISTINCT ip) FROM hosts",
          -1, &cnt, nullptr) == SQLITE_OK) {
      if (sqlite3_step(cnt) == SQLITE_ROW)
        total_hosts += sqlite3_column_int64(cnt, 0);
      sqlite3_finalize(cnt);
    }
  }

  if (total_hosts == 0) {
    log_write(LOG_STDOUT,
      "net-scan: no hosts found in shard databases.\n");
    for (int i = 0; i < NET_SHARD_COUNT; i++)
      if (shard_dbs[i]) net_db_close(shard_dbs[i]);
    return 0;
  }

  log_write(LOG_STDOUT,
    "net-scan: generating findings for %s hosts...\n",
    format_count(total_hosts).c_str());

  std::vector<IpEntry> batch;
  batch.reserve(HOSTS_PER_FILE);
  int64_t emitted_total = 0;
  int64_t file_count = 0;

  auto flush_batch = [&]() {
    if (batch.empty()) return;
    int64_t batch_start = emitted_total + 1;
    int64_t batch_count = static_cast<int64_t>(batch.size());
    int64_t batch_end = emitted_total + batch_count;

    char filename[512];
    snprintf(filename, sizeof(filename),
             "%s/findings_%07lld-%07lld.txt",
             findings_dir,
             (long long)batch_start,
             (long long)batch_end);

    FILE *fp = fopen(filename, "w");
    if (!fp) {
      log_write(LOG_STDOUT,
        "net-scan: ERROR: cannot create %s\n", filename);
      emitted_total = batch_end;
      file_count++;
      batch.clear();
      return;
    }

    write_file_header(fp,
                      batch.front().ip,
                      batch.back().ip,
                      batch_count);

    FileSummary summary{};
    for (const auto &entry : batch) {
      sqlite3 *db = shard_dbs[entry.shard_idx];
      std::vector<NetHost> ports;
      if (db) ports = net_db_get_host(db, entry.ip.c_str());
      write_host_section(fp, entry.ip, ports, summary);
    }

    write_file_summary(fp, summary);
    fclose(fp);

    double pct = 100.0 * static_cast<double>(batch_end) /
                 static_cast<double>(total_hosts);
    log_write(LOG_STDOUT,
      "net-scan: wrote %s (%s / %s hosts) [%.1f%%]\n",
      filename,
      format_count(batch_end).c_str(),
      format_count(total_hosts).c_str(),
      pct);

    emitted_total = batch_end;
    file_count++;
    batch.clear();
  };

  for (int shard = 0; shard < NET_SHARD_COUNT; shard++) {
    sqlite3 *db = shard_dbs[shard];
    if (!db) continue;

    std::vector<IpEntry> shard_ips;
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db,
          "SELECT DISTINCT ip FROM hosts",
          -1, &stmt, nullptr) == SQLITE_OK) {
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *txt = sqlite3_column_text(stmt, 0);
        if (txt) {
          shard_ips.push_back({
            std::string(reinterpret_cast<const char *>(txt)),
            shard
          });
        }
      }
      sqlite3_finalize(stmt);
    }
    if (shard_ips.empty()) continue;

    /* Numeric sort within shard. Pre-compute keys so the comparator is
       O(1) instead of re-parsing dotted-quad per compare. */
    std::vector<uint32_t> keys(shard_ips.size());
    for (size_t i = 0; i < shard_ips.size(); i++)
      keys[i] = ip_to_u32(shard_ips[i].ip.c_str());

    std::vector<size_t> order(shard_ips.size());
    for (size_t i = 0; i < order.size(); i++) order[i] = i;
    std::sort(order.begin(), order.end(),
      [&keys](size_t a, size_t b) { return keys[a] < keys[b]; });

    for (size_t idx : order) {
      batch.push_back(std::move(shard_ips[idx]));
      if (static_cast<int64_t>(batch.size()) >= HOSTS_PER_FILE)
        flush_batch();
    }
    /* shard_ips + keys + order go out of scope here -- memory released
       before opening the next shard. */
  }

  flush_batch();

  for (int i = 0; i < NET_SHARD_COUNT; i++) {
    if (shard_dbs[i]) net_db_close(shard_dbs[i]);
  }

  log_write(LOG_STDOUT,
    "net-scan: report generation complete -- %lld file(s) in %s/\n",
    (long long)file_count, findings_dir);

  return 0;
}
