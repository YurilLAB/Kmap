/*
 * net_scan.cc -- Internet-scale scanning orchestrator for Kmap.
 *
 * Coordinates the pipeline: discover → enrich → report.
 * Also handles watchlist mode and the --net-query search interface.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_scan.h"
#include "net_db.h"
#include "fast_syn.h"
#include "net_enrich.h"
#include "net_report.h"
#include "net_query.h"
#include "KmapOps.h"
#include "kmap.h"
#include "output.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <fstream>
#include <set>

#ifndef WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>
#endif

extern KmapOps o;

/* -----------------------------------------------------------------------
 * Watchlist scanning
 *
 * Reads IPs from a file, scans just those targets, compares against
 * previous results in watchlist.db, outputs diff + full report.
 * ----------------------------------------------------------------------- */

static int run_watchlist(const char *targets_file, const char *data_dir,
                         const char *findings_dir) {
  /* Read target IPs from file */
  std::vector<uint32_t> targets;
  std::ifstream f(targets_file);
  if (!f.is_open()) {
    fprintf(stderr, "net-scan: cannot open watchlist file: %s\n", targets_file);
    return 1;
  }

  std::string line;
  while (std::getline(f, line)) {
    size_t start = line.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) continue;
    line = line.substr(start);
    line.erase(line.find_last_not_of(" \t\r\n") + 1);
    if (line.empty() || line[0] == '#') continue;

    /* Handle CIDR notation — expand small ranges */
    size_t slash = line.find('/');
    if (slash != std::string::npos) {
      int prefix = atoi(line.substr(slash + 1).c_str());
      if (prefix < 0 || prefix > 32) {
        fprintf(stderr, "watchlist: invalid CIDR prefix /%d in '%s'\n",
                prefix, line.c_str());
        continue;
      }
      uint32_t base = ip_to_u32(line.substr(0, slash).c_str());
      if (prefix >= 24 && prefix <= 30) {
        uint32_t count = 1u << (32 - prefix);
        uint32_t mask = ~(count - 1);
        base &= mask;
        for (uint32_t i = 1; i < count - 1; i++) /* skip network + broadcast */
          targets.push_back(base + i);
      } else if (prefix == 31) {
        /* /31: RFC 3021 point-to-point — both addresses usable */
        uint32_t mask = ~1u;
        base &= mask;
        targets.push_back(base);
        targets.push_back(base + 1);
      } else if (prefix == 32) {
        /* /32: single host */
        targets.push_back(base);
      } else {
        /* Large range — just add the base */
        targets.push_back(base);
      }
    } else {
      uint32_t ip = ip_to_u32(line.c_str());
      if (ip != 0) targets.push_back(ip);
    }
  }

  if (targets.empty()) {
    fprintf(stderr, "net-scan: no valid targets in %s\n", targets_file);
    return 1;
  }

  log_write(LOG_STDOUT, "\nnet-scan: Watchlist mode — %d targets from %s\n",
            (int)targets.size(), targets_file);

  /* Open watchlist database */
  std::string wl_path = std::string(data_dir) + "/watchlist.db";
  sqlite3 *wl_db = net_db_open(wl_path);
  if (!wl_db) return 1;

  /* Load previous state for diff */
  struct PrevEntry {
    std::string ip;
    int port;
    std::string service;
    std::string version;
    std::string cves;
    std::string web_title;
  };
  std::vector<PrevEntry> prev_state;
  {
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(wl_db,
      "SELECT ip, port, service, version, cves, web_title FROM hosts",
      -1, &stmt, nullptr);
    if (stmt) {
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        PrevEntry pe;
        auto col = [&](int c) -> std::string {
          const unsigned char *p = sqlite3_column_text(stmt, c);
          return p ? reinterpret_cast<const char *>(p) : "";
        };
        pe.ip = col(0);
        pe.port = sqlite3_column_int(stmt, 1);
        pe.service = col(2);
        pe.version = col(3);
        pe.cves = col(4);
        pe.web_title = col(5);
        prev_state.push_back(pe);
      }
      sqlite3_finalize(stmt);
    }
  }

  /* Clear old data and re-scan */
  sqlite3_exec(wl_db, "DELETE FROM hosts", nullptr, nullptr, nullptr);

  /* Scan each target — using connect probes for the top ports */
  std::vector<int> ports = parse_port_spec(nullptr); /* top 100 */
  int64_t now_ts = static_cast<int64_t>(time(nullptr));

  net_db_begin(wl_db);
  int found = 0;
  for (uint32_t ip : targets) {
    for (int port : ports) {
      /* Quick connect probe with 2s timeout */
      struct sockaddr_in sa{};
      sa.sin_family = AF_INET;
      sa.sin_port = htons(static_cast<uint16_t>(port));
      sa.sin_addr.s_addr = htonl(ip);

#ifdef WIN32
      SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd == INVALID_SOCKET) continue;
      u_long nb = 1;
      ioctlsocket(fd, FIONBIO, &nb);
#else
      int fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0) continue;
      int flags = fcntl(fd, F_GETFL, 0);
      fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

      connect(fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa));
      fd_set wset;
      FD_ZERO(&wset);
      FD_SET(fd, &wset);
      struct timeval tv;
      tv.tv_sec = 2;
      tv.tv_usec = 0;

      bool open = false;
#ifdef WIN32
      /* Windows ignores the nfds argument; using a fixed value avoids the
       * SOCKET-to-int truncation warning on 64-bit builds. */
      if (select(0, nullptr, &wset, nullptr, &tv) > 0) {
#else
      if (select(fd + 1, nullptr, &wset, nullptr, &tv) > 0) {
#endif
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&err), &elen);
        open = (err == 0);
      }

#ifdef WIN32
      closesocket(fd);
#else
      close(fd);
#endif

      if (open) {
        net_db_insert_host(wl_db, ip, port, "tcp", now_ts);
        found++;
      }
    }
  }
  net_db_commit(wl_db);

  log_write(LOG_STDOUT, "  Discovery: %d open ports found\n", found);

  /* Enrich the watchlist hosts using the enrichment pipeline */
  log_write(LOG_STDOUT, "  Enriching watchlist hosts...\n");
  {
    std::vector<std::string> unenriched = net_db_get_unenriched(wl_db, 10000);
    /* Locate CVE database */
    char cve_buf[1024];
    std::string cve_db_path;
    if (kmap_fetchfile(cve_buf, sizeof(cve_buf), "kmap-cve.db") > 0)
      cve_db_path = cve_buf;

    int enriched_count = 0;
    int enrich_errors = 0;
    net_db_begin(wl_db);
    for (const auto &ip_str : unenriched) {
      auto host_ports = net_db_get_host(wl_db, ip_str.c_str());
      if (host_ports.empty()) continue;

      std::vector<int> port_nums;
      std::vector<std::string> protos;
      for (const auto &h : host_ports) {
        port_nums.push_back(h.port);
        protos.push_back(h.proto);
      }

      std::vector<std::string> services, versions, cves_out;
      std::vector<std::string> web_titles, web_servers, web_headers, web_paths;

      int erc = enrich_single_host(ip_str.c_str(), port_nums, protos,
                         cve_db_path.empty() ? nullptr : cve_db_path.c_str(),
                         5000, services, versions, cves_out,
                         web_titles, web_servers, web_headers, web_paths);

      if (erc != 0) {
        /* Enrichment failed for this host -- mark as enriched with empty
           data so it doesn't retry, and continue to next host */
        log_write(LOG_STDOUT, "  WARNING: enrichment failed for %s, skipping\n",
                  ip_str.c_str());
        for (size_t i = 0; i < port_nums.size(); i++) {
          net_db_update_enrichment(wl_db, ip_str.c_str(), port_nums[i],
                                   "", "", "", "", "", "", "");
        }
        enrich_errors++;
        continue;
      }

      for (size_t i = 0; i < port_nums.size(); i++) {
        net_db_update_enrichment(wl_db, ip_str.c_str(), port_nums[i],
          i < services.size() ? services[i].c_str() : "",
          i < versions.size() ? versions[i].c_str() : "",
          i < cves_out.size() ? cves_out[i].c_str() : "",
          i < web_titles.size() ? web_titles[i].c_str() : "",
          i < web_servers.size() ? web_servers[i].c_str() : "",
          i < web_headers.size() ? web_headers[i].c_str() : "",
          i < web_paths.size() ? web_paths[i].c_str() : "");
      }
      enriched_count++;
    }
    net_db_commit(wl_db);
    log_write(LOG_STDOUT, "  Enriched %d hosts", enriched_count);
    if (enrich_errors > 0)
      log_write(LOG_STDOUT, " (%d failed)", enrich_errors);
    log_write(LOG_STDOUT, "\n");
  }

  /* Generate diff */
  std::string wl_dir = std::string(findings_dir) + "/watchlist";
#ifdef WIN32
  _mkdir(findings_dir);
  _mkdir(wl_dir.c_str());
#else
  mkdir(findings_dir, 0755);
  mkdir(wl_dir.c_str(), 0755);
#endif

  /* Get current state */
  std::vector<NetHost> current;
  {
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(wl_db,
      "SELECT ip, port, proto, service, version, cves, web_title FROM hosts",
      -1, &stmt, nullptr);
    if (stmt) {
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        NetHost h;
        auto col = [&](int c) -> std::string {
          const unsigned char *p = sqlite3_column_text(stmt, c);
          return p ? reinterpret_cast<const char *>(p) : "";
        };
        h.ip = col(0);
        h.port = sqlite3_column_int(stmt, 1);
        h.proto = col(2);
        h.service = col(3);
        h.version = col(4);
        h.cves = col(5);
        h.web_title = col(6);
        current.push_back(h);
      }
      sqlite3_finalize(stmt);
    }
  }

  /* Write diff report */
  char datebuf[32];
  {
    time_t now = time(nullptr);
    struct tm *tm = localtime(&now);
    strftime(datebuf, sizeof(datebuf), "%Y-%m-%d", tm);
  }

  std::string diff_path = wl_dir + "/diff_" + datebuf + ".txt";
  FILE *diff_fp = fopen(diff_path.c_str(), "w");
  if (!diff_fp) {
    log_write(LOG_STDOUT, "  WARNING: cannot create diff report %s, skipping\n",
              diff_path.c_str());
  }
  if (diff_fp) {
    fprintf(diff_fp, "================================================================================\n");
    fprintf(diff_fp, "                    WATCHLIST DIFF — %s\n", datebuf);
    fprintf(diff_fp, "================================================================================\n");
    fprintf(diff_fp, "  Targets scanned: %d\n", (int)targets.size());

    /* Build lookup maps */
    std::set<std::string> prev_keys, curr_keys;
    for (const auto &pe : prev_state) {
      std::string key = pe.ip + ":" + std::to_string(pe.port);
      prev_keys.insert(key);
    }
    for (const auto &h : current) {
      std::string key = h.ip + ":" + std::to_string(h.port);
      curr_keys.insert(key);
    }

    int changes = 0;

    /* New ports */
    for (const auto &h : current) {
      std::string key = h.ip + ":" + std::to_string(h.port);
      if (prev_keys.find(key) == prev_keys.end()) {
        fprintf(diff_fp, "\n  [NEW PORT] %s:%d/%s\n", h.ip.c_str(), h.port, h.proto.c_str());
        if (!h.service.empty())
          fprintf(diff_fp, "    Service: %s  Version: %s\n", h.service.c_str(), h.version.c_str());
        changes++;
      }
    }

    /* Closed ports */
    for (const auto &pe : prev_state) {
      std::string key = pe.ip + ":" + std::to_string(pe.port);
      if (curr_keys.find(key) == curr_keys.end()) {
        fprintf(diff_fp, "\n  [CLOSED] %s:%d\n", pe.ip.c_str(), pe.port);
        if (!pe.service.empty())
          fprintf(diff_fp, "    Was: %s %s\n", pe.service.c_str(), pe.version.c_str());
        changes++;
      }
    }

    fprintf(diff_fp, "\n  Changes detected: %d\n", changes);
    fprintf(diff_fp, "================================================================================\n");
    fclose(diff_fp);

    log_write(LOG_STDOUT, "  Diff report: %s (%d changes)\n", diff_path.c_str(), changes);
  }

  /* Write full report */
  std::string full_path = wl_dir + "/full_" + datebuf + ".txt";
  FILE *full_fp = fopen(full_path.c_str(), "w");
  if (!full_fp) {
    log_write(LOG_STDOUT, "  WARNING: cannot create full report %s, skipping\n",
              full_path.c_str());
  }
  if (full_fp) {
    fprintf(full_fp, "================================================================================\n");
    fprintf(full_fp, "                    WATCHLIST FULL REPORT — %s\n", datebuf);
    fprintf(full_fp, "================================================================================\n");
    fprintf(full_fp, "  Targets: %d | Open ports: %d\n\n", (int)targets.size(), (int)current.size());

    std::string last_ip;
    for (const auto &h : current) {
      if (h.ip != last_ip) {
        if (!last_ip.empty()) fprintf(full_fp, "\n");
        fprintf(full_fp, "================================================================================\n");
        fprintf(full_fp, "  TARGET: %s\n", h.ip.c_str());
        fprintf(full_fp, "================================================================================\n");
        last_ip = h.ip;
      }
      fprintf(full_fp, "  %d/%s  %s  %s\n",
              h.port, h.proto.c_str(),
              h.service.empty() ? "unknown" : h.service.c_str(),
              h.version.c_str());
    }
    fprintf(full_fp, "\n================================================================================\n");
    fclose(full_fp);

    log_write(LOG_STDOUT, "  Full report: %s\n", full_path.c_str());
  }

  net_db_close(wl_db);
  return 0;
}

/* -----------------------------------------------------------------------
 * Main orchestrator
 * ----------------------------------------------------------------------- */

int run_net_scan() {
  const char *data_dir = o.net_data_dir ? o.net_data_dir : "kmap-data";
  const char *findings_dir = o.net_findings_dir ? o.net_findings_dir : "Findings";

  /* Validate that data-dir is writable before starting scan */
  {
    std::string test_path = std::string(data_dir) + "/.kmap_write_test";
    FILE *test_fp = fopen(test_path.c_str(), "w");
    if (test_fp) {
      fclose(test_fp);
      remove(test_path.c_str());
    } else {
      /* Try creating the directory first, then re-test */
#ifdef WIN32
      _mkdir(data_dir);
#else
      mkdir(data_dir, 0755);
#endif
      test_fp = fopen(test_path.c_str(), "w");
      if (test_fp) {
        fclose(test_fp);
        remove(test_path.c_str());
      } else {
        fprintf(stderr,
          "net-scan: ERROR: --data-dir '%s' is not writable\n", data_dir);
        return 1;
      }
    }
  }

  /* Watchlist mode */
  if (o.net_watchlist) {
    return run_watchlist(o.net_watchlist, data_dir, findings_dir);
  }

  int rc = 0;

  /* Phase 1: Discover */
  if (!o.net_enrich_only && !o.net_report_only) {
    /* Build exclusion list */
    auto excludes = builtin_excludes();
    if (o.net_exclude_file) {
      auto user_excl = load_exclude_list(o.net_exclude_file);
      excludes.insert(excludes.end(), user_excl.begin(), user_excl.end());
    }

    /* Parse ports */
    std::vector<int> ports = parse_port_spec(
      o.portlist ? o.portlist : nullptr);

    int rate = o.net_rate > 0 ? o.net_rate : 25000;

    rc = fast_syn_scan(data_dir, ports, rate, excludes, o.net_resume);
    if (rc != 0) {
      fprintf(stderr, "net-scan: discovery phase failed\n");
      return rc;
    }

    if (o.net_discover_only) return 0;
  }

  /* Phase 2: Enrich */
  if (!o.net_discover_only && !o.net_report_only) {
    log_write(LOG_STDOUT, "\nnet-scan: Starting enrichment phase\n");
    rc = run_enrichment(data_dir, 1000);
    if (rc != 0) {
      fprintf(stderr, "net-scan: enrichment phase had errors (continuing to report)\n");
      /* Non-fatal — generate report with whatever was enriched */
    }

    if (o.net_enrich_only) return 0;
  }

  /* Phase 3: Report */
  if (!o.net_discover_only && !o.net_enrich_only) {
    log_write(LOG_STDOUT, "\nnet-scan: Generating findings reports\n");
    rc = generate_findings(data_dir, findings_dir);
    if (rc != 0) {
      fprintf(stderr, "net-scan: report generation had errors\n");
    }
  }

  return rc;
}

/* -----------------------------------------------------------------------
 * Query interface
 * ----------------------------------------------------------------------- */

int run_net_query_cli() {
  const char *data_dir = o.net_data_dir ? o.net_data_dir : "kmap-data";

  return run_net_query(
    data_dir,
    o.nq_port,
    o.nq_service,
    o.nq_cve,
    o.nq_min_cvss,
    o.nq_web_title,
    o.nq_web_server,
    o.nq_ip_range,
    o.nq_output,
    o.nq_count
  );
}
