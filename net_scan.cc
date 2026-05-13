/*
 * net_scan.cc -- Internet-scale scanning orchestrator for Kmap.
 *
 * Coordinates the pipeline: discover -> enrich -> report.
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
#include "os_profile.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <fstream>
#include <set>
#include <map>
#include <algorithm>

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

    /* Handle CIDR notation -- expand small ranges */
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
        /* /31: RFC 3021 point-to-point -- both addresses usable */
        uint32_t mask = ~1u;
        base &= mask;
        targets.push_back(base);
        targets.push_back(base + 1);
      } else if (prefix == 32) {
        /* /32: single host */
        targets.push_back(base);
      } else {
        /* Large range -- just add the base */
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

  log_write(LOG_STDOUT, "\nnet-scan: Watchlist mode -- %d targets from %s\n",
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

  /* Scan each target -- using connect probes for the top ports */
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

      /* OS spoofing profile (--spoof-os). No-op when not set. Stable
         per-target: same IP -> same profile across retries / port loops. */
      os_profile_apply_socket(static_cast<intptr_t>(fd), AF_INET,
                              os_profile_get_for_target(
                                  o.spoof_os,
                                  os_profile_seed_from_ipv4(ip)));

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
      std::vector<std::string> powered_by, x_generator, redirects;
      std::vector<TlsCapture> tls_caps;

      int erc = enrich_single_host(ip_str.c_str(), port_nums, protos,
                         cve_db_path.empty() ? nullptr : cve_db_path.c_str(),
                         5000, services, versions, cves_out,
                         web_titles, web_servers, web_headers, web_paths,
                         powered_by, x_generator, redirects,
                         &tls_caps);

      if (erc != 0) {
        /* Enrichment failed for this host -- record the error so the row
           stays eligible for retry once the cooldown elapses, and continue
           to the next host. */
        log_write(LOG_STDOUT, "  WARNING: enrichment failed for %s, will retry later\n",
                  ip_str.c_str());
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf), "enrich_single_host rc=%d", erc);
        for (size_t i = 0; i < port_nums.size(); i++) {
          net_db_record_enrichment_error(wl_db, ip_str.c_str(), port_nums[i],
                                         err_buf);
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
          i < web_paths.size() ? web_paths[i].c_str() : "",
          i < powered_by.size() ? powered_by[i].c_str() : nullptr,
          i < x_generator.size() ? x_generator[i].c_str() : nullptr,
          i < redirects.size() ? redirects[i].c_str() : nullptr,
          nullptr /* robots_disallowed_json: not captured by net_enrich path */);

        /* TLS cert details — watchlist mode wants this most of all, since
           cert rotation on a tracked asset is a strong tampering signal. */
        if (i < tls_caps.size()) {
          const TlsCapture &tc = tls_caps[i];
          bool have_tls = !tc.subject_cn.empty() || !tc.issuer.empty() ||
                          !tc.sha256.empty()     || !tc.protocol.empty();
          if (have_tls) {
            net_db_update_tls(
              wl_db, ip_str.c_str(), port_nums[i],
              tc.subject_cn.empty() ? nullptr : tc.subject_cn.c_str(),
              tc.issuer.empty()     ? nullptr : tc.issuer.c_str(),
              tc.san_json.empty()   ? nullptr : tc.san_json.c_str(),
              tc.not_after.empty()  ? nullptr : tc.not_after.c_str(),
              tc.self_signed,
              tc.protocol.empty()   ? nullptr : tc.protocol.c_str(),
              tc.sha256.empty()     ? nullptr : tc.sha256.c_str());
          }
        }
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
    fprintf(diff_fp, "                    WATCHLIST DIFF -- %s\n", datebuf);
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
    fprintf(full_fp, "                    WATCHLIST FULL REPORT -- %s\n", datebuf);
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
      /* Non-fatal -- generate report with whatever was enriched */
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

/* -----------------------------------------------------------------------
 * Relationship cluster lookup
 *
 * Two-phase walk:
 *   1. Open the shard that owns o.nc_ip and pull every fingerprint row
 *      that IP carries.
 *   2. For each (kind, value) the target carries, walk all 32 shards and
 *      collect the IPs that also carry it (i.e. the cohort that shares
 *      this fingerprint with the target).
 * The cohort map (ip -> set of matching kind:value strings) deduplicates
 * across kinds, so an IP that shares both a SAN and a tls_sha256 with
 * the target shows up once with both signals listed.
 *
 * Output: one line per cohort IP, prefixed by the share count.  The
 * format is pipeable: `kmap --net-cluster 1.2.3.4 | awk '{print $1}'`
 * gets a clean IP list ready for downstream chaining (e.g. into
 * tracemap or another scan).
 * ----------------------------------------------------------------------- */

int run_net_cluster_cli() {
  if (!o.nc_ip || !o.nc_ip[0]) {
    fprintf(stderr, "net-cluster: --net-cluster requires an IP argument\n");
    return 1;
  }
  uint32_t target_u32 = ip_to_u32(o.nc_ip);
  if (target_u32 == 0) {
    fprintf(stderr, "net-cluster: cannot parse IP '%s'\n", o.nc_ip);
    return 1;
  }

  const char *data_dir = o.net_data_dir ? o.net_data_dir : "kmap-data";
  int min_shared = o.nc_min_shared > 0 ? o.nc_min_shared : 1;

  /* Step 1: get the target's own fingerprint set from its shard. */
  int target_shard = net_shard_index(target_u32);
  std::string target_shard_path = net_shard_path(data_dir, target_shard);
  sqlite3 *target_db = net_db_open(target_shard_path);
  if (!target_db) {
    fprintf(stderr, "net-cluster: cannot open shard %s\n",
            target_shard_path.c_str());
    return 1;
  }
  std::vector<NetFingerprint> target_fps =
      net_db_get_fingerprints_for_ip(target_db, o.nc_ip);
  net_db_close(target_db);

  if (target_fps.empty()) {
    fprintf(stderr,
            "net-cluster: IP %s has no fingerprints in the database. "
            "Has it been enriched yet?\n", o.nc_ip);
    return 1;
  }

  /* Step 2: for each shard, run every (kind, value) lookup against
     that shard's fingerprints table, THEN close.  Doing it shard-major
     (vs fingerprint-major) reduces SQLite opens from N*32 to just 32
     even when the target carries dozens of fingerprints — important on
     Windows where CreateFile is much more expensive than a Linux open(2).
     Keyed by uint32 so two-byte comparison is fastest; the set<string>
     per IP preserves which fingerprints matched so the output can show
     why each IP was clustered. */
  std::map<uint32_t, std::set<std::string>> cohort;

  for (int sh = 0; sh < NET_SHARD_COUNT; sh++) {
    std::string sp = net_shard_path(data_dir, sh);
    /* Skip shards whose file does not exist — saves a noisy stderr
       from net_db_open when shards have not been populated yet. */
    FILE *test = fopen(sp.c_str(), "r");
    if (!test) continue;
    fclose(test);

    sqlite3 *db = net_db_open(sp);
    if (!db) continue;

    for (const NetFingerprint &fp : target_fps) {
      std::vector<NetFingerprint> matches =
          net_db_find_by_fingerprint(db, fp.kind.c_str(), fp.value.c_str());
      std::string sig = fp.kind + ":" + fp.value;
      for (const NetFingerprint &m : matches) {
        if (m.ip_u32 == target_u32) continue;  /* exclude the target itself */
        cohort[m.ip_u32].insert(sig);
      }
    }

    net_db_close(db);
  }

  /* Step 3: emit, sorted by share count descending then IP ascending. */
  struct Row { uint32_t ip; int count; std::vector<std::string> sigs; };
  std::vector<Row> rows;
  rows.reserve(cohort.size());
  for (const auto &kv : cohort) {
    if (static_cast<int>(kv.second.size()) < min_shared) continue;
    Row r;
    r.ip    = kv.first;
    r.count = static_cast<int>(kv.second.size());
    r.sigs.assign(kv.second.begin(), kv.second.end());
    rows.push_back(std::move(r));
  }
  std::sort(rows.begin(), rows.end(),
            [](const Row &a, const Row &b) {
              if (a.count != b.count) return a.count > b.count;
              return a.ip < b.ip;
            });

  FILE *fp_out = stdout;
  if (o.nc_output && o.nc_output[0]) {
    fp_out = fopen(o.nc_output, "w");
    if (!fp_out) {
      fprintf(stderr, "net-cluster: cannot open output %s\n", o.nc_output);
      return 1;
    }
  }

  /* JSON-escape helper — only quote and backslash escapes, sufficient
     for the fingerprint signature values we ever emit here. */
  auto jesc = [](const std::string &s) {
    std::string out; out.reserve(s.size() + 4);
    for (char c : s) {
      if      (c == '"')  out += "\\\"";
      else if (c == '\\') out += "\\\\";
      else if (c == '\n') out += "\\n";
      else if (c == '\r') out += "\\r";
      else if (c == '\t') out += "\\t";
      else                out += c;
    }
    return out;
  };

  const std::string fmt = o.nc_format ? o.nc_format : "text";

  if (fmt == "dot") {
    /* Graphviz: target as the hub node, cohort IPs as leaves, each edge
       labeled with the shared fingerprint kinds (deduplicated).  Style
       hints separate the target from the cohort visually. */
    fprintf(fp_out, "graph net_cluster {\n");
    fprintf(fp_out, "  graph [layout=neato, overlap=false, splines=true];\n");
    fprintf(fp_out, "  node  [shape=ellipse, style=filled, fontname=\"Helvetica\"];\n");
    fprintf(fp_out, "  \"%s\" [fillcolor=\"#ff6b6b\", label=\"%s\\n(target)\"];\n",
            o.nc_ip, o.nc_ip);
    for (const Row &r : rows) {
      std::string ip_s = u32_to_ip(r.ip);
      fprintf(fp_out, "  \"%s\" [fillcolor=\"#4ecdc4\"];\n", ip_s.c_str());
      /* Build edge label from kind-only set (the values are noisy hex
         hashes and SANs — kinds tell the story). */
      std::set<std::string> kinds;
      for (const std::string &sig : r.sigs) {
        size_t c = sig.find(':');
        kinds.insert(c == std::string::npos ? sig : sig.substr(0, c));
      }
      std::string label;
      for (const std::string &k : kinds) {
        if (!label.empty()) label += ",";
        label += k;
      }
      fprintf(fp_out, "  \"%s\" -- \"%s\" [label=\"%s (%d)\"];\n",
              o.nc_ip, ip_s.c_str(), label.c_str(), r.count);
    }
    fprintf(fp_out, "}\n");
  } else if (fmt == "json") {
    fprintf(fp_out, "{\n");
    fprintf(fp_out, "  \"target\": \"%s\",\n", o.nc_ip);
    fprintf(fp_out, "  \"min_shared\": %d,\n", min_shared);
    fprintf(fp_out, "  \"target_fingerprints\": %zu,\n", target_fps.size());
    fprintf(fp_out, "  \"cohort\": [\n");
    for (size_t i = 0; i < rows.size(); i++) {
      const Row &r = rows[i];
      fprintf(fp_out, "    { \"ip\": \"%s\", \"shared\": %d, \"matches\": [",
              u32_to_ip(r.ip).c_str(), r.count);
      for (size_t j = 0; j < r.sigs.size(); j++) {
        fprintf(fp_out, "%s\"%s\"",
                (j == 0) ? "" : ", ",
                jesc(r.sigs[j]).c_str());
      }
      fprintf(fp_out, "] }%s\n",
              (i + 1 == rows.size()) ? "" : ",");
    }
    fprintf(fp_out, "  ]\n");
    fprintf(fp_out, "}\n");
  } else {
    /* Default text format — pipeable.  Header lines start with '#' so
       `kmap --net-cluster IP | grep -v '^#' | awk '{print $1}'` yields
       a clean IP list ready for chaining. */
    fprintf(fp_out, "# net-cluster cohort for %s (min_shared=%d)\n",
            o.nc_ip, min_shared);
    fprintf(fp_out, "# target carries %zu fingerprints; %zu IPs share >= %d\n",
            target_fps.size(), rows.size(), min_shared);
    for (const Row &r : rows) {
      fprintf(fp_out, "%-15s\t%d shared", u32_to_ip(r.ip).c_str(), r.count);
      for (size_t i = 0; i < r.sigs.size(); i++) {
        fprintf(fp_out, "%s%s",
                (i == 0) ? "\t" : ", ",
                r.sigs[i].c_str());
      }
      fprintf(fp_out, "\n");
    }
  }

  if (fp_out != stdout) fclose(fp_out);
  return 0;
}

/* -----------------------------------------------------------------------
 * Topology export
 *
 * Reads the persisted topo.db that tracemap writes through to and emits
 * the full graph in dot or json.  Filters:
 *   --topo-around IP [--topo-around-depth N]  -> BFS neighborhood of IP
 *   --topo-asn N                              -> nodes in ASN N only
 *   (no filter)                               -> full graph (caps emit
 *                                                at 100k nodes to keep
 *                                                downstream renderers
 *                                                from melting)
 *
 * The interned string columns are resolved at read time via the joins
 * in net_db_get_topo_node, so the output sees the literal hostnames /
 * AS names instead of the integer ids stored on disk.
 * ----------------------------------------------------------------------- */

static std::string json_escape_topo(const std::string &s) {
  std::string out; out.reserve(s.size() + 4);
  for (char c : s) {
    if      (c == '"')  out += "\\\"";
    else if (c == '\\') out += "\\\\";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else if (c == '\t') out += "\\t";
    else                out += c;
  }
  return out;
}

/* BFS expansion of the neighborhood around `start` up to `depth` hops
   in either direction.  Returns the set of node ip_u32 values to
   include in the export.

   Capped at BFS_NODE_CAP nodes so a depth-6 expansion from a hub
   router (Cogent core, T-Mobile gateway) does not produce a half-
   gigabyte DOT file.  When the cap trips we stop expanding the
   frontier but still emit whatever we collected up to that point,
   plus a stderr warning so the caller knows the result is partial. */
#define BFS_NODE_CAP 50000

static std::set<uint32_t>
bfs_neighborhood(sqlite3 *db, uint32_t start, int depth) {
  std::set<uint32_t> seen;
  std::vector<uint32_t> frontier;
  seen.insert(start);
  frontier.push_back(start);
  bool capped = false;
  for (int d = 0; d < depth && !frontier.empty() && !capped; d++) {
    std::vector<uint32_t> next;
    for (uint32_t u : frontier) {
      if (seen.size() >= BFS_NODE_CAP) { capped = true; break; }
      auto outs = net_db_get_topo_edges_from(db, u);
      auto ins  = net_db_get_topo_edges_to  (db, u);
      for (const auto &e : outs) {
        if (seen.size() >= BFS_NODE_CAP) { capped = true; break; }
        if (seen.insert(e.to_u32).second)   next.push_back(e.to_u32);
      }
      if (capped) break;
      for (const auto &e : ins) {
        if (seen.size() >= BFS_NODE_CAP) { capped = true; break; }
        if (seen.insert(e.from_u32).second) next.push_back(e.from_u32);
      }
    }
    frontier = std::move(next);
  }
  if (capped) {
    fprintf(stderr,
            "topo-export: BFS hit the %d-node cap; result is partial. "
            "Try a smaller --topo-around-depth.\n", BFS_NODE_CAP);
  }
  return seen;
}

int run_topo_export_cli() {
  if (!o.topo_export_file || !o.topo_export_file[0]) {
    fprintf(stderr,
            "topo-export: --topo-export requires an output file path\n");
    return 1;
  }

  const char *data_dir = o.net_data_dir ? o.net_data_dir : "kmap-data";
  char topo_path[1024];
  snprintf(topo_path, sizeof(topo_path), "%s/topo.db", data_dir);

  sqlite3 *db = net_db_open(topo_path);
  if (!db) {
    fprintf(stderr, "topo-export: cannot open %s -- run --tracemap first\n",
            topo_path);
    return 1;
  }

  /* Build the include-set of nodes.  Order of precedence:
       --topo-around > --topo-asn > everything (capped). */
  std::set<uint32_t> include_nodes;

  if (o.topo_around_ip != 0) {
    include_nodes = bfs_neighborhood(db, o.topo_around_ip,
                                     o.topo_around_depth);
  } else if (o.topo_asn_filter != 0) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db,
          "SELECT ip_u32 FROM topo_nodes WHERE asn = ?",
          -1, &stmt, nullptr) == SQLITE_OK) {
      sqlite3_bind_int64(stmt, 1, o.topo_asn_filter);
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        include_nodes.insert(
          static_cast<uint32_t>(sqlite3_column_int64(stmt, 0)));
      }
      sqlite3_finalize(stmt);
    }
  } else {
    /* No filter: include everything up to a sanity cap so a 50M-node
       graph doesn't produce a 5 GB DOT file. */
    const int64_t cap = 100000;
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db,
          "SELECT ip_u32 FROM topo_nodes ORDER BY path_count DESC LIMIT ?",
          -1, &stmt, nullptr) == SQLITE_OK) {
      sqlite3_bind_int64(stmt, 1, cap);
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        include_nodes.insert(
          static_cast<uint32_t>(sqlite3_column_int64(stmt, 0)));
      }
      sqlite3_finalize(stmt);
    }
  }

  if (include_nodes.empty()) {
    fprintf(stderr, "topo-export: no nodes match the filter\n");
    net_db_close(db);
    return 1;
  }

  FILE *fp = fopen(o.topo_export_file, "w");
  if (!fp) {
    fprintf(stderr, "topo-export: cannot open output %s\n",
            o.topo_export_file);
    net_db_close(db);
    return 1;
  }

  const std::string fmt = o.topo_format ? o.topo_format : "json";

  if (fmt == "dot") {
    fprintf(fp, "digraph topology {\n");
    fprintf(fp, "  graph [layout=sfdp, overlap=false, splines=true];\n");
    fprintf(fp, "  node  [shape=ellipse, style=filled];\n");
    /* Emit nodes first so DOT positions them stably. */
    for (uint32_t u : include_nodes) {
      NetTopoNode n{};
      if (!net_db_get_topo_node(db, u, &n)) continue;
      std::string ip_s = u32_to_ip(u);
      const char *color = (n.role == "target") ? "#ff6b6b"
                        : (n.role == "hub")    ? "#ffd93d"
                        : (n.role == "ixp")    ? "#a78bfa"
                        : "#4ecdc4";
      fprintf(fp, "  \"%s\" [fillcolor=\"%s\", label=\"%s\\nAS%u\"];\n",
              ip_s.c_str(), color, ip_s.c_str(), n.asn);
    }
    /* Edges between included nodes only. */
    for (uint32_t u : include_nodes) {
      auto outs = net_db_get_topo_edges_from(db, u);
      for (const auto &e : outs) {
        if (include_nodes.count(e.to_u32) == 0) continue;
        const char *style = e.asn_boundary ? "dashed" : "solid";
        fprintf(fp, "  \"%s\" -> \"%s\" [style=%s, label=\"%.1fms\"];\n",
                u32_to_ip(e.from_u32).c_str(),
                u32_to_ip(e.to_u32).c_str(),
                style, e.avg_latency_ms);
      }
    }
    fprintf(fp, "}\n");
  } else {
    /* JSON: nodes + edges arrays.  Stable enough for downstream
       ingestion (cytoscape, d3-force, gephi, etc). */
    fprintf(fp, "{\n  \"nodes\": [\n");
    bool first = true;
    for (uint32_t u : include_nodes) {
      NetTopoNode n{};
      if (!net_db_get_topo_node(db, u, &n)) continue;
      fprintf(fp,
        "%s    { \"ip\": \"%s\", \"hostname\": \"%s\", \"asn\": %u, "
        "\"as_name\": \"%s\", \"country\": \"%s\", \"role\": \"%s\", "
        "\"path_count\": %d, \"avg_rtt_ms\": %.3f }",
        first ? "" : ",\n",
        u32_to_ip(u).c_str(),
        json_escape_topo(n.hostname).c_str(),
        n.asn,
        json_escape_topo(n.as_name).c_str(),
        json_escape_topo(n.country).c_str(),
        json_escape_topo(n.role).c_str(),
        n.path_count, n.avg_rtt_ms);
      first = false;
    }
    fprintf(fp, "\n  ],\n  \"edges\": [\n");
    first = true;
    for (uint32_t u : include_nodes) {
      auto outs = net_db_get_topo_edges_from(db, u);
      for (const auto &e : outs) {
        if (include_nodes.count(e.to_u32) == 0) continue;
        fprintf(fp,
          "%s    { \"from\": \"%s\", \"to\": \"%s\", "
          "\"asn_boundary\": %s, \"avg_latency_ms\": %.3f, "
          "\"path_count\": %d }",
          first ? "" : ",\n",
          u32_to_ip(e.from_u32).c_str(),
          u32_to_ip(e.to_u32).c_str(),
          e.asn_boundary ? "true" : "false",
          e.avg_latency_ms, e.path_count);
        first = false;
      }
    }
    fprintf(fp, "\n  ]\n}\n");
  }

  fclose(fp);
  fprintf(stderr,
          "topo-export: wrote %zu nodes to %s (%s)\n",
          include_nodes.size(), o.topo_export_file, fmt.c_str());
  net_db_close(db);
  return 0;
}
