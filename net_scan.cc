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
#include "cloud_map.h"   /* lookup_cloud, cloud_ranges_load */
#include "entity_graph.h" /* entity_graph_build / _emit */
#include "net_enrich_async.h"
#include "net_report.h"
#include "net_query.h"
#include "asn_lookup.h"
#include "KmapOps.h"
#include "sys_resources.h"
#include "cpu_meter.h"
#include "kmap.h"
#include "output.h"
#include "os_profile.h"

#include <cstdarg>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <fstream>
#include <set>
#include <map>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

#ifndef WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <signal.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

extern KmapOps o;

/* -----------------------------------------------------------------------
 * Resource metrics gather
 *
 * Same shape as the helper in fast_syn.cc -- duplicated here rather
 * than factored out because both files already include their own
 * platform socket / Windows-API headers and pulling in a shared header
 * just to share 30 lines isn't worth the include shuffle.
 *
 * Reports current RSS (kB) plus accumulated process CPU time
 * (seconds, user+kernel).  Caller derives CPU% from the delta over
 * the interval between samples.
 * ----------------------------------------------------------------------- */
struct ProcMetrics {
  double  cpu_seconds;
  size_t  rss_kb;
};

static ProcMetrics gather_proc_metrics() {
  ProcMetrics m{};
#ifdef WIN32
  HANDLE proc = GetCurrentProcess();
  PROCESS_MEMORY_COUNTERS pmc;
  if (GetProcessMemoryInfo(proc, &pmc, sizeof(pmc))) {
    m.rss_kb = (size_t)(pmc.WorkingSetSize / 1024);
  }
  FILETIME ftC, ftE, ftK, ftU;
  if (GetProcessTimes(proc, &ftC, &ftE, &ftK, &ftU)) {
    ULONGLONG kernel = ((ULONGLONG)ftK.dwHighDateTime << 32) | ftK.dwLowDateTime;
    ULONGLONG user   = ((ULONGLONG)ftU.dwHighDateTime << 32) | ftU.dwLowDateTime;
    m.cpu_seconds = (double)(kernel + user) / 10000000.0;
  }
#else
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) == 0) {
    m.rss_kb = (size_t)ru.ru_maxrss;
    m.cpu_seconds =
      (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1e6 +
      (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec / 1e6;
  }
#endif
  return m;
}

/* -----------------------------------------------------------------------
 * Scan interrupt flag
 *
 * Set by SIGINT (POSIX) / Ctrl+C console handler (Windows) so worker
 * threads and the main enrichment / report loop can exit cleanly
 * mid-scan instead of leaving the thread pool unjoined (which on
 * Windows MSVC's std::thread implementation aborts the process via
 * terminate()).
 *
 * std::atomic<int> (not volatile int) because the workers read this
 * from many threads concurrently and the C++ memory model only
 * guarantees racy access correctness on atomics.  POSIX would also
 * accept sig_atomic_t for the handler side, but std::atomic<int> is
 * lock-free for int and works uniformly on both platforms. */
static std::atomic<int> g_scan_interrupted{0};

#ifndef WIN32
static void watchlist_sigint(int /*sig*/) { g_scan_interrupted.store(1); }
#else
static BOOL WINAPI watchlist_ctrl_handler(DWORD /*type*/) {
  g_scan_interrupted.store(1);
  return TRUE;
}
#endif

/* -----------------------------------------------------------------------
 * Scan event log
 *
 * Persists warnings / errors / phase-transition events from a single
 * scan run into `<data_dir>/kmap.log` with ISO timestamps and a severity
 * tag.  Mirrors to stderr so the running user still sees them.  Designed
 * to be the one log an operator opens after a failed scan to figure out
 * what went wrong without re-running with -vvv attached to a screen
 * session.  Append-only; rotation is left to the operator (rare
 * enough -- each line is ~120 bytes and a scan emits dozens, not
 * thousands).
 * ----------------------------------------------------------------------- */

static FILE *g_scan_log_fp = nullptr;

static void scan_log_open(const char *data_dir) {
  if (g_scan_log_fp) return;  /* already open from a prior call */
  std::string path = std::string(data_dir) + "/kmap.log";
  g_scan_log_fp = fopen(path.c_str(), "a");
  /* fopen failure is non-fatal: scan_log() falls back to stderr-only.
   *
   * Note: do NOT call setvbuf(fp, NULL, _IOLBF, 0) here -- MSVC's CRT
   * fast-fails (STATUS_STACK_BUFFER_OVERRUN 0xC0000409) on a NULL
   * buffer + size 0 combination.  Default block buffering plus the
   * explicit fflush() inside scan_log() gives the same get-it-on-disk
   * guarantee we want. */
}

static void scan_log_close() {
  if (g_scan_log_fp) {
    fclose(g_scan_log_fp);
    g_scan_log_fp = nullptr;
  }
}

/* Emit one log line at the given severity ("INFO", "WARN", "ERROR").
 * Goes to both the log file (if open) and stderr (so live runs still
 * surface problems).  Severity is a string -- no enum to keep call
 * sites readable without an extra include. */
/* Shared core: timestamp + format + write to the kmap.log fp (if open),
   and optionally echo to stderr. scan_log() echoes; net_event_log() does
   not (its callers already produce their own terminal output). */
static void scan_log_v(const char *severity, const char *fmt, va_list ap,
                       bool to_stderr) {
  char ts[32];
  time_t now = time(nullptr);
  struct tm tm_buf{};
#ifdef WIN32
  if (localtime_s(&tm_buf, &now) != 0) tm_buf = {};
#else
  if (!localtime_r(&now, &tm_buf)) tm_buf = {};
#endif
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_buf);

  char msg[1024];
  vsnprintf(msg, sizeof(msg), fmt, ap);

  if (g_scan_log_fp) {
    fprintf(g_scan_log_fp, "%s  %-5s  %s\n", ts, severity, msg);
    fflush(g_scan_log_fp);
  }
  if (to_stderr)
    fprintf(stderr, "%s  %-5s  %s\n", ts, severity, msg);
}

static void scan_log(const char *severity, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  scan_log_v(severity, fmt, ap, /*to_stderr=*/true);
  va_end(ap);
}

/* Public file-only logger (declared in net_scan.h) so other translation
   units can mirror events into kmap.log without a second terminal echo. */
void net_event_log(const char *severity, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  scan_log_v(severity, fmt, ap, /*to_stderr=*/false);
  va_end(ap);
}

/* -----------------------------------------------------------------------
 * Watchlist scanning
 *
 * Reads IPs from a file, scans just those targets, compares against
 * previous results in watchlist.db, outputs diff + full report.
 * ----------------------------------------------------------------------- */

/* Raise the open-file-descriptor soft limit toward the hard limit so a
   high-concurrency watchlist sweep (KMAP_WATCHLIST_CONCURRENCY up to 1024)
   can hold one socket per worker without socket() failing EMFILE -- which
   connect_probe would otherwise report as a closed host (silent false
   negative). Only raises, never lowers; best-effort. No-op on Windows. */
static void raise_fd_limit(int desired) {
#ifndef WIN32
  struct rlimit r;
  if (getrlimit(RLIMIT_NOFILE, &r) != 0) return;
  if (r.rlim_cur == RLIM_INFINITY || r.rlim_cur >= (rlim_t)desired) return;
  r.rlim_cur = (r.rlim_max == RLIM_INFINITY || (rlim_t)desired < r.rlim_max)
                 ? (rlim_t)desired : r.rlim_max;
  setrlimit(RLIMIT_NOFILE, &r);   /* best-effort */
  if (getrlimit(RLIMIT_NOFILE, &r) == 0 &&
      r.rlim_cur != RLIM_INFINITY && r.rlim_cur < (rlim_t)desired) {
    log_write(LOG_STDOUT,
      "  WARNING: open-file limit is %lu but this scan needs ~%d descriptors; "
      "raise it (ulimit -Hn) or lower KMAP_WATCHLIST_CONCURRENCY, otherwise "
      "some probes will fail with EMFILE and those hosts get marked closed.\n",
      (unsigned long)r.rlim_cur, desired);
  }
#else
  (void)desired;
#endif
}

static int run_watchlist(const char *targets_file, const char *data_dir,
                         const char *findings_dir) {
  /* Open the persistent scan log so every WARN/ERROR survives the
   * scrolled terminal -- one file for the operator to grep when a
   * scan looks weird. */
  scan_log_open(data_dir);
  scan_log("INFO", "watchlist scan starting: targets_file=%s data_dir=%s",
           targets_file, data_dir);

  /* Per-phase timing for the SCAN COMPLETE summary. */
  auto t_phase_start = std::chrono::steady_clock::now();
  auto t_discovery_end = t_phase_start;
  auto t_enrich_end    = t_phase_start;

  /* Install SIGINT / Ctrl+C handler so the operator can break the
   * scan without leaving worker threads dangling.  fast_syn's loop
   * already does this for net-scan mode; watchlist needs the same so
   * a Ctrl+C in the middle of a 5-minute parallel probe wave doesn't
   * crash through std::thread's destructor (which calls terminate()
   * on an un-joined thread).  Workers and the enrichment loop poll
   * g_scan_interrupted and exit cleanly so join() returns promptly. */
  g_scan_interrupted.store(0);
#ifndef WIN32
  struct sigaction sa_old{}, sa_new{};
  sa_new.sa_handler = watchlist_sigint;
  sigaction(SIGINT, &sa_new, &sa_old);
#else
  SetConsoleCtrlHandler(watchlist_ctrl_handler, TRUE);
#endif

  /* Read target IPs from file */
  std::vector<uint32_t> targets;
  std::ifstream f(targets_file);
  if (!f.is_open()) {
    scan_log("ERROR", "cannot open watchlist file: %s", targets_file);
#ifndef WIN32
    sigaction(SIGINT, &sa_old, nullptr);
#else
    SetConsoleCtrlHandler(watchlist_ctrl_handler, FALSE);
#endif
    scan_log_close();
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
      /* Strict prefix parse: atoi() would turn a non-numeric/empty prefix
         into 0, which then falls through to the misleading "exceeds cap"
         warning below. Reject malformed prefixes with an accurate message. */
      std::string ptok = line.substr(slash + 1);
      int prefix = -1;
      if (!ptok.empty()) {
        char *endp = nullptr;
        long pv = strtol(ptok.c_str(), &endp, 10);
        if (endp != ptok.c_str() && *endp == '\0' && pv >= 0 && pv <= 32)
          prefix = (int)pv;
      }
      if (prefix < 0) {
        scan_log("WARN", "invalid CIDR prefix in '%s' (skipped)", line.c_str());
        continue;
      }
      uint32_t base = ip_to_u32(line.substr(0, slash).c_str());
      if (prefix >= 16 && prefix <= 30) {
        /* Up to /16 (65,534 hosts) expands fully -- skip network + broadcast
           addresses. /16 is the practical ceiling for a watchlist: it fits
           in memory, finishes inside a single discovery batch, and matches
           the "targeted asset list" use case the watchlist mode is designed
           for. Larger prefixes are rejected below rather than silently
           collapsing to the network address -- the previous behavior turned
           an operator's office /14 into a single-IP scan with no warning. */
        uint32_t count = 1u << (32 - prefix);
        uint32_t mask = ~(count - 1);
        base &= mask;
        for (uint32_t i = 1; i < count - 1; i++)
          targets.push_back(base + i);
      } else if (prefix == 31) {
        uint32_t mask = ~1u;
        base &= mask;
        targets.push_back(base);
        targets.push_back(base + 1);
      } else if (prefix == 32) {
        targets.push_back(base);
      } else {
        scan_log("WARN",
          "CIDR prefix /%d in '%s' exceeds watchlist cap (/16 = 65,534 hosts) -- skipped",
          prefix, line.c_str());
        continue;
      }
    } else {
      uint32_t ip = ip_to_u32(line.c_str());
      if (ip != 0) targets.push_back(ip);
    }
  }

  if (targets.empty()) {
    scan_log("ERROR", "no valid targets in %s", targets_file);
#ifndef WIN32
    sigaction(SIGINT, &sa_old, nullptr);
#else
    SetConsoleCtrlHandler(watchlist_ctrl_handler, FALSE);
#endif
    scan_log_close();
    return 1;
  }

  log_write(LOG_STDOUT, "\nnet-scan: Watchlist mode -- %d targets from %s\n",
            (int)targets.size(), targets_file);

  /* Open watchlist database */
  std::string wl_path = std::string(data_dir) + "/watchlist.db";
  sqlite3 *wl_db = net_db_open(wl_path);
  if (!wl_db) {
    scan_log("ERROR", "cannot open watchlist DB at %s", wl_path.c_str());
#ifndef WIN32
    sigaction(SIGINT, &sa_old, nullptr);
#else
    SetConsoleCtrlHandler(watchlist_ctrl_handler, FALSE);
#endif
    scan_log_close();
    return 1;
  }

  /* Per-watchlist-DB metadata. Remembers the previous scan's start timestamp
     so the diff below can scope "previously open" to the PRIOR run rather than
     the entire cumulative history -- otherwise a port that opened once and
     closed permanently is re-reported [CLOSED] on every subsequent run forever.
     A separate table is safe to add to an existing DB: CREATE TABLE IF NOT
     EXISTS materializes a whole new table (unlike ADD COLUMN it needs no
     migration-list entry). Read here, rewritten at the end of a completed run. */
  sqlite3_exec(wl_db,
    "CREATE TABLE IF NOT EXISTS scan_meta (key TEXT PRIMARY KEY, value INTEGER)",
    nullptr, nullptr, nullptr);
  int64_t prev_scan_ts = 0;
  {
    sqlite3_stmt *st = nullptr;
    if (sqlite3_prepare_v2(wl_db,
          "SELECT value FROM scan_meta WHERE key='last_scan_ts'",
          -1, &st, nullptr) == SQLITE_OK) {
      if (sqlite3_step(st) == SQLITE_ROW)
        prev_scan_ts = sqlite3_column_int64(st, 0);
      sqlite3_finalize(st);
    }
  }

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
    /* Scope to the previous run's open set when we know when that was: a port
       that went dark BEFORE the previous run is already-reported history and
       must not resurface as [CLOSED] every run. Since nothing but a watchlist
       run writes this DB, every row open as of the prior run has
       last_seen >= prev_scan_ts, and earlier closures have less. On the first
       run under this scheme (prev_scan_ts == 0) fall back to all rows. */
    const char *prev_sql = (prev_scan_ts > 0)
      ? "SELECT ip, port, service, version, cves, web_title FROM hosts "
        "WHERE last_seen >= ?"
      : "SELECT ip, port, service, version, cves, web_title FROM hosts";
    sqlite3_prepare_v2(wl_db, prev_sql, -1, &stmt, nullptr);
    if (stmt) {
      if (prev_scan_ts > 0) sqlite3_bind_int64(stmt, 1, prev_scan_ts);
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

  /* Scan each target -- using connect probes for the top ports.
   * We do NOT DELETE the hosts table before re-scanning.  The original
   * code wiped the table here, which destroyed first_seen, scan_count,
   * and the prev_cves/prev_service/prev_version history columns that
   * net_db_update_enrichment depends on for cross-scan diffing.  Net
   * effect: every watchlist run was a fresh slate, so "we saw CVE-X
   * last week and it's still here this week" was impossible to tell
   * from the DB itself.
   *
   * Rows that no longer respond stay in the DB with their stale
   * last_seen timestamp; the "[CLOSED]" branch of the diff report
   * below picks them up by comparing prev_state (in-memory snapshot
   * from before the scan) against current (rows whose last_seen was
   * advanced by this scan -- see scan_start_ts gate). */
  /* Honor an explicit -p just like the full net-scan path (line ~1281);
   * fall back to the built-in top-100 set when the user gave no -p.
   * Previously this hardcoded nullptr, so a watchlist of assets on
   * non-standard ports (e.g. -p 8080,9000) silently scanned the default
   * top-100 instead and reported zero open ports. */
  std::vector<int> ports = parse_port_spec(o.portlist ? o.portlist : nullptr);
  int64_t scan_start_ts = static_cast<int64_t>(time(nullptr));
  int64_t now_ts = scan_start_ts;

  /* Parallel connect-probe loop.
   *
   * The previous serial implementation took ~33 minutes for 10 hosts x
   * 100 ports because filtered ports drop SYN packets and the 2-second
   * select() timeout fires sequentially for each.  Wall time was
   * dominated by O(N_hosts * N_ports * timeout_seconds).
   *
   * The new loop builds the (ip, port) task list up front, dispatches
   * to a thread pool of `worker_count` workers (env override
   * KMAP_WATCHLIST_CONCURRENCY, default 100), and collects opens into a
   * mutex-guarded vector.  net_db inserts happen serially after the
   * probe phase because SQLite serializes writes anyway -- doing them
   * inside workers would just contend on the wl_db handle without
   * speed-up.
   *
   * 100 concurrent connects is well under any practical OS fd limit
   * (Linux default 1024, Windows kernel handle table is unbounded) and
   * stays under the noise floor of any reasonable upstream firewall.
   * Wall time on the same 10-host / 100-port set drops from ~33 min
   * to roughly N_total_ports * timeout / concurrency = 1000 * 2 / 50
   * = 40 seconds for the worst-case (all filtered) case, plus the time
   * the OS spends queueing/closing sockets. */
  /* Task granularity is per-IP (was per-(ip,port) pair).  Per-IP
   * grouping lets the worker apply the early-bail heuristic: after
   * N consecutive timeouts with zero sign of life from the host,
   * skip the remaining ports for that IP.  Single biggest discovery
   * win on filtered hosts (a wholly-firewalled host that used to burn
   * N_ports * timeout_ms now burns only N_bail * timeout_ms). */
  std::atomic<size_t> next_ip_idx{0};
  std::vector<std::pair<uint32_t, int>> opens;  /* ip, port */
  std::mutex opens_mu;

  /* Default 100 (was 50) -- matches the net-scan default after
   * resource metrics showed kmap discovery is RTT-bound, not
   * CPU/RAM-bound. */
  int worker_count = 100;
  /* --efficient / --fast derive a resource-aware default; the env var
   * still overrides (checked after) so explicit tuning wins. */
  {
    const KmapPerfProfile &pp = kmap_perf_profile();
    if (pp.mode != KMAP_PERF_NORMAL && pp.discovery_workers > 0)
      worker_count = pp.discovery_workers;
  }
  if (const char *env = getenv("KMAP_WATCHLIST_CONCURRENCY")) {
    int v = atoi(env);
    if (v > 0 && v <= 1024) worker_count = v;
  }
  if (static_cast<size_t>(worker_count) > targets.size())
    worker_count = static_cast<int>(targets.size());
  if (worker_count < 1) worker_count = 1;

  /* Per-probe TCP-connect timeout, milliseconds.  500 ms default --
   * matches fast_syn after a 250-ms attempt cut off cross-continent
   * services with marginal RTT (us-east-1 from .au lands at ~210 ms
   * SYN-ACK, blowing through a 250-ms window often enough to drop
   * ~37% of real opens on the validation scan).  KMAP_PROBE_TIMEOUT_MS
   * shared with fast_syn so a single env var tunes both discovery
   * paths. */
  int probe_timeout_ms = 500;
  if (const char *env = getenv("KMAP_PROBE_TIMEOUT_MS")) {
    int v = atoi(env);
    if (v >= 50 && v <= 30000) probe_timeout_ms = v;
  }

  int bail_after_timeouts = 8;
  if (const char *env = getenv("KMAP_BAIL_AFTER_TIMEOUTS")) {
    int v = atoi(env);
    if (v >= 1 && v <= 100) bail_after_timeouts = v;
  }

  /* Inline probe (same outcome enum semantics as fast_syn's
   * connect_probe but watchlist uses targets as a flat vector and
   * does not need rate-limit/db-mutex hooks here, so duplicating
   * the inner is clearer than reaching across to fast_syn). */
  auto probe_one = [&](uint32_t ip, int port) -> int {
    /* 0=TIMEOUT, 1=OPEN, 2=CLOSED -- matches the bail logic below. */
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(static_cast<uint16_t>(port));
    sa.sin_addr.s_addr = htonl(ip);
#ifdef WIN32
    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) return 2;
    u_long nb = 1;
    ioctlsocket(fd, FIONBIO, &nb);
#else
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
    int nodelay = 1;
    setsockopt(static_cast<int>(fd), IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char *>(&nodelay), sizeof(nodelay));
    /* Abortive close (RST, not FIN): a successful probe must not leave the
       local ephemeral port in TIME_WAIT, which would exhaust the dynamic-port
       range on a dense scan. Harmless for filtered/closed probes. See
       fuzz/test_linger.cc for the RST-on-close proof. */
    struct linger lg; lg.l_onoff = 1; lg.l_linger = 0;
    setsockopt(fd, SOL_SOCKET, SO_LINGER,
               reinterpret_cast<const char *>(&lg), sizeof(lg));
    os_profile_apply_socket(static_cast<intptr_t>(fd), AF_INET,
                            os_profile_get_for_target(
                                o.spoof_os,
                                os_profile_seed_from_ipv4(ip)));
    connect(fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa));
    int out = 0;
#ifdef WIN32
    /* Windows fd_set is a counted SOCKET-handle array -- value-safe. */
    fd_set wset; FD_ZERO(&wset); FD_SET(fd, &wset);
    struct timeval tv;
    tv.tv_sec  = probe_timeout_ms / 1000;
    tv.tv_usec = (probe_timeout_ms % 1000) * 1000;
    int sel = select(0, nullptr, &wset, nullptr, &tv);
#else
    /* poll(), NOT select(): a POSIX fd_set is a bitmask indexed by fd VALUE
       and capped at FD_SETSIZE (1024). Watchlist discovery runs up to
       KMAP_WATCHLIST_CONCURRENCY=1024 workers, so fd values climb past 1024
       and FD_SET(fd >= 1024) would write past the fd_set and corrupt the
       stack. poll takes the fd by value with no FD_SETSIZE ceiling. */
    struct pollfd pfd; pfd.fd = fd; pfd.events = POLLOUT; pfd.revents = 0;
    int sel = poll(&pfd, 1, probe_timeout_ms);
#endif
    if (sel > 0) {
      int err = 0;
      socklen_t elen = sizeof(err);
      getsockopt(fd, SOL_SOCKET, SO_ERROR,
                 reinterpret_cast<char *>(&err), &elen);
      out = (err == 0) ? 1 : 2;
    } else if (sel < 0) {
      out = 2;
    }
#ifdef WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return out;
  };

  auto worker = [&]() {
    while (true) {
      if (g_scan_interrupted.load(std::memory_order_relaxed)) return;
      size_t i = next_ip_idx.fetch_add(1, std::memory_order_relaxed);
      if (i >= targets.size()) return;
      uint32_t ip = targets[i];

      int bail_streak = 0;
      bool any_response = false;

      for (int port : ports) {
        if (g_scan_interrupted.load(std::memory_order_relaxed)) break;

        int pr = probe_one(ip, port);

        if (pr == 0 /* TIMEOUT */) {
          bail_streak++;
          if (bail_streak >= bail_after_timeouts && !any_response) break;
        } else {
          bail_streak = 0;
          any_response = true;
          if (pr == 1 /* OPEN */) {
            std::lock_guard<std::mutex> lk(opens_mu);
            opens.push_back({ip, port});
          }
        }
      }
    }  /* while (true) -- next IP */
  };

  /* One socket per worker plus the watchlist DB, log and std streams. */
  raise_fd_limit(worker_count + 64);

  log_write(LOG_STDOUT, "  Probing %d IPs (%d ports each) with %d workers"
            " [timeout=%dms, bail_after=%d]...\n",
            (int)targets.size(), (int)ports.size(), worker_count,
            probe_timeout_ms, bail_after_timeouts);

  std::vector<std::thread> pool;
  pool.reserve(worker_count);
  for (int i = 0; i < worker_count; i++) pool.emplace_back(worker);
  for (auto &th : pool) th.join();

  /* Serial insert phase -- SQLite serializes writes via the wl_db
   * handle anyway, so concurrent inserts would just contend. */
  net_db_begin(wl_db);
  for (const auto &t : opens)
    net_db_insert_host(wl_db, t.first, t.second, "tcp", now_ts);
  net_db_commit(wl_db);
  int found = static_cast<int>(opens.size());
  t_discovery_end = std::chrono::steady_clock::now();

  if (g_scan_interrupted.load()) {
    scan_log("WARN", "scan interrupted during discovery, skipping enrichment");
  }

  log_write(LOG_STDOUT, "  Discovery: %d open ports found\n", found);

  /* Enrich the watchlist hosts using the enrichment pipeline.
   * Skipped entirely when Ctrl+C was seen during discovery -- we want
   * to flush whatever discovery captured rather than spending another
   * five minutes on enrichment for a scan the operator already
   * abandoned. */
  if (g_scan_interrupted.load()) {
    scan_log("INFO", "enrichment skipped due to interrupt");
  } else {
  log_write(LOG_STDOUT, "  Enriching watchlist hosts...\n");
  {
    std::vector<std::string> unenriched = net_db_get_unenriched(wl_db, 10000);
    /* Locate CVE database.  Tries kmap_fetchfile's standard search
     * (--datadir, $KMAPDIR, %APPDATA%/kmap or ~/.kmap, exe-dir,
     * /usr/share/kmap).  Falls back to ./kmap-cve.db so users
     * running kmap from the source tree get matches without needing
     * to install or copy the DB into exe-dir. */
    char cve_buf[1024];
    std::string cve_db_path;
    if (kmap_fetchfile(cve_buf, sizeof(cve_buf), "kmap-cve.db") > 0) {
      cve_db_path = cve_buf;
    } else {
      FILE *cwd_db = fopen("kmap-cve.db", "rb");
      if (cwd_db) {
        fclose(cwd_db);
        cve_db_path = "kmap-cve.db";
      }
    }
    if (cve_db_path.empty()) {
      scan_log("WARN", "kmap-cve.db not found (searched exe-dir, %%APPDATA%%/kmap, $KMAPDIR, ./) -- CVE lookups disabled");
    } else {
      scan_log("INFO", "CVE database: %s", cve_db_path.c_str());
    }

    /* Load the offline cloud-provider range table once for the phase. */
    {
      char cbuf[1024];
      std::string cloud_path;
      if (kmap_fetchfile(cbuf, sizeof(cbuf), "kmap-cloud-ranges.csv") > 0) {
        cloud_path = cbuf;
      } else {
        FILE *cwd = fopen("kmap-cloud-ranges.csv", "rb");
        if (cwd) { fclose(cwd); cloud_path = "kmap-cloud-ranges.csv"; }
      }
      size_t nr = cloud_ranges_load(cloud_path.empty() ? "" : cloud_path.c_str());
      if (nr > 0)
        scan_log("INFO", "cloud-ranges: %llu ranges from %s",
                 (unsigned long long)nr, cloud_path.c_str());
      else
        scan_log("INFO", "cloud-ranges: none loaded (kmap-cloud-ranges.csv not found)");
    }

    /* Open the CVE DB ONCE for the entire enrichment phase.  Sqlite is
     * built SQLITE_THREADSAFE=0 (no internal mutexes), so this single
     * read-only handle is NOT inherently safe to share -- concurrent
     * access from the worker pool below is serialized by the static
     * mutex inside lookup_cves() (net_enrich.cc), through which both this
     * watchlist path and the net-scan path reach the handle.  The
     * previous design opened+closed the DB inside every call to
     * enrich_single_host -- hundreds of thousands of redundant stat
     * + open + page-cache-warm cycles on a full sweep. */
    sqlite3 *cve_db = nullptr;
    if (!cve_db_path.empty()) {
      if (sqlite3_open_v2(cve_db_path.c_str(), &cve_db,
                          SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        if (cve_db) { sqlite3_close(cve_db); cve_db = nullptr; }
        scan_log("WARN", "could not open CVE database %s -- continuing without CVE matches",
                 cve_db_path.c_str());
      }
    }

    /* Parallel enrichment.
     *
     * The serial loop was O(N_hosts * (avg_ports*banner_timeout +
     * http_timeout + tls_handshake + asn_dns_rtt)).  On a 10-host
     * watchlist that came out to ~260 seconds -- the bulk of the
     * pre-parallel scan wall time.  Per-host work is fully independent
     * (enrich_single_host opens its own per-call sockets; the shared
     * read-only CVE db is serialized inside lookup_cves and the SSL_CTX
     * is built once via call_once; lookup_asn does its own UDP DNS), so
     * we can fan out with N workers.  Default 10 -- enough to hide the
     * per-host RTT
     * waits without saturating local CPU on banner-pattern matching.
     * Tunable via KMAP_WATCHLIST_ENRICH_CONCURRENCY for very large
     * watchlists.
     *
     * DB writes stay serial in a second phase: sqlite serializes them
     * anyway via the shared wl_db handle, and keeping all UPDATEs
     * inside one transaction is what makes the post-scan SELECTs
     * see a consistent view. */
    struct HostResult {
      std::string ip;
      std::vector<int> port_nums;
      std::vector<std::string> protos;
      std::vector<std::string> services, versions, cves_out;
      std::vector<std::string> web_titles, web_servers, web_headers, web_paths;
      std::vector<std::string> powered_by, x_generator, redirects;
      std::vector<TlsCapture> tls_caps;
      AsnInfo asn_info{};
      CloudInfo cloud_info{};
      int erc = 0;
      bool empty_host = false;  /* host had no ports in DB, skip */
    };

    /* Stage A: build per-host work units serially from the DB.
     * net_db_get_host is the only piece that has to be serial because
     * it touches wl_db, which we don't share between threads. */
    std::vector<HostResult> results;
    results.reserve(unenriched.size());
    for (const auto &ip_str : unenriched) {
      HostResult hr;
      hr.ip = ip_str;
      auto host_ports = net_db_get_host(wl_db, ip_str.c_str());
      if (host_ports.empty()) {
        hr.empty_host = true;
        results.push_back(std::move(hr));
        continue;
      }
      for (const auto &h : host_ports) {
        hr.port_nums.push_back(h.port);
        hr.protos.push_back(h.proto);
      }
      /* Pre-populate from prior scan -- see banner-grab fallback note
       * in the comment above the run_watchlist scan_start_ts setup. */
      hr.services.resize(hr.port_nums.size());
      hr.versions.resize(hr.port_nums.size());
      for (size_t i = 0; i < host_ports.size() && i < hr.port_nums.size(); i++) {
        hr.services[i] = host_ports[i].service;
        hr.versions[i] = host_ports[i].version;
      }
      results.push_back(std::move(hr));
    }

    /* Stage B-pre (opt-in async pre-pass): when KMAP_ASYNC_ENRICH=1, run
       banner-grab + CVE for every host via async_enrich_batch
       (nsock-driven, one or more parallel pools). The sync Stage B
       below honours the same env and skips banner/CVE on slots already
       filled by the async pass, so the net effect is: async covers the
       network-heavy banner+CVE half, sync still covers HTTP probe and
       TLS handshake (Phase 1b/1c will migrate those into the state
       machine). Per-host budget still applies; metrics still reported.

       Defaulting OFF for now -- Phase 1a is an A/B experiment. Set
       KMAP_ASYNC_ENRICH=1 to opt in. */
    bool async_enrich_mode = false;
    if (const char *env = getenv("KMAP_ASYNC_ENRICH")) {
      if (atoi(env) > 0) async_enrich_mode = true;
    }
    if (async_enrich_mode) {
      /* Build flat vectors for async_enrich_batch. */
      std::vector<std::string> async_ips;
      std::vector<std::vector<int>> async_ports;
      std::vector<size_t> async_back_idx;  /* map result-list slot -> results[] */
      async_ips.reserve(results.size());
      async_ports.reserve(results.size());
      async_back_idx.reserve(results.size());
      for (size_t i = 0; i < results.size(); i++) {
        if (results[i].empty_host) continue;
        async_ips.push_back(results[i].ip);
        async_ports.push_back(results[i].port_nums);
        async_back_idx.push_back(i);
      }

      log_write(LOG_STDOUT,
        "  Async pre-pass: banner+CVE+HTTP+TLS for %d hosts via nsock event loop...\n",
        (int)async_ips.size());

      std::vector<std::vector<std::string>> async_svcs, async_vers, async_cves;
      std::vector<std::vector<std::string>> async_wtitles, async_wservers,
                                            async_wheaders, async_wpaths,
                                            async_powered_by, async_x_generator,
                                            async_redirects;
      std::vector<std::vector<TlsCapture>> async_tls;
      auto async_start = std::chrono::steady_clock::now();
      async_enrich_batch(async_ips, async_ports, 3000, cve_db,
                         async_svcs, async_vers, async_cves,
                         async_wtitles, async_wservers, async_wheaders,
                         async_wpaths, async_powered_by, async_x_generator,
                         async_redirects, &async_tls);
      auto async_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - async_start).count();
      log_write(LOG_STDOUT,
        "  Async pre-pass: %d hosts in %.2fs (%.1f hps)\n",
        (int)async_ips.size(),
        static_cast<double>(async_elapsed) / 1000.0,
        async_elapsed > 0
          ? static_cast<double>(async_ips.size()) * 1000.0 /
            static_cast<double>(async_elapsed)
          : 0.0);

      /* Fold async results back into HostResult vectors.  After Phase 1c
         the async pass covers banner+CVE+HTTP+TLS; the sync Stage B
         checks each slot under KMAP_ASYNC_ENRICH=1 and skips the
         corresponding step when it is already populated, so we just
         dump the async outputs into the HostResult fields.  Reverse-DNS
         and ASN still run synchronously after enrich_single_host. */
      for (size_t k = 0; k < async_back_idx.size(); k++) {
        HostResult &hr = results[async_back_idx[k]];
        size_t np = hr.port_nums.size();
        if (hr.cves_out.size()    < np) hr.cves_out.resize(np);
        if (hr.web_titles.size()  < np) hr.web_titles.resize(np);
        if (hr.web_servers.size() < np) hr.web_servers.resize(np);
        if (hr.web_headers.size() < np) hr.web_headers.resize(np);
        if (hr.web_paths.size()   < np) hr.web_paths.resize(np);
        if (hr.powered_by.size()  < np) hr.powered_by.resize(np);
        if (hr.x_generator.size() < np) hr.x_generator.resize(np);
        if (hr.redirects.size()   < np) hr.redirects.resize(np);
        if (hr.tls_caps.size()    < np) hr.tls_caps.resize(np);
        for (size_t p = 0; p < np && p < async_svcs[k].size(); p++) {
          if (!async_svcs   [k][p].empty()) hr.services   [p] = async_svcs   [k][p];
          if (!async_vers   [k][p].empty()) hr.versions   [p] = async_vers   [k][p];
          if (!async_cves   [k][p].empty()) hr.cves_out   [p] = async_cves   [k][p];
          if (!async_wtitles[k][p].empty()) hr.web_titles [p] = async_wtitles[k][p];
          if (!async_wservers[k][p].empty()) hr.web_servers[p] = async_wservers[k][p];
          if (!async_wheaders[k][p].empty()) hr.web_headers[p] = async_wheaders[k][p];
          if (!async_wpaths [k][p].empty()) hr.web_paths  [p] = async_wpaths [k][p];
          if (!async_powered_by [k][p].empty()) hr.powered_by [p] = async_powered_by [k][p];
          if (!async_x_generator[k][p].empty()) hr.x_generator[p] = async_x_generator[k][p];
          if (!async_redirects  [k][p].empty()) hr.redirects  [p] = async_redirects  [k][p];
          if (p < async_tls[k].size()) {
            const TlsCapture &tc = async_tls[k][p];
            /* self_signed != -1 means the async TLS stage ran far enough
               to inspect the cert; copy the whole struct in that case. */
            if (tc.self_signed != -1 || !tc.subject_cn.empty() ||
                !tc.issuer.empty() || !tc.sha256.empty())
              hr.tls_caps[p] = tc;
          }
        }
      }
    }

    /* Stage B: parallel enrichment.  Workers do all the network /
     * pattern-matching work; the results vector is pre-sized so
     * each worker writes only to its own slot (no mutex needed). */
    /* Default 40 (was 10) -- same reasoning as the net-scan
     * enrichment bump.  Stage C DB writes still serialize. */
    int enrich_worker_count = 40;
    /* --efficient / --fast derive a resource-aware default; env still wins. */
    {
      const KmapPerfProfile &pp = kmap_perf_profile();
      if (pp.mode != KMAP_PERF_NORMAL && pp.enrich_workers > 0)
        enrich_worker_count = pp.enrich_workers;
    }
    if (const char *env = getenv("KMAP_WATCHLIST_ENRICH_CONCURRENCY")) {
      int v = atoi(env);
      if (v > 0 && v <= 256) enrich_worker_count = v;
    }
    if (static_cast<size_t>(enrich_worker_count) > results.size())
      enrich_worker_count = static_cast<int>(results.size());
    if (enrich_worker_count < 1) enrich_worker_count = 1;

    /* Per-port connect timeout, matching the main net-scan enrichment path
       (KMAP_ENRICH_CONNECT_TIMEOUT_MS, default 3000ms). Previously hardcoded to
       5000ms here, which made watchlist enrichment slower than --net-scan and
       silently ignored the operator's KMAP_ENRICH_CONNECT_TIMEOUT_MS tuning. */
    int wl_connect_to = 3000;
    if (const char *env = getenv("KMAP_ENRICH_CONNECT_TIMEOUT_MS")) {
      int v = atoi(env);
      if (v >= 50 && v <= 60000) wl_connect_to = v;
    }

    std::atomic<size_t> enrich_next{0};
    auto enrich_worker = [&]() {
      while (true) {
        if (g_scan_interrupted.load(std::memory_order_relaxed)) return;
        size_t i = enrich_next.fetch_add(1, std::memory_order_relaxed);
        if (i >= results.size()) return;
        HostResult &hr = results[i];
        if (hr.empty_host) continue;
        hr.erc = enrich_single_host(hr.ip.c_str(), hr.port_nums, hr.protos,
                           cve_db,
                           wl_connect_to, hr.services, hr.versions, hr.cves_out,
                           hr.web_titles, hr.web_servers, hr.web_headers,
                           hr.web_paths, hr.powered_by, hr.x_generator,
                           hr.redirects, &hr.tls_caps);
        if (hr.erc == 0) {
          /* asn_info was filled by the batched ASN pre-pass (below, before the
             worker pool spawns); only the offline cloud match remains here. */
          uint32_t ipu = ip_to_u32(hr.ip.c_str());
          if (ipu) hr.cloud_info = lookup_cloud(ipu);
        }
        /* --fast / --efficient CPU governor (no-op in normal mode). */
        kmap_cpu_governor_throttle();
      }
    };

    /* Batched ASN pre-pass -- same rationale as the main net-scan path: pull the
       per-host Cymru lookup out of the enrich worker's critical path so the
       round-trips overlap each other (the prefix cache dedups same-/24 hosts).
       Runs before the worker pool spawns; each worker writes only its own slot.
       KMAP_NO_ASN=1 skips it; KMAP_ASN_BATCH_CONCURRENCY tunes the in-flight count. */
    {
      bool wl_do_asn = true;
      if (const char *env = getenv("KMAP_NO_ASN")) { if (atoi(env) > 0) wl_do_asn = false; }
      int wl_asn_hosts = 0;
      for (auto &hr : results) if (!hr.empty_host) wl_asn_hosts++;
      if (wl_do_asn && wl_asn_hosts > 0) {
        int wl_asn_workers = 64;
        if (const char *env = getenv("KMAP_ASN_BATCH_CONCURRENCY")) {
          int v = atoi(env); if (v >= 1 && v <= 1024) wl_asn_workers = v;
        }
        if (wl_asn_workers > wl_asn_hosts) wl_asn_workers = wl_asn_hosts;
        std::atomic<size_t> wl_asn_next{0};
        std::vector<std::thread> wl_asn_pool;
        wl_asn_pool.reserve(wl_asn_workers);
        for (int w = 0; w < wl_asn_workers; w++) {
          wl_asn_pool.emplace_back([&]() {
            for (;;) {
              size_t i = wl_asn_next.fetch_add(1, std::memory_order_relaxed);
              if (i >= results.size()) return;
              if (results[i].empty_host) continue;
              results[i].asn_info = lookup_asn(results[i].ip.c_str(), 2000);
            }
          });
        }
        for (auto &t : wl_asn_pool) t.join();
      }
    }

    log_write(LOG_STDOUT, "  Enriching %d hosts with %d workers...\n",
              (int)results.size(), enrich_worker_count);
    /* Peak concurrent sockets = hosts in flight * ports probed per host
       (enrich_single_host fans out to KMAP_HOST_PORT_PARALLELISM threads). */
    {
      int enrich_pp = 8;
      if (const char *env = getenv("KMAP_HOST_PORT_PARALLELISM")) {
        int v = atoi(env);
        if (v >= 1 && v <= 32) enrich_pp = v;
      }
      raise_fd_limit(enrich_worker_count * enrich_pp + 64);
    }
    enrich_reset_metrics();
    kmap_cpu_governor_init(kmap_perf_cpu_target_cores());
    {
      std::vector<std::thread> epool;
      epool.reserve(enrich_worker_count);
      for (int i = 0; i < enrich_worker_count; i++)
        epool.emplace_back(enrich_worker);
      for (auto &th : epool) th.join();
    }
    {
      EnrichMetrics m = enrich_get_metrics();
      if (m.hosts_done > 0) {
        log_write(LOG_STDOUT,
          "  Enrichment timing: avg=%.2fs max=%.2fs budget-bailed=%u/%u\n",
          static_cast<double>(m.total_ms) / static_cast<double>(m.hosts_done) / 1000.0,
          static_cast<double>(m.max_ms) / 1000.0,
          static_cast<unsigned>(m.budget_bails),
          static_cast<unsigned>(m.hosts_done));
        scan_log("INFO",
          "enrichment: hosts=%llu avg_ms=%llu max_ms=%llu budget_bails=%llu",
          (unsigned long long)m.hosts_done,
          (unsigned long long)(m.hosts_done ? m.total_ms / m.hosts_done : 0),
          (unsigned long long)m.max_ms,
          (unsigned long long)m.budget_bails);
      }
    }

    /* Stage C: serial DB write phase.  All sqlite UPDATEs go through
     * one transaction so a reader sees either pre-scan or post-scan
     * state, never a half-finished mid-scan view. */
    int enriched_count = 0;
    int enrich_errors = 0;
    net_db_begin(wl_db);
    for (const auto &hr : results) {
      if (hr.empty_host) continue;
      if (hr.erc != 0) {
        scan_log("WARN", "enrichment failed for %s (rc=%d), will retry after cooldown",
                 hr.ip.c_str(), hr.erc);
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf), "enrich_single_host rc=%d", hr.erc);
        for (size_t i = 0; i < hr.port_nums.size(); i++) {
          net_db_record_enrichment_error(wl_db, hr.ip.c_str(), hr.port_nums[i],
                                         err_buf);
        }
        enrich_errors++;
        continue;
      }
      for (size_t i = 0; i < hr.port_nums.size(); i++) {
        std::string wl_cpe = net_enrich_cpe_for(
          i < hr.services.size() ? hr.services[i] : std::string(),
          i < hr.versions.size() ? hr.versions[i] : std::string());
        net_db_update_enrichment(wl_db, hr.ip.c_str(), hr.port_nums[i],
          i < hr.services.size()    ? hr.services[i].c_str()    : "",
          i < hr.versions.size()    ? hr.versions[i].c_str()    : "",
          i < hr.cves_out.size()    ? hr.cves_out[i].c_str()    : "",
          i < hr.web_titles.size()  ? hr.web_titles[i].c_str()  : "",
          i < hr.web_servers.size() ? hr.web_servers[i].c_str() : "",
          i < hr.web_headers.size() ? hr.web_headers[i].c_str() : "",
          i < hr.web_paths.size()   ? hr.web_paths[i].c_str()   : "",
          i < hr.powered_by.size()  ? hr.powered_by[i].c_str()  : nullptr,
          i < hr.x_generator.size() ? hr.x_generator[i].c_str() : nullptr,
          i < hr.redirects.size()   ? hr.redirects[i].c_str()   : nullptr,
          nullptr,                                  /* robots_disallowed_json */
          wl_cpe.empty() ? nullptr : wl_cpe.c_str());

        if (i < hr.tls_caps.size()) {
          const TlsCapture &tc = hr.tls_caps[i];
          bool have_tls = !tc.subject_cn.empty() || !tc.issuer.empty() ||
                          !tc.sha256.empty()     || !tc.protocol.empty();
          if (have_tls) {
            net_db_update_tls(
              wl_db, hr.ip.c_str(), hr.port_nums[i],
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
      if (hr.asn_info.asn > 0) {
        net_db_update_asn(wl_db, hr.ip.c_str(), hr.asn_info.asn,
                          hr.asn_info.as_name.c_str(),
                          hr.asn_info.country.c_str(),
                          hr.asn_info.bgp_prefix.c_str(),
                          hr.asn_info.registry.c_str(),
                          hr.asn_info.region.c_str());
      }
      /* Cloud match is independent of ASN (not gated on asn > 0). */
      if (!hr.cloud_info.provider.empty()) {
        net_db_update_cloud(wl_db, hr.ip.c_str(),
                            hr.cloud_info.provider.c_str(),
                            hr.cloud_info.region.empty()  ? nullptr : hr.cloud_info.region.c_str(),
                            hr.cloud_info.service.empty() ? nullptr : hr.cloud_info.service.c_str());
      }
      enriched_count++;
    }
    net_db_commit(wl_db);
    if (g_scan_interrupted.load()) {
      scan_log("INFO", "enrichment interrupted after %d hosts", enriched_count);
    }
    log_write(LOG_STDOUT, "  Enriched %d hosts", enriched_count);
    if (enrich_errors > 0)
      log_write(LOG_STDOUT, " (%d failed)", enrich_errors);
    log_write(LOG_STDOUT, "\n");

    /* Release the single shared CVE DB handle now that workers have
     * joined and the serial write phase is done. */
    if (cve_db) { sqlite3_close(cve_db); cve_db = nullptr; }
  }
  }  /* end of (!g_scan_interrupted) guard */
  t_enrich_end = std::chrono::steady_clock::now();

  /* Generate diff */
  std::string wl_dir = std::string(findings_dir) + "/watchlist";
#ifdef WIN32
  _mkdir(findings_dir);
  _mkdir(wl_dir.c_str());
#else
  mkdir(findings_dir, 0755);
  mkdir(wl_dir.c_str(), 0755);
#endif

  /* Get current state -- only rows whose last_seen advanced during this
   * scan, since we no longer DELETE before scanning.  Anything with an
   * older last_seen represents a host/port that was open historically
   * but did not respond this run; the diff loop below uses absence from
   * `current` to flag those as [CLOSED]. */
  std::vector<NetHost> current;
  {
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(wl_db,
      "SELECT ip, port, proto, service, version, cves, web_title "
      "FROM hosts WHERE last_seen >= ?",
      -1, &stmt, nullptr);
    if (stmt) {
      sqlite3_bind_int64(stmt, 1, scan_start_ts);
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
    struct tm tm_buf{};
#ifdef WIN32
    if (localtime_s(&tm_buf, &now) != 0) tm_buf = {};
#else
    if (!localtime_r(&now, &tm_buf)) tm_buf = {};
#endif
    strftime(datebuf, sizeof(datebuf), "%Y-%m-%d", &tm_buf);
  }

  std::string diff_path = wl_dir + "/diff_" + datebuf + ".txt";
  FILE *diff_fp = fopen(diff_path.c_str(), "w");
  if (!diff_fp) {
    scan_log("WARN", "cannot create diff report %s (errno=%d), skipping",
             diff_path.c_str(), errno);
  }
  if (diff_fp) {
    fprintf(diff_fp, "================================================================================\n");
    fprintf(diff_fp, "                    WATCHLIST DIFF -- %s\n", datebuf);
    fprintf(diff_fp, "================================================================================\n");
    fprintf(diff_fp, "  Targets scanned: %d\n", (int)targets.size());

    /* Build lookup maps. Keep the prior service/version per key so a port
       open in BOTH scans can be checked for service/version drift -- the
       "changed" half of the report, which the loop below previously never
       emitted despite the docs describing it. */
    std::set<std::string> prev_keys, curr_keys;
    std::map<std::string, std::string> prev_svc, prev_ver;
    for (const auto &pe : prev_state) {
      std::string key = pe.ip + ":" + std::to_string(pe.port);
      prev_keys.insert(key);
      prev_svc[key] = pe.service;
      prev_ver[key] = pe.version;
    }
    for (const auto &h : current) {
      std::string key = h.ip + ":" + std::to_string(h.port);
      curr_keys.insert(key);
    }

    int changes = 0;

    /* New + changed ports */
    for (const auto &h : current) {
      std::string key = h.ip + ":" + std::to_string(h.port);
      if (prev_keys.find(key) == prev_keys.end()) {
        fprintf(diff_fp, "\n  [NEW PORT] %s:%d/%s\n", h.ip.c_str(), h.port, h.proto.c_str());
        if (!h.service.empty())
          fprintf(diff_fp, "    Service: %s  Version: %s\n", h.service.c_str(), h.version.c_str());
        changes++;
      } else {
        /* Open in both scans -- report a service or version change. Guard on a
           non-empty NEW value so a transient enrichment miss this run (which
           leaves service/version empty) is not misreported as a change. */
        const std::string &ps = prev_svc[key];
        const std::string &pv = prev_ver[key];
        bool svc_changed = !h.service.empty() && h.service != ps;
        bool ver_changed = !h.version.empty() && h.version != pv;
        if (svc_changed || ver_changed) {
          fprintf(diff_fp, "\n  [CHANGED] %s:%d/%s\n",
                  h.ip.c_str(), h.port, h.proto.c_str());
          if (svc_changed)
            fprintf(diff_fp, "    Service: %s -> %s\n",
                    ps.empty() ? "(none)" : ps.c_str(), h.service.c_str());
          if (ver_changed)
            fprintf(diff_fp, "    Version: %s -> %s\n",
                    pv.empty() ? "(none)" : pv.c_str(), h.version.c_str());
          changes++;
        }
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

  /* Advance the diff boundary to this run's start so the NEXT run compares
     against what THIS run found open. Only on a completed run -- an
     interrupted run saw a partial set, and advancing would make the next run
     misreport the unreached ports as [CLOSED]; leaving the boundary at the
     last full run keeps the next diff correct. */
  if (!g_scan_interrupted.load()) {
    sqlite3_stmt *st = nullptr;
    if (sqlite3_prepare_v2(wl_db,
          "INSERT OR REPLACE INTO scan_meta(key,value) VALUES('last_scan_ts',?)",
          -1, &st, nullptr) == SQLITE_OK) {
      sqlite3_bind_int64(st, 1, scan_start_ts);
      sqlite3_step(st);
      sqlite3_finalize(st);
    }
  }

  /* Write full report.
   *
   * Renders every enrichment column the DB carries -- web title/server,
   * TLS subject/issuer, ASN+as_name+country, hostname, CVE deltas
   * (prev_cves vs cves), scan_count for "how many times have we seen
   * this row".  The previous version dropped all of this on the floor
   * and only printed port/proto + service + version, leaving the
   * operator no choice but to inspect kmap-data/watchlist.db directly
   * with sqlite3 to see what enrichment actually captured.
   *
   * Per-port data is fetched via net_db_get_host() rather than a
   * direct SELECT so the column-to-field mapping lives in one place
   * (net_db.cc), keeping this section invariant to future schema
   * additions. */
  std::string full_path = wl_dir + "/full_" + datebuf + ".txt";
  FILE *full_fp = fopen(full_path.c_str(), "w");
  if (!full_fp) {
    scan_log("WARN", "cannot create full report %s (errno=%d), skipping",
             full_path.c_str(), errno);
  }
  if (full_fp) {
    fprintf(full_fp, "================================================================================\n");
    fprintf(full_fp, "                    WATCHLIST FULL REPORT -- %s\n", datebuf);
    fprintf(full_fp, "================================================================================\n");
    fprintf(full_fp, "  Targets: %d | Open ports: %d\n\n", (int)targets.size(), (int)current.size());

    /* Build list of unique IPs that responded this scan, in stable order. */
    std::vector<std::string> uniq_ips;
    {
      std::set<std::string> seen;
      for (const auto &h : current) {
        if (seen.insert(h.ip).second) uniq_ips.push_back(h.ip);
      }
    }

    for (const auto &ip : uniq_ips) {
      auto rows = net_db_get_host(wl_db, ip.c_str());
      if (rows.empty()) continue;

      /* IP-level banner: hostname + AS/country if known. */
      fprintf(full_fp, "================================================================================\n");
      fprintf(full_fp, "  TARGET: %s", ip.c_str());
      const NetHost &any = rows.front();
      if (!any.hostname.empty()) fprintf(full_fp, "  (%s)", any.hostname.c_str());
      fprintf(full_fp, "\n");
      if (any.asn > 0) {
        fprintf(full_fp, "    AS%u  %s%s%s\n",
                any.asn,
                any.as_name.empty() ? "unknown" : any.as_name.c_str(),
                any.country.empty() ? "" : "  ",
                any.country.c_str());
        if (!any.bgp_prefix.empty())
          fprintf(full_fp, "    Prefix: %s\n", any.bgp_prefix.c_str());
      }
      fprintf(full_fp, "================================================================================\n");

      for (const auto &r : rows) {
        /* Only include ports that responded in this scan. */
        if (r.last_seen < scan_start_ts) continue;

        fprintf(full_fp, "  %d/%s  %s",
                r.port, r.proto.c_str(),
                r.service.empty() ? "unknown" : r.service.c_str());
        if (!r.version.empty()) fprintf(full_fp, "  %s", r.version.c_str());
        if (r.scan_count > 1)   fprintf(full_fp, "   [scans=%d]", r.scan_count);
        fprintf(full_fp, "\n");

        if (!r.web_title.empty())
          fprintf(full_fp, "    Title:    %s\n", r.web_title.c_str());
        if (!r.web_server.empty())
          fprintf(full_fp, "    Server:   %s\n", r.web_server.c_str());
        if (!r.powered_by.empty())
          fprintf(full_fp, "    X-Powered: %s\n", r.powered_by.c_str());
        if (!r.redirect_target.empty())
          fprintf(full_fp, "    Redirect: %s\n", r.redirect_target.c_str());
        if (!r.tls_subject_cn.empty() || !r.tls_issuer.empty()) {
          fprintf(full_fp, "    TLS:      CN=%s", r.tls_subject_cn.c_str());
          if (!r.tls_issuer.empty())    fprintf(full_fp, "  Issuer=%s", r.tls_issuer.c_str());
          if (!r.tls_protocol.empty())  fprintf(full_fp, "  %s", r.tls_protocol.c_str());
          if (!r.tls_not_after.empty()) fprintf(full_fp, "  exp=%s", r.tls_not_after.c_str());
          fprintf(full_fp, "\n");
        }
        /* CVE summary -- compact "id [CONFIDENCE]" of the first entry plus
         * a count of how many more, and an aggregate confidence tally that
         * tells the operator which matches deserve immediate attention.
         *
         * Confidence comes from the per-CVE "remote" field that lookup_cves
         * writes when the row's CVSS v3 vector is "AV:N / PR:N / UI:N" --
         * i.e. a remote unauthed attacker can trigger it. Rows missing the
         * vector entirely (legacy CVE-DB pre-Tier-1) count as "unknown" so
         * a partial backfill does not blank out the report. */
        if (!r.cves.empty() && r.cves != "[]") {
          size_t id_pos = r.cves.find("\"id\":\"");
          if (id_pos != std::string::npos) {
            id_pos += 6;
            size_t id_end = r.cves.find('"', id_pos);
            if (id_end != std::string::npos) {
              std::string cve_id = r.cves.substr(id_pos, id_end - id_pos);

              /* Count entries + tally remote_unauthed = 1 / 0 / unknown.
                 Each entry has exactly one "id":, so total comes from that
                 occurrence count. */
              int count = 0;
              size_t scan = 0;
              while ((scan = r.cves.find("\"id\":", scan)) != std::string::npos) {
                count++; scan++;
              }
              int remote_yes = 0, remote_no = 0;
              for (size_t p = 0; (p = r.cves.find("\"remote\":1", p)) != std::string::npos; p++)
                remote_yes++;
              for (size_t p = 0; (p = r.cves.find("\"remote\":0", p)) != std::string::npos; p++)
                remote_no++;
              int unknown = count - remote_yes - remote_no;

              /* Find the first CVE's remote field, if any, for the headline
                 tag. Scan inside the first object only. */
              const char *first_tag = "[unknown]";
              size_t obj_close = r.cves.find('}', id_end);
              if (obj_close != std::string::npos) {
                std::string first_obj = r.cves.substr(0, obj_close);
                if (first_obj.find("\"remote\":1") != std::string::npos)
                  first_tag = "[REMOTE]";
                else if (first_obj.find("\"remote\":0") != std::string::npos)
                  first_tag = "[needs-auth/other]";
              }

              fprintf(full_fp, "    CVE:      %s %s", cve_id.c_str(), first_tag);
              if (count > 1)
                fprintf(full_fp, " (+%d more)", count - 1);
              fprintf(full_fp, "\n");
              fprintf(full_fp,
                      "    Confidence: %d remote-unauth, %d needs-auth/other, %d unknown\n",
                      remote_yes, remote_no, unknown);
            }
          }
        }
        /* Patch-status delta -- only when prev_cves was populated by a
         * prior enrichment. */
        if (!r.prev_cves.empty() && r.prev_cves != "[]" && r.prev_cves != r.cves) {
          fprintf(full_fp, "    NOTE:     CVE list changed since prior scan\n");
        }
      }
    }
    fprintf(full_fp, "\n================================================================================\n");
    fclose(full_fp);

    log_write(LOG_STDOUT, "  Full report: %s\n", full_path.c_str());
  }

  net_db_close(wl_db);

  /* Restore the signal handler before printing the summary so a
   * second Ctrl+C interrupts the operator's pager / tail, not our
   * teardown. */
#ifndef WIN32
  sigaction(SIGINT, &sa_old, nullptr);
#else
  SetConsoleCtrlHandler(watchlist_ctrl_handler, FALSE);
#endif

  auto t_report_end = std::chrono::steady_clock::now();
  auto elapsed_s = [](std::chrono::steady_clock::time_point a,
                      std::chrono::steady_clock::time_point b) -> double {
    return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count()
           / 1000.0;
  };
  double discovery_s = elapsed_s(t_phase_start, t_discovery_end);
  double enrich_s    = elapsed_s(t_discovery_end, t_enrich_end);
  double report_s    = elapsed_s(t_enrich_end, t_report_end);
  double total_s     = elapsed_s(t_phase_start, t_report_end);

  /* Final resource metrics.  cpu_pct here is "average CPU across the
   * whole scan" (total CPU seconds / wall seconds), which is more
   * useful at scan-end than the instantaneous-delta the periodic
   * progress line shows. */
  ProcMetrics fin_metrics = gather_proc_metrics();
  double avg_cpu_pct = (total_s > 0.001)
                       ? 100.0 * fin_metrics.cpu_seconds / total_s : 0.0;
  double rss_mb = (double)fin_metrics.rss_kb / 1024.0;

  /* Post-scan summary -- the easy-to-find pointer block.  Operators
   * scrolling through hundreds of probe lines should land on this and
   * know exactly where to look next without rummaging in kmap-data/. */
  std::string db_path_disp = std::string(data_dir) + "/watchlist.db";
  log_write(LOG_STDOUT, "\n");
  log_write(LOG_STDOUT, "================================================================================\n");
  log_write(LOG_STDOUT, "  SCAN %s -- watchlist mode\n",
            g_scan_interrupted.load() ? "INTERRUPTED" : "COMPLETE");
  log_write(LOG_STDOUT, "================================================================================\n");
  log_write(LOG_STDOUT, "  Targets scanned:  %d\n", (int)targets.size());
  log_write(LOG_STDOUT, "  Open ports found: %d\n", (int)current.size());
  log_write(LOG_STDOUT, "\n");
  log_write(LOG_STDOUT, "  Timing:\n");
  log_write(LOG_STDOUT, "    Discovery:      %.1fs\n", discovery_s);
  log_write(LOG_STDOUT, "    Enrichment:     %.1fs\n", enrich_s);
  log_write(LOG_STDOUT, "    Report:         %.1fs\n", report_s);
  log_write(LOG_STDOUT, "    Total:          %.1fs\n", total_s);
  log_write(LOG_STDOUT, "\n");
  /* Throughput: a "completed host" traversed the full discover->enrich
     pipeline (enrich_get_metrics().hosts_done). Rates guard a sub-ms denom. */
  EnrichMetrics wl_em = enrich_get_metrics();
  double wl_disc_rate = discovery_s > 0.001 ? targets.size()  / discovery_s : 0.0;
  double wl_enr_rate  = enrich_s    > 0.001 ? wl_em.hosts_done / enrich_s    : 0.0;
  double wl_pipe_rate = total_s     > 0.001 ? wl_em.hosts_done / total_s     : 0.0;
  log_write(LOG_STDOUT, "  Throughput:\n");
  log_write(LOG_STDOUT, "    Discovery:      %.1f IPs/sec  (%d IPs)\n",
            wl_disc_rate, (int)targets.size());
  log_write(LOG_STDOUT, "    Enrichment:     %.1f hosts/sec  (%llu hosts)\n",
            wl_enr_rate, (unsigned long long)wl_em.hosts_done);
  log_write(LOG_STDOUT, "    Pipeline:       %.2f completed hosts/sec\n",
            wl_pipe_rate);
  log_write(LOG_STDOUT, "\n");
  log_write(LOG_STDOUT, "  Resources:\n");
  log_write(LOG_STDOUT, "    Avg CPU:        %.1f%%\n", avg_cpu_pct);
  log_write(LOG_STDOUT, "    Peak RSS:       %.0f MB\n", rss_mb);
  log_write(LOG_STDOUT, "    Total CPU time: %.1fs\n", fin_metrics.cpu_seconds);
  log_write(LOG_STDOUT, "\n");
  log_write(LOG_STDOUT, "  Reports:\n");
  log_write(LOG_STDOUT, "    Diff:           %s\n", diff_path.c_str());
  log_write(LOG_STDOUT, "    Full:           %s\n", full_path.c_str());
  log_write(LOG_STDOUT, "\n");
  log_write(LOG_STDOUT, "  Database:         %s\n", db_path_disp.c_str());
  log_write(LOG_STDOUT, "  Scan log:         %s/kmap.log\n", data_dir);
  log_write(LOG_STDOUT, "\n");
  log_write(LOG_STDOUT, "  Inspect from the CLI:\n");
  log_write(LOG_STDOUT, "    kmap --net-query --nq-port 443\n");
  log_write(LOG_STDOUT, "    kmap --net-query --nq-format json --nq-min-cvss 7\n");
  log_write(LOG_STDOUT, "    kmap --net-query --nq-device web\n");
  log_write(LOG_STDOUT, "================================================================================\n");

  scan_log("INFO", "watchlist scan %s: %d ports across %d targets, "
           "%llu hosts pipelined "
           "(discovery=%.1fs enrich=%.1fs report=%.1fs total=%.1fs; "
           "%.2f hosts/sec) | cpu_avg=%.1f%% rss=%.0fMB cpu_total=%.1fs",
           g_scan_interrupted.load() ? "interrupted" : "complete",
           (int)current.size(), (int)targets.size(),
           (unsigned long long)wl_em.hosts_done,
           discovery_s, enrich_s, report_s, total_s, wl_pipe_rate,
           avg_cpu_pct, rss_mb, fin_metrics.cpu_seconds);
  scan_log_close();
  return g_scan_interrupted.load() ? 130 : 0;
}

/* -----------------------------------------------------------------------
 * Main orchestrator
 * ----------------------------------------------------------------------- */

/* Sum the eligible-for-enrichment host count across every shard on disk.
 * Mirrors the predicate run_enrichment uses (enriched=0 OR re-seen, and
 * not inside the error cool-down), so this is the authoritative "is there
 * more enrichment work?" signal that drives the drain loop below.  Opens
 * each shard read-only, counts, closes -- cheap relative to a batch of
 * network enrichment, and avoids holding 32 handles open between passes. */
static int64_t net_count_unenriched_all(const char *data_dir) {
  int64_t total = 0;
  for (int shard = 0; shard < NET_SHARD_COUNT; shard++) {
    std::string p = net_shard_path(data_dir, shard);
    FILE *test = fopen(p.c_str(), "r");
    if (!test) continue;           /* shard never created -- nothing here */
    fclose(test);
    sqlite3 *db = net_db_open(p);
    if (!db) continue;
    int64_t c = net_db_count_unenriched(db);
    if (c > 0) total += c;
    net_db_close(db);
  }
  return total;
}

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

  /* Persistent event log for the discover -> enrich -> report path, mirroring
     watchlist mode. A mass sweep can run unattended for hours; kmap.log
     records the lifecycle (start, per-phase outcome + timing, completion)
     with ISO timestamps so an operator can reconstruct what happened after
     stdout has scrolled away or the terminal closed. Every scan_log line is
     fflush'd immediately, so the trail survives even a hard kill. Each early
     return below closes it (scan_log_close is null-guarded, so the repeated
     calls are harmless). */
  scan_log_open(data_dir);
  time_t ns_start = time(nullptr);
  /* Monotonic clock for the throughput summary (hosts/sec). time() is kept for
     the existing per-phase second-granularity logs; steady_clock gives the
     final rate sub-second accuracy on short scans. ns_disc_end/ns_enr_end stay
     at ns_t0 if their phase is skipped (discover-only / report-only). */
  auto ns_t0 = std::chrono::steady_clock::now();
  auto ns_disc_end = ns_t0;
  auto ns_enr_end  = ns_t0;
  uint64_t ns_ips_scanned = 0;  /* IPs covered by discovery; set in Phase 1 */
  scan_log("INFO", "net-scan starting%s%s",
           o.net_discover_only ? " [discover-only]"
             : o.net_enrich_only ? " [enrich-only]"
             : o.net_report_only ? " [report-only]" : "",
           o.net_resume ? " [resume]" : "");

  /* Phase 1: Discover */
  if (!o.net_enrich_only && !o.net_report_only) {
    /* Build exclusion list. The built-in reserved/private/DoD ranges are
       included by default; --no-builtin-excludes opts out for operators who
       have authorization to scan one of them (e.g. a range they own). This is
       a footgun, so make the choice loud rather than silent. */
    std::vector<ExcludeRange> excludes;
    if (o.net_no_builtin_excludes) {
      log_write(LOG_STDOUT,
        "net-scan: WARNING: --no-builtin-excludes set -- built-in "
        "reserved/private/DoD exclusions are DISABLED. Scan only ranges you "
        "are authorized to.\n");
      scan_log("WARN",
        "built-in excludes disabled via --no-builtin-excludes");
    } else {
      excludes = builtin_excludes();
    }
    if (o.net_exclude_file) {
      auto user_excl = load_exclude_list(o.net_exclude_file);
      excludes.insert(excludes.end(), user_excl.begin(), user_excl.end());
    }

    /* Parse ports */
    std::vector<int> ports = parse_port_spec(
      o.portlist ? o.portlist : nullptr);

    int rate = o.net_rate > 0 ? o.net_rate : 25000;

    /* If a positional target was given (kmap --net-scan 192.0.2.0/24), bound
       the sweep to that CIDR/IP.  Previously the target was ignored and the
       scan ALWAYS swept the entire IPv4 space -- a serious footgun.  An
       unparseable target is a hard error (never silently fall back to the full
       internet).  No target -> full sweep (the headline mode). */
    uint32_t target_base = 0;
    uint64_t target_count = 0;
    if (o.net_scan_target && o.net_scan_target[0]) {
      std::string tgt = o.net_scan_target;
      int prefix = 32;
      std::string host = tgt;
      size_t slash = tgt.find('/');
      if (slash != std::string::npos) {
        host = tgt.substr(0, slash);
        const char *pp = tgt.c_str() + slash + 1;
        char *endp = nullptr;
        long pv = strtol(pp, &endp, 10);
        if (*pp == '\0' || endp == pp || *endp != '\0' || pv < 0 || pv > 32) {
          fprintf(stderr, "net-scan: invalid CIDR prefix in target '%s'\n", tgt.c_str());
          scan_log_close();
          return 1;
        }
        prefix = static_cast<int>(pv);
      }
      uint32_t base = ip_to_u32(host.c_str());
      if (base == 0 && host != "0.0.0.0") {
        fprintf(stderr, "net-scan: target '%s' is not a valid IPv4 address/CIDR "
                "(hostnames are not yet supported as --net-scan targets)\n",
                host.c_str());
        scan_log_close();
        return 1;
      }
      uint32_t mask = (prefix == 0) ? 0u
                    : (prefix >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - prefix)) - 1));
      target_base  = base & mask;
      target_count = (prefix == 0) ? 0x100000000ULL : (1ULL << (32 - prefix));
      log_write(LOG_STDOUT, "  Target range: %s/%d (%llu address(es))\n",
                u32_to_ip(target_base).c_str(), prefix,
                (unsigned long long)target_count);
      scan_log("INFO", "bounded scan target: %s/%d (%llu addresses)",
               u32_to_ip(target_base).c_str(), prefix,
               (unsigned long long)target_count);
    } else {
      log_write(LOG_STDOUT,
        "  Target: FULL IPv4 space (no range given -- pass a CIDR to limit, "
        "e.g. --net-scan 192.0.2.0/24)\n");
    }

    scan_log("INFO",
             "discovery starting: %d port(s), rate=%d pps, %d exclude range(s)%s",
             (int)ports.size(), rate, (int)excludes.size(),
             o.net_max_ips ? " (sampled)" : "");
    time_t disc_t0 = time(nullptr);
    rc = fast_syn_scan(data_dir, ports, rate, excludes, o.net_resume,
                       o.net_max_ips, target_base, target_count);
    if (rc != 0) {
      scan_log("ERROR", "discovery phase failed (rc=%d)", rc);
      fprintf(stderr, "net-scan: discovery phase failed\n");
      scan_log_close();
      return rc;
    }
    ns_disc_end = std::chrono::steady_clock::now();
    ns_ips_scanned = target_count ? target_count
                     : (o.net_max_ips ? (uint64_t)o.net_max_ips : 0);
    scan_log("INFO", "discovery phase complete (%lds)",
             (long)(time(nullptr) - disc_t0));

    if (o.net_discover_only) {
      scan_log("INFO", "net-scan finished: discover-only (%lds total)",
               (long)(time(nullptr) - ns_start));
      scan_log_close();
      return 0;
    }
  }

  /* Phase 2: Enrich.
   *
   * run_enrichment processes at most batch_size (1000) hosts PER shard
   * per call -- a deliberate memory bound so a sweep that finds millions
   * of open hosts does not load them all into RAM at once.  A single call
   * therefore tops out near 1000 * 32 = 32k hosts; an internet-scale
   * discovery can easily exceed that, and the overflow used to sit
   * permanently unenriched until an operator happened to re-run
   * --enrich-only.  Drain it here instead: loop until no eligible host
   * remains, one bounded batch per pass.  net_count_unenriched_all uses
   * the same predicate run_enrichment does, so a host that was enriched
   * (enriched=1) or that errored (and is now inside the retry cool-down)
   * drops out of the count -- the loop strictly converges to zero.  A
   * no-progress guard breaks defensively if a pass somehow marks nothing
   * (e.g. the unreachable empty-host row Stage C skips), so this can
   * never spin forever. */
  if (!o.net_discover_only && !o.net_report_only) {
    log_write(LOG_STDOUT, "\nnet-scan: Starting enrichment phase\n");
    scan_log("INFO", "enrichment phase starting");
    time_t enr_t0 = time(nullptr);
    int64_t prev_remaining = -1;
    int pass = 0;
    for (;;) {
      int prc = run_enrichment(data_dir, 1000);
      if (prc != 0) {
        rc = prc;
        fprintf(stderr,
          "net-scan: enrichment pass %d had errors (continuing)\n", pass + 1);
        /* Non-fatal -- keep draining / fall through to report. */
      }
      pass++;

      if (g_scan_interrupted.load()) {
        log_write(LOG_STDOUT,
          "net-scan: enrichment interrupted; remaining hosts kept for "
          "--enrich-only\n");
        break;
      }

      int64_t remaining = net_count_unenriched_all(data_dir);
      if (remaining <= 0) break;            /* fully drained */

      if (prev_remaining >= 0 && remaining >= prev_remaining) {
        /* The pool did not shrink -- nothing this pass could mark. Bail
         * rather than loop forever; surface it so the operator knows
         * some rows still need attention. */
        log_write(LOG_STDOUT,
          "net-scan: WARNING: enrichment made no progress with %lld host(s) "
          "still eligible after pass %d; re-run with --enrich-only to retry\n",
          (long long)remaining, pass);
        break;
      }
      prev_remaining = remaining;
      log_write(LOG_STDOUT,
        "net-scan: %lld host(s) still need enrichment; continuing (pass %d)\n",
        (long long)remaining, pass + 1);
    }
    ns_enr_end = std::chrono::steady_clock::now();
    scan_log("INFO", "enrichment phase complete (%lds, %d pass%s)",
             (long)(time(nullptr) - enr_t0), pass, pass == 1 ? "" : "es");

    if (o.net_enrich_only) {
      scan_log("INFO", "net-scan finished: enrich-only (%lds total)",
               (long)(time(nullptr) - ns_start));
      scan_log_close();
      return 0;
    }
  }

  /* Phase 3: Report */
  if (!o.net_discover_only && !o.net_enrich_only) {
    log_write(LOG_STDOUT, "\nnet-scan: Generating findings reports\n");
    time_t rep_t0 = time(nullptr);
    rc = generate_findings(data_dir, findings_dir);
    if (rc != 0) {
      scan_log("ERROR", "report generation had errors (rc=%d)", rc);
      fprintf(stderr, "net-scan: report generation had errors\n");
    } else {
      scan_log("INFO", "report phase complete (%lds)",
               (long)(time(nullptr) - rep_t0));
    }
  }

  /* Throughput summary. A "completed host" is one that traversed the full
     discover->enrich pipeline (i.e. was enriched); hosts/sec is that count
     over wall time. Rates are guarded against a zero/sub-ms denominator. */
  {
    auto secs = [](std::chrono::steady_clock::time_point a,
                   std::chrono::steady_clock::time_point b) -> double {
      return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count()
             / 1000.0;
    };
    double disc_s  = secs(ns_t0, ns_disc_end);
    double enr_s   = secs(ns_disc_end, ns_enr_end);
    double total_s = secs(ns_t0, std::chrono::steady_clock::now());
    EnrichMetrics em = enrich_get_metrics();
    uint64_t ips_scanned = ns_ips_scanned;
    double disc_rate = disc_s  > 0.001 ? ips_scanned   / disc_s  : 0.0;
    double enr_rate  = enr_s   > 0.001 ? em.hosts_done / enr_s   : 0.0;
    double pipe_rate = total_s > 0.001 ? em.hosts_done / total_s : 0.0;
    const char *state = g_scan_interrupted.load() ? "INTERRUPTED" : "COMPLETE";

    log_write(LOG_STDOUT,
      "\n================================================================================\n");
    log_write(LOG_STDOUT, "  NET-SCAN %s\n", state);
    log_write(LOG_STDOUT,
      "================================================================================\n");
    if (ips_scanned)
      log_write(LOG_STDOUT,
        "  Discovery:   %llu IPs in %.1fs  (%.0f IPs/sec)\n",
        (unsigned long long)ips_scanned, disc_s, disc_rate);
    else
      log_write(LOG_STDOUT, "  Discovery:   %.1fs\n", disc_s);
    log_write(LOG_STDOUT,
      "  Enrichment:  %llu hosts in %.1fs  (%.1f hosts/sec)\n",
      (unsigned long long)em.hosts_done, enr_s, enr_rate);
    log_write(LOG_STDOUT, "  Total:       %.1fs\n", total_s);
    log_write(LOG_STDOUT,
      "  Pipeline:    %llu completed host(s)  (%.2f hosts/sec over total)\n",
      (unsigned long long)em.hosts_done, pipe_rate);
    uint64_t asn_q = asn_origin_query_count();
    log_write(LOG_STDOUT,
      "  ASN:         %llu Cymru origin quer%s for %llu host(s)  (prefix-deduped)\n",
      (unsigned long long)asn_q, asn_q == 1 ? "y" : "ies",
      (unsigned long long)em.hosts_done);
    log_write(LOG_STDOUT,
      "================================================================================\n");

    scan_log("INFO",
      "net-scan %s: %llu hosts pipelined in %.1fs total "
      "(discovery=%.1fs %.0f IPs/sec, enrich=%.1fs %.1f hosts/sec; "
      "%.2f hosts/sec overall)",
      g_scan_interrupted.load() ? "interrupted" : "complete",
      (unsigned long long)em.hosts_done, total_s,
      disc_s, disc_rate, enr_s, enr_rate, pipe_rate);
  }
  scan_log_close();
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
    o.nq_asn,
    o.nq_country,
    o.nq_device,
    o.nq_output,
    o.nq_format,
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
  /* Normalized dotted-quad for all OUTPUT. ip_to_u32 accepts non-canonical
     input (sscanf stops after 4 octets, ignoring trailing junk like
     "1.2.3.4x"), so emitting the raw o.nc_ip could put unescaped junk into
     the DOT/JSON and would display inconsistently with the cohort rows, which
     all use u32_to_ip. Using the normalized form keeps the target consistent
     with the cohort and free of any characters that could break the markup.
     (The DB lookup below already self-normalizes -- it queries by ip_u32 --
     and the stderr diagnostics keep the raw string so the user sees what they
     typed.) */
  std::string target_ip = u32_to_ip(target_u32);

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
  /* RFC 8259 JSON string escaping. Fingerprint values are network-derived
     (tls_subject_cn / tls_san come straight off the peer certificate, redirect
     and PTR hosts off the wire), so they can carry raw control bytes; emitting
     those unescaped produced invalid JSON. Escape every control char < 0x20
     via \uXXXX (matching net_enrich.cc::json_escape and tracemap.cc::json_str)
     and iterate as unsigned char so UTF-8 high bytes pass through untouched. */
  auto jesc = [](const std::string &s) {
    std::string out; out.reserve(s.size() + 8);
    for (unsigned char c : s) {
      switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        default:
          if (c < 0x20) {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\u%04x", c);
            out += buf;
          } else {
            out += static_cast<char>(c);
          }
      }
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
            target_ip.c_str(), target_ip.c_str());
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
              target_ip.c_str(), ip_s.c_str(), label.c_str(), r.count);
    }
    fprintf(fp_out, "}\n");
  } else if (fmt == "json") {
    fprintf(fp_out, "{\n");
    fprintf(fp_out, "  \"target\": \"%s\",\n", target_ip.c_str());
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
            target_ip.c_str(), min_shared);
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
 * Entity graph (--entity-graph)
 *
 * Assembles the asset-attribution graph around a seed IP from the data the
 * net-scan pipeline already catalogs -- no new schema, on-the-fly like
 * --net-cluster.  Node types and the edges between them:
 *
 *   ip ──serves/resolves_to──▶ domain ──certified_by──▶ cert
 *   ip ──presents───────────▶ cert
 *   ip ──announced_by───────▶ asn ──operated_by──▶ org   (AS owner = as_name)
 *                                  └─registered_in──▶ country
 *   ip ──hosted_on──────────▶ cloud   (provider, when known)
 *
 * With --eg-depth 1 (default) the graph also pulls in other IPs that share the
 * seed's certificate or a domain (the infrastructure cohort) and their own
 * asn/org/country, so an analyst can pivot from one host to the operator's
 * wider footprint.  (A direct cert──issued_to──▶org edge from the certificate's
 * subject O= field is a planned enhancement; today the org node is the AS
 * owner.)
 * ----------------------------------------------------------------------- */
int run_entity_graph_cli() {
  if (!o.eg_seed || !o.eg_seed[0]) {
    fprintf(stderr, "entity-graph: --entity-graph requires a seed IP argument\n");
    return 1;
  }
  const char *data_dir = o.net_data_dir ? o.net_data_dir : "kmap-data";
  int depth = o.eg_depth >= 0 ? o.eg_depth : 1;

  std::map<std::string, EgNode> nodes;
  std::vector<EgEdge> edges;
  size_t cohort = 0;
  int rc = entity_graph_build(data_dir, o.eg_seed, depth, nodes, edges, &cohort);
  if (rc == -1) {
    fprintf(stderr, "entity-graph: cannot parse IP '%s'\n", o.eg_seed);
    return 1;
  }
  if (rc == -2) {
    fprintf(stderr, "entity-graph: IP %s has no enriched data in the store. "
            "Has it been scanned and enriched yet?\n", o.eg_seed);
    return 1;
  }

  FILE *out = stdout;
  if (o.eg_output && o.eg_output[0]) {
    out = fopen(o.eg_output, "w");
    if (!out) {
      fprintf(stderr, "entity-graph: cannot open output %s\n", o.eg_output);
      return 1;
    }
  }
  std::string seed_ip = u32_to_ip(ip_to_u32(o.eg_seed));
  entity_graph_emit(out, o.eg_format ? o.eg_format : "text",
                    seed_ip, depth, cohort, nodes, edges);
  if (out != stdout) fclose(out);
  return 0;
}

/* -----------------------------------------------------------------------
 * Full-text / faceted search (--search)
 *
 * Runs an FTS5 MATCH query (net_db_search_fts) across every shard, merges the
 * hits by bm25 rank, and emits the top matches.  Lets an operator do
 * Shodan/Censys-style free-text + faceted queries over the catalog, e.g.
 *   kmap --search 'service:nginx country:US cloudflare'
 *   kmap --search '"apache httpd" NOT country:CN' --search-format json
 * which the structured --net-query LIKE filters cannot express.
 * ----------------------------------------------------------------------- */
int run_search_cli() {
  if (!o.search_query || !o.search_query[0]) {
    fprintf(stderr, "search: --search requires a query string\n");
    return 1;
  }
  const char *data_dir = o.net_data_dir ? o.net_data_dir : "kmap-data";
  int limit = o.search_limit > 0 ? o.search_limit : 100;

  std::vector<NetSearchHit> all;
  std::string err;
  for (int sh = 0; sh < NET_SHARD_COUNT; sh++) {
    std::string sp = net_shard_path(data_dir, sh);
    FILE *t = fopen(sp.c_str(), "r");
    if (!t) continue;
    fclose(t);
    sqlite3 *db = net_db_open(sp.c_str());
    if (!db) continue;
    std::string e2;
    std::vector<NetSearchHit> hits = net_db_search_fts(db, o.search_query, limit, &e2);
    net_db_close(db);
    if (!e2.empty() && err.empty()) err = e2;
    for (auto &h : hits) all.push_back(std::move(h));
  }
  /* A query-syntax / FTS5-availability error (vs. simply no matches) is worth
     surfacing rather than silently printing zero results. */
  if (all.empty() && !err.empty()) {
    fprintf(stderr, "search: query error: %s\n", err.c_str());
    return 1;
  }
  std::sort(all.begin(), all.end(),
            [](const NetSearchHit &a, const NetSearchHit &b) { return a.rank < b.rank; });
  if (static_cast<int>(all.size()) > limit) all.resize(limit);

  FILE *out = stdout;
  if (o.search_output && o.search_output[0]) {
    out = fopen(o.search_output, "w");
    if (!out) { fprintf(stderr, "search: cannot open output %s\n", o.search_output); return 1; }
  }
  auto jesc = [](const std::string &s) {
    std::string r; r.reserve(s.size() + 8);
    for (unsigned char c : s) {
      switch (c) {
        case '"':  r += "\\\""; break; case '\\': r += "\\\\"; break;
        case '\n': r += "\\n";  break; case '\r': r += "\\r";  break;
        case '\t': r += "\\t";  break; case '\b': r += "\\b";  break;
        case '\f': r += "\\f";  break;
        default: if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); r += b; }
                 else r += static_cast<char>(c);
      }
    }
    return r;
  };

  const std::string fmt = o.search_format ? o.search_format : "text";
  if (fmt == "json") {
    fprintf(out, "[\n");
    for (size_t i = 0; i < all.size(); i++) {
      const NetSearchHit &h = all[i];
      fprintf(out, "  {\"ip\":\"%s\",\"port\":%d,\"service\":\"%s\",\"version\":\"%s\","
                   "\"cpe\":\"%s\",\"as_name\":\"%s\",\"country\":\"%s\",\"cloud\":\"%s\","
                   "\"web_title\":\"%s\"}%s\n",
              jesc(h.ip).c_str(), h.port, jesc(h.service).c_str(), jesc(h.version).c_str(),
              jesc(h.cpe).c_str(), jesc(h.as_name).c_str(), jesc(h.country).c_str(),
              jesc(h.cloud_provider).c_str(), jesc(h.web_title).c_str(),
              (i + 1 == all.size()) ? "" : ",");
    }
    fprintf(out, "]\n");
  } else {
    fprintf(out, "# search '%s': %zu match(es)\n", o.search_query, all.size());
    for (const NetSearchHit &h : all) {
      fprintf(out, "%-15s %-6d %-10s %-22s", h.ip.c_str(), h.port,
              h.service.empty() ? "-" : h.service.c_str(),
              h.version.empty() ? "-" : h.version.c_str());
      if (!h.country.empty())        fprintf(out, " %s", h.country.c_str());
      if (!h.as_name.empty())        fprintf(out, " [%s]", h.as_name.c_str());
      if (!h.cloud_provider.empty()) fprintf(out, " {%s}", h.cloud_provider.c_str());
      if (!h.web_title.empty())      fprintf(out, " \"%s\"", h.web_title.c_str());
      fprintf(out, "\n");
    }
  }
  if (out != stdout) fclose(out);
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

/* RFC 8259 JSON string escaping: structural chars plus ALL control
   characters U+0000..U+001F. unsigned char iteration so UTF-8 high bytes
   pass through rather than being mis-escaped as negative < 0x20. */
static std::string json_escape_topo(const std::string &s) {
  std::string out; out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b";  break;
      case '\f': out += "\\f";  break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
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
