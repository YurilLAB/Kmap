/*
 * fast_syn.cc -- High-speed asynchronous SYN scanner for Kmap net-scan.
 *
 * Uses raw sockets for TX and libpcap for RX.  Scans the IPv4 space
 * in randomized order using a multiplicative-inverse permutation.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "fast_syn.h"
#include "net_db.h"
#include "kmap.h"
#include "tcpip.h"
#include "KmapOps.h"
#include "sys_resources.h"
#include "output.h"
#include "os_profile.h"

#include <pcap.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>
#include <set>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <signal.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>
#include <io.h>
#include <mmsystem.h>
#include <psapi.h>
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "psapi.lib")
#endif

extern KmapOps o;

/* -----------------------------------------------------------------------
 * Exclusion list handling
 * ----------------------------------------------------------------------- */

static uint32_t cidr_mask(int prefix_len) {
  if (prefix_len <= 0) return 0;
  if (prefix_len >= 32) return 0xFFFFFFFF;
  return ~((1u << (32 - prefix_len)) - 1);
}

static bool parse_cidr(const char *line, uint32_t &net, uint32_t &mask) {
  char ip_buf[64];
  int prefix = 32;

  const char *slash = strchr(line, '/');
  if (slash) {
    size_t ip_len = static_cast<size_t>(slash - line);
    if (ip_len >= sizeof(ip_buf)) return false;
    memcpy(ip_buf, line, ip_len);
    ip_buf[ip_len] = '\0';
    /* Parse the prefix STRICTLY. atoi() silently returns 0 for a
     * non-numeric or empty prefix ("1.2.3.4/abc", "1.2.3.4/"), which made
     * cidr_mask(0) produce mask=0 -- and a {net=0, mask=0} range matches
     * EVERY IP in is_excluded(). A single typo in a user exclude file would
     * therefore silently exclude the entire internet and the scan would
     * find nothing. Require a non-empty, all-digits prefix and reject the
     * line otherwise; an explicit "x.x.x.x/0" is still honored as the
     * legitimate "match everything" CIDR. */
    const char *pp = slash + 1;
    if (*pp == '\0') return false;            /* empty prefix */
    char *endp = nullptr;
    long pv = strtol(pp, &endp, 10);
    if (endp == pp || *endp != '\0') return false;  /* non-numeric/trailing junk */
    if (pv < 0 || pv > 32) return false;
    prefix = static_cast<int>(pv);
  } else {
    strncpy(ip_buf, line, sizeof(ip_buf) - 1);
    ip_buf[sizeof(ip_buf) - 1] = '\0';
  }

  net = ip_to_u32(ip_buf);
  if (net == 0 && strcmp(ip_buf, "0.0.0.0") != 0) return false;
  mask = cidr_mask(prefix);
  net &= mask;
  return true;
}

std::vector<ExcludeRange> builtin_excludes() {
  std::vector<ExcludeRange> list;
  static const char *ranges[] = {
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", /* 6to4 relay anycast -- deprecated (RFC 7526), no hosts */
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
    /* DoD ranges */
    "6.0.0.0/8", "7.0.0.0/8", "11.0.0.0/8", "21.0.0.0/8",
    "22.0.0.0/8", "26.0.0.0/8", "28.0.0.0/8", "29.0.0.0/8",
    "30.0.0.0/8", "33.0.0.0/8", "55.0.0.0/8",
    "214.0.0.0/8", "215.0.0.0/8",
    nullptr
  };
  for (const char **r = ranges; *r; ++r) {
    ExcludeRange er;
    if (parse_cidr(*r, er.network, er.mask))
      list.push_back(er);
  }
  return list;
}

std::vector<ExcludeRange> load_exclude_list(const char *path) {
  std::vector<ExcludeRange> list;
  std::ifstream f(path);
  if (!f.is_open()) {
    fprintf(stderr, "net-scan: WARNING: cannot open exclude file: %s\n", path);
    return list;
  }
  std::string line;
  while (std::getline(f, line)) {
    /* Trim */
    size_t start = line.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) continue;
    line = line.substr(start);
    line.erase(line.find_last_not_of(" \t\r\n") + 1);
    /* Skip comments and empty lines */
    if (line.empty() || line[0] == '#') continue;

    ExcludeRange er;
    if (parse_cidr(line.c_str(), er.network, er.mask)) {
      list.push_back(er);
    } else {
      /* Surface malformed lines instead of dropping them silently -- a
       * bad CIDR that we ignore could otherwise leave the operator
       * believing a range is excluded when it is not. */
      fprintf(stderr,
        "net-scan: WARNING: ignoring malformed exclude line: %s\n",
        line.c_str());
    }
  }
  return list;
}

bool is_excluded(uint32_t ip, const std::vector<ExcludeRange> &excludes) {
  for (const auto &er : excludes) {
    if ((ip & er.mask) == er.network)
      return true;
  }
  return false;
}

/* -----------------------------------------------------------------------
 * Port spec parser
 * ----------------------------------------------------------------------- */

std::vector<int> parse_port_spec(const char *spec) {
  std::set<int> ports;
  if (!spec || !spec[0]) {
    /* Default: top 100 common ports, numeric order. Tried reordering
       most-common-first to make the early-bail fire faster -- it
       actually slightly hurt coverage on a real 1000-IP sweep, because
       legacy low-number ports (7/20/21/etc) tend to elicit CLOSED RSTs
       from real hosts which reset the bail streak and let us continue
       probing weird-port-only services. Common ports (80/443/22/etc)
       are more often firewall-DROPped (no response) which builds the
       streak instead. Numeric order it is. */
    static const int top100[] = {
      7,20,21,22,23,25,43,53,67,68,69,79,80,88,110,111,113,119,123,
      135,137,138,139,143,161,162,179,194,389,443,445,465,514,515,
      520,523,554,587,631,636,873,902,993,995,1025,1080,1194,1433,
      1434,1521,1723,1883,2049,2082,2083,2086,2087,2181,2375,2376,
      3000,3128,3306,3389,3690,4443,4848,5000,5432,5555,5672,5683,
      5900,5901,5984,6379,6443,6660,6667,6697,7001,7077,7474,8000,
      8008,8009,8080,8081,8443,8880,8888,9000,9090,9200,9300,9418,
      9999,10000,11211,27017,27018,50000,50070
    };
    for (int p : top100) ports.insert(p);
    return std::vector<int>(ports.begin(), ports.end());
  }

  auto parse_num = [](const std::string &s, int &out) -> bool {
    if (s.empty()) return false;
    for (char c : s) if (c < '0' || c > '9') return false;
    char *end = nullptr;
    long v = strtol(s.c_str(), &end, 10);
    if (!end || *end != '\0' || v < 0 || v > 65535) return false;
    out = (int)v;
    return true;
  };

  std::istringstream ss(spec);
  std::string token;
  while (std::getline(ss, token, ',')) {
    size_t dash = token.find('-');
    if (dash != std::string::npos) {
      int lo = 0, hi = 0;
      std::string lo_s = token.substr(0, dash);
      std::string hi_s = token.substr(dash + 1);
      if (!parse_num(lo_s, lo) || !parse_num(hi_s, hi)) {
        fprintf(stderr, "net-scan: invalid port range '%s' -- skipping\n",
                token.c_str());
        continue;
      }
      if (lo < 1) lo = 1;
      if (hi > 65535) hi = 65535;
      if (lo > hi) {
        fprintf(stderr, "net-scan: port range '%s' has lo > hi -- skipping\n",
                token.c_str());
        continue;
      }
      for (int p = lo; p <= hi; p++) ports.insert(p);
    } else {
      int p = 0;
      if (!parse_num(token, p) || p < 1 || p > 65535) {
        fprintf(stderr, "net-scan: invalid port '%s' -- skipping\n",
                token.c_str());
        continue;
      }
      ports.insert(p);
    }
  }
  return std::vector<int>(ports.begin(), ports.end());
}

/* -----------------------------------------------------------------------
 * IP randomization -- multiplicative inverse permutation
 *
 * Maps index 0..N-1 to a unique IP in 0..N-1 using:
 *   permuted = (index * PRIME) mod N
 * where PRIME is coprime to N.  This visits every value exactly once.
 * ----------------------------------------------------------------------- */

static const uint64_t IP_SPACE = 0x100000000ULL; /* 2^32 */
/* A large prime coprime to 2^32 (any odd prime works) */
static const uint64_t PERMUTE_PRIME = 3948573427ULL;
/* Offset for additional randomization per-scan */
static const uint64_t PERMUTE_OFFSET = 1103515245ULL;

static uint32_t permute_ip(uint64_t index, uint64_t seed) {
  return static_cast<uint32_t>(((index * PERMUTE_PRIME) + seed) & 0xFFFFFFFF);
}

/* -----------------------------------------------------------------------
 * Checkpoint / resume
 * ----------------------------------------------------------------------- */

struct ScanCheckpoint {
  uint64_t next_index;     /* next IP index to scan */
  uint64_t packets_sent;
  uint64_t hosts_found;
  uint64_t seed;           /* permutation seed -- must match on resume */
  time_t   last_save;
};

static std::string checkpoint_path(const char *data_dir) {
  return std::string(data_dir) + "/.net-scan-checkpoint";
}

static bool save_checkpoint(const char *data_dir, const ScanCheckpoint &cp) {
  std::string path = checkpoint_path(data_dir);
  std::string tmp_path = path + ".tmp";
  FILE *f = fopen(tmp_path.c_str(), "w");
  if (!f) return false;
  int n = fprintf(f, "%llu\n%llu\n%llu\n%llu\n%lld\n",
                  (unsigned long long)cp.next_index,
                  (unsigned long long)cp.packets_sent,
                  (unsigned long long)cp.hosts_found,
                  (unsigned long long)cp.seed,
                  (long long)cp.last_save);
  if (n < 0 || fflush(f) != 0) {
    fclose(f);
    remove(tmp_path.c_str());
    return false;
  }
  if (fclose(f) != 0) {
    remove(tmp_path.c_str());
    return false;
  }
  /* Atomic replace. On Windows rename() fails if the destination exists,
   * so remove the old checkpoint first. A crash between remove() and
   * rename() still leaves the .tmp file, which we can fall back to on load. */
#ifdef WIN32
  remove(path.c_str());
#endif
  if (rename(tmp_path.c_str(), path.c_str()) != 0) {
    remove(tmp_path.c_str());
    return false;
  }
  return true;
}

static bool load_checkpoint(const char *data_dir, ScanCheckpoint &cp) {
  std::string path = checkpoint_path(data_dir);
  FILE *f = fopen(path.c_str(), "r");
  /* If the atomic rename didn't complete, the last successful write may
   * still be in the .tmp file. Fall back to it. */
  if (!f) {
    std::string tmp_path = path + ".tmp";
    f = fopen(tmp_path.c_str(), "r");
    if (!f) return false;
  }
  unsigned long long ni, ps, hf, sd;
  long long ls;
  if (fscanf(f, "%llu\n%llu\n%llu\n%llu\n%lld", &ni, &ps, &hf, &sd, &ls) != 5) {
    fclose(f);
    return false;
  }
  cp.next_index = ni;
  cp.packets_sent = ps;
  cp.hosts_found = hf;
  cp.seed = sd;
  cp.last_save = static_cast<time_t>(ls);
  fclose(f);
  return true;
}

/* -----------------------------------------------------------------------
 * Rate limiter -- token bucket
 * ----------------------------------------------------------------------- */

struct RateLimiter {
  double tokens;
  double max_tokens;
  double refill_rate;  /* tokens per microsecond */
  int64_t last_refill; /* microsecond timestamp */
};

static int64_t now_usec() {
#ifdef WIN32
  /* QueryPerformanceCounter is monotonic on every Windows version we
   * support, so the rate-limiter math cannot see time step backwards. */
  static LARGE_INTEGER freq = {};
  if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
  LARGE_INTEGER counter;
  QueryPerformanceCounter(&counter);
  return (int64_t)((double)counter.QuadPart / (double)freq.QuadPart * 1000000.0);
#else
  /* CLOCK_MONOTONIC, not gettimeofday(): on long-running scans NTP slew
   * can step the wall clock backwards, which made the previous
   * gettimeofday() path return a "now" earlier than rl.last_refill.
   * That produced a negative elapsed and the token bucket would silently
   * lose tokens, stalling the limiter until it caught back up. */
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000;
#endif
}

static void rate_init(RateLimiter &rl, int pps) {
  /* Cap burst capacity at ~20 ms of refill. The previous value of
   * pps * 1.5 (1.5 seconds of accumulated tokens) caused a huge
   * opening burst at scan start -- for --rate 25000 the first ~37,500
   * packets fired as fast as the CPU could drive them, before any
   * throttling kicked in. That spike triggers IDS on the receiving
   * end and overflows upstream NIC buffers. A 20 ms ceiling absorbs
   * normal scheduler hiccups without producing detectable spikes. */
  rl.max_tokens = (double)pps * 0.02;
  if (rl.max_tokens < 4.0) rl.max_tokens = 4.0;  /* floor for low pps */
  rl.tokens = 1.0;                /* ramp up smoothly, don't burst */
  rl.refill_rate = (double)pps / 1000000.0;
  rl.last_refill = now_usec();
}

/* Acquire one token from the shared bucket.  Caller passes the mutex
 * protecting the bucket; we hold it only across the refill+decrement
 * arithmetic, NOT across the sleep, so 50 parallel workers do not
 * serialize on the lock while one is sleeping for 1 ms waiting for
 * more tokens.  That serialization was the real cause of the
 * net-scan run measuring only ~14 pps despite a 5000 pps target. */
static void rate_wait(RateLimiter &rl, std::mutex &mu) {
  while (true) {
    bool got_token = false;
    {
      std::lock_guard<std::mutex> lk(mu);
      int64_t now = now_usec();
      double elapsed = (double)(now - rl.last_refill);
      rl.tokens += elapsed * rl.refill_rate;
      if (rl.tokens > rl.max_tokens) rl.tokens = rl.max_tokens;
      rl.last_refill = now;
      if (rl.tokens >= 1.0) {
        rl.tokens -= 1.0;
        got_token = true;
      }
    }
    if (got_token) return;
    /* Sleep briefly to avoid busy-waiting -- mutex released so other
     * workers can race for the next refill. */
#ifdef WIN32
    Sleep(1);
#else
    usleep(100);
#endif
  }
}

/* -----------------------------------------------------------------------
 * Global scan interrupt flag
 * ----------------------------------------------------------------------- */

static volatile int scan_interrupted = 0;

#ifndef WIN32
static void sigint_handler(int /*sig*/) {
  scan_interrupted = 1;
}
#else
/* Named handler so SetConsoleCtrlHandler(.., FALSE) at scan exit can
 * actually remove it; passing nullptr only resets default Ctrl+C
 * behavior, it does not unregister an installed handler. */
static BOOL WINAPI win_console_ctrl_handler(DWORD /*type*/) {
  scan_interrupted = 1;
  return TRUE;
}
#endif

/* -----------------------------------------------------------------------
 * Fast SYN scan implementation
 *
 * This is a simplified scanner that works without Kmap's full Target
 * infrastructure.  It:
 *   1. Iterates IPs in permuted order
 *   2. For each IP+port, crafts a SYN packet using Kmap's build_tcp_raw
 *   3. Sends it via a raw socket
 *   4. Captures responses via pcap
 *   5. Inserts discovered open ports into shard databases
 *
 * For systems where raw sockets are not available (unprivileged users),
 * falls back to connect() scanning (slower but works without root).
 * ----------------------------------------------------------------------- */

/* Open shard databases -- one per shard index.  Returns nullptr entries
   for shards that fail to open (non-fatal). */
static std::vector<sqlite3 *> open_all_shards(const char *data_dir) {
  std::vector<sqlite3 *> shards(NET_SHARD_COUNT, nullptr);
  for (int i = 0; i < NET_SHARD_COUNT; i++) {
    std::string path = net_shard_path(data_dir, i);
    shards[i] = net_db_open(path);
  }
  return shards;
}

static void close_all_shards(std::vector<sqlite3 *> &shards) {
  for (auto *db : shards) {
    if (db) net_db_close(db);
  }
  shards.clear();
}

/* -----------------------------------------------------------------------
 * Connect-scan fallback (for unprivileged users)
 *
 * When raw sockets are unavailable, we fall back to non-blocking
 * connect() probes.  Slower but works without root/admin.
 * ----------------------------------------------------------------------- */

/* Probe outcome.  CLOSED = host explicitly replied (RST / ECONNREFUSED),
 * arrives in microseconds and tells us the host is alive.  TIMEOUT =
 * select() expired with no response, the costly outcome and the one
 * we want to detect-and-bail on.  OPEN = SYN-ACK accepted. */
enum class ProbeResult { OPEN, CLOSED, TIMEOUT };

static ProbeResult connect_probe(uint32_t ip, int port, int timeout_ms) {
  struct sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(static_cast<uint16_t>(port));
  sa.sin_addr.s_addr = htonl(ip);

#ifdef WIN32
  SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == INVALID_SOCKET) return ProbeResult::CLOSED;
  u_long nb = 1;
  ioctlsocket(fd, FIONBIO, &nb);
#else
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return ProbeResult::CLOSED;
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

  int nodelay = 1;
  setsockopt(static_cast<int>(fd), IPPROTO_TCP, TCP_NODELAY,
             reinterpret_cast<const char *>(&nodelay), sizeof(nodelay));

  /* Abortive close (RST, not FIN) so a successful probe does not park the
     local ephemeral port in TIME_WAIT. A dense mass scan that connects to
     many open ports would otherwise exhaust the ~16k Windows dynamic-port
     range within minutes and stall; SO_LINGER{1,0} returns the port
     immediately. Harmless for filtered/closed probes -- there is no
     established connection to linger over. (RST-on-close verified in
     fuzz/test_linger.cc.) */
  struct linger lg; lg.l_onoff = 1; lg.l_linger = 0;
  setsockopt(fd, SOL_SOCKET, SO_LINGER,
             reinterpret_cast<const char *>(&lg), sizeof(lg));

  os_profile_apply_socket(static_cast<intptr_t>(fd), AF_INET,
                          os_profile_get_for_target(
                              o.spoof_os,
                              os_profile_seed_from_ipv4(ip)));

  connect(fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa));

  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(fd, &wset);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

  ProbeResult result = ProbeResult::TIMEOUT;
  int sel = select(static_cast<int>(fd) + 1, nullptr, &wset, nullptr, &tv);
  if (sel > 0) {
    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR,
               reinterpret_cast<char *>(&err), &elen);
    result = (err == 0) ? ProbeResult::OPEN : ProbeResult::CLOSED;
  }
  /* sel == 0 -> TIMEOUT (already the default).
   * sel < 0 -> select error; treat as CLOSED so the bail heuristic
   *           does not over-trigger on transient kernel hiccups. */
  if (sel < 0) result = ProbeResult::CLOSED;

#ifdef WIN32
  closesocket(fd);
#else
  close(fd);
#endif
  return result;
}

/* -----------------------------------------------------------------------
 * Main scan function
 * ----------------------------------------------------------------------- */

int fast_syn_scan(const char *data_dir,
                  const std::vector<int> &ports,
                  int rate_pps,
                  const std::vector<ExcludeRange> &excludes,
                  bool resume,
                  uint64_t max_ips) {
  if (ports.empty()) {
    fprintf(stderr, "net-scan: no ports to scan\n");
    return 1;
  }

  /* Validate rate -- warn if unreasonably high */
  if (rate_pps > 1000000) {
    fprintf(stderr,
      "net-scan: WARNING: --rate %d exceeds 1,000,000 pps; "
      "this may overwhelm your network or trigger IDS alerts.\n",
      rate_pps);
  }

  /* Create data directory */
#ifdef WIN32
  _mkdir(data_dir);
#else
  mkdir(data_dir, 0755);
#endif

  /* Open all shard databases */
  auto shards = open_all_shards(data_dir);
  int shards_ok = 0;
  for (auto *db : shards) if (db) shards_ok++;
  if (shards_ok == 0) {
    fprintf(stderr, "net-scan: failed to open any shard databases\n");
    return 1;
  }

  /* Load checkpoint if resuming */
  ScanCheckpoint cp{};
  cp.next_index = 0;
  cp.packets_sent = 0;
  cp.hosts_found = 0;
  cp.seed = 0;
  cp.last_save = time(nullptr);

  bool resumed = false;
  if (resume) {
    if (load_checkpoint(data_dir, cp)) {
      /* A checkpoint that indicates progress but lacks a seed cannot
       * be resumed safely -- without the original permutation seed the
       * scanner would walk a different IP order, leaving some IPs
       * never scanned and others scanned twice. Older checkpoints
       * from before seed tracking land here. */
      if (cp.seed == 0 && cp.next_index > 0) {
        fprintf(stderr,
          "net-scan: ERROR: checkpoint at %s shows progress (index %llu) "
          "but has no permutation seed; cannot resume safely. Delete the "
          "checkpoint and restart, or use a checkpoint from a newer kmap "
          "build that records the seed.\n",
          checkpoint_path(data_dir).c_str(),
          (unsigned long long)cp.next_index);
        close_all_shards(shards);
        return 1;
      }
      /* Reset last_save to "now" so ETA calculations measure rate
       * since-resume rather than since-original-checkpoint (which
       * could be days ago and produces a useless "calculating..."
       * for the first 60 s post-resume). */
      cp.last_save = time(nullptr);
      log_write(LOG_STDOUT, "net-scan: Resuming from index %llu (%llu packets sent, %llu hosts found)\n",
                (unsigned long long)cp.next_index,
                (unsigned long long)cp.packets_sent,
                (unsigned long long)cp.hosts_found);
      resumed = true;
    } else {
      log_write(LOG_STDOUT, "net-scan: No checkpoint found, starting fresh\n");
    }
  }

  /* Set up rate limiter */
  RateLimiter rl;
  rate_init(rl, rate_pps);

  /* Set up interrupt handler */
#ifndef WIN32
  struct sigaction sa_old, sa_new;
  memset(&sa_new, 0, sizeof(sa_new));
  sa_new.sa_handler = sigint_handler;
  sigaction(SIGINT, &sa_new, &sa_old);
#else
  SetConsoleCtrlHandler(win_console_ctrl_handler, TRUE);
  /* Raise Windows timer resolution so Sleep(1) in the rate limiter
   * actually sleeps ~1 ms instead of the default ~15.6 ms. Without
   * this, the limiter degenerates into 15 ms-long pauses followed by
   * burst sends, which makes high --rate values much noisier on
   * Windows than on Linux. timeEndPeriod() restores the system
   * default at scan exit. */
  timeBeginPeriod(1);
#endif
  scan_interrupted = 0;

  /* Seed for IP permutation -- stored in checkpoint so resume uses
     the same permutation order as the original scan. */
  uint64_t seed;
  if (resumed && cp.seed != 0) {
    seed = cp.seed;
  } else {
    seed = static_cast<uint64_t>(time(nullptr)) ^ PERMUTE_OFFSET;
    cp.seed = seed;
  }

  log_write(LOG_STDOUT, "\nnet-scan: Starting discovery scan\n");
  log_write(LOG_STDOUT, "  Rate:       %d pps\n", rate_pps);
  log_write(LOG_STDOUT, "  Ports:      %d\n", (int)ports.size());
  log_write(LOG_STDOUT, "  Excludes:   %d ranges\n", (int)excludes.size());
  log_write(LOG_STDOUT, "  Shards:     %d databases\n", shards_ok);
  log_write(LOG_STDOUT, "\n");

  /* Begin transactions on all shards for batch insert performance */
  for (auto *db : shards) {
    if (db) net_db_begin(db);
  }

  /* Discovery timestamp stamped on every inserted host. Refreshed on the
     60s checkpoint cadence (below) so a multi-day sweep records each host's
     actual discovery window instead of freezing every row at scan-start.
     Atomic because the insert reads it from worker threads. */
  std::atomic<int64_t> now_ts{static_cast<int64_t>(time(nullptr))};
  time_t last_status = time(nullptr);
  time_t last_checkpoint = time(nullptr);
  uint64_t batch_inserts = 0;

  /* Main scan loop -- using connect() fallback for safety.
   * Raw SYN scanning requires root privileges and careful pcap setup
   * that varies by OS.  The connect() approach works everywhere and
   * for a home-machine scanner at 25k pps is adequate.  The rate
   * limiter controls the pace. */

  /* Compute the stop index.  When max_ips is set we cap the loop at
   * (resume-start + max_ips) so a re-run with the same checkpoint
   * advances past the previously-scanned slice instead of re-scanning
   * the same first-N IPs.  Clamp to IP_SPACE so a giant max_ips just
   * means "scan everything from here on". */
  uint64_t scan_end = IP_SPACE;
  if (max_ips > 0) {
    if (cp.next_index < IP_SPACE - max_ips)
      scan_end = cp.next_index + max_ips;
  }
  if (max_ips > 0) {
    log_write(LOG_STDOUT,
      "  Sample mode: scanning %llu IPs starting at index %llu\n",
      (unsigned long long)max_ips,
      (unsigned long long)cp.next_index);
  }

  /* Parallel probe pool.
   *
   * The original serial loop was dominated by the 500 ms connect()
   * timeout on filtered IPs: a 150-IP random sample over the top-100
   * ports came out to ~2 hours wall time, well below the configured
   * rate ceiling because the limiter never even got to release
   * tokens before connect_probe returned.  Same fan-out treatment
   * I gave watchlist: N workers pop an IP index from an atomic
   * counter and walk the inner port loop themselves.  The token
   * bucket stays shared (rate_mu) so the global pps cap still
   * applies across all threads, and the per-shard sqlite handles
   * stay shared too (db_mu) so writes are serialized. */
  /* Default 100 workers (was 50): the metric emit added in this commit
   * confirmed kmap discovery runs at ~1-2% CPU and ~23MB RSS during
   * a 150-IP probe wave -- the bottleneck is purely network RTT on
   * filtered ports, not local resources.  100 saturates the RTT
   * waits without straining a typical client machine.  1024 cap
   * retained as the sanity ceiling. */
  int worker_count = 100;
  /* --efficient / --fast derive a resource-aware default from the detected
   * CPU/RAM. The KMAP_NETSCAN_CONCURRENCY env var still wins (checked
   * after), so explicit operator overrides keep their priority. */
  {
    const KmapPerfProfile &pp = kmap_perf_profile();
    if (pp.mode != KMAP_PERF_NORMAL && pp.discovery_workers > 0)
      worker_count = pp.discovery_workers;
  }
  if (const char *env = getenv("KMAP_NETSCAN_CONCURRENCY")) {
    int v = atoi(env);
    if (v > 0 && v <= 1024) worker_count = v;
  }

  /* Per-probe TCP-connect timeout, milliseconds.  500 ms default --
   * I briefly tried 250 ms but it cut off legitimate services on
   * cross-continent paths (a host in us-east-1 from Australia has
   * ~200 ms RTT, leaving 50 ms of margin which lost ~37% of real
   * opens on the validation scan).  500 ms covers any reasonable
   * one-way RTT and the early-bail heuristic below handles the
   * 100%-filtered-host case without needing the lower timeout.
   * Tunable via KMAP_PROBE_TIMEOUT_MS for LAN-only scans (lower)
   * or satellite-tier paths (higher). */
  int probe_timeout_ms = 500;
  if (const char *env = getenv("KMAP_PROBE_TIMEOUT_MS")) {
    int v = atoi(env);
    if (v >= 50 && v <= 30000) probe_timeout_ms = v;
  }

  /* Per-IP early-bail threshold: after this many CONSECUTIVE timeouts
   * with zero opens seen on the current IP, skip the remaining ports
   * for that IP.  Single biggest discovery-time win on random-IPv4
   * samples: a fully-filtered host that would otherwise burn
   * N_ports * timeout_ms now burns only N_bail * timeout_ms.  A
   * single early CLOSED reply resets the counter -- so a host that
   * is up but firewalled on most ports still gets fully scanned
   * because the RST tells us it's alive. */
  /* Default 8. Tested 5 and 7: bail=5 collapsed host count 727 -> 150
     on a 1000-IP random sweep (real alive hosts got bailed before we
     reached their listening port). bail=7 cost about the same time as
     bail=8 with slightly worse coverage, so there is no benefit to
     lowering it -- discovery wall time is dominated by responsive hosts
     probing all 100 ports, not by bail-streak-on-dead-hosts. Real perf
     wins come from parallelizing within-host enrichment (Phase 0) and
     async I/O (Phase 1), not from tightening this counter. */
  int bail_after_timeouts = 8;
  if (const char *env = getenv("KMAP_BAIL_AFTER_TIMEOUTS")) {
    int v = atoi(env);
    if (v >= 1 && v <= 100) bail_after_timeouts = v;
  }

  std::atomic<uint64_t> probe_idx{cp.next_index};
  std::atomic<uint64_t> probes_done{0};
  std::atomic<uint64_t> hosts_found_atomic{0};
  std::mutex rate_mu;
  std::mutex db_mu;

  /* Discovery concurrency is a single flat pool of persistent workers.
     The previous design was two-level -- worker_count outer threads each
     spawning up to KMAP_DISCOVERY_PORT_PARALLELISM *inner* threads PER IP
     to probe that IP's ports in parallel, then joining them. On a
     multi-port sweep that created and destroyed inner_workers threads for
     every single IP: cheap-looking per IP, catastrophic in aggregate
     (a multi-port internet sweep would churn billions of thread
     create/destroy cycles -- pure scheduler/handle overhead on a desktop).

     This pool folds the two levels into one: total_workers persistent
     threads, each of which claims an IP and probes its ports SEQUENTIALLY
     with a thread-local bail counter, then moves to the next IP. The peak
     number of concurrent connect() probes -- and therefore aggregate probe
     throughput, since every probe still draws from the one shared
     rate-limiter token bucket -- is unchanged (total_workers ==
     worker_count * inner_workers at the old peak). We simply keep more
     distinct IPs in flight instead of more ports of fewer IPs, and pay the
     thread create/destroy cost once per worker for the whole scan instead
     of once per IP. For a single-port sweep (inner_workers == 1, the
     canonical internet-scale workload) total_workers == worker_count, so
     that path is unchanged. */
  int port_parallelism = 8;
  if (const char *env = getenv("KMAP_DISCOVERY_PORT_PARALLELISM")) {
    int v = atoi(env);
    if (v >= 1 && v <= 32) port_parallelism = v;
  }
  int inner_workers = port_parallelism;
  if (inner_workers > static_cast<int>(ports.size()))
    inner_workers = static_cast<int>(ports.size());
  if (inner_workers < 1) inner_workers = 1;

  /* Flat worker total = old (outer x inner) peak concurrency. Clamped so
     that cranking both knobs to their maxima (1024 * 32) cannot request a
     pathological number of persistent threads; 4096 concurrent connects is
     already far past what a residential uplink can usefully drive. */
  long total_workers = static_cast<long>(worker_count) *
                       static_cast<long>(inner_workers);
  const long TOTAL_WORKER_CAP = 4096;
  if (total_workers > TOTAL_WORKER_CAP) total_workers = TOTAL_WORKER_CAP;
  if (total_workers < 1) total_workers = 1;

  /* Per-worker in-flight index tracking for an EXACT resume low-water-mark.
     Each worker publishes the index it is currently probing; INFLIGHT_NONE
     means it holds nothing (idle between claims, or exited). The checkpoint's
     resume position is min(probe_idx, every worker's in-flight index) -- i.e.
     the lowest index claimed but not yet fully probed+inserted.

     This replaces the old "cur_idx - total_workers" rewind heuristic, which
     under-rewound whenever a worker stalled on a slow LIVE host (bail
     disabled -> every port probed at up to probe_timeout_ms) while the rest
     of the pool raced thousands of indices ahead -- they share one global
     rate limiter, not a per-worker budget, so probe_idx can outrun a stalled
     worker by far more than total_workers. A crash-resume then skipped the
     stalled host. Re-covering the exact in-flight window on resume is
     harmless: the permutation seed is preserved (same indices -> same IPs)
     and host inserts are idempotent UPSERTs. */
  static const uint64_t INFLIGHT_NONE = UINT64_MAX;
  std::vector<std::atomic<uint64_t>> worker_inflight(total_workers);
  for (long wi = 0; wi < total_workers; wi++)
    worker_inflight[wi].store(INFLIGHT_NONE, std::memory_order_relaxed);

  auto compute_low_water = [&]() -> uint64_t {
    uint64_t p  = probe_idx.load(std::memory_order_acquire);
    uint64_t lw = p;
    /* (a) Slow PROCESSING workers: each publishes its index before probing,
       so the exact minimum of the published in-flight set covers a worker
       stalled on a slow live host -- the case the old heuristic missed. */
    for (long w = 0; w < total_workers; w++) {
      uint64_t v = worker_inflight[w].load(std::memory_order_acquire);
      if (v != INFLIGHT_NONE && v < lw) lw = v;
    }
    /* (b) The fetch_add(claim) -> store(publish) gap: an index claimed but
       not yet published is invisible to (a). That gap is non-blocking (two
       atomics + a permute), so such indices are always within total_workers
       of probe_idx. Floor by (probe_idx - total_workers) to cover them.
       Combined, every claimed-but-unfinished index is >= the saved position,
       so resume never skips one; the extra overlap is harmless (seed
       preserved, inserts idempotent). */
    uint64_t floor = (p > (uint64_t)total_workers)
                       ? p - (uint64_t)total_workers : 0;
    if (floor < lw) lw = floor;
    return lw;
  };

  auto worker = [&](long w) {
    while (!scan_interrupted) {
      uint64_t my_idx = probe_idx.fetch_add(1, std::memory_order_relaxed);
      if (my_idx >= scan_end) {
        worker_inflight[w].store(INFLIGHT_NONE, std::memory_order_release);
        return;
      }
      /* Publish the claim BEFORE any probing so a checkpoint racing this
         worker always sees the index as in-flight and never skips it. */
      worker_inflight[w].store(my_idx, std::memory_order_release);
      uint32_t ip = permute_ip(my_idx, seed);

      if (is_excluded(ip, excludes)) {
        worker_inflight[w].store(INFLIGHT_NONE, std::memory_order_release);
        continue;
      }

      /* Thread-local per-IP bail state -- no atomics needed because one
         worker owns the whole IP. Matches the established bail semantics:
         after bail_after_timeouts no-response probes from the start of the
         IP's port list (i.e. before any sign of life), skip the remaining
         ports. Any CLOSED/OPEN reply marks the host alive (sticky) and
         permanently disables the bail for this IP, so a host that is up but
         firewalled on most ports still gets every port probed. */
      int  timeout_streak = 0;
      bool any_response   = false;

      for (size_t i = 0; i < ports.size(); i++) {
        if (scan_interrupted) return;

        rate_wait(rl, rate_mu);

        int port = ports[i];
        ProbeResult pr = connect_probe(ip, port, probe_timeout_ms);
        probes_done.fetch_add(1, std::memory_order_relaxed);

        if (pr == ProbeResult::TIMEOUT) {
          if (!any_response && ++timeout_streak >= bail_after_timeouts) {
            /* Host has shown zero life across N probes from the start --
               almost certainly filtered or offline. Skip the rest of its
               ports; the dominant time sink on filtered random samples. */
            break;
          }
        } else {
          /* CLOSED counts as a sign of life and is sticky for this IP. */
          any_response = true;
          if (pr == ProbeResult::OPEN) {
            hosts_found_atomic.fetch_add(1, std::memory_order_relaxed);
            int shard_idx = net_shard_index(ip);
            sqlite3 *db = shards[shard_idx];
            if (db) {
              std::lock_guard<std::mutex> lk(db_mu);
              net_db_insert_host(db, ip, port, "tcp",
                                 now_ts.load(std::memory_order_relaxed));
            }
            if (o.verbose) {
              std::string ip_str = u32_to_ip(ip);
              std::lock_guard<std::mutex> lk(db_mu);
              log_write(LOG_STDOUT, "  OPEN %s:%d\n", ip_str.c_str(), port);
            }
          }
        }
      }
      /* Index fully probed and any opens inserted -- release it from the
         in-flight set so the resume low-water-mark can advance past it.
         The scan_interrupted return inside the port loop deliberately does
         NOT reach here, so an abandoned index stays published for re-cover. */
      worker_inflight[w].store(INFLIGHT_NONE, std::memory_order_release);
    }
  };

  log_write(LOG_STDOUT, "  Probing with %ld workers...\n", total_workers);

  /* Throughput reality check for internet-scale sweeps.
   *
   * This is a connect()-based scanner: on unresponsive (filtered / dark)
   * IP space every probe runs to the full timeout before the worker is
   * freed, so the pool can issue at most
   *     total_workers / (probe_timeout_ms / 1000)
   * probes per second there -- a hard ceiling INDEPENDENT of --rate. With
   * the defaults (100 workers, 500 ms) that is ~200 pps, so a single-port
   * internet sweep started with `--rate 25000` actually crawls and the
   * token bucket never even engages. That surprise is the single most
   * common "why is my mass scan so slow" report, so surface the knob up
   * front when the worker ceiling sits well under the requested rate.
   * (Responsive hosts answer in microseconds, so real-world throughput on
   * live ranges is higher; this is the worst-case dark-space floor.) */
  {
    double worst_case_pps =
        (double)total_workers * 1000.0 / (double)probe_timeout_ms;
    if (worst_case_pps < (double)rate_pps * 0.5) {
      log_write(LOG_STDOUT,
        "  NOTE: on unresponsive ranges this pool tops out near %.0f pps "
        "(%ld workers / %d ms timeout) -- below the --rate %d target. To "
        "push filtered-space throughput, raise KMAP_NETSCAN_CONCURRENCY "
        "(e.g. 512-1024) or lower KMAP_PROBE_TIMEOUT_MS.\n",
        worst_case_pps, total_workers, probe_timeout_ms, rate_pps);
    }
  }

  /* Resource-metrics gather, cross-platform.  Caller keeps a "last"
   * snapshot and we derive CPU% from the delta in process CPU time
   * over the wall-clock interval since the last snapshot.  RSS is
   * a point-in-time reading. */
  struct ProcMetrics {
    double  cpu_seconds;   /* user+kernel CPU time, total since start */
    size_t  rss_kb;        /* current working set / resident set, KB */
    int64_t wall_usec;     /* wall-clock at sample time, microseconds */
  };
  auto gather_metrics = []() -> ProcMetrics {
    ProcMetrics m{};
    m.wall_usec = now_usec();
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
      /* FILETIME is in 100-ns units */
      m.cpu_seconds = (double)(kernel + user) / 10000000.0;
    }
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
      /* Linux: ru_maxrss is kilobytes.  macOS: bytes (caller can
       * normalize if cross-targeting; for now Linux assumption is fine
       * since the Windows path is the production target.) */
      m.rss_kb = (size_t)ru.ru_maxrss;
      m.cpu_seconds =
        (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1e6 +
        (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec / 1e6;
    }
#endif
    return m;
  };

  /* Prime so the first emit shows accurate CPU% rather than zero. */
  ProcMetrics last_metrics = gather_metrics();

  std::vector<std::thread> pool;
  pool.reserve(total_workers);
  for (long i = 0; i < total_workers; i++) pool.emplace_back(worker, i);

  /* Monitor loop on the main thread: emit per-10s status, save a
   * checkpoint per 60s, and trigger periodic per-shard transaction
   * rollovers so a long sweep does not pile everything into one
   * giant transaction.  Loop exits when probe_idx has been claimed
   * past scan_end (every worker has bailed) or scan_interrupted.
   *
   * Progress emission is two-track:
   *   - `\r`-rewritten line every 10s for interactive terminals
   *   - `\n`-terminated line every KMAP_PROGRESS_INTERVAL_SECS
   *     (default 30s) so pipes / logs / scrollback all capture the
   *     progress even when stdout is not a TTY.  Without the \n
   *     variant, `kmap --net-scan | tee log.txt` shows no progress
   *     at all because every \r line overwrites the previous one in
   *     the pipe buffer. */
  int progress_n_interval = 30;
  if (const char *env = getenv("KMAP_PROGRESS_INTERVAL_SECS")) {
    int v = atoi(env);
    if (v > 0 && v <= 3600) progress_n_interval = v;
  }
  time_t last_progress_n = time(nullptr);
  time_t scan_start_time = time(nullptr);
  /* Capture the slice anchor ONCE so periodic checkpoints (which
   * mutate cp.next_index every 60 s) cannot shift the displayed
   * percentage.  Without this, after a checkpoint cp.next_index ==
   * cur_idx and the displayed slice_done collapses to 0 / (scan_end
   * - cur_idx), which renders the progress line as "0/29 IPs (0.0%)"
   * partway through a 150-IP scan instead of "121/150 (80.7%)". */
  uint64_t scan_start_idx = cp.next_index;
  while (!scan_interrupted) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    uint64_t cur_idx  = probe_idx.load();
    uint64_t done     = probes_done.load();
    uint64_t found    = hosts_found_atomic.load();
    bool finished = (cur_idx >= scan_end);

    time_t now_time = time(nullptr);

    if (finished) break;

    /* Pct relative to the SLICE we are actually scanning, not the
     * full IPv4 space.  For sample mode (max_ips > 0) the slice is
     * small and a 0.0001% number is useless; for a full sweep it
     * collapses to the same thing because scan_start_idx = 0.
     *
     * Uses the immutable scan_start_idx captured before the monitor
     * loop, not the live cp.next_index which the per-60s checkpoint
     * code mutates and would otherwise rebase the slice mid-scan. */
    uint64_t slice_total = scan_end - scan_start_idx;
    uint64_t slice_done  = cur_idx > scan_start_idx
                           ? cur_idx - scan_start_idx : 0;
    double pct = (slice_total > 0)
                 ? 100.0 * (double)slice_done / (double)slice_total : 100.0;
    time_t scan_elapsed = now_time - scan_start_time + 1;
    double ips_per_sec = (scan_elapsed > 0 && slice_done > 0)
                         ? (double)slice_done / (double)scan_elapsed : 0;
    uint64_t ips_left = scan_end - cur_idx;
    int64_t eta_sec = (ips_per_sec > 0)
                      ? static_cast<int64_t>((double)ips_left / ips_per_sec)
                      : -1;

    auto fmt_eta = [](int64_t s, char *buf, size_t n) {
      if (s < 0) { snprintf(buf, n, "calculating..."); return; }
      if (s > 86400) {
        int days = (int)(s / 86400);
        int hrs  = (int)((s % 86400) / 3600);
        int mins = (int)((s % 3600) / 60);
        snprintf(buf, n, "%dd %02d:%02d", days, hrs, mins);
      } else {
        int hrs  = (int)(s / 3600);
        int mins = (int)((s % 3600) / 60);
        int secs = (int)(s % 60);
        snprintf(buf, n, "%02d:%02d:%02d", hrs, mins, secs);
      }
    };
    char eta_buf[32];
    fmt_eta(eta_sec, eta_buf, sizeof(eta_buf));

    if (now_time - last_status >= 10) {
      log_write(LOG_STDOUT,
        "  Progress: %.2f%% | IPs: %llu/%llu | Packets: %llu | Found: %llu | %.0f pps | ETA: %-15s\r",
                pct,
                (unsigned long long)slice_done,
                (unsigned long long)slice_total,
                (unsigned long long)done,
                (unsigned long long)found,
                ips_per_sec,
                eta_buf);
      fflush(stdout);
      last_status = now_time;
    }

    /* Pipe-friendly progress line: same data, newline-terminated, less
     * frequent.  Survives `kmap | tee` / log redirection / journalctl.
     * Includes resource metrics so operators running long scans can
     * tell at a glance whether the box is CPU-bound, memory-pressured,
     * or just network-RTT bound. */
    if (now_time - last_progress_n >= progress_n_interval) {
      ProcMetrics cur = gather_metrics();
      double cpu_delta = cur.cpu_seconds - last_metrics.cpu_seconds;
      double wall_delta_s = (double)(cur.wall_usec - last_metrics.wall_usec) / 1e6;
      double cpu_pct = (wall_delta_s > 0.001)
                       ? 100.0 * cpu_delta / wall_delta_s : 0.0;
      double rss_mb  = (double)cur.rss_kb / 1024.0;
      last_metrics = cur;

      log_write(LOG_STDOUT,
        "  [%lds] discover: %llu/%llu IPs (%.1f%%) opens=%llu rate=%.0f pps "
        "| cpu=%.1f%% rss=%.0fMB | ETA %s\n",
        (long)(now_time - scan_start_time),
        (unsigned long long)slice_done,
        (unsigned long long)slice_total,
        pct,
        (unsigned long long)found,
        ips_per_sec,
        cpu_pct,
        rss_mb,
        eta_buf);
      fflush(stdout);
      last_progress_n = now_time;
    }

    /* Periodic checkpoint + per-shard transaction rollover. */
    if (now_time - last_checkpoint >= 60) {
      /* Advance the host-insert timestamp so rows discovered in this window
         are stamped with the current time, not the scan-start time. */
      now_ts.store(static_cast<int64_t>(now_time), std::memory_order_relaxed);
      cp.packets_sent = done;
      cp.hosts_found  = found;
      /* Save the EXACT in-flight low-water-mark (see worker_inflight): the
         lowest index any worker is still probing, or probe_idx if every
         worker is idle. A crash right after this checkpoint resumes here and
         re-covers exactly the in-flight window -- no skips (the old
         cur_idx - total_workers heuristic under-rewound whenever a worker
         stalled while the pool raced ahead) and no needless rescan past it.
         cur_idx itself is untouched, so the live progress display is
         unaffected. */
      cp.next_index   = compute_low_water();
      cp.last_save    = now_time;
      {
        std::lock_guard<std::mutex> lk(db_mu);
        for (auto *db : shards) {
          if (db) { net_db_commit(db); net_db_begin(db); }
        }
      }
      save_checkpoint(data_dir, cp);
      last_checkpoint = now_time;
    }
  }

  /* All probes claimed (or interrupted): drain the worker pool. */
  for (auto &th : pool) th.join();

  /* Final discovery metrics -- always emitted regardless of how long
   * the scan ran so short bounded-sample scans (--net-max-ips) still
   * surface resource usage in the log. */
  {
    ProcMetrics fin = gather_metrics();
    double cpu_delta = fin.cpu_seconds - last_metrics.cpu_seconds;
    double wall_delta_s =
      (double)(fin.wall_usec - last_metrics.wall_usec) / 1e6;
    double cpu_pct = (wall_delta_s > 0.001)
                     ? 100.0 * cpu_delta / wall_delta_s : 0.0;
    double rss_mb = (double)fin.rss_kb / 1024.0;
    time_t scan_elapsed = time(nullptr) - scan_start_time;
    log_write(LOG_STDOUT,
      "  [%lds] discover DONE  cpu=%.1f%% rss=%.0fMB total_cpu=%.1fs\n",
      (long)scan_elapsed, cpu_pct, rss_mb, fin.cpu_seconds);
    fflush(stdout);
  }

  /* Sync stats vector to atomic results before the final checkpoint. */
  cp.packets_sent = probes_done.load();
  cp.hosts_found  = hosts_found_atomic.load();
  uint64_t idx    = probe_idx.load();
  if (idx > scan_end) idx = scan_end;
  (void)batch_inserts;  /* kept for ABI -- replaced by 60s commit cycle */

  /* Final commit */
  for (auto *db : shards) {
    if (db) net_db_commit(db);
  }

  /* Save final checkpoint -- use actual loop position so a follow-up
   * resume picks up where this run stopped.  For max_ips=0 (full
   * sweep) and a clean completion we save IP_SPACE so resume becomes
   * a no-op; for max_ips>0 we save the actual end-of-sample idx so
   * subsequent runs can keep walking the permutation past this slice. */
  if (scan_interrupted) {
    /* Exact in-flight low-water-mark, computed after the pool has joined:
       workers that abandoned a claimed-but-unfinished index on interrupt
       left it published in worker_inflight, so resume restarts before the
       lowest such index. Harmless overlap on resume (seed preserved, inserts
       idempotent). A clean completion below needs no rewind: a worker
       finishes processing each claimed index < scan_end before it claims the
       out-of-range index that makes it return, so nothing is left in flight
       (and every worker_inflight slot is INFLIGHT_NONE, so this would equal
       idx anyway). */
    cp.next_index = compute_low_water();
  } else if (max_ips > 0) {
    cp.next_index = idx;  /* end of this sample; next run starts here */
  } else {
    cp.next_index = IP_SPACE;
  }
  cp.last_save = time(nullptr);
  save_checkpoint(data_dir, cp);

  log_write(LOG_STDOUT, "\n\nnet-scan: Discovery %s\n",
            scan_interrupted ? "interrupted (use --resume to continue)" : "complete");
  log_write(LOG_STDOUT, "  Packets sent:   %llu\n", (unsigned long long)cp.packets_sent);
  log_write(LOG_STDOUT, "  Open ports:     %llu\n", (unsigned long long)cp.hosts_found);

  /* Print per-shard counts */
  for (int i = 0; i < NET_SHARD_COUNT; i++) {
    if (shards[i]) {
      int64_t cnt = net_db_count(shards[i]);
      if (cnt > 0) {
        log_write(LOG_STDOUT, "  shard_%03d.db:   %lld entries\n", i, (long long)cnt);
      }
    }
  }

  /* Restore signal handler */
#ifndef WIN32
  sigaction(SIGINT, &sa_old, nullptr);
#else
  /* Pass our actual handler pointer (not nullptr) so the Ctrl+C
   * handler we installed is removed; SetConsoleCtrlHandler(NULL, FALSE)
   * only restores default Ctrl+C behavior, it does not unregister
   * an installed handler. Then drop the elevated timer resolution. */
  SetConsoleCtrlHandler(win_console_ctrl_handler, FALSE);
  timeEndPeriod(1);
#endif

  close_all_shards(shards);
  return 0;
}
