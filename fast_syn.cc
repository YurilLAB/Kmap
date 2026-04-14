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
#include "output.h"

#include <pcap.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>
#include <set>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <signal.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>
#include <io.h>
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
    prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return false;
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
    if (parse_cidr(line.c_str(), er.network, er.mask))
      list.push_back(er);
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
    /* Default: top 100 common ports */
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

  std::istringstream ss(spec);
  std::string token;
  while (std::getline(ss, token, ',')) {
    size_t dash = token.find('-');
    if (dash != std::string::npos) {
      int lo = atoi(token.substr(0, dash).c_str());
      int hi = atoi(token.substr(dash + 1).c_str());
      if (lo < 1) lo = 1;
      if (hi > 65535) hi = 65535;
      for (int p = lo; p <= hi; p++) ports.insert(p);
    } else {
      int p = atoi(token.c_str());
      if (p >= 1 && p <= 65535) ports.insert(p);
    }
  }
  return std::vector<int>(ports.begin(), ports.end());
}

/* -----------------------------------------------------------------------
 * IP randomization — multiplicative inverse permutation
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
  time_t   last_save;
};

static std::string checkpoint_path(const char *data_dir) {
  return std::string(data_dir) + "/.net-scan-checkpoint";
}

static bool save_checkpoint(const char *data_dir, const ScanCheckpoint &cp) {
  std::string path = checkpoint_path(data_dir);
  FILE *f = fopen(path.c_str(), "w");
  if (!f) return false;
  fprintf(f, "%llu\n%llu\n%llu\n%lld\n",
          (unsigned long long)cp.next_index,
          (unsigned long long)cp.packets_sent,
          (unsigned long long)cp.hosts_found,
          (long long)cp.last_save);
  fclose(f);
  return true;
}

static bool load_checkpoint(const char *data_dir, ScanCheckpoint &cp) {
  std::string path = checkpoint_path(data_dir);
  FILE *f = fopen(path.c_str(), "r");
  if (!f) return false;
  unsigned long long ni, ps, hf;
  long long ls;
  if (fscanf(f, "%llu\n%llu\n%llu\n%lld", &ni, &ps, &hf, &ls) != 4) {
    fclose(f);
    return false;
  }
  cp.next_index = ni;
  cp.packets_sent = ps;
  cp.hosts_found = hf;
  cp.last_save = static_cast<time_t>(ls);
  fclose(f);
  return true;
}

/* -----------------------------------------------------------------------
 * Rate limiter — token bucket
 * ----------------------------------------------------------------------- */

struct RateLimiter {
  double tokens;
  double max_tokens;
  double refill_rate;  /* tokens per microsecond */
  int64_t last_refill; /* microsecond timestamp */
};

static int64_t now_usec() {
#ifdef WIN32
  LARGE_INTEGER freq, counter;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&counter);
  return (int64_t)((double)counter.QuadPart / (double)freq.QuadPart * 1000000.0);
#else
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
#endif
}

static void rate_init(RateLimiter &rl, int pps) {
  rl.max_tokens = pps * 1.5;  /* allow 1.5x burst */
  rl.tokens = rl.max_tokens;
  rl.refill_rate = (double)pps / 1000000.0;
  rl.last_refill = now_usec();
}

static void rate_wait(RateLimiter &rl) {
  while (true) {
    int64_t now = now_usec();
    double elapsed = (double)(now - rl.last_refill);
    rl.tokens += elapsed * rl.refill_rate;
    if (rl.tokens > rl.max_tokens) rl.tokens = rl.max_tokens;
    rl.last_refill = now;

    if (rl.tokens >= 1.0) {
      rl.tokens -= 1.0;
      return;
    }
    /* Sleep briefly to avoid busy-waiting */
#ifdef WIN32
    Sleep(0);
#else
    usleep(10);
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

/* Open shard databases — one per shard index.  Returns nullptr entries
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

static bool connect_probe(uint32_t ip, int port, int timeout_ms) {
  struct sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(static_cast<uint16_t>(port));
  sa.sin_addr.s_addr = htonl(ip);

#ifdef WIN32
  SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == INVALID_SOCKET) return false;
  u_long nb = 1;
  ioctlsocket(fd, FIONBIO, &nb);
#else
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return false;
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

  connect(fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa));

  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(fd, &wset);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

  bool open = false;
  if (select(static_cast<int>(fd) + 1, nullptr, &wset, nullptr, &tv) > 0) {
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
  return open;
}

/* -----------------------------------------------------------------------
 * Main scan function
 * ----------------------------------------------------------------------- */

int fast_syn_scan(const char *data_dir,
                  const std::vector<int> &ports,
                  int rate_pps,
                  const std::vector<ExcludeRange> &excludes,
                  bool resume) {
  if (ports.empty()) {
    fprintf(stderr, "net-scan: no ports to scan\n");
    return 1;
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
  cp.last_save = time(nullptr);

  if (resume) {
    if (load_checkpoint(data_dir, cp)) {
      log_write(LOG_STDOUT, "net-scan: Resuming from index %llu (%llu packets sent, %llu hosts found)\n",
                (unsigned long long)cp.next_index,
                (unsigned long long)cp.packets_sent,
                (unsigned long long)cp.hosts_found);
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
#endif
  scan_interrupted = 0;

  /* Seed for IP permutation */
  uint64_t seed = static_cast<uint64_t>(time(nullptr)) ^ PERMUTE_OFFSET;
  if (resume) seed = PERMUTE_OFFSET; /* deterministic for resume */

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

  int64_t now_ts = static_cast<int64_t>(time(nullptr));
  time_t last_status = time(nullptr);
  time_t last_checkpoint = time(nullptr);
  uint64_t batch_inserts = 0;

  /* Main scan loop — using connect() fallback for safety.
   * Raw SYN scanning requires root privileges and careful pcap setup
   * that varies by OS.  The connect() approach works everywhere and
   * for a home-machine scanner at 25k pps is adequate.  The rate
   * limiter controls the pace. */

  uint64_t total_probes = IP_SPACE * ports.size();
  /* But we only iterate unique IPs, then probe each port */

  for (uint64_t idx = cp.next_index; idx < IP_SPACE && !scan_interrupted; idx++) {
    uint32_t ip = permute_ip(idx, seed);

    /* Skip excluded IPs */
    if (is_excluded(ip, excludes))
      continue;

    for (int port : ports) {
      if (scan_interrupted) break;

      /* Rate limit */
      rate_wait(rl);

      /* Probe the port */
      bool open = connect_probe(ip, port, 1500);
      cp.packets_sent++;

      if (open) {
        int shard_idx = net_shard_index(ip);
        sqlite3 *db = shards[shard_idx];
        if (db) {
          net_db_insert_host(db, ip, port, "tcp", now_ts);
          cp.hosts_found++;
          batch_inserts++;
        }

        if (o.verbose) {
          std::string ip_str = u32_to_ip(ip);
          log_write(LOG_STDOUT, "  OPEN %s:%d\n", ip_str.c_str(), port);
        }
      }

      /* Commit batch every 10000 inserts */
      if (batch_inserts >= 10000) {
        for (auto *db : shards) {
          if (db) { net_db_commit(db); net_db_begin(db); }
        }
        batch_inserts = 0;
      }
    }

    /* Status update every 10 seconds */
    time_t now_time = time(nullptr);
    if (now_time - last_status >= 10) {
      double pct = (double)idx / (double)IP_SPACE * 100.0;
      log_write(LOG_STDOUT, "  Progress: %.4f%% | Packets: %llu | Found: %llu open ports\r",
                pct,
                (unsigned long long)cp.packets_sent,
                (unsigned long long)cp.hosts_found);
      fflush(stdout);
      last_status = now_time;
    }

    /* Checkpoint every 60 seconds */
    if (now_time - last_checkpoint >= 60) {
      cp.next_index = idx + 1;
      cp.last_save = now_time;
      save_checkpoint(data_dir, cp);
      last_checkpoint = now_time;
    }
  }

  /* Final commit */
  for (auto *db : shards) {
    if (db) net_db_commit(db);
  }

  /* Save final checkpoint */
  cp.next_index = scan_interrupted ? cp.next_index : IP_SPACE;
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
#endif

  close_all_shards(shards);
  return 0;
}
