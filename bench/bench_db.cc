/*
 * bench_db.cc -- measures real net_db write throughput and on-disk growth.
 *
 * Writes N fully-enriched host:port rows (discover + enrich + asn + cloud +
 * tls + fingerprints) through the REAL net_db.cc against a real sqlite file,
 * then reports rows/sec and bytes-per-host so DB growth can be extrapolated.
 *
 * Build (no fstream -> no static-libstdc++ needed; net_db is C+sqlite):
 *   gcc -O1 -c sqlite/sqlite3.c -o /tmp/sqlite3.o
 *   g++ -O2 -std=gnu++17 -DWIN32 -I. -Inbase bench/bench_db.cc net_db.cc \
 *       /tmp/sqlite3.o -lws2_32 -lbcrypt -o bench/bench_db.exe
 *   bench/bench_db.exe [N]
 */

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <chrono>

#include "net_db.h"

#ifdef _WIN32
#include <sys/stat.h>
static long long file_size(const char *p) {
  struct _stat64 s; return _stat64(p, &s) == 0 ? (long long)s.st_size : -1;
}
#else
#include <sys/stat.h>
static long long file_size(const char *p) {
  struct stat s; return stat(p, &s) == 0 ? (long long)s.st_size : -1;
}
#endif

static double secs_since(std::chrono::steady_clock::time_point t0) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

int main(int argc, char **argv) {
  long N = (argc > 1) ? atol(argv[1]) : 200000;
  const char *path = "bench_db.sqlite";
  remove(path);
  std::string wal = std::string(path) + "-wal", shm = std::string(path) + "-shm";
  remove(wal.c_str()); remove(shm.c_str());

  sqlite3 *db = net_db_open(path);
  if (!db) { printf("cannot open db\n"); return 1; }

  /* A realistic enriched web host: nginx on 443 with CVEs, web + TLS metadata,
     ASN, cloud, CPE, and a handful of fingerprints (the typical fan-out). */
  const char *cves =
    "[{\"id\":\"CVE-2021-23017\",\"cvss\":7.7},{\"id\":\"CVE-2019-20372\",\"cvss\":5.3}]";
  const char *headers =
    "{\"Server\":\"nginx/1.18.0\",\"Content-Type\":\"text/html\",\"X-Frame-Options\":\"SAMEORIGIN\"}";
  const char *paths = "[{\"path\":\"/\",\"status\":200,\"title\":\"Welcome\"}]";
  const char *san = "[\"example.com\",\"www.example.com\"]";
  const char *cpe = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*";

  auto t0 = std::chrono::steady_clock::now();
  net_db_begin(db);
  for (long i = 0; i < N; i++) {
    uint32_t ipu = 0x01000000u + (uint32_t)i;   /* 1.0.0.0 + i */
    std::string ip = u32_to_ip(ipu);
    int port = 443;
    net_db_insert_host(db, ipu, port, "tcp", 1718000000 + i);
    net_db_update_enrichment(db, ip.c_str(), port, "https", "nginx 1.18.0",
        cves, "Welcome", "nginx/1.18.0", headers, paths,
        nullptr, nullptr, nullptr, nullptr, cpe);
    net_db_update_asn(db, ip.c_str(), 13335, "CLOUDFLARENET", "US",
                      "1.0.0.0/24", "arin", "North America");
    net_db_update_cloud(db, ip.c_str(), "cloudflare", "", "");
    net_db_update_tls(db, ip.c_str(), port, "example.com", "Let's Encrypt",
                      san, "2026-09-01", 0, "TLSv1.3",
                      "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
    int64_t ts = 1718000000 + i;
    net_db_insert_fingerprint(db, ipu, port, "tls_sha256",
        "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", ts);
    net_db_insert_fingerprint(db, ipu, port, "tls_subject_cn", "example.com", ts);
    net_db_insert_fingerprint(db, ipu, port, "tls_san", "www.example.com", ts);
    net_db_insert_fingerprint(db, ipu, port, "favicon_mmh3", "-1234567890", ts);
    net_db_insert_fingerprint(db, ipu, port, "http_body_sha256",
        "0011223344556677889900112233445566778899001122334455667788990011", ts);
    if ((i % 5000) == 4999) { net_db_commit(db); net_db_begin(db); }
  }
  net_db_commit(db);
  double write_s = secs_since(t0);

  /* Force the WAL into the main file so the on-disk size is the real total. */
  sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", nullptr, nullptr, nullptr);
  net_db_close(db);

  long long bytes = file_size(path);
  long long walb = file_size(wal.c_str());
  if (walb > 0) bytes += walb;

  double host_bytes = (double)bytes / (double)N;
  printf("=== net_db write benchmark ===\n");
  printf("hosts written        : %ld (1 port + 5 fingerprints each)\n", N);
  printf("write wall time      : %.2f s\n", write_s);
  printf("host-write throughput: %.0f hosts/sec  (%.0f row-ops/sec)\n",
         N / write_s, (N * 7.0) / write_s);
  printf("on-disk DB size      : %.1f MB\n", bytes / 1048576.0);
  printf("bytes per host       : %.0f B  (host row + 5 fp rows + asn/cloud/tls)\n",
         host_bytes);
  /* Extrapolate: only IPs with an open port are stored.  Show a hit-rate band. */
  printf("--- DB growth per 1e9 IPs scanned (only open-port hosts stored) ---\n");
  for (double hit : {0.005, 0.01, 0.02}) {
    double gb = (1e9 * hit * host_bytes) / 1073741824.0;
    printf("  at %.1f%% open-port hit rate : %.1f GB\n", hit * 100.0, gb);
  }
  remove(path); remove(wal.c_str()); remove(shm.c_str());
  return 0;
}
