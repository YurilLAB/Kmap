/*
 * net_db.h -- Sharded SQLite database manager for Kmap net-scan.
 *
 * Manages multiple SQLite database files ("shards"), each covering a
 * /5 IPv4 prefix block.  Provides insert, query, and enrichment-tracking
 * operations.  All functions are safe to call repeatedly (idempotent
 * schema creation, INSERT OR IGNORE for duplicates).
 */

#ifndef NET_DB_H
#define NET_DB_H

#include "sqlite/sqlite3.h"
#include <string>
#include <vector>
#include <cstdint>

/* -----------------------------------------------------------------------
 * Shard management
 * ----------------------------------------------------------------------- */

/* Number of shards — each covers a /5 block (134M IPs).
   32 shards cover the full 0.0.0.0 – 255.255.255.255 range. */
#define NET_SHARD_COUNT 32

/* Return the shard index (0..31) for a given IPv4 address. */
int net_shard_index(uint32_t ip);

/* Return the shard database filename for a given index.
   e.g. "kmap-data/shard_007.db" */
std::string net_shard_path(const char *data_dir, int shard_idx);

/* Open (or create) a shard database.  Creates the schema if missing.
   Returns nullptr on failure (error printed to stderr). */
sqlite3 *net_db_open(const std::string &path);

/* Close a shard database. */
void net_db_close(sqlite3 *db);

/* -----------------------------------------------------------------------
 * Host records
 * ----------------------------------------------------------------------- */

struct NetHost {
  std::string ip;
  int         port;
  std::string proto;       /* "tcp" or "udp" */
  int64_t     first_seen;
  int64_t     last_seen;
  /* Enrichment fields (empty until enriched) */
  std::string service;
  std::string version;
  std::string cves;        /* JSON array */
  std::string web_title;
  std::string web_server;
  std::string web_headers;  /* JSON object */
  std::string web_paths;    /* JSON array */
  uint32_t    asn;
  std::string as_name;
  std::string country;
  std::string bgp_prefix;
  int         enriched;
};

/* Insert a discovered host/port.  Ignores duplicates (INSERT OR IGNORE).
   Returns 1 if inserted, 0 if duplicate, -1 on error. */
int net_db_insert_host(sqlite3 *db, uint32_t ip, int port,
                       const char *proto, int64_t timestamp);

/* Update a host with enrichment data.  Sets enriched=1.
   Returns 0 on success, -1 on error. */
int net_db_update_enrichment(sqlite3 *db, const char *ip, int port,
                             const char *service, const char *version,
                             const char *cves_json,
                             const char *web_title, const char *web_server,
                             const char *web_headers, const char *web_paths);

/* Update ASN/GeoIP data for all ports of an IP.
   Returns 0 on success, -1 on error. */
int net_db_update_asn(sqlite3 *db, const char *ip,
                      uint32_t asn, const char *as_name,
                      const char *country, const char *bgp_prefix);

/* Fetch up to `limit` unenriched hosts (enriched=0) as distinct IPs.
   Returns a vector of IP strings. */
std::vector<std::string> net_db_get_unenriched(sqlite3 *db, int limit);

/* Fetch all port records for a given IP. */
std::vector<NetHost> net_db_get_host(sqlite3 *db, const char *ip);

/* Count total rows in the hosts table. */
int64_t net_db_count(sqlite3 *db);

/* Count unenriched rows. */
int64_t net_db_count_unenriched(sqlite3 *db);

/* -----------------------------------------------------------------------
 * Batch operations (for performance during scanning)
 * ----------------------------------------------------------------------- */

/* Begin/commit a transaction.  Call begin before a batch of inserts,
   commit after.  Safe to call even if no transaction is active. */
void net_db_begin(sqlite3 *db);
void net_db_commit(sqlite3 *db);

/* -----------------------------------------------------------------------
 * IP conversion helpers
 * ----------------------------------------------------------------------- */

/* Convert a dotted-quad string to a 32-bit host-order integer.
   Returns 0 on parse failure. */
uint32_t ip_to_u32(const char *ip_str);

/* Convert a 32-bit host-order integer to a dotted-quad string. */
std::string u32_to_ip(uint32_t ip);

#endif /* NET_DB_H */
