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

  /* Patch-status / re-scan tracking. Populated by the atomic capture
     inside net_db_update_enrichment() each time enrichment runs against
     an already-enriched row. Stay empty / zero on first-ever enrichment.
     enriched_at is the wall-clock timestamp the *current* cves/service
     were stored; prev_enriched_at is the timestamp the values now in
     prev_* were stored. The pair lets a report show "scanned T1, scanned
     again T2 -- here's what changed". scan_count counts how many times
     the host/port has been re-discovered (incremented by the UPSERT in
     net_db_insert_host on every re-scan, regardless of whether it was
     re-enriched). */
  std::string prev_cves;
  std::string prev_service;
  std::string prev_version;
  int64_t     prev_enriched_at = 0;
  int64_t     enriched_at = 0;
  int         scan_count = 0;

  /* v4 — public data previously collected but discarded at the persistence
     boundary.  Mirrors the new columns in net_db.cc MIGRATIONS[]. */
  std::string hostname;                /* reverse DNS (PTR) */
  std::string powered_by;              /* HTTP X-Powered-By */
  std::string x_generator;             /* HTTP X-Generator */
  std::string redirect_target;         /* HTTP Location: from GET / */
  std::string robots_disallowed_json;  /* JSON array of robots.txt entries */
  std::string screenshot_path;         /* PNG path from screenshot capture */
  std::string asn_registry;            /* RIR name (arin/ripe/etc.) */
  std::string asn_region;              /* Human-readable region */
  /* v5 — TLS columns.  Populated by web_recon today and by the net_enrich
     TLS handshake leg (see tls_capture_cert in net_enrich.cc). */
  std::string tls_subject_cn;
  std::string tls_issuer;
  std::string tls_san_json;            /* JSON array of cert SAN values */
  std::string tls_not_after;           /* cert expiry, ISO-8601 or epoch */
  int         tls_self_signed = -1;    /* tri-state: -1=unknown (no TLS data),
                                          0=chain-validated, 1=self-signed */
  std::string tls_protocol;            /* "TLSv1.2" / "TLSv1.3" */
  std::string tls_sha256;              /* server cert SHA-256 fingerprint hex */
};

/* Insert a discovered host/port.  Ignores duplicates (INSERT OR IGNORE).
   Returns 1 if inserted, 0 if duplicate, -1 on error. */
int net_db_insert_host(sqlite3 *db, uint32_t ip, int port,
                       const char *proto, int64_t timestamp);

/* Update a host with enrichment data.  Sets enriched=1 and clears any
   prior enrichment_error / enrichment_error_at fields.
   The trailing v4 params (powered_by, x_generator, redirect_target,
   robots_disallowed_json) accept NULL to leave the column unchanged.
   Returns 0 on success, -1 on error. */
int net_db_update_enrichment(sqlite3 *db, const char *ip, int port,
                             const char *service, const char *version,
                             const char *cves_json,
                             const char *web_title, const char *web_server,
                             const char *web_headers, const char *web_paths,
                             const char *powered_by = nullptr,
                             const char *x_generator = nullptr,
                             const char *redirect_target = nullptr,
                             const char *robots_disallowed_json = nullptr);

/* Set the reverse-DNS hostname for an IP.  Applies to every port row for
   the IP (one hostname per host, not per port).  Pass NULL/empty to clear.
   Returns 0 on success, -1 on error. */
int net_db_set_hostname(sqlite3 *db, const char *ip, const char *hostname);

/* Set the screenshot file path for a specific (ip, port) row. */
int net_db_set_screenshot(sqlite3 *db, const char *ip, int port,
                          const char *screenshot_path);

/* Update TLS cert details for a specific (ip, port) row.  Any NULL/empty
   string field leaves that column unchanged; tls_self_signed of -1 means
   "leave unchanged", 0 or 1 writes the value. */
int net_db_update_tls(sqlite3 *db, const char *ip, int port,
                      const char *tls_subject_cn,
                      const char *tls_issuer,
                      const char *tls_san_json,
                      const char *tls_not_after,
                      int tls_self_signed,
                      const char *tls_protocol,
                      const char *tls_sha256);

/* Record a transient enrichment failure for a host/port without marking
   it enriched.  Stores the error message and the current timestamp so
   subsequent calls to net_db_get_unenriched() can decide whether enough
   time has passed to retry.  Returns 0 on success, -1 on error. */
int net_db_record_enrichment_error(sqlite3 *db, const char *ip, int port,
                                   const char *error_msg);

/* Update ASN/GeoIP data for all ports of an IP.  asn_registry and asn_region
   are optional (NULL/empty leaves the column unchanged).
   Returns 0 on success, -1 on error. */
int net_db_update_asn(sqlite3 *db, const char *ip,
                      uint32_t asn, const char *as_name,
                      const char *country, const char *bgp_prefix,
                      const char *asn_registry = nullptr,
                      const char *asn_region = nullptr);

/* Default cool-down (seconds) before a host whose last enrichment attempt
   failed becomes eligible to retry. */
#define NET_DB_ENRICH_RETRY_SECONDS 3600

/* Fetch up to `limit` distinct IPs that need enrichment.  Picks rows where
   (enriched=0 OR last_seen > enriched_at) AND (no prior error OR the
   prior error is older than `retry_after_seconds`).  The second leg of
   the OR is what makes re-discovered hosts get re-enriched on a fresh
   scan; without it, the prev_cves/prev_service/prev_version snapshot
   columns were declared but never populated.  Pass
   NET_DB_ENRICH_RETRY_SECONDS as the default retry window. */
std::vector<std::string> net_db_get_unenriched(sqlite3 *db, int limit,
                                               int64_t retry_after_seconds =
                                                   NET_DB_ENRICH_RETRY_SECONDS);

/* Fetch all port records for a given IP. */
std::vector<NetHost> net_db_get_host(sqlite3 *db, const char *ip);

/* Count total rows in the hosts table. */
int64_t net_db_count(sqlite3 *db);

/* Count rows currently eligible for enrichment.  Mirrors the filter used by
   net_db_get_unenriched(): (enriched=0 OR last_seen > enriched_at) and
   not in an active error cool-down. */
int64_t net_db_count_unenriched(sqlite3 *db,
                                int64_t retry_after_seconds =
                                    NET_DB_ENRICH_RETRY_SECONDS);

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

/* -----------------------------------------------------------------------
 * Fingerprints — relationship-matching index
 *
 * Every host carries a small set of derived "fingerprints" that can also
 * appear on unrelated hosts: a TLS cert SHA-256, a subject CN, each DNS
 * SAN on its cert, its reverse-DNS hostname, the hostname it redirects
 * to, and (over time) favicon hashes, SSH host-key prints, etc.  Two
 * hosts sharing one of these are very likely part of the same deployment,
 * fleet, or hosting account — even when the IPs themselves give no hint.
 *
 * The fingerprints table stores (ip_u32, port, kind, value, observed_at)
 * with the same primary key shape, so an UPSERT just refreshes the
 * observed_at timestamp on re-scan and the cluster cohort stays stable.
 *
 * Indexes are sized for the *inverse* lookup ("who else has value X for
 * kind K?") — the relationship engine's hot query path — and for the
 * forward lookup ("what fingerprints does this IP carry?").
 *
 * Each shard owns its own fingerprints table.  Cross-shard cohort
 * resolution is the caller's responsibility (the CLI walks all 32).
 * ----------------------------------------------------------------------- */

/* A single fingerprint row. Pure value type — no DB handle. */
struct NetFingerprint {
  uint32_t    ip_u32;
  int         port;
  std::string kind;        /* "tls_sha256", "tls_subject_cn", "tls_san",
                              "hostname", "redirect_host", future kinds */
  std::string value;
  int64_t     observed_at;
};

/* Insert (or refresh observed_at on) a single fingerprint. Idempotent —
   primary key is (ip_u32, kind, value, port).  Returns 0 on success. */
int net_db_insert_fingerprint(sqlite3 *db,
                              uint32_t ip_u32, int port,
                              const char *kind, const char *value,
                              int64_t observed_at);

/* Inverse lookup: every (ip_u32, port) row in this shard whose
   (kind, value) matches.  Used by --net-cluster to enumerate the
   cohort that shares a given fingerprint. */
std::vector<NetFingerprint>
net_db_find_by_fingerprint(sqlite3 *db,
                           const char *kind, const char *value);

/* Forward lookup: every fingerprint row for a given IP in this shard.
   ip is the dotted-quad form for caller convenience; internally we
   convert to ip_u32 via ip_to_u32 and query the indexed column. */
std::vector<NetFingerprint>
net_db_get_fingerprints_for_ip(sqlite3 *db, const char *ip);

/* -----------------------------------------------------------------------
 * Persistent topology — incremental graph storage
 *
 * Tracemap historically built its graph in memory from a single run and
 * threw it away when the process exited.  At internet scale that means
 * every traceroute starts from zero, and shared hops between successive
 * scans are never combined.  These tables store the graph durably so
 * repeated traceroutes refine the same node/edge set instead.
 *
 * Compression: ip_u32 columns are 4-byte INTEGER, not the dotted-quad
 * TEXT form (~15 bytes).  hostname / as_name use string IDs that index
 * into the strings(id, val) interning table — at internet scale, AS
 * names appear thousands of times across millions of rows and an int
 * reference is ~1/8 the size of the literal.  See net_db_intern_string.
 *
 * Indexes are sized for graph traversal: every edge can be found by
 * its endpoint via the PK, and a separate idx_topo_edges_to lets you
 * look up the in-edges of a node ("who points at me?") without a scan.
 * ----------------------------------------------------------------------- */

struct NetTopoNode {
  uint32_t    ip_u32      = 0;
  std::string hostname;
  uint32_t    asn         = 0;
  std::string as_name;
  std::string country;
  std::string role;       /* "source", "gateway", "router", "ixp",
                             "target", "border", "hub", "" */
  int         path_count  = 0; /* traces that visited this node in the
                                  in-memory batch being persisted; the
                                  upsert sums it into the DB total */
  double      avg_rtt_ms  = 0.0;
  int64_t     last_seen   = 0;
};

struct NetTopoEdge {
  uint32_t from_u32       = 0;
  uint32_t to_u32         = 0;
  int      asn_boundary   = 0;   /* 1 if from.asn != to.asn, else 0 */
  double   avg_latency_ms = 0.0; /* mean of `path_count` samples */
  int      path_count     = 0;   /* traces using this edge in the batch */
  int64_t  last_seen      = 0;
};

/* UPSERT a node.  Re-observed nodes accumulate path_count (the new
   row's path_count is ADDED to the existing total, so a batch of 50
   traces lands as +50, not +1) and refresh last_seen.  The other
   columns are only filled when the caller passes non-empty values, so
   repeat probes that learned nothing new about hostname/asn won't wipe
   previously-captured data.  A caller-supplied path_count of 0 is
   treated as 1, since 0 would freeze the counter forever.  Returns
   0 on success, -1 on error. */
int net_db_upsert_topo_node(sqlite3 *db, const NetTopoNode &node);

/* UPSERT an edge.  path_count is summed across batches (same as nodes)
   and avg_latency_ms is updated via the batch-weighted running-mean
   formula `new_avg = old_avg + N*(sample - old_avg)/(M + N)` where M
   is the prior count and N is the new batch's count, so successive
   probes refine the mean without bias from observation order.  NULL
   samples (a `* * *` hop) keep the prior average.  Returns 0/-1. */
int net_db_upsert_topo_edge(sqlite3 *db, const NetTopoEdge &edge);

/* Out-neighbors of an IP: every node this IP has been observed
   pointing at.  Uses the PK leading-column index on from_u32. */
std::vector<NetTopoEdge>
net_db_get_topo_edges_from(sqlite3 *db, uint32_t from_u32);

/* In-neighbors of an IP: every node observed pointing at it.  Uses
   the explicit idx_topo_edges_to index for the reverse direction. */
std::vector<NetTopoEdge>
net_db_get_topo_edges_to(sqlite3 *db, uint32_t to_u32);

/* Read a single node by IP.  Returns true if found and populates *out;
   false if the IP has never been seen. */
bool net_db_get_topo_node(sqlite3 *db, uint32_t ip_u32, NetTopoNode *out);

/* Count rows in topo_nodes / topo_edges respectively. */
int64_t net_db_count_topo_nodes(sqlite3 *db);
int64_t net_db_count_topo_edges(sqlite3 *db);

/* -----------------------------------------------------------------------
 * String interning — compress repeated values to int IDs
 *
 * Hot columns like as_name ("CLOUDFLARENET") and hostname suffixes
 * repeat across billions of rows.  Storing each as TEXT costs ~bytes
 * per row × billions of rows.  Interning collapses every duplicate to
 * one 8-byte rowid reference + one row in the strings table.
 *
 * Tradeoff: every read joins through strings.  The strings table is
 * small enough that SQLite keeps it in cache, and the join is on the
 * primary key — fast in practice for analytical queries.  Hot-path
 * inserts on hosts still use TEXT for compatibility; interning is
 * opt-in for the topology layer where the win pays off the most.
 * ----------------------------------------------------------------------- */

/* Get or create a row in strings(id, val) for the given value.  Returns
   the row id on success, 0 on error (or for NULL/empty input).  Calls
   are idempotent — the UNIQUE constraint on val collapses duplicates
   and the existing id is returned on conflict. */
int64_t net_db_intern_string(sqlite3 *db, const char *val);

/* Reverse: look up the literal value for an interned id.  Returns the
   empty string on miss or error. */
std::string net_db_lookup_string(sqlite3 *db, int64_t id);

/* -----------------------------------------------------------------------
 * Patch-status diff helpers
 *
 * On a re-scan, kmap captures the previous enrichment's CVE list into
 * prev_cves before overwriting cves with the new findings. These helpers
 * turn that pair into a structured patch diff that the report engine
 * surfaces as "what was patched", "what is still vulnerable", and
 * "what is new since last scan".
 *
 * The JSON parser is intentionally permissive and only extracts the
 * "id" field of each entry -- it does not allocate a full JSON tree.
 * The format it accepts is the one written by net_enrich's cves_to_json
 * (`[{"id":"CVE-...","cvss":...,...},...]`); other shapes return an
 * empty list rather than throwing, so a corrupt prev_cves cell never
 * blocks a report run.
 * ----------------------------------------------------------------------- */

/* Parse a CVE JSON-array string into the bare list of CVE IDs. Empty
   string, "[]", or malformed input all return an empty vector. */
std::vector<std::string> net_db_parse_cve_ids(const std::string &cves_json);

/* Diff result returned by net_db_cve_diff. Each list is sorted ascending
   by CVE ID for stable, grep-friendly output. */
struct NetDbCveDiff {
  std::vector<std::string> persisting; /* in both prev and current */
  std::vector<std::string> introduced; /* in current only (new this scan) */
  std::vector<std::string> patched;    /* in prev only (gone this scan) */
};

/* Compute the patch diff between two CVE JSON arrays (typically the
   prev_cves and cves columns of one host/port row). Result is sorted
   per the contract above. Pure function -- no DB access -- so callers
   can unit-test it without a fixture. */
NetDbCveDiff net_db_cve_diff(const std::string &prev_cves_json,
                             const std::string &current_cves_json);

#endif /* NET_DB_H */
