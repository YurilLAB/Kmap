/* Actual enrichment persistence handoff + SQLite; inert records, no networking. */
#include "enrichment_store.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <stdexcept>

static int checks = 0, failures = 0;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; \
  std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); } } while (0)

static void sql(sqlite3 *db, const char *text) {
  if (sqlite3_exec(db, text, nullptr, nullptr, nullptr) != SQLITE_OK) {
    std::fprintf(stderr, "fixture SQL failed: %s\n", sqlite3_errmsg(db));
    std::exit(2);
  }
}
static int64_t scalar(sqlite3 *db, const char *text) {
  sqlite3_stmt *st = nullptr;
  CHECK(sqlite3_prepare_v2(db, text, -1, &st, nullptr) == SQLITE_OK);
  if (!st) return -999;
  const int rc = sqlite3_step(st);
  CHECK(rc == SQLITE_ROW);
  const int64_t value = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -999;
  CHECK(sqlite3_finalize(st) == SQLITE_OK);
  return value;
}
static sqlite3 *fixture() {
  sqlite3 *db = net_db_open(":memory:");
  CHECK(db);
  if (!db) std::exit(2);
  CHECK(net_db_insert_host(db, 0xc0000201u, 80, "tcp", 1) == 1);
  CHECK(net_db_insert_host(db, 0xc0000201u, 81, "tcp", 1) == 1);
  return db;
}
static void close_db(sqlite3 *db) {
  CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
  CHECK(sqlite3_get_autocommit(db));
  CHECK(sqlite3_close(db) == SQLITE_OK);
}
static std::string inert_cpe(const std::string &, const std::string &) {
  return "cpe:2.3:a:fixture:inert:1:*:*:*:*:*:*:*";
}
static NetEnrichResult result(bool metadata = false) {
  NetEnrichResult r;
  r.shard_idx = 0; r.ip = "192.0.2.1"; r.ports = {80, 81};
  r.services = {"fixture", "fixture"}; r.versions = {"1", "2"};
  r.cves_json = {"[]", "[]"}; r.web_titles = {"title", "second"};
  if (metadata) {
    r.hostname = "inert.example";
    r.tls_caps.resize(1);
    r.tls_caps[0].subject_cn = "certificate.example";
    r.tls_caps[0].issuer = "fixture issuer";
    r.tls_caps[0].sha256 = "inert-certificate-value";
    r.asn_info.asn = 64512; r.asn_info.as_name = "fixture ASN";
    r.asn_info.country = "ZZ";
    r.cloud_info.provider = "fixture-cloud";
    // Active fingerprint probes and their network behavior are not tested.
  }
  return r;
}
static NetEnrichStoreStatus store(sqlite3 *db, const std::vector<NetEnrichResult> &rs) {
  return net_store_enrichment_results({db}, rs, inert_cpe);
}
static void unchanged(sqlite3 *db) {
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE enriched=1 OR hostname IS NOT NULL OR service IS NOT NULL") == 0);
  CHECK(scalar(db, "SELECT COUNT(*) FROM fingerprints") == 0);
  CHECK(sqlite3_get_autocommit(db));
  CHECK(net_db_count_unenriched(db) == 1); // Distinct eligible IPs, not port rows.
}
static void successful_metadata() {
  sqlite3 *db = fixture();
  const auto status = store(db, {result(true)});
  CHECK(status.failed_shards == 0 && status.written == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE enriched=1 AND hostname='inert.example' AND service='fixture' AND asn=64512 AND cloud_provider='fixture-cloud' AND cpe='cpe:2.3:a:fixture:inert:1:*:*:*:*:*:*:*'") == 2);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE port=80 AND tls_subject_cn='certificate.example' AND web_title='title'") == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM fingerprints") == 3);
  CHECK(net_db_count_unenriched(db) == 0);
  close_db(db);
}
static void failed_middle_write(bool automatic_rollback) {
  sqlite3 *db = fixture();
  sql(db, automatic_rollback
      ? "CREATE TEMP TRIGGER reject_second BEFORE UPDATE ON hosts WHEN NEW.port=81 BEGIN SELECT RAISE(ROLLBACK,'inert fixture'); END"
      : "CREATE TEMP TRIGGER reject_second BEFORE UPDATE ON hosts WHEN NEW.port=81 BEGIN SELECT RAISE(ABORT,'inert fixture'); END");
  const auto status = store(db, {result()});
  CHECK(status.failed_shards == 1 && status.written == 0);
  unchanged(db);
  sql(db, "DROP TRIGGER reject_second");
  const auto retry = store(db, {result()});
  CHECK(retry.failed_shards == 0 && retry.written == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE enriched=1") == 2);
  close_db(db);
}
struct Denial { const char *column; int calls = 0; };
static int deny_write(void *context, int action, const char *table,
                      const char *column, const char *, const char *) {
  auto &d = *static_cast<Denial *>(context);
  const bool fingerprint = std::string(d.column) == "fingerprints";
  if ((fingerprint && action == SQLITE_INSERT && table && std::string(table) == "fingerprints") ||
      (!fingerprint && action == SQLITE_UPDATE && column && std::string(column) == d.column)) {
    ++d.calls; return SQLITE_DENY;
  }
  return SQLITE_OK;
}
static void metadata_write_failures() {
  for (const char *column : {"hostname", "service", "tls_subject_cn", "asn", "cloud_provider", "fingerprints"}) {
    sqlite3 *db = fixture(); Denial denial{column};
    sqlite3_set_authorizer(db, deny_write, &denial);
    const auto status = store(db, {result(true)});
    sqlite3_set_authorizer(db, nullptr, nullptr);
    CHECK(denial.calls > 0);
    CHECK(status.failed_shards == 1 && status.written == 0);
    unchanged(db);
    close_db(db);
  }
}
static int reject_commit(void *calls) { ++*static_cast<int *>(calls); return 1; }
static void commit_failure() {
  sqlite3 *db = fixture(); int calls = 0;
  sqlite3_commit_hook(db, reject_commit, &calls);
  const auto status = store(db, {result(true)});
  sqlite3_commit_hook(db, nullptr, nullptr);
  CHECK(calls == 1);
  CHECK(status.failed_shards == 1 && status.written == 0);
  unchanged(db);
  const auto retry = store(db, {result(true)});
  CHECK(retry.failed_shards == 0 && retry.written == 1);
  close_db(db);
}
static void preexisting_transaction() {
  sqlite3 *db = fixture();
  CHECK(net_db_begin(db) == 0);
  sql(db, "UPDATE hosts SET web_title='caller-owned' WHERE port=80");
  const auto status = store(db, {result()});
  CHECK(status.failed_shards == 1 && status.written == 0);
  CHECK(!sqlite3_get_autocommit(db));
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE web_title='caller-owned'") == 1);
  CHECK(net_db_rollback(db) == 0);
  unchanged(db); close_db(db);
}
static void skipped_and_failed_collection() {
  sqlite3 *db = fixture();
  NetEnrichResult skipped = result(); skipped.skipped = true;
  NetEnrichResult empty = result(); empty.empty_host = true;
  auto status = store(db, {skipped, empty});
  CHECK(status.failed_shards == 0 && status.written == 0);
  unchanged(db);
  NetEnrichResult failed = result(); failed.rc = 7;
  status = store(db, {failed});
  CHECK(status.failed_shards == 0 && status.written == 0);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE enriched=0 AND enrichment_error='enrich_single_host rc=7'") == 2);
  close_db(db);

  db = fixture(); Denial denial{"enrichment_error"};
  sqlite3_set_authorizer(db, deny_write, &denial);
  status = store(db, {failed});
  sqlite3_set_authorizer(db, nullptr, nullptr);
  CHECK(denial.calls > 0 && status.failed_shards == 1 && status.written == 0);
  unchanged(db); close_db(db);
}
static int deny_count(void *, int action, const char *, const char *, const char *, const char *) {
  return action == SQLITE_SELECT ? SQLITE_DENY : SQLITE_OK;
}
static void failed_counts() {
  sqlite3 *db = fixture(); int64_t total = 91, pending = 92;
  sqlite3_set_authorizer(db, deny_count, nullptr);
  CHECK(!net_enrichment_counts(db, total, pending));
  CHECK(total == 91 && pending == 92);
  sqlite3_set_authorizer(db, nullptr, nullptr);
  CHECK(net_enrichment_counts(db, total, pending));
  CHECK(total == 2 && pending == 1);
  close_db(db);
}
static void independent_shards() {
  sqlite3 *bad = fixture(), *good = fixture();
  sql(bad, "CREATE TEMP TRIGGER reject_all BEFORE UPDATE ON hosts BEGIN SELECT RAISE(ABORT,'inert fixture'); END");
  auto first = result(), second = result(); second.shard_idx = 1;
  const auto status = net_store_enrichment_results({bad, good}, {first, second}, inert_cpe);
  CHECK(status.failed_shards == 1 && status.written == 1);
  unchanged(bad);
  CHECK(scalar(good, "SELECT COUNT(*) FROM hosts WHERE enriched=1") == 2);
  close_db(bad); close_db(good);
}
static void vanished_port() {
  sqlite3 *db = fixture();
  sql(db, "DELETE FROM hosts WHERE port=81");
  const auto status = store(db, {result()});
  CHECK(status.failed_shards == 1 && status.written == 0);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE enriched=1") == 0);
  CHECK(net_db_count_unenriched(db) == 1);
  close_db(db);
}
static int cpe_calls = 0;
static std::string throwing_cpe(const std::string &, const std::string &) {
  if (++cpe_calls == 2) throw std::runtime_error("inert allocation-style failure");
  return "";
}
static void unwind_rolls_back() {
  sqlite3 *db = fixture(); cpe_calls = 0; bool caught = false;
  try { net_store_enrichment_results({db}, {result()}, throwing_cpe); }
  catch (const std::runtime_error &) { caught = true; }
  CHECK(caught && cpe_calls == 2);
  unchanged(db); close_db(db);
}
static void metadata_parity_and_retry() {
  sqlite3 *db = fixture();
  NetEnrichResult r = result(true);
  r.web_servers = {"fixture-server", "second-server"};
  r.web_headers = {"{\"header\":\"quoted value\"}"};
  r.web_paths = {"[]"};
  r.powered_by = {"inert-runtime"};
  r.x_generator = {"inert-generator"};
  r.redirects = {"https://redirect.example/owned"};
  r.tls_caps[0].san_json = "[\"san.example\",\"192.0.2.44\"]";
  r.tls_caps[0].not_after = "2030-01-02";
  r.tls_caps[0].self_signed = 1;
  r.tls_caps[0].protocol = "TLSv1.3";
  r.asn_info.asn = 4000000000u;
  r.asn_info.bgp_prefix = "192.0.2.0/24";
  r.asn_info.registry = "fixture-registry";
  r.asn_info.region = "fixture-region";
  r.cloud_info.region = "cloud-region";
  r.cloud_info.service = "cloud-service";
  const auto stored = store(db, {r});
  CHECK(stored.failed_shards == 0 && stored.written == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE first_seen=1 AND asn=4000000000 AND bgp_prefix='192.0.2.0/24' AND asn_registry='fixture-registry' AND asn_region='fixture-region' AND cloud_region='cloud-region' AND cloud_service='cloud-service'") == 2);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE port=80 AND powered_by='inert-runtime' AND x_generator='inert-generator' AND redirect_target='https://redirect.example/owned' AND tls_not_after='2030-01-02' AND tls_self_signed=1 AND tls_protocol='TLSv1.3' AND web_server='fixture-server' AND web_paths='[]'") == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM fingerprints WHERE kind='tls_san' AND value='san.example'") == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM fingerprints WHERE kind='redirect_host' AND value='redirect.example'") == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM fingerprints WHERE kind='tls_san' AND value='192.0.2.44'") == 0);
  // A retry with absent optional fields preserves previously collected data.
  NetEnrichResult partial = result();
  partial.services = {"fixture-new"};
  partial.versions = {"updated"};
  const auto retried = store(db, {partial});
  CHECK(retried.failed_shards == 0 && retried.written == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE port=80 AND prev_service='fixture' AND prev_version='1' AND service='fixture-new' AND version='updated' AND hostname='inert.example' AND powered_by='inert-runtime' AND tls_protocol='TLSv1.3'") == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE port=81 AND service='fixture' AND version='2' AND web_server='second-server'") == 1);
  CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE first_seen=1 AND last_seen>=enriched_at AND enriched_at>1") == 2);
  close_db(db);
}
static void multi_host_failure_rolls_back() {
  for (bool record_collection_error : {false, true}) {
    sqlite3 *db = fixture();
    CHECK(net_db_insert_host(db, 0xc0000202u, 80, "tcp", 1) == 1);
    sql(db, "CREATE TEMP TRIGGER reject_host BEFORE UPDATE ON hosts WHEN NEW.ip='192.0.2.2' BEGIN SELECT RAISE(ABORT,'second inert host'); END");
    NetEnrichResult first = result(true), second = result();
    second.ip = "192.0.2.2"; second.ports = {80};
    second.rc = record_collection_error ? 9 : 0;
    const auto status = store(db, {first, second});
    CHECK(status.failed_shards == 1 && status.written == 0);
    CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE enriched=1 OR hostname IS NOT NULL OR enrichment_error IS NOT NULL") == 0);
    CHECK(scalar(db, "SELECT COUNT(*) FROM fingerprints") == 0);
    CHECK(net_db_count_unenriched(db) == 2);
    CHECK(sqlite3_get_autocommit(db));
    sql(db, "DROP TRIGGER reject_host");
    const auto retry = store(db, {first, second});
    CHECK(retry.failed_shards == 0 && retry.written == (record_collection_error ? 1 : 2));
    CHECK(scalar(db, "SELECT COUNT(*) FROM hosts WHERE enriched=1") == (record_collection_error ? 2 : 3));
    close_db(db);
  }
}
int main() {
  successful_metadata();
  failed_middle_write(false); failed_middle_write(true);
  metadata_write_failures(); commit_failure(); preexisting_transaction();
  skipped_and_failed_collection(); failed_counts(); independent_shards();
  vanished_port(); unwind_rolls_back();
  metadata_parity_and_retry(); multi_host_failure_rolls_back();
  std::printf("enrichment persistence: checks=%d failures=%d\n", checks, failures);
  return failures ? 1 : 0;
}
