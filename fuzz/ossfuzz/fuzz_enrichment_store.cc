/* Bounded storage-only property target. Link the production handoff, net_db.cc,
 * net_fp_helpers.cc and bundled SQLite. No workers or network probes are called.
 * Every input owns a fresh in-memory database with <=3 hosts and <=3 ports each.
 */
#ifdef WIN32
#include "../../kmap_winconfig.h"
#endif
#include "../../enrichment_store.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {
void require(bool ok) { if (!ok) std::abort(); }

struct Input {
  const uint8_t *data;
  size_t size, offset = 0;
  uint8_t byte() { return offset < size ? data[offset++] : 0; }
  std::string text() {
    // Printable bytes, including quotes: exercise bindings without embedded-NUL
    // truncation becoming an ambiguity in the independent text oracle.
    const size_t length = byte() % 17;
    std::string value;
    for (size_t i = 0; i < length; ++i) value.push_back(char(32 + byte() % 95));
    return value;
  }
};

void sql(sqlite3 *db, const std::string &command) {
  require(sqlite3_exec(db, command.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

std::string column(sqlite3_stmt *stmt, int index) {
  const unsigned char *value = sqlite3_column_text(stmt, index);
  return value ? reinterpret_cast<const char *>(value) : "";
}

std::string inert_cpe(const std::string &, const std::string &) {
  return "cpe:2.3:a:fixture:storage:1:*:*:*:*:*:*:*";
}

int reject_commit(void *context) {
  ++*static_cast<int *>(context);
  return 1;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 4096) return 0;
  Input input{data, size};
  const unsigned fault = input.byte() % 3; // normal, row constraint, commit failure
  const unsigned host_count = 1 + input.byte() % 3;
  const unsigned failed_host = input.byte() % host_count;
  std::vector<NetEnrichResult> records;
  unsigned total_ports = 0, active_hosts = 0, successful_hosts = 0;
  sqlite3 *db = net_db_open(":memory:");
  require(db != nullptr);

  for (unsigned host = 0; host < host_count; ++host) {
    NetEnrichResult record;
    record.shard_idx = 0;
    record.ip = "192.0.2." + std::to_string(host + 1);
    const unsigned ports = 1 + input.byte() % 3;
    const unsigned flags = input.byte();
    record.skipped = (flags & 1) != 0;
    record.empty_host = (flags & 2) != 0;
    record.rc = (flags & 4) ? 9 : 0;
    record.hostname = input.text();
    if (!record.skipped && !record.empty_host) {
      ++active_hosts;
      if (record.rc == 0) ++successful_hosts;
    }
    for (unsigned port = 0; port < ports; ++port) {
      const int number = 10000 + static_cast<int>(port);
      require(net_db_insert_host(db, 0xc0000201u + host, number, "tcp", 1) == 1);
      record.ports.push_back(number);
      record.services.push_back(input.text());
      record.web_titles.push_back(input.text());
    }
    total_ports += ports;
    records.push_back(std::move(record));
  }

  const bool selected_active = !records[failed_host].skipped && !records[failed_host].empty_host;
  if (fault == 1) {
    // Reject one row on either the data-write or error-record path. Its host
    // may be skipped; the oracle then requires an ordinary successful commit.
    sql(db, "CREATE TEMP TRIGGER reject_row BEFORE UPDATE ON hosts WHEN NEW.ip='" +
        records[failed_host].ip + "' AND NEW.port=10000 BEGIN SELECT RAISE(ABORT,'owned fixture'); END");
  }
  int commit_calls = 0;
  if (fault == 2) sqlite3_commit_hook(db, reject_commit, &commit_calls);
  const bool rejected = (fault == 1 && selected_active) || (fault == 2 && active_hosts != 0);
  const auto status = net_store_enrichment_results({db}, records, inert_cpe);
  sqlite3_commit_hook(db, nullptr, nullptr);
  require(status.failed_shards == (rejected ? 1 : 0));
  require(status.written == (rejected ? 0 : successful_hosts));
  require(sqlite3_get_autocommit(db) != 0);
  if (fault == 2) require(commit_calls == (active_hosts ? 1 : 0));

  // The oracle reads raw rows, independently of the production getters and
  // reported count. A rejected transaction must preserve every original row.
  sqlite3_stmt *stmt = nullptr;
  require(sqlite3_prepare_v2(db,
      "SELECT ip,port,first_seen,last_seen,enriched,service,hostname,enrichment_error,web_title "
      "FROM hosts ORDER BY ip,port", -1, &stmt, nullptr) == SQLITE_OK);
  unsigned observed = 0;
  for (const auto &record : records) {
    const bool active = !rejected && !record.skipped && !record.empty_host;
    for (size_t port = 0; port < record.ports.size(); ++port) {
      require(sqlite3_step(stmt) == SQLITE_ROW);
      ++observed;
      require(column(stmt, 0) == record.ip);
      require(sqlite3_column_int(stmt, 1) == record.ports[port]);
      require(sqlite3_column_int64(stmt, 2) == 1);
      const bool saved = active && record.rc == 0;
      require(sqlite3_column_int(stmt, 4) == (saved ? 1 : 0));
      require(column(stmt, 5) == (saved ? record.services[port] : ""));
      require(column(stmt, 6) == (saved ? record.hostname : ""));
      require(column(stmt, 7) == (active && record.rc ? "enrich_single_host rc=9" : ""));
      require(column(stmt, 8) == (saved ? record.web_titles[port] : ""));
      require(saved ? sqlite3_column_int64(stmt, 3) >= 1 : sqlite3_column_int64(stmt, 3) == 1);
    }
  }
  require(observed == total_ports && sqlite3_step(stmt) == SQLITE_DONE);
  require(sqlite3_finalize(stmt) == SQLITE_OK);
  require(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM fingerprints", -1, &stmt, nullptr) == SQLITE_OK);
  require(sqlite3_step(stmt) == SQLITE_ROW);
  unsigned expected_fingerprints = 0;
  if (!rejected) for (const auto &record : records)
    if (!record.skipped && !record.empty_host && record.rc == 0 && !record.hostname.empty())
      ++expected_fingerprints;
  require(sqlite3_column_int64(stmt, 0) == expected_fingerprints);
  require(sqlite3_finalize(stmt) == SQLITE_OK);
  require(sqlite3_next_stmt(db, nullptr) == nullptr);
  require(sqlite3_close(db) == SQLITE_OK);
  return 0;
}
