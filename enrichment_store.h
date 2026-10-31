/* Storage-only enrichment handoff. No network calls or worker execution. */
#ifndef KMAP_ENRICHMENT_STORE_H
#define KMAP_ENRICHMENT_STORE_H

#include "net_db.h"
#include "net_enrich.h"
#include "asn_lookup.h"
#include "cloud_map.h"
#include "net_fp_helpers.h"
#include <cstdio>
#include <ctime>

struct NetEnrichResult {
  int shard_idx = -1;
  std::string ip;
  std::vector<int> ports;
  std::vector<std::string> protos;
  std::vector<std::string> services, versions, cves_json;
  std::vector<std::string> web_titles, web_servers, web_headers, web_paths;
  std::vector<std::string> powered_by, x_generator, redirects;
  std::vector<TlsCapture> tls_caps;
  std::vector<HostFingerprints> host_fps;
  std::string hostname;
  AsnInfo asn_info{};
  CloudInfo cloud_info{};
  int rc = 0;
  bool empty_host = false;
  /* Set when a worker declined this entry because the operator interrupted
     the scan.  Distinct from rc: rc defaults to 0 (success), so without this
     flag an unprocessed entry would look like a clean enrichment with no
     data and Stage C would mark the host enriched, dropping it out of the
     re-enrich queue with nothing collected. */
  bool skipped = false;
};

struct NetEnrichStoreStatus {
  int64_t written = 0;        // Successful hosts in committed shard transactions.
  int failed_shards = 0;
};

// A failed count is unknown, never an empty backlog or a negative total.
inline bool net_enrichment_counts(sqlite3 *db, int64_t &total, int64_t &eligible) {
  const int64_t rows = net_db_count(db);
  const int64_t pending = net_db_count_unenriched(db);
  if (rows < 0 || pending < 0) return false;
  total = rows;
  eligible = pending;
  return true;
}

namespace kmap_enrichment_store {
class Transaction {
 public:
  explicit Transaction(sqlite3 *db) : db_(db), active_(net_db_begin(db) == 0) {}
  ~Transaction() { if (active_) net_db_rollback(db_); }
  Transaction(const Transaction &) = delete;
  Transaction &operator=(const Transaction &) = delete;
  bool active() const { return active_; }
  bool write(int rc, bool require_row = false) const {
    return active_ && rc == 0 && !sqlite3_get_autocommit(db_) &&
        (!require_row || sqlite3_changes(db_) > 0);
  }
  bool commit() {
    if (!active_ || net_db_commit(db_) != 0) return false;
    active_ = false;
    return true;
  }
 private:
  sqlite3 *db_;
  bool active_;
};

using CpeFor = std::string (*)(const std::string &, const std::string &);

inline bool write_host(sqlite3 *db, Transaction &transaction,
                       const NetEnrichResult &r, CpeFor cpe_for) {
  if (r.rc != 0) {
    char err_buf[64];
    snprintf(err_buf, sizeof(err_buf),
             "enrich_single_host rc=%d", r.rc);
    for (size_t j = 0; j < r.ports.size(); j++) {
      if (!transaction.write(net_db_record_enrichment_error(db, r.ip.c_str(),
                                     r.ports[j], err_buf), true)) return false;
    }
    return true;
  }

  if (!r.hostname.empty())
    if (!transaction.write(net_db_set_hostname(db, r.ip.c_str(), r.hostname.c_str()))) return false;

  for (size_t j = 0; j < r.ports.size(); j++) {
    std::string enr_cpe = cpe_for(
      j < r.services.size() ? r.services[j] : std::string(),
      j < r.versions.size() ? r.versions[j] : std::string());
    if (!transaction.write(net_db_update_enrichment(
      db, r.ip.c_str(), r.ports[j],
      j < r.services.size()    ? r.services[j].c_str()    : "",
      j < r.versions.size()    ? r.versions[j].c_str()    : "",
      j < r.cves_json.size()   ? r.cves_json[j].c_str()   : "",
      j < r.web_titles.size()  ? r.web_titles[j].c_str()  : "",
      j < r.web_servers.size() ? r.web_servers[j].c_str() : "",
      j < r.web_headers.size() ? r.web_headers[j].c_str() : "",
      j < r.web_paths.size()   ? r.web_paths[j].c_str()   : "",
      j < r.powered_by.size()  ? r.powered_by[j].c_str()  : nullptr,
      j < r.x_generator.size() ? r.x_generator[j].c_str() : nullptr,
      j < r.redirects.size()   ? r.redirects[j].c_str()   : nullptr,
      nullptr,                                  /* robots_disallowed_json */
      enr_cpe.empty() ? nullptr : enr_cpe.c_str()), true)) return false;

    if (j < r.tls_caps.size()) {
      const TlsCapture &tc = r.tls_caps[j];
      bool have_tls = !tc.subject_cn.empty() || !tc.issuer.empty() ||
                      !tc.sha256.empty()     || !tc.protocol.empty();
      if (have_tls) {
        if (!transaction.write(net_db_update_tls(
          db, r.ip.c_str(), r.ports[j],
          tc.subject_cn.empty() ? nullptr : tc.subject_cn.c_str(),
          tc.issuer.empty()     ? nullptr : tc.issuer.c_str(),
          tc.san_json.empty()   ? nullptr : tc.san_json.c_str(),
          tc.not_after.empty()  ? nullptr : tc.not_after.c_str(),
          tc.self_signed,
          tc.protocol.empty()   ? nullptr : tc.protocol.c_str(),
          tc.sha256.empty()     ? nullptr : tc.sha256.c_str()))) return false;
      }
    }
  }

  if (r.asn_info.asn > 0) {
    if (!transaction.write(net_db_update_asn(db, r.ip.c_str(), r.asn_info.asn,
                      r.asn_info.as_name.c_str(),
                      r.asn_info.country.c_str(),
                      r.asn_info.bgp_prefix.c_str(),
                      r.asn_info.registry.c_str(),
                      r.asn_info.region.c_str()))) return false;
  }
  /* Cloud match is independent of ASN -- a host can be in a cloud range
     with no ASN result, so this is NOT gated on asn > 0. */
  if (!r.cloud_info.provider.empty()) {
    if (!transaction.write(net_db_update_cloud(db, r.ip.c_str(),
                        r.cloud_info.provider.c_str(),
                        r.cloud_info.region.empty()  ? nullptr : r.cloud_info.region.c_str(),
                        r.cloud_info.service.empty() ? nullptr : r.cloud_info.service.c_str()))) return false;
  }

  uint32_t ip_u32 = ip_to_u32(r.ip.c_str());
  if (ip_u32 != 0) {
    int64_t fp_ts = static_cast<int64_t>(time(nullptr));
    if (!r.hostname.empty()) {
      if (!transaction.write(net_db_insert_fingerprint(db, ip_u32, 0, "hostname",
                                r.hostname.c_str(), fp_ts))) return false;
    }
    for (size_t j = 0; j < r.ports.size(); j++) {
      if (j < r.tls_caps.size()) {
        const TlsCapture &tc = r.tls_caps[j];
        if (!tc.sha256.empty()) {
          if (!transaction.write(net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                    "tls_sha256",
                                    tc.sha256.c_str(), fp_ts))) return false;
        }
        if (!tc.subject_cn.empty() && !fp_looks_like_ip(tc.subject_cn)) {
          if (!transaction.write(net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                    "tls_subject_cn",
                                    tc.subject_cn.c_str(), fp_ts))) return false;
        }
        if (!tc.san_json.empty()) {
          std::vector<std::string> sans =
              fp_parse_san_json(tc.san_json);
          for (const std::string &san : sans) {
            if (san.empty() || fp_looks_like_ip(san)) continue;
            if (!transaction.write(net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                      "tls_san",
                                      san.c_str(), fp_ts))) return false;
          }
        }
      }
      if (j < r.redirects.size() && !r.redirects[j].empty()) {
        std::string rh = fp_extract_redirect_host(r.redirects[j]);
        if (!rh.empty()) {
          if (!transaction.write(net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                    "redirect_host",
                                    rh.c_str(), fp_ts))) return false;
        }
      }
      /* Active fingerprints (ASCII-safe values: a decimal mmh3 and a hex
         SHA-256 -- no JSON/control-char escaping needed). */
      if (j < r.host_fps.size()) {
        const HostFingerprints &fp = r.host_fps[j];
        if (!fp.favicon_mmh3.empty()) {
          if (!transaction.write(net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                    "favicon_mmh3",
                                    fp.favicon_mmh3.c_str(), fp_ts))) return false;
        }
        if (!fp.body_sha256.empty()) {
          if (!transaction.write(net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                    "http_body_sha256",
                                    fp.body_sha256.c_str(), fp_ts))) return false;
        }
        if (!fp.hassh.empty()) {
          if (!transaction.write(net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                    "hassh",
                                    fp.hassh.c_str(), fp_ts))) return false;
        }
        if (!fp.jarm.empty()) {
          if (!transaction.write(net_db_insert_fingerprint(db, ip_u32, r.ports[j],
                                    "jarm",
                                    fp.jarm.c_str(), fp_ts))) return false;
        }
      }
    }
  }
  return true;
}
} // namespace kmap_enrichment_store

// A shard commits every host/port/metadata write together. Stop on the first
// failed write, including automatic rollback, and never report pending work
// as saved. Other shards remain independent; failed ones stay retryable.
inline NetEnrichStoreStatus net_store_enrichment_results(
    const std::vector<sqlite3 *> &shard_dbs,
    const std::vector<NetEnrichResult> &results,
    kmap_enrichment_store::CpeFor cpe_for) {
  NetEnrichStoreStatus status;
  for (size_t shard = 0; shard < shard_dbs.size(); ++shard) {
    sqlite3 *db = shard_dbs[shard];
    if (!db) continue;
    bool any = false;
    for (const auto &r : results)
      if (r.shard_idx == static_cast<int>(shard) && !r.empty_host && !r.skipped) {
        any = true; break;
      }
    if (!any) continue;
    kmap_enrichment_store::Transaction transaction(db);
    bool complete = transaction.active() && cpe_for;
    int64_t pending = 0;
    if (complete) for (const auto &r : results) {
      if (r.shard_idx != static_cast<int>(shard) || r.empty_host || r.skipped) continue;
      if (!kmap_enrichment_store::write_host(db, transaction, r, cpe_for)) {
        complete = false;
        break;
      }
      if (r.rc == 0) ++pending;
    }
    if (complete && transaction.commit()) status.written += pending;
    else ++status.failed_shards;
  }
  return status;
}

#endif
