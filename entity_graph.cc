/*
 * entity_graph.cc -- implementation of the --entity-graph assembly + emitters.
 *
 * Pure read-side logic over net_db (no sockets, no OpenSSL).  Node types and the
 * edges between them:
 *
 *   ip ──serves/resolves_to──▶ domain ──certified_by──▶ cert
 *   ip ──presents───────────▶ cert
 *   ip ──announced_by───────▶ asn ──operated_by──▶ org   (AS owner = as_name)
 *                                  └─registered_in──▶ country
 *   ip ──hosted_on──────────▶ cloud   (provider, when known)
 *
 * depth >= 1 also pulls in other IPs sharing the seed's certificate or a domain
 * (the infrastructure cohort) and their own asn/org/country.  A direct
 * cert──issued_to──▶org edge from the certificate's subject O= is a planned
 * enhancement; today the org node is the AS owner.
 */

#include "entity_graph.h"
#include "net_db.h"
#include "json_escape.h"

#include <cctype>
#include <filesystem>
#include <memory>
#include <set>
#include <utility>

namespace {

void add_node(std::map<std::string, EgNode> &nodes, const std::string &id,
              const char *type, const std::string &label) {
  if (id.empty()) return;
  if (nodes.find(id) == nodes.end()) nodes[id] = EgNode{type, label};
}

void add_edge(std::vector<EgEdge> &edges, std::set<std::string> &seen,
              const std::string &from, const std::string &to, const char *label) {
  if (from.empty() || to.empty()) return;
  std::string k = from + "\x1f" + to + "\x1f" + label;
  if (seen.insert(k).second) edges.push_back(EgEdge{from, to, label});
}

/* Crude "is this value an IP literal, not a domain" filter so a reverse-DNS PTR
   or cert CN that is just an address does not become a bogus domain node. */
bool looks_like_ip(const std::string &s) {
  if (s.empty()) return false;
  for (unsigned char c : s)
    if (!isdigit(c) && c != '.' && c != ':') return false;
  return true;
}

/* Add one IP's subgraph (its host rows + fingerprints).  When out_certs /
   out_domains are non-null (the seed pass) collect its cert SHAs / domains so
   the caller can expand the shared-infrastructure cohort. */
bool add_ip_subgraph(sqlite3 *db, uint32_t ipu,
                     std::map<std::string, EgNode> &nodes,
                     std::vector<EgEdge> &edges, std::set<std::string> &eseen,
                     std::set<std::string> *out_certs,
                     std::set<std::string> *out_domains,
                     std::string &error) {
  std::string ip = u32_to_ip(ipu);
  std::string ip_id = "ip:" + ip;
  add_node(nodes, ip_id, "ip", ip);

  std::vector<NetHost> hrows = net_db_get_host(db, ip.c_str(), &error);
  if (!error.empty()) return false;
  for (const NetHost &h : hrows) {
    if (h.asn > 0) {
      std::string asn_id = "asn:" + std::to_string(h.asn);
      add_node(nodes, asn_id, "asn", "AS" + std::to_string(h.asn));
      add_edge(edges, eseen, ip_id, asn_id, "announced_by");
      if (!h.as_name.empty()) {
        std::string org_id = "org:" + h.as_name;
        add_node(nodes, org_id, "org", h.as_name);
        add_edge(edges, eseen, asn_id, org_id, "operated_by");
      }
      if (!h.country.empty()) {
        std::string c_id = "country:" + h.country;
        add_node(nodes, c_id, "country", h.country);
        add_edge(edges, eseen, asn_id, c_id, "registered_in");
      }
    }
    if (!h.tls_sha256.empty()) {
      std::string cert_id = "cert:" + h.tls_sha256;
      add_node(nodes, cert_id, "cert", h.tls_sha256.substr(0, 12) + "...");
      add_edge(edges, eseen, ip_id, cert_id, "presents");
      if (out_certs) out_certs->insert(h.tls_sha256);
      if (!h.tls_subject_cn.empty() && !looks_like_ip(h.tls_subject_cn)) {
        std::string d_id = "domain:" + h.tls_subject_cn;
        add_node(nodes, d_id, "domain", h.tls_subject_cn);
        add_edge(edges, eseen, d_id, cert_id, "certified_by");
      }
    }
    if (!h.cloud_provider.empty()) {
      std::string cl_id = "cloud:" + h.cloud_provider;
      add_node(nodes, cl_id, "cloud", h.cloud_provider);
      add_edge(edges, eseen, ip_id, cl_id, "hosted_on");
    }
  }

  std::vector<NetFingerprint> fps = net_db_get_fingerprints_for_ip(db, ip.c_str(), &error);
  if (!error.empty()) return false;
  for (const NetFingerprint &fp : fps) {
    if (fp.kind == "hostname" || fp.kind == "tls_subject_cn" ||
        fp.kind == "tls_san") {
      if (fp.value.empty() || looks_like_ip(fp.value)) continue;
      std::string d_id = "domain:" + fp.value;
      add_node(nodes, d_id, "domain", fp.value);
      add_edge(edges, eseen, ip_id, d_id,
               fp.kind == "hostname" ? "resolves_to" : "serves");
      if (out_domains) out_domains->insert(fp.value);
    } else if (fp.kind == "tls_sha256") {
      std::string cert_id = "cert:" + fp.value;
      add_node(nodes, cert_id, "cert", fp.value.substr(0, 12) + "...");
      add_edge(edges, eseen, ip_id, cert_id, "presents");
      if (out_certs) out_certs->insert(fp.value);
    }
  }
  return true;
}

/* Metadata may contain malformed UTF-8 as well as JSON control characters. */
std::string jesc(const std::string &s) {
  return kmap_json_escape(s);
}

/* Lossy UTF-8 repair is appropriate for display labels, but two different
   invalid byte strings must not collapse into one graph identity. Escape the
   reserved prefix too, making this mapping injective even for caller-supplied
   ids. Ordinary valid UTF-8 ids keep their existing external representation. */
std::string external_id(const std::string &id) {
  if (id.compare(0, 6, "bytes:") != 0 && kmap_json_repair_utf8(id) == id)
    return id;
  static const char hex[] = "0123456789abcdef";
  std::string encoded = "bytes:";
  for (unsigned char byte : id) {
    encoded += hex[byte >> 4];
    encoded += hex[byte & 15];
  }
  return encoded;
}

const char *type_color(const std::string &t) {
  if (t == "ip")      return "#ff6b6b";
  if (t == "domain")  return "#4ecdc4";
  if (t == "cert")    return "#ffe066";
  if (t == "org")     return "#a685e2";
  if (t == "asn")     return "#74c0fc";
  if (t == "country") return "#b2f2bb";
  if (t == "cloud")   return "#ffd8a8";
  return "#dddddd";
}

} /* namespace */

int entity_graph_build(const char *data_dir, const char *seed_ip, int depth,
                       std::map<std::string, EgNode> &nodes,
                       std::vector<EgEdge> &edges, size_t *cohort_ips,
                       std::string *error, bool *limit_reached) {
  nodes.clear();
  edges.clear();
  if (cohort_ips) *cohort_ips = 0;
  if (error) error->clear();
  if (limit_reached) *limit_reached = false;
  if (!data_dir || !seed_ip || !seed_ip[0] || depth < 0 || depth > 3) return -1;
  uint32_t seed_u32 = ip_to_u32(seed_ip);
  if (seed_u32 == 0) return -1;

  std::map<std::string, EgNode> assembled_nodes;
  std::vector<EgEdge> assembled_edges;
  std::set<std::string> eseen;
  std::set<std::string> certs, domains;
  std::string read_error;
  using Database = std::unique_ptr<sqlite3, decltype(&net_db_close)>;
  auto failure = [&](const std::string &path) {
    if (error) *error = path + ": " + read_error;
    return -3;
  };
  auto exists = [&](const std::string &path) {
    std::error_code status;
    bool found = std::filesystem::exists(path, status);
    read_error = status ? status.message() : "";
    return found;
  };
  auto make_lookups = [](const std::set<std::string> &cs,
                         const std::set<std::string> &ds) {
    std::set<std::pair<std::string, std::string>> result;
    for (const auto &c : cs) result.insert({"tls_sha256", c});
    for (const auto &d : ds) {
      result.insert({"tls_san", d});
      result.insert({"tls_subject_cn", d});
      result.insert({"hostname", d});
    }
    return result;
  };
  {
    std::string path = net_shard_path(data_dir, net_shard_index(seed_u32));
    if (!exists(path)) return read_error.empty() ? -2 : failure(path);
    Database db(net_db_open(path), net_db_close);
    if (!db) { read_error = "cannot open shard"; return failure(path); }
    if (!add_ip_subgraph(db.get(), seed_u32, assembled_nodes, assembled_edges,
                        eseen, &certs, &domains, read_error)) return failure(path);
  }
  if (assembled_nodes.size() <= 1) return -2;

  // Breadth-first expansion preserves the existing 500-peer cap across all
  // levels. Ordered lookups, shards and IPs make truncation deterministic.
  const size_t COHORT_CAP = 500;
  std::set<uint32_t> visited{seed_u32};
  auto lookups = make_lookups(certs, domains);
  for (int level = 0; level < depth && !lookups.empty() &&
       visited.size() - 1 < COHORT_CAP; ++level) {
    std::set<uint32_t> next;
    for (int sh = 0; sh < NET_SHARD_COUNT &&
         visited.size() - 1 + next.size() < COHORT_CAP; ++sh) {
      std::string path = net_shard_path(data_dir, sh);
      if (!exists(path)) {
        if (!read_error.empty()) return failure(path);
        continue;
      }
      Database db(net_db_open(path), net_db_close);
      if (!db) { read_error = "cannot open shard"; return failure(path); }
      for (const auto &lookup : lookups) {
        // A fingerprint has one row per IP. At most 501 already-selected
        // IPs can precede eligible peers, so 1001 rows suffice to fill the
        // cap without materializing an arbitrarily large matching cohort.
        auto matches = net_db_find_by_fingerprint(db.get(), lookup.first.c_str(),
            lookup.second.c_str(), &read_error, static_cast<int>(2 * COHORT_CAP + 1));
        if (!read_error.empty()) return failure(path);
        for (const auto &match : matches) {
          if (!visited.count(match.ip_u32)) next.insert(match.ip_u32);
          if (visited.size() - 1 + next.size() >= COHORT_CAP) break;
        }
        if (visited.size() - 1 + next.size() >= COHORT_CAP) break;
      }
    }
    certs.clear();
    domains.clear();
    std::map<int, std::vector<uint32_t>> by_shard;
    for (uint32_t ip : next) by_shard[net_shard_index(ip)].push_back(ip);
    for (const auto &group : by_shard) {
      std::string path = net_shard_path(data_dir, group.first);
      if (!exists(path)) {
        if (read_error.empty()) read_error = "cohort shard disappeared";
        return failure(path);
      }
      Database db(net_db_open(path), net_db_close);
      if (!db) { read_error = "cannot open shard"; return failure(path); }
      for (uint32_t ip : group.second) {
        if (!add_ip_subgraph(db.get(), ip, assembled_nodes, assembled_edges,
                            eseen, &certs, &domains, read_error)) return failure(path);
        visited.insert(ip);
      }
    }
    lookups = make_lookups(certs, domains);
  }
  nodes.swap(assembled_nodes);
  edges.swap(assembled_edges);
  if (cohort_ips) *cohort_ips = visited.size() - 1;
  if (limit_reached) *limit_reached = visited.size() - 1 == COHORT_CAP;
  return 0;
}

void entity_graph_emit(FILE *out, const char *fmt, const std::string &seed_ip,
                       int depth, size_t cohort_ips,
                       const std::map<std::string, EgNode> &nodes,
                       const std::vector<EgEdge> &edges, bool cohort_limit_reached) {
  std::string f = fmt ? fmt : "text";
  if (f == "dot") {
    fprintf(out, "digraph entity_graph {\n");
    if (cohort_limit_reached) fprintf(out, "  // Cohort limit reached; graph may be incomplete.\n");
    fprintf(out, "  graph [rankdir=LR, overlap=false, splines=true];\n");
    fprintf(out, "  node  [style=filled, fontname=\"Helvetica\"];\n");
    for (const auto &kv : nodes) {
      fprintf(out, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", shape=%s];\n",
              jesc(external_id(kv.first)).c_str(), jesc(kv.second.label).c_str(),
              type_color(kv.second.type),
              kv.second.type == "ip" ? "box" : "ellipse");
    }
    for (const EgEdge &e : edges) {
      fprintf(out, "  \"%s\" -> \"%s\" [label=\"%s\"];\n",
              jesc(external_id(e.from)).c_str(), jesc(external_id(e.to)).c_str(), e.label.c_str());
    }
    fprintf(out, "}\n");
  } else if (f == "json") {
    fprintf(out, "{\n  \"seed\": \"%s\",\n  \"depth\": %d,\n",
            jesc(seed_ip).c_str(), depth);
    fprintf(out, "  \"cohort_ips\": %zu,\n  \"cohort_limit\": 500,\n"
                 "  \"cohort_limit_reached\": %s,\n  \"nodes\": [\n",
            cohort_ips, cohort_limit_reached ? "true" : "false");
    size_t i = 0;
    for (const auto &kv : nodes) {
      fprintf(out, "    {\"id\": \"%s\", \"type\": \"%s\", \"label\": \"%s\"}%s\n",
              jesc(external_id(kv.first)).c_str(), kv.second.type.c_str(),
              jesc(kv.second.label).c_str(),
              (++i == nodes.size()) ? "" : ",");
    }
    fprintf(out, "  ],\n  \"edges\": [\n");
    for (size_t j = 0; j < edges.size(); j++) {
      fprintf(out, "    {\"from\": \"%s\", \"to\": \"%s\", \"label\": \"%s\"}%s\n",
              jesc(external_id(edges[j].from)).c_str(), jesc(external_id(edges[j].to)).c_str(),
              jesc(edges[j].label).c_str(), (j + 1 == edges.size()) ? "" : ",");
    }
    fprintf(out, "  ]\n}\n");
  } else {
    fprintf(out, "# entity-graph for %s (depth=%d): %zu nodes, %zu edges, "
            "%zu cohort IPs\n", seed_ip.c_str(), depth, nodes.size(),
            edges.size(), cohort_ips);
    if (cohort_limit_reached) fprintf(out, "# Cohort limit reached; graph may be incomplete.\n");
    for (const EgEdge &e : edges) {
      auto info = [&](const std::string &id) -> std::pair<std::string, std::string> {
        auto it = nodes.find(id);
        if (it == nodes.end()) return {"?", id};
        return {it->second.type, it->second.label};
      };
      auto fi = info(e.from), ti = info(e.to);
      fprintf(out, "[%-7s] %-22s --%s--> [%-7s] %s\n",
              fi.first.c_str(), fi.second.c_str(), e.label.c_str(),
              ti.first.c_str(), ti.second.c_str());
    }
  }
}
