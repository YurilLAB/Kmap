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

#include <cctype>
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
void add_ip_subgraph(sqlite3 *db, uint32_t ipu,
                     std::map<std::string, EgNode> &nodes,
                     std::vector<EgEdge> &edges, std::set<std::string> &eseen,
                     std::set<std::string> *out_certs,
                     std::set<std::string> *out_domains) {
  std::string ip = u32_to_ip(ipu);
  std::string ip_id = "ip:" + ip;
  add_node(nodes, ip_id, "ip", ip);

  std::vector<NetHost> hrows = net_db_get_host(db, ip.c_str());
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

  std::vector<NetFingerprint> fps = net_db_get_fingerprints_for_ip(db, ip.c_str());
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
}

/* RFC 8259 JSON string escaping; node ids/labels come off certs/PTR so they can
   carry control bytes. unsigned-char iteration so UTF-8 passes through. */
std::string jesc(const std::string &s) {
  std::string o; o.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\r': o += "\\r";  break;
      case '\t': o += "\\t";  break;
      case '\b': o += "\\b";  break;
      case '\f': o += "\\f";  break;
      default:
        if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
        else o += static_cast<char>(c);
    }
  }
  return o;
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
                       std::vector<EgEdge> &edges, size_t *cohort_ips) {
  if (cohort_ips) *cohort_ips = 0;
  if (!seed_ip || !seed_ip[0]) return -1;
  uint32_t seed_u32 = ip_to_u32(seed_ip);
  if (seed_u32 == 0) return -1;

  std::set<std::string> eseen;
  std::set<std::string> seed_certs, seed_domains;

  /* Phase 1: the seed's own subgraph. */
  {
    std::string sp = net_shard_path(data_dir, net_shard_index(seed_u32));
    sqlite3 *db = net_db_open(sp.c_str());
    if (!db) return -2;
    add_ip_subgraph(db, seed_u32, nodes, edges, eseen, &seed_certs, &seed_domains);
    net_db_close(db);
  }
  if (nodes.size() <= 1) return -2;   /* only the ip node, no enriched data */

  /* Phase 2: cohort expansion -- IPs sharing the seed's cert or a domain. */
  if (depth >= 1 && (!seed_certs.empty() || !seed_domains.empty())) {
    std::vector<std::pair<std::string, std::string>> lookups;
    for (const std::string &c : seed_certs) lookups.push_back({"tls_sha256", c});
    for (const std::string &d : seed_domains) {
      lookups.push_back({"tls_san", d});
      lookups.push_back({"tls_subject_cn", d});
      lookups.push_back({"hostname", d});
    }
    const size_t COHORT_CAP = 500;
    std::set<uint32_t> cohort;
    for (int sh = 0; sh < NET_SHARD_COUNT && cohort.size() < COHORT_CAP; sh++) {
      std::string sp = net_shard_path(data_dir, sh);
      FILE *t = fopen(sp.c_str(), "r");
      if (!t) continue;
      fclose(t);
      sqlite3 *db = net_db_open(sp.c_str());
      if (!db) continue;
      for (const auto &lv : lookups) {
        std::vector<NetFingerprint> m =
            net_db_find_by_fingerprint(db, lv.first.c_str(), lv.second.c_str());
        for (const NetFingerprint &fp : m) {
          if (fp.ip_u32 != seed_u32) cohort.insert(fp.ip_u32);
          if (cohort.size() >= COHORT_CAP) break;
        }
        if (cohort.size() >= COHORT_CAP) break;
      }
      net_db_close(db);
    }
    std::map<int, std::vector<uint32_t>> by_shard;
    for (uint32_t ipu : cohort) by_shard[net_shard_index(ipu)].push_back(ipu);
    for (const auto &kv : by_shard) {
      std::string sp = net_shard_path(data_dir, kv.first);
      sqlite3 *db = net_db_open(sp.c_str());
      if (!db) continue;
      for (uint32_t ipu : kv.second) {
        add_ip_subgraph(db, ipu, nodes, edges, eseen, nullptr, nullptr);
        if (cohort_ips) (*cohort_ips)++;
      }
      net_db_close(db);
    }
  }
  return 0;
}

void entity_graph_emit(FILE *out, const char *fmt, const std::string &seed_ip,
                       int depth, size_t cohort_ips,
                       const std::map<std::string, EgNode> &nodes,
                       const std::vector<EgEdge> &edges) {
  std::string f = fmt ? fmt : "text";
  if (f == "dot") {
    fprintf(out, "digraph entity_graph {\n");
    fprintf(out, "  graph [rankdir=LR, overlap=false, splines=true];\n");
    fprintf(out, "  node  [style=filled, fontname=\"Helvetica\"];\n");
    for (const auto &kv : nodes) {
      fprintf(out, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", shape=%s];\n",
              jesc(kv.first).c_str(), jesc(kv.second.label).c_str(),
              type_color(kv.second.type),
              kv.second.type == "ip" ? "box" : "ellipse");
    }
    for (const EgEdge &e : edges) {
      fprintf(out, "  \"%s\" -> \"%s\" [label=\"%s\"];\n",
              jesc(e.from).c_str(), jesc(e.to).c_str(), e.label.c_str());
    }
    fprintf(out, "}\n");
  } else if (f == "json") {
    fprintf(out, "{\n  \"seed\": \"%s\",\n  \"depth\": %d,\n",
            jesc(seed_ip).c_str(), depth);
    fprintf(out, "  \"cohort_ips\": %zu,\n  \"nodes\": [\n", cohort_ips);
    size_t i = 0;
    for (const auto &kv : nodes) {
      fprintf(out, "    {\"id\": \"%s\", \"type\": \"%s\", \"label\": \"%s\"}%s\n",
              jesc(kv.first).c_str(), kv.second.type.c_str(),
              jesc(kv.second.label).c_str(),
              (++i == nodes.size()) ? "" : ",");
    }
    fprintf(out, "  ],\n  \"edges\": [\n");
    for (size_t j = 0; j < edges.size(); j++) {
      fprintf(out, "    {\"from\": \"%s\", \"to\": \"%s\", \"label\": \"%s\"}%s\n",
              jesc(edges[j].from).c_str(), jesc(edges[j].to).c_str(),
              jesc(edges[j].label).c_str(), (j + 1 == edges.size()) ? "" : ",");
    }
    fprintf(out, "  ]\n}\n");
  } else {
    fprintf(out, "# entity-graph for %s (depth=%d): %zu nodes, %zu edges, "
            "%zu cohort IPs\n", seed_ip.c_str(), depth, nodes.size(),
            edges.size(), cohort_ips);
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
