#ifndef KMAP_TOPOLOGY_STORE_H
#define KMAP_TOPOLOGY_STORE_H

#include "net_db.h"
#include "tracemap.h"

// Store one assembled graph as a single transaction. No probing or I/O beyond
// the caller-owned SQLite connection. Counts describe committed rows only.
static inline bool persist_topology(sqlite3 *db, const Topology &topology,
                                    int64_t now, int &nodes, int &edges) {
  nodes = edges = 0;
  if (net_db_begin(db) != 0) return false;
  auto failed = [&]() {
    net_db_rollback(db);
    nodes = edges = 0;
    return false;
  };
  for (const TopoNode &n : topology.nodes) {
    uint32_t ip = ip_to_u32(n.ip.c_str());
    if (ip == 0) continue; // Preserve the existing non-IPv4/unknown-node rule.
    NetTopoNode value{};
    value.ip_u32 = ip;
    value.hostname = n.hostname;
    value.asn = n.asn;
    value.as_name = n.as_name;
    value.country = n.country;
    value.role = n.role;
    value.path_count = n.path_count;
    value.avg_rtt_ms = n.avg_rtt_ms;
    value.rtt_sample_count = n.rtt_sample_count;
    value.last_seen = now;
    if (net_db_upsert_topo_node(db, value) != 0) return failed();
    ++nodes;
  }
  for (const TopoEdge &e : topology.edges) {
    uint32_t from = ip_to_u32(e.from_ip.c_str());
    uint32_t to = ip_to_u32(e.to_ip.c_str());
    if (from == 0 || to == 0) continue;
    NetTopoEdge value{};
    value.from_u32 = from;
    value.to_u32 = to;
    value.asn_boundary = e.asn_boundary ? 1 : 0;
    value.avg_latency_ms = e.avg_latency_ms;
    value.path_count = e.path_count;
    value.latency_sample_count = e.latency_sample_count;
    value.last_seen = now;
    if (net_db_upsert_topo_edge(db, value) != 0) return failed();
    ++edges;
  }
  if (net_db_commit(db) != 0) return failed();
  return true;
}

#endif
