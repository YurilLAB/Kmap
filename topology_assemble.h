/* Pure topology assembly from recorded traces. No sockets, DNS or I/O.
 * Shared by the production pipeline and offline accuracy regressions. */
#ifndef KMAP_TOPOLOGY_ASSEMBLE_H
#define KMAP_TOPOLOGY_ASSEMBLE_H

#include "tracemap.h"
#include <algorithm>
#include <cmath>

static inline Topology build_topology(const std::vector<TraceResult> &traces,
                                      const std::string &source_ip) {
  Topology topo{};
  topo.source_ip = source_ip;
  topo.targets_total = static_cast<int>(traces.size());
  std::map<std::string, TopoNode> nodes;
  std::map<std::string, TopoEdge> edges;
  TopoNode source{};
  source.ip = source_ip;
  source.path_count = static_cast<int>(traces.size());
  source.rtt_sample_count = static_cast<int64_t>(traces.size());
  source.role = "source";
  nodes[source_ip] = source;

  for (const auto &trace : traces) {
    if (trace.reached) ++topo.targets_reached;
    std::string previous_ip = source_ip;
    double previous_rtt = 0.0;
    bool previous_measured = true;
    for (const auto &hop : trace.hops) {
      if (hop.timeout || hop.ip == "*") continue;
      bool measured = std::isfinite(hop.rtt_ms) && hop.rtt_ms >= 0;
      auto &node = nodes[hop.ip];
      if (node.ip.empty()) {
        node.ip = hop.ip;
        node.asn = hop.asn;
        node.as_name = hop.as_name;
        node.country = hop.country;
        node.hostname = hop.hostname;
        node.role = "router";
      }
      ++node.path_count;
      if (measured) {
        ++node.rtt_sample_count;
        node.avg_rtt_ms += (hop.rtt_ms - node.avg_rtt_ms) / node.rtt_sample_count;
      }
      if (hop.ip == trace.target_ip) node.role = "target";

      if (previous_ip != hop.ip) {
        auto &edge = edges[previous_ip + "->" + hop.ip];
        if (edge.from_ip.empty()) {
          edge.from_ip = previous_ip;
          edge.to_ip = hop.ip;
        }
        ++edge.path_count;
        // Use the predecessor observation in THIS trace, never its average
        // over other traces. Unknown RTTs contribute paths but no samples.
        if (measured && previous_measured) {
          double latency = std::max(0.0, hop.rtt_ms - previous_rtt);
          ++edge.latency_sample_count;
          edge.avg_latency_ms += (latency - edge.avg_latency_ms) / edge.latency_sample_count;
        }
      }
      previous_ip = hop.ip;
      previous_rtt = hop.rtt_ms;
      previous_measured = measured;
    }
  }
  for (auto &entry : nodes) topo.nodes.push_back(entry.second);
  for (auto &entry : edges) topo.edges.push_back(entry.second);
  topo.total_nodes = static_cast<int>(topo.nodes.size());
  topo.total_edges = static_cast<int>(topo.edges.size());
  return topo;
}
#endif
