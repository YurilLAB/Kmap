/*
 * tracemap.h -- Network topology mapper for Kmap.
 *
 * Performs parallel traceroute to multiple targets, builds a unified
 * network topology graph, and runs smart analysis to identify:
 *   - Shared infrastructure (gateways, core routers)
 *   - ASN boundaries (peering points, transit links)
 *   - Hub nodes (high-connectivity routers)
 *   - Latency bottlenecks
 *
 * Output formats: text tree, DOT (Graphviz), JSON.
 */

#ifndef TRACEMAP_H
#define TRACEMAP_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>

/* -------------------------------------------------------------------
 * Data structures
 * ------------------------------------------------------------------- */

/* A single hop in a traceroute */
struct TraceHop {
  int         ttl;
  std::string ip;       /* dotted-quad, or "*" if no reply */
  std::string hostname; /* reverse DNS, empty if unresolved */
  double      rtt_ms;   /* round-trip time, -1.0 if timeout */
  uint32_t    asn;      /* from ASN lookup, 0 = unknown */
  std::string as_name;
  std::string country;
  bool        timeout;      /* true = no reply at this TTL */
  bool        load_balanced; /* true = different IPs seen across probes (ECMP) */
};

/* A complete traceroute to one target */
struct TraceResult {
  std::string target_ip;
  std::string target_host; /* hostname if resolved */
  int         hops_used;
  bool        reached;     /* did we reach the target? */
  std::vector<TraceHop> hops;
};

/* A node in the topology graph */
struct TopoNode {
  std::string ip;
  std::string hostname;
  uint32_t    asn;
  std::string as_name;
  std::string country;

  /* Analysis results */
  int         path_count;       /* how many traces pass through this node */
  double      avg_rtt_ms;
  std::string role;             /* "source", "gateway", "router", "ixp",
                                   "target", "border", "hub" */
  bool        convergence_point; /* true = multiple paths merge here */
};

/* An edge connecting two topology nodes */
struct TopoEdge {
  std::string from_ip;
  std::string to_ip;
  double      avg_latency_ms; /* avg (to.rtt - from.rtt) */
  int         path_count;     /* how many traces use this edge */
  bool        asn_boundary;   /* true if ASN changes on this edge */
};

/* The complete topology graph */
struct Topology {
  std::string              source_ip;
  std::vector<TopoNode>    nodes;
  std::vector<TopoEdge>    edges;
  std::vector<TraceResult> traces;

  /* Analysis summary */
  int  total_nodes;
  int  total_edges;
  int  unique_asns;
  int  asn_boundaries;
  int  targets_reached;
  int  targets_total;
};

/* -------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------- */

/* Run the full tracemap pipeline: trace → build graph → analyze → output.
 *   targets     — comma-separated IPs or CIDR ranges, or path to targets file
 *   output_file — output filename (NULL = stdout)
 *   format      — "txt", "dot", or "json"
 *   max_hops    — maximum TTL (default 30)
 *   timeout_ms  — per-probe timeout (default 2000)
 * Returns 0 on success, 1 on error. */
int run_tracemap(const char *targets, const char *output_file,
                 const char *format, int max_hops, int timeout_ms);

#endif /* TRACEMAP_H */
