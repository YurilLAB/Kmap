/*
 * entity_graph.h -- asset-attribution graph assembly for --entity-graph.
 *
 * Builds the IP -> Domain -> Certificate -> Organization -> ASN -> Country graph
 * around a seed IP from the data the net-scan pipeline already catalogs (the
 * fingerprints + hosts tables across shards) -- no new schema, assembled on the
 * fly.  Extracted into its own TU (depends only on net_db.h) so the test
 * harness links the real assembly, mirroring net_hash_helpers / cloud_map.
 */

#ifndef ENTITY_GRAPH_H
#define ENTITY_GRAPH_H

#include <cstdio>
#include <map>
#include <string>
#include <vector>

struct EgNode { std::string type; std::string label; };
struct EgEdge { std::string from; std::string to; std::string label; };

/* Assemble the graph around seed_ip from the shard store at data_dir, expanding
   `depth` hops into the shared-certificate / shared-domain cohort (0 = seed
   only).  Fills `nodes` (keyed by typed id, e.g. "ip:1.2.3.4") and `edges`,
   and sets *cohort_ips to the number of cohort IPs pulled in.
   Returns 0 on success, -1 on an unparseable seed IP, -2 when the seed has no
   enriched data in the store. */
int entity_graph_build(const char *data_dir, const char *seed_ip, int depth,
                       std::map<std::string, EgNode> &nodes,
                       std::vector<EgEdge> &edges, size_t *cohort_ips);

/* Emit the assembled graph to `out`.  fmt is "dot", "json", or anything else
   for the default pipeable text format. */
void entity_graph_emit(FILE *out, const char *fmt, const std::string &seed_ip,
                       int depth, size_t cohort_ips,
                       const std::map<std::string, EgNode> &nodes,
                       const std::vector<EgEdge> &edges);

#endif /* ENTITY_GRAPH_H */
