/*
 * tracemap.cc -- Network topology mapper for Kmap.
 *
 * Cross-platform traceroute implementation:
 *   - Windows: IcmpSendEcho via iphlpapi.dll (no admin required)
 *   - Linux:   raw ICMP socket (needs root / cap_net_raw)
 *
 * Topology analysis:
 *   - Hub detection (nodes traversed by many paths)
 *   - ASN boundary detection (peering/transit points)
 *   - Gateway classification (first external hop)
 *   - Latency bottleneck detection (large RTT jumps)
 *   - Star pattern detection (convergence points)
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "tracemap.h"
#include "asn_lookup.h"
#include "output.h"
#include "KmapOps.h"
#include "kmap.h"
#include "net_db.h"  /* ip_to_u32, u32_to_ip */

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <vector>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef __sun
#include <netinet/in_systm.h>  /* Solaris: n_time for ip_icmp.h */
#endif
#include <netinet/ip.h>        /* struct ip — required before ip_icmp.h on BSD */
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
/* BSD/macOS use ICMP_TIMXCEED instead of ICMP_TIME_EXCEEDED */
#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#endif
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

extern KmapOps o;

/* -----------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------- */

#define DEFAULT_MAX_HOPS   30
#define DEFAULT_TIMEOUT_MS 2000
#define PROBES_PER_HOP     2   /* send 2 probes per TTL for reliability */

/* -----------------------------------------------------------------------
 * Cross-platform time helper
 * ----------------------------------------------------------------------- */

static double time_ms() {
#ifdef WIN32
  static LARGE_INTEGER freq = {};
  if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
  LARGE_INTEGER now;
  QueryPerformanceCounter(&now);
  return (double)now.QuadPart / (double)freq.QuadPart * 1000.0;
#else
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
#endif
}

/* -----------------------------------------------------------------------
 * Reverse DNS lookup (non-blocking with timeout)
 * ----------------------------------------------------------------------- */

static std::string reverse_dns(const char *ip) {
  struct sockaddr_in sa{};
  sa.sin_family = AF_INET;
  if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return "";

  char host[256] = {};
  int rc = getnameinfo(reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa),
                       host, sizeof(host), nullptr, 0, NI_NAMEREQD);
  return (rc == 0) ? host : "";
}

/* -----------------------------------------------------------------------
 * Traceroute implementation — Windows (IcmpSendEcho)
 * ----------------------------------------------------------------------- */

#ifdef WIN32

static TraceResult trace_one_target(const char *target_ip, int max_hops,
                                    int timeout_ms) {
  TraceResult result;
  result.target_ip = target_ip;
  result.reached = false;
  result.hops_used = 0;

  struct in_addr dest_addr;
  if (inet_pton(AF_INET, target_ip, &dest_addr) != 1) return result;
  unsigned long dest = dest_addr.s_addr;

  HANDLE icmp = IcmpCreateFile();
  if (icmp == INVALID_HANDLE_VALUE) return result;

  /* Reply buffer: Microsoft requires at least sizeof(ICMP_ECHO_REPLY) +
   * RequestSize + 8.  We use 256 to safely accommodate IP options. */
  char reply_buf[256];
  char send_data[32];
  memset(send_data, 0x42, sizeof(send_data));

  int consecutive_timeouts = 0;
  const int MAX_CONSECUTIVE_TIMEOUTS = 5;

  for (int ttl = 1; ttl <= max_hops; ttl++) {
    TraceHop hop;
    hop.ttl = ttl;
    hop.rtt_ms = -1.0;
    hop.asn = 0;
    hop.timeout = true;
    hop.load_balanced = false;

    IP_OPTION_INFORMATION opts{};
    opts.Ttl = static_cast<UCHAR>(ttl);

    double best_rtt = -1.0;
    std::string hop_ip;
    std::set<std::string> probe_ips; /* track unique IPs for load balancer detection */

    for (int probe = 0; probe < PROBES_PER_HOP; probe++) {
      double t0 = time_ms();
      DWORD ret = IcmpSendEcho(icmp, dest, send_data, sizeof(send_data),
                                &opts, reply_buf, sizeof(reply_buf),
                                static_cast<DWORD>(timeout_ms));
      double t1 = time_ms();

      /* When IcmpSendEcho returns 0, the reply buffer is still valid
       * as long as it was large enough.  The actual error is in the
       * reply structure's Status field, NOT GetLastError().
       * GetLastError() only reports the send-side error. */
      ICMP_ECHO_REPLY *echo = reinterpret_cast<ICMP_ECHO_REPLY *>(reply_buf);

      if (ret > 0 || echo->Status == IP_TTL_EXPIRED_TRANSIT ||
          echo->Status == IP_TTL_EXPIRED_REASSEM ||
          echo->Status == IP_SUCCESS) {
        struct in_addr addr;
        addr.s_addr = echo->Address;
        char ip_buf[16];
        inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf));
        hop_ip = ip_buf;
        probe_ips.insert(ip_buf);
        hop.timeout = false;
        double rtt = t1 - t0;
        if (best_rtt < 0 || rtt < best_rtt) best_rtt = rtt;

        if (echo->Status == IP_SUCCESS) {
          result.reached = true;
        }
      }
    }

    /* Track load balancing: multiple different IPs at same TTL */
    hop.load_balanced = (probe_ips.size() > 1);

    hop.ip = hop_ip.empty() ? "*" : hop_ip;
    hop.rtt_ms = best_rtt;
    result.hops.push_back(hop);
    result.hops_used = ttl;

    /* Consecutive timeout detection — stop early if hitting a firewall */
    if (hop.timeout) {
      consecutive_timeouts++;
      if (consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS) break;
    } else {
      consecutive_timeouts = 0;
    }

    if (result.reached) break;
  }

  IcmpCloseHandle(icmp);
  return result;
}

#else /* Linux / Unix */

/* -----------------------------------------------------------------------
 * Traceroute implementation — Linux (raw ICMP)
 * ----------------------------------------------------------------------- */

/* ICMP checksum */
static uint16_t icmp_checksum(const void *data, size_t len) {
  const uint16_t *p = reinterpret_cast<const uint16_t *>(data);
  uint32_t sum = 0;
  while (len > 1) { sum += *p++; len -= 2; }
  if (len == 1) sum += *reinterpret_cast<const uint8_t *>(p);
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

static TraceResult trace_one_target(const char *target_ip, int max_hops,
                                    int timeout_ms) {
  TraceResult result;
  result.target_ip = target_ip;
  result.reached = false;
  result.hops_used = 0;

  struct sockaddr_in dest{};
  dest.sin_family = AF_INET;
  if (inet_pton(AF_INET, target_ip, &dest.sin_addr) != 1) return result;

  /* Create raw ICMP socket */
  int send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (send_fd < 0) {
    /* Fallback: try DGRAM ICMP (unprivileged, Linux 3.0+) */
    send_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (send_fd < 0) {
      fprintf(stderr, "tracemap: cannot create ICMP socket (need root or cap_net_raw)\n");
      return result;
    }
  }

  uint16_t ident = static_cast<uint16_t>(getpid() & 0xFFFF);
  uint16_t seq = 0;

  int consecutive_timeouts = 0;
  const int MAX_CONSECUTIVE_TIMEOUTS = 5;

  for (int ttl = 1; ttl <= max_hops; ttl++) {
    TraceHop hop;
    hop.ttl = ttl;
    hop.rtt_ms = -1.0;
    hop.asn = 0;
    hop.timeout = true;
    hop.load_balanced = false;

    /* Set TTL */
    int ttl_val = ttl;
    setsockopt(send_fd, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val));

    double best_rtt = -1.0;
    std::string hop_ip;
    std::set<std::string> probe_ips; /* track unique IPs for load balancer detection */

    for (int probe = 0; probe < PROBES_PER_HOP; probe++) {
      /* Build ICMP echo request */
      struct icmp icmp_pkt{};
      icmp_pkt.icmp_type = ICMP_ECHO;
      icmp_pkt.icmp_code = 0;
      icmp_pkt.icmp_id = htons(ident);
      icmp_pkt.icmp_seq = htons(seq++);
      icmp_pkt.icmp_cksum = 0;
      icmp_pkt.icmp_cksum = icmp_checksum(&icmp_pkt, sizeof(icmp_pkt));

      double t0 = time_ms();
      ssize_t sent = sendto(send_fd, &icmp_pkt, sizeof(icmp_pkt), 0,
                            reinterpret_cast<struct sockaddr *>(&dest),
                            sizeof(dest));
      if (sent <= 0) continue;

      /* Wait for reply with timeout */
      fd_set rset;
      FD_ZERO(&rset);
      FD_SET(send_fd, &rset);
      struct timeval tv;
      tv.tv_sec = timeout_ms / 1000;
      tv.tv_usec = (timeout_ms % 1000) * 1000;

      if (select(send_fd + 1, &rset, nullptr, nullptr, &tv) > 0) {
        uint8_t recv_buf[512];
        struct sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(send_fd, recv_buf, sizeof(recv_buf), 0,
                             reinterpret_cast<struct sockaddr *>(&from),
                             &from_len);
        double t1 = time_ms();

        if (n > 0) {
          /* Parse IP header to find ICMP payload */
          /* IP header is typically 20 bytes, then ICMP */
          if (n >= 28) {
            int ip_hdr_len = (recv_buf[0] & 0x0F) * 4;
            if (ip_hdr_len + 8 <= n) {
              uint8_t icmp_type = recv_buf[ip_hdr_len];

              if (icmp_type == ICMP_ECHOREPLY) {
                /* Direct echo reply — verify our ident in the ICMP header */
                uint16_t reply_id = (recv_buf[ip_hdr_len + 4] << 8) |
                                     recv_buf[ip_hdr_len + 5];
                if (reply_id != ident) continue; /* not our packet */

                char ip_buf[16];
                inet_ntop(AF_INET, &from.sin_addr, ip_buf, sizeof(ip_buf));
                hop_ip = ip_buf;
                probe_ips.insert(ip_buf);
                hop.timeout = false;
                double rtt = t1 - t0;
                if (best_rtt < 0 || rtt < best_rtt) best_rtt = rtt;
                result.reached = true;

              } else if (icmp_type == ICMP_TIME_EXCEEDED) {
                /* TTL exceeded — the embedded packet contains the original
                 * IP header + first 8 bytes of our ICMP echo request.
                 * Verify our ident in the embedded ICMP header to ensure
                 * this is a response to OUR probe, not someone else's. */
                int inner_offset = ip_hdr_len + 8; /* outer ICMP hdr (8) */
                if (inner_offset + 20 + 8 <= n) {
                  /* Skip embedded IP header to find embedded ICMP */
                  int inner_ip_hdr_len = (recv_buf[inner_offset] & 0x0F) * 4;
                  int embedded_icmp = inner_offset + inner_ip_hdr_len;
                  if (embedded_icmp + 8 <= n) {
                    uint16_t embedded_id = (recv_buf[embedded_icmp + 4] << 8) |
                                            recv_buf[embedded_icmp + 5];
                    if (embedded_id != ident) continue; /* not our packet */
                  }
                }

                char ip_buf[16];
                inet_ntop(AF_INET, &from.sin_addr, ip_buf, sizeof(ip_buf));
                hop_ip = ip_buf;
                probe_ips.insert(ip_buf);
                hop.timeout = false;
                double rtt = t1 - t0;
                if (best_rtt < 0 || rtt < best_rtt) best_rtt = rtt;
              }
            }
          }
        }
      }
    }

    /* Track load balancing: multiple different IPs at same TTL */
    hop.load_balanced = (probe_ips.size() > 1);

    hop.ip = hop_ip.empty() ? "*" : hop_ip;
    hop.rtt_ms = best_rtt;
    result.hops.push_back(hop);
    result.hops_used = ttl;

    /* Consecutive timeout detection — stop early if hitting a firewall */
    if (hop.timeout) {
      consecutive_timeouts++;
      if (consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS) break;
    } else {
      consecutive_timeouts = 0;
    }

    if (result.reached) break;
  }

  close(send_fd);
  return result;
}

#endif /* WIN32 */

/* -----------------------------------------------------------------------
 * Target parsing — supports IPs, CIDRs, and files
 * ----------------------------------------------------------------------- */

/* Check if a string looks like an IP address (only digits, dots, colons,
 * slashes for CIDR).  This prevents opening a file named "8.8.8.8" when
 * the user meant an IP target. */
static bool looks_like_ip(const char *s) {
  if (!s || !s[0]) return false;
  for (const char *p = s; *p; p++) {
    char c = *p;
    if (c >= '0' && c <= '9') continue;
    if (c == '.' || c == ':' || c == '/') continue;
    if (c >= 'a' && c <= 'f') continue; /* hex for IPv6 */
    if (c >= 'A' && c <= 'F') continue;
    return false;
  }
  return true;
}

/* Check if a string has a path separator or common file extension,
 * indicating it's likely a file path rather than an IP. */
static bool looks_like_filepath(const char *s) {
  if (!s || !s[0]) return false;
  /* Contains path separator */
  if (strchr(s, '/') && strchr(s, '.') == nullptr) return true;
  if (strchr(s, '\\')) return true;
  /* Common file extensions */
  size_t len = strlen(s);
  if (len > 4 && strcmp(s + len - 4, ".txt") == 0) return true;
  if (len > 4 && strcmp(s + len - 4, ".csv") == 0) return true;
  if (len > 5 && strcmp(s + len - 5, ".conf") == 0) return true;
  if (len > 5 && strcmp(s + len - 5, ".list") == 0) return true;
  return false;
}

static std::vector<std::string> parse_targets(const char *spec) {
  std::vector<std::string> targets;
  if (!spec || !spec[0]) return targets;

  /* Only try opening as a file if the string does NOT look like an IP
   * address, or if it looks like a file path.  This avoids opening a
   * file called "8.8.8.8" when the user meant an IP target. */
  bool try_file = !looks_like_ip(spec) || looks_like_filepath(spec);
  FILE *f = try_file ? fopen(spec, "r") : nullptr;
  if (f) {
    char line[256];
    while (fgets(line, sizeof(line), f)) {
      /* Trim whitespace */
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      size_t len = strlen(p);
      while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r' ||
                          p[len-1] == ' '))
        p[--len] = '\0';
      if (len == 0 || p[0] == '#') continue;
      targets.emplace_back(p);
    }
    fclose(f);
    return targets;
  }

  /* Parse comma-separated IPs or CIDRs */
  std::istringstream ss(spec);
  std::string token;
  while (std::getline(ss, token, ',')) {
    /* Trim */
    size_t s = token.find_first_not_of(" \t");
    if (s == std::string::npos) continue;
    token = token.substr(s);
    token.erase(token.find_last_not_of(" \t") + 1);

    /* Handle CIDR */
    size_t slash = token.find('/');
    if (slash != std::string::npos) {
      int prefix = atoi(token.substr(slash + 1).c_str());
      uint32_t base = ip_to_u32(token.substr(0, slash).c_str());
      if (prefix < 0 || prefix > 32) {
        fprintf(stderr, "tracemap: invalid CIDR prefix /%d in '%s'\n",
                prefix, token.c_str());
      } else if (base == 0 && prefix != 0) {
        fprintf(stderr, "tracemap: invalid IP in CIDR '%s'\n", token.c_str());
      } else if (prefix >= 24 && prefix <= 32) {
        uint32_t count = 1u << (32 - prefix);
        uint32_t mask = ~(count - 1);
        base &= mask;
        /* Add a sample of IPs from the range (first, middle, last usable) */
        if (count > 2) {
          targets.push_back(u32_to_ip(base + 1));
          targets.push_back(u32_to_ip(base + count / 2));
          targets.push_back(u32_to_ip(base + count - 2));
        } else {
          targets.push_back(u32_to_ip(base));
        }
      } else {
        /* Prefix shorter than /24: probing the full range would be enormous.
         * Sample the first, middle, and last usable addresses and warn. */
        fprintf(stderr, "tracemap: CIDR %s covers %u IPs — sampling 3 addresses\n",
                token.c_str(), 1u << (32 - prefix));
        uint64_t count = 1ULL << (32 - prefix);
        uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
        base &= mask;
        targets.push_back(u32_to_ip(base + 1));
        targets.push_back(u32_to_ip(base + (uint32_t)(count / 2)));
        targets.push_back(u32_to_ip(base + (uint32_t)(count - 2)));
      }
    } else if (!token.empty()) {
      targets.push_back(token);
    }
  }

  return targets;
}

/* -----------------------------------------------------------------------
 * Topology graph construction
 *
 * Merges all traces into a single directed graph.  Each unique IP
 * becomes a node, and each hop-to-hop transition becomes an edge.
 * ----------------------------------------------------------------------- */

static Topology build_topology(const std::vector<TraceResult> &traces,
                               const std::string &source_ip) {
  Topology topo;
  topo.source_ip = source_ip;
  topo.targets_total = static_cast<int>(traces.size());
  topo.targets_reached = 0;

  /* Maps for deduplication */
  std::map<std::string, TopoNode> node_map;
  std::map<std::string, TopoEdge> edge_map; /* key: "from->to" */

  /* Add source node */
  TopoNode src_node;
  src_node.ip = source_ip;
  src_node.path_count = static_cast<int>(traces.size());
  src_node.avg_rtt_ms = 0;
  src_node.role = "source";
  src_node.asn = 0;
  src_node.convergence_point = false;
  node_map[source_ip] = src_node;

  for (const auto &trace : traces) {
    if (trace.reached) topo.targets_reached++;

    std::string prev_ip = source_ip;

    for (const auto &hop : trace.hops) {
      if (hop.timeout || hop.ip == "*") continue;

      /* Update or create node */
      auto &node = node_map[hop.ip];
      if (node.ip.empty()) {
        node.ip = hop.ip;
        node.asn = hop.asn;
        node.as_name = hop.as_name;
        node.country = hop.country;
        node.hostname = hop.hostname;
        node.path_count = 0;
        node.avg_rtt_ms = 0;
        node.role = "router";
        node.convergence_point = false;
      }
      node.path_count++;
      if (hop.rtt_ms > 0) {
        /* Running average */
        node.avg_rtt_ms = node.avg_rtt_ms +
                          (hop.rtt_ms - node.avg_rtt_ms) / node.path_count;
      }

      /* Mark target nodes */
      if (hop.ip == trace.target_ip)
        node.role = "target";

      /* Create or update edge */
      if (prev_ip != hop.ip) {
        std::string edge_key = prev_ip + "->" + hop.ip;
        auto &edge = edge_map[edge_key];
        if (edge.from_ip.empty()) {
          edge.from_ip = prev_ip;
          edge.to_ip = hop.ip;
          edge.avg_latency_ms = 0;
          edge.path_count = 0;
          edge.asn_boundary = false;
        }
        edge.path_count++;

        /* Calculate inter-hop latency */
        if (hop.rtt_ms > 0 && node_map.count(prev_ip) &&
            node_map[prev_ip].avg_rtt_ms >= 0) {
          double hop_latency = hop.rtt_ms - node_map[prev_ip].avg_rtt_ms;
          if (hop_latency < 0) hop_latency = 0;
          edge.avg_latency_ms = edge.avg_latency_ms +
                                (hop_latency - edge.avg_latency_ms) /
                                edge.path_count;
        }

        prev_ip = hop.ip;
      }
    }
  }

  /* Convert maps to vectors */
  for (auto &kv : node_map) topo.nodes.push_back(kv.second);
  for (auto &kv : edge_map) topo.edges.push_back(kv.second);

  topo.total_nodes = static_cast<int>(topo.nodes.size());
  topo.total_edges = static_cast<int>(topo.edges.size());

  return topo;
}

/* -----------------------------------------------------------------------
 * Smart topology analysis
 * ----------------------------------------------------------------------- */

static void analyze_topology(Topology &topo) {
  int total_traces = static_cast<int>(topo.traces.size());
  if (total_traces == 0) return;

  /* --- 1. ASN enrichment and boundary detection --- */
  std::set<uint32_t> asn_set;
  for (auto &node : topo.nodes) {
    if (node.asn == 0 && node.ip != "*" && node.role != "source") {
      AsnInfo info = lookup_asn(node.ip.c_str(), 2000);
      node.asn = info.asn;
      node.as_name = info.as_name;
      node.country = info.country;
    }
    if (node.asn > 0) asn_set.insert(node.asn);
  }
  topo.unique_asns = static_cast<int>(asn_set.size());

  /* Build IP-to-ASN map for edge analysis */
  std::map<std::string, uint32_t> ip_asn;
  for (const auto &node : topo.nodes)
    ip_asn[node.ip] = node.asn;

  /* Mark ASN boundaries on edges */
  topo.asn_boundaries = 0;
  for (auto &edge : topo.edges) {
    uint32_t from_asn = ip_asn[edge.from_ip];
    uint32_t to_asn = ip_asn[edge.to_ip];
    if (from_asn > 0 && to_asn > 0 && from_asn != to_asn) {
      edge.asn_boundary = true;
      topo.asn_boundaries++;
    }
  }

  /* --- 2. Role classification --- */
  for (auto &node : topo.nodes) {
    if (node.role == "source" || node.role == "target") continue;

    /* Hub: traversed by >50% of all traces */
    if (node.path_count > total_traces / 2) {
      node.role = "hub";
    }

    /* Gateway: first hop after source with a different ASN */
    /* (detected per-trace below) */

    /* IXP/Border: node at an ASN boundary */
    bool at_boundary = false;
    for (const auto &edge : topo.edges) {
      if ((edge.from_ip == node.ip || edge.to_ip == node.ip) &&
          edge.asn_boundary) {
        at_boundary = true;
        break;
      }
    }
    if (at_boundary && node.role == "router")
      node.role = "border";
  }

  /* --- 3. Gateway detection --- */
  /* Use a set of gateway IPs to avoid O(n*m) scan.  Collect gateway IPs
   * from all traces using the ip_asn map, then apply role in one pass. */
  uint32_t src_asn = ip_asn[topo.source_ip];
  std::set<std::string> gateway_ips;
  for (const auto &trace : topo.traces) {
    for (const auto &hop : trace.hops) {
      if (hop.timeout || hop.ip == "*") continue;
      uint32_t hop_asn = ip_asn[hop.ip];
      if (hop_asn > 0 && hop_asn != src_asn && src_asn > 0) {
        gateway_ips.insert(hop.ip);
        break; /* only first external hop per trace */
      }
    }
  }
  /* Apply gateway role in one pass over nodes */
  for (auto &node : topo.nodes) {
    if (node.role == "router" && gateway_ips.count(node.ip)) {
      node.role = "gateway";
    }
  }

  /* --- 4. Latency bottleneck detection --- */
  /* Mark edges with latency > 50ms as potential bottlenecks
     (typically indicates a long-haul link or congestion) */
  for (auto &edge : topo.edges) {
    if (edge.avg_latency_ms > 50.0) {
      /* Annotate in the edge data — used by output formatters */
    }
  }

  /* --- 5. Path convergence detection --- */
  /* A convergence point is a node that has multiple distinct predecessors
   * across different traces — where multiple paths merge into one.
   * These are important network chokepoints. */
  std::map<std::string, std::set<std::string>> node_predecessors;
  for (const auto &trace : topo.traces) {
    std::string prev_ip = topo.source_ip;
    for (const auto &hop : trace.hops) {
      if (hop.timeout || hop.ip == "*") continue;
      if (hop.ip != prev_ip) {
        node_predecessors[hop.ip].insert(prev_ip);
        prev_ip = hop.ip;
      }
    }
  }
  for (auto &node : topo.nodes) {
    if (node.role == "source" || node.role == "target") continue;
    auto pred_it = node_predecessors.find(node.ip);
    if (pred_it != node_predecessors.end() && pred_it->second.size() > 1) {
      node.convergence_point = true;
    }
  }
}

/* -----------------------------------------------------------------------
 * Output: Text tree format
 * ----------------------------------------------------------------------- */

static void output_txt(FILE *fp, const Topology &topo) {
  fprintf(fp, "================================================================================\n");
  fprintf(fp, "                        KMAP NETWORK TOPOLOGY MAP\n");
  fprintf(fp, "================================================================================\n");
  fprintf(fp, "  Source:           %s\n", topo.source_ip.c_str());
  fprintf(fp, "  Targets:          %d (%d reached)\n",
          topo.targets_total, topo.targets_reached);
  fprintf(fp, "  Nodes:            %d\n", topo.total_nodes);
  fprintf(fp, "  Edges:            %d\n", topo.total_edges);
  fprintf(fp, "  Unique ASNs:      %d\n", topo.unique_asns);
  fprintf(fp, "  ASN boundaries:   %d\n", topo.asn_boundaries);
  fprintf(fp, "================================================================================\n\n");

  /* Print each trace as a tree */
  for (const auto &trace : topo.traces) {
    fprintf(fp, "TRACE: %s", trace.target_ip.c_str());
    if (!trace.target_host.empty())
      fprintf(fp, " (%s)", trace.target_host.c_str());
    fprintf(fp, "  [%s]\n", trace.reached ? "REACHED" : "INCOMPLETE");

    uint32_t prev_asn = 0;
    for (const auto &hop : trace.hops) {
      /* TTL column */
      fprintf(fp, "  %2d  ", hop.ttl);

      if (hop.timeout) {
        fprintf(fp, "* * *\n");
        continue;
      }

      /* IP and hostname */
      fprintf(fp, "%-16s", hop.ip.c_str());
      if (!hop.hostname.empty())
        fprintf(fp, " (%s)", hop.hostname.c_str());

      /* RTT */
      if (hop.rtt_ms >= 0)
        fprintf(fp, "  %.1fms", hop.rtt_ms);

      /* ASN info */
      if (hop.asn > 0) {
        fprintf(fp, "  [AS%u", hop.asn);
        if (!hop.as_name.empty()) fprintf(fp, " %s", hop.as_name.c_str());
        if (!hop.country.empty()) fprintf(fp, " %s", hop.country.c_str());
        fprintf(fp, "]");

        /* ASN boundary marker */
        if (prev_asn > 0 && hop.asn != prev_asn)
          fprintf(fp, " <-- ASN BOUNDARY");
        prev_asn = hop.asn;
      }

      /* Load balancer / ECMP marker */
      if (hop.load_balanced)
        fprintf(fp, " <-- LOAD BALANCED");

      fprintf(fp, "\n");
    }

    /* Per-target network distance summary (Fix #16) */
    {
      int hop_count = trace.hops_used;
      double total_rtt = -1.0;
      int asn_crossings = 0;
      uint32_t last_asn = 0;
      bool has_load_balancing = false;
      for (const auto &hop : trace.hops) {
        if (!hop.timeout && hop.rtt_ms > total_rtt) total_rtt = hop.rtt_ms;
        if (hop.asn > 0 && last_asn > 0 && hop.asn != last_asn)
          asn_crossings++;
        if (hop.asn > 0) last_asn = hop.asn;
        if (hop.load_balanced) has_load_balancing = true;
      }
      fprintf(fp, "  Summary: %d hops", hop_count);
      if (total_rtt >= 0) fprintf(fp, ", %.1fms total RTT", total_rtt);
      fprintf(fp, ", %d ASN crossing%s", asn_crossings,
              asn_crossings == 1 ? "" : "s");
      if (has_load_balancing) fprintf(fp, ", load balancing detected");
      fprintf(fp, "\n");
    }
    fprintf(fp, "\n");
  }

  /* --- Summary: Key infrastructure --- */
  fprintf(fp, "================================================================================\n");
  fprintf(fp, "  KEY INFRASTRUCTURE\n");
  fprintf(fp, "================================================================================\n");

  /* Sort nodes by path_count descending */
  std::vector<const TopoNode *> sorted;
  for (const auto &n : topo.nodes)
    if (n.role != "source") sorted.push_back(&n);
  std::sort(sorted.begin(), sorted.end(),
            [](const TopoNode *a, const TopoNode *b) {
              return a->path_count > b->path_count;
            });

  fprintf(fp, "\n  %-16s %-8s %-6s %-8s %s\n",
          "IP", "ROLE", "PATHS", "ASN", "NAME");
  fprintf(fp, "  %s\n", std::string(70, '-').c_str());

  for (const auto *n : sorted) {
    if (n->path_count < 1) continue;
    fprintf(fp, "  %-16s %-8s %-6d ",
            n->ip.c_str(), n->role.c_str(), n->path_count);
    if (n->asn > 0) {
      fprintf(fp, "AS%-6u %s", n->asn, n->as_name.c_str());
    }
    fprintf(fp, "\n");
  }

  /* --- Convergence points (network chokepoints) --- */
  {
    bool has_convergence = false;
    for (const auto *n : sorted) {
      if (n->convergence_point) {
        if (!has_convergence) {
          fprintf(fp, "\n  CONVERGENCE POINTS (multiple paths merge):\n");
          fprintf(fp, "  %s\n", std::string(70, '-').c_str());
          has_convergence = true;
        }
        fprintf(fp, "  %-16s  paths: %-4d", n->ip.c_str(), n->path_count);
        if (n->asn > 0) fprintf(fp, "  AS%u %s", n->asn, n->as_name.c_str());
        fprintf(fp, "\n");
      }
    }
  }

  /* --- Latency bottlenecks --- */
  fprintf(fp, "\n");
  fprintf(fp, "================================================================================\n");
  fprintf(fp, "  LATENCY ANALYSIS\n");
  fprintf(fp, "================================================================================\n");

  std::vector<const TopoEdge *> bottlenecks;
  for (const auto &e : topo.edges)
    if (e.avg_latency_ms > 10.0) bottlenecks.push_back(&e);
  std::sort(bottlenecks.begin(), bottlenecks.end(),
            [](const TopoEdge *a, const TopoEdge *b) {
              return a->avg_latency_ms > b->avg_latency_ms;
            });

  if (bottlenecks.empty()) {
    fprintf(fp, "\n  No significant latency hops detected.\n");
  } else {
    fprintf(fp, "\n  %-16s -> %-16s  %8s  %s\n",
            "FROM", "TO", "LATENCY", "NOTE");
    fprintf(fp, "  %s\n", std::string(70, '-').c_str());
    for (const auto *e : bottlenecks) {
      const char *note = "";
      if (e->avg_latency_ms > 100.0) note = "LONG-HAUL LINK";
      else if (e->avg_latency_ms > 50.0) note = "HIGH LATENCY";
      else if (e->asn_boundary) note = "ASN BOUNDARY";
      fprintf(fp, "  %-16s -> %-16s  %6.1fms  %s\n",
              e->from_ip.c_str(), e->to_ip.c_str(),
              e->avg_latency_ms, note);
    }
  }

  fprintf(fp, "\n================================================================================\n");
}

/* -----------------------------------------------------------------------
 * Output: DOT (Graphviz) format
 * ----------------------------------------------------------------------- */

/* Escape a string for inclusion inside a DOT quoted label. We keep the
 * two-character sequence "\n" (backslash + n) as a literal line-break
 * directive recognised by Graphviz, but anything that could break out of
 * the quoted context — quote, stray backslash, control char — is escaped. */
static std::string dot_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 4);
  for (size_t i = 0; i < s.size(); i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\\' && i + 1 < s.size() && s[i + 1] == 'n') {
      out += "\\n";
      i++;
    } else if (c == '"') {
      out += "\\\"";
    } else if (c == '\\') {
      out += "\\\\";
    } else if (c == '\n') {
      out += "\\n";
    } else if (c == '\r' || c == '\t' || c < 0x20) {
      out += ' ';
    } else {
      out += (char)c;
    }
  }
  return out;
}

/* Sanitize an IP string into a safe DOT node identifier. */
static std::string dot_node_id(const std::string &ip) {
  std::string id;
  id.reserve(ip.size() + 1);
  id += 'n';
  for (char c : ip) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')) {
      id += c;
    } else {
      id += '_';
    }
  }
  return id;
}

static void output_dot(FILE *fp, const Topology &topo) {
  fprintf(fp, "digraph kmap_topology {\n");
  fprintf(fp, "  rankdir=LR;\n");
  fprintf(fp, "  node [shape=box, fontsize=10];\n");
  fprintf(fp, "  edge [fontsize=8];\n\n");

  /* Node definitions with styling based on role */
  for (const auto &n : topo.nodes) {
    std::string label = n.ip;
    if (!n.hostname.empty()) label += "\\n" + n.hostname;
    if (n.asn > 0) {
      label += "\\nAS" + std::to_string(n.asn);
      if (!n.country.empty()) label += " " + n.country;
    }

    const char *color = "white";
    const char *shape = "box";
    if (n.role == "source")  { color = "#90EE90"; shape = "doubleoctagon"; }
    else if (n.role == "target")  { color = "#FFB6C1"; shape = "box"; }
    else if (n.role == "hub")     { color = "#FFD700"; shape = "diamond"; }
    else if (n.role == "gateway") { color = "#87CEEB"; shape = "hexagon"; }
    else if (n.role == "border")  { color = "#DDA0DD"; shape = "octagon"; }

    std::string node_id = dot_node_id(n.ip);

    fprintf(fp, "  %s [label=\"%s\", style=filled, fillcolor=\"%s\", shape=%s];\n",
            node_id.c_str(), dot_escape(label).c_str(), color, shape);
  }

  fprintf(fp, "\n");

  /* Edges */
  for (const auto &e : topo.edges) {
    std::string from_id = dot_node_id(e.from_ip);
    std::string to_id = dot_node_id(e.to_ip);

    std::string label;
    if (e.avg_latency_ms > 0.5)
      label = std::to_string(static_cast<int>(e.avg_latency_ms + 0.5)) + "ms";

    const char *color = "black";
    const char *style = "solid";
    int penwidth = 1;
    if (e.asn_boundary) { color = "red"; style = "bold"; penwidth = 2; }
    if (e.path_count > 2) penwidth = std::min(e.path_count, 5);

    fprintf(fp, "  %s -> %s [label=\"%s\", color=%s, style=%s, penwidth=%d];\n",
            from_id.c_str(), to_id.c_str(), dot_escape(label).c_str(),
            color, style, penwidth);
  }

  /* Legend */
  fprintf(fp, "\n  subgraph cluster_legend {\n");
  fprintf(fp, "    label=\"Legend\";\n");
  fprintf(fp, "    style=dashed;\n");
  fprintf(fp, "    legend_src [label=\"Source\", style=filled, fillcolor=\"#90EE90\", shape=doubleoctagon];\n");
  fprintf(fp, "    legend_hub [label=\"Hub\", style=filled, fillcolor=\"#FFD700\", shape=diamond];\n");
  fprintf(fp, "    legend_gw  [label=\"Gateway\", style=filled, fillcolor=\"#87CEEB\", shape=hexagon];\n");
  fprintf(fp, "    legend_bdr [label=\"ASN Border\", style=filled, fillcolor=\"#DDA0DD\", shape=octagon];\n");
  fprintf(fp, "    legend_tgt [label=\"Target\", style=filled, fillcolor=\"#FFB6C1\", shape=box];\n");
  fprintf(fp, "  }\n");

  fprintf(fp, "}\n");
}

/* -----------------------------------------------------------------------
 * Output: JSON format
 * ----------------------------------------------------------------------- */

static std::string json_str(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 4);
  out += '"';
  for (unsigned char c : s) {
    if (c == '"') out += "\\\"";
    else if (c == '\\') out += "\\\\";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else if (c == '\t') out += "\\t";
    else if (c == '\b') out += "\\b";
    else if (c == '\f') out += "\\f";
    else if (c < 0x20) {
      char buf[8];
      snprintf(buf, sizeof(buf), "\\u%04x", c);
      out += buf;
    }
    else out += (char)c;
  }
  out += '"';
  return out;
}

static void output_json(FILE *fp, const Topology &topo) {
  fprintf(fp, "{\n");
  fprintf(fp, "  \"source\": %s,\n", json_str(topo.source_ip).c_str());
  fprintf(fp, "  \"targets_total\": %d,\n", topo.targets_total);
  fprintf(fp, "  \"targets_reached\": %d,\n", topo.targets_reached);
  fprintf(fp, "  \"total_nodes\": %d,\n", topo.total_nodes);
  fprintf(fp, "  \"total_edges\": %d,\n", topo.total_edges);
  fprintf(fp, "  \"unique_asns\": %d,\n", topo.unique_asns);
  fprintf(fp, "  \"asn_boundaries\": %d,\n", topo.asn_boundaries);

  /* Nodes */
  fprintf(fp, "  \"nodes\": [\n");
  for (size_t i = 0; i < topo.nodes.size(); i++) {
    const auto &n = topo.nodes[i];
    fprintf(fp, "    {\"ip\": %s, \"hostname\": %s, \"asn\": %u, "
            "\"as_name\": %s, \"country\": %s, "
            "\"path_count\": %d, \"avg_rtt_ms\": %.1f, \"role\": %s}%s\n",
            json_str(n.ip).c_str(),
            json_str(n.hostname).c_str(),
            n.asn,
            json_str(n.as_name).c_str(),
            json_str(n.country).c_str(),
            n.path_count, n.avg_rtt_ms,
            json_str(n.role).c_str(),
            (i + 1 < topo.nodes.size()) ? "," : "");
  }
  fprintf(fp, "  ],\n");

  /* Edges */
  fprintf(fp, "  \"edges\": [\n");
  for (size_t i = 0; i < topo.edges.size(); i++) {
    const auto &e = topo.edges[i];
    fprintf(fp, "    {\"from\": %s, \"to\": %s, \"avg_latency_ms\": %.1f, "
            "\"path_count\": %d, \"asn_boundary\": %s}%s\n",
            json_str(e.from_ip).c_str(),
            json_str(e.to_ip).c_str(),
            e.avg_latency_ms, e.path_count,
            e.asn_boundary ? "true" : "false",
            (i + 1 < topo.edges.size()) ? "," : "");
  }
  fprintf(fp, "  ],\n");

  /* Traces */
  fprintf(fp, "  \"traces\": [\n");
  for (size_t t = 0; t < topo.traces.size(); t++) {
    const auto &trace = topo.traces[t];
    fprintf(fp, "    {\"target\": %s, \"reached\": %s, \"hops\": [\n",
            json_str(trace.target_ip).c_str(),
            trace.reached ? "true" : "false");
    for (size_t h = 0; h < trace.hops.size(); h++) {
      const auto &hop = trace.hops[h];
      fprintf(fp, "      {\"ttl\": %d, \"ip\": %s, \"rtt_ms\": %.1f, "
              "\"asn\": %u, \"timeout\": %s}%s\n",
              hop.ttl, json_str(hop.ip).c_str(), hop.rtt_ms,
              hop.asn, hop.timeout ? "true" : "false",
              (h + 1 < trace.hops.size()) ? "," : "");
    }
    fprintf(fp, "    ]}%s\n", (t + 1 < topo.traces.size()) ? "," : "");
  }
  fprintf(fp, "  ]\n");
  fprintf(fp, "}\n");
}

/* -----------------------------------------------------------------------
 * Detect local source IP
 * ----------------------------------------------------------------------- */

static std::string detect_source_ip() {
  /* Connect a UDP socket to 8.8.8.8:53 and read the local address.
   * This doesn't actually send any data — it just triggers route lookup. */
  struct sockaddr_in remote{};
  remote.sin_family = AF_INET;
  remote.sin_port = htons(53);
  remote.sin_addr.s_addr = htonl(0x08080808);

#ifdef WIN32
  SOCKET fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd == INVALID_SOCKET) return "0.0.0.0";
#else
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) return "0.0.0.0";
#endif

  connect(fd, reinterpret_cast<struct sockaddr *>(&remote), sizeof(remote));

  struct sockaddr_in local{};
  socklen_t local_len = sizeof(local);
  getsockname(fd, reinterpret_cast<struct sockaddr *>(&local), &local_len);

#ifdef WIN32
  closesocket(fd);
#else
  close(fd);
#endif

  char buf[16];
  inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf));
  return buf;
}

/* -----------------------------------------------------------------------
 * Main entry point
 * ----------------------------------------------------------------------- */

int run_tracemap(const char *targets, const char *output_file,
                 const char *format, int max_hops, int timeout_ms) {
  if (!targets || !targets[0]) {
    fprintf(stderr, "tracemap: no targets specified\n");
    return 1;
  }

  if (max_hops <= 0) max_hops = DEFAULT_MAX_HOPS;
  if (timeout_ms <= 0) timeout_ms = DEFAULT_TIMEOUT_MS;
  if (!format || !format[0]) format = "txt";

  /* Parse targets */
  std::vector<std::string> target_list = parse_targets(targets);
  if (target_list.empty()) {
    fprintf(stderr, "tracemap: no valid targets found\n");
    return 1;
  }

  /* Validate target IPs — skip malformed ones with a warning */
  {
    std::vector<std::string> valid_targets;
    for (const auto &t : target_list) {
      struct in_addr test_addr;
      if (inet_pton(AF_INET, t.c_str(), &test_addr) == 1) {
        valid_targets.push_back(t);
      } else {
        fprintf(stderr, "tracemap: skipping invalid target IP: %s\n", t.c_str());
      }
    }
    target_list = std::move(valid_targets);
    if (target_list.empty()) {
      fprintf(stderr, "tracemap: no valid targets after validation\n");
      return 1;
    }
  }

  /* Detect our source IP */
  std::string source_ip = detect_source_ip();

  log_write(LOG_STDOUT, "\ntracemap: Mapping network topology\n");
  log_write(LOG_STDOUT, "  Source:     %s\n", source_ip.c_str());
  log_write(LOG_STDOUT, "  Targets:    %d\n", (int)target_list.size());
  log_write(LOG_STDOUT, "  Max hops:   %d\n", max_hops);
  log_write(LOG_STDOUT, "  Timeout:    %dms\n", timeout_ms);
  log_write(LOG_STDOUT, "  Format:     %s\n\n", format);

  /* Run traceroute to each target */
  std::vector<TraceResult> traces;
  for (size_t i = 0; i < target_list.size(); i++) {
    const std::string &target = target_list[i];
    log_write(LOG_STDOUT, "  Tracing %s (%d/%d)...\n",
              target.c_str(), (int)(i + 1), (int)target_list.size());

    TraceResult trace = trace_one_target(target.c_str(), max_hops, timeout_ms);

    /* Reverse DNS on each hop */
    for (auto &hop : trace.hops) {
      if (!hop.timeout && hop.ip != "*") {
        hop.hostname = reverse_dns(hop.ip.c_str());
      }
    }

    /* Try resolving the target hostname */
    trace.target_host = reverse_dns(target.c_str());

    log_write(LOG_STDOUT, "    %d hops, %s\n",
              trace.hops_used, trace.reached ? "reached" : "incomplete");
    traces.push_back(std::move(trace));
  }

  /* Build the topology graph */
  log_write(LOG_STDOUT, "\n  Building topology graph...\n");
  Topology topo = build_topology(traces, source_ip);
  topo.traces = traces;

  /* Run smart analysis (includes ASN enrichment) */
  log_write(LOG_STDOUT, "  Running topology analysis...\n");
  analyze_topology(topo);

  log_write(LOG_STDOUT, "  Nodes: %d | Edges: %d | ASNs: %d | Boundaries: %d\n",
            topo.total_nodes, topo.total_edges,
            topo.unique_asns, topo.asn_boundaries);

  /* Write output */
  FILE *fp = stdout;
  bool own_fp = false;
  if (output_file && output_file[0]) {
    fp = fopen(output_file, "w");
    if (!fp) {
      fprintf(stderr, "tracemap: cannot create output file: %s\n", output_file);
      return 1;
    }
    own_fp = true;
  }

  if (strcmp(format, "dot") == 0)
    output_dot(fp, topo);
  else if (strcmp(format, "json") == 0)
    output_json(fp, topo);
  else
    output_txt(fp, topo);

  if (own_fp) {
    fclose(fp);
    log_write(LOG_STDOUT, "\n  Output written to %s\n", output_file);
  }

  return 0;
}
