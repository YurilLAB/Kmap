/*
 * fast_syn.h -- High-speed asynchronous SYN scanner for Kmap net-scan.
 *
 * Sends TCP SYN packets at a configurable rate across the IPv4 space
 * (or a target list) and records hosts that respond with SYN-ACK.
 * Uses libpcap for raw packet capture and Kmap's existing raw socket
 * infrastructure for packet transmission.
 *
 * Design:
 *   - TX loop sends SYN packets at --rate pps using a token bucket
 *   - RX runs via pcap capturing SYN-ACK responses
 *   - IP iteration uses a multiplicative-inverse permutation for
 *     randomized scanning order (avoids sequential sweeps)
 *   - Exclusion ranges are checked before each packet is sent
 *   - Results written directly to shard SQLite databases
 */

#ifndef FAST_SYN_H
#define FAST_SYN_H

#include <cstdint>
#include <string>
#include <vector>

/* Exclusion range (network + mask in host byte order) */
struct ExcludeRange {
  uint32_t network;
  uint32_t mask;
};

/* Load exclusion ranges from a file.  Lines: "10.0.0.0/8", "#" comments. */
std::vector<ExcludeRange> load_exclude_list(const char *path);

/* Load the built-in hard-coded exclusion ranges. */
std::vector<ExcludeRange> builtin_excludes();

/* Check if an IP (host byte order) falls in any exclusion range. */
bool is_excluded(uint32_t ip, const std::vector<ExcludeRange> &excludes);

/* Run the fast SYN discovery scan.
   - data_dir:     directory for shard databases
   - ports:        list of TCP ports to scan
   - rate_pps:     packets per second
   - excludes:     combined exclusion list
   - resume:       if true, resume from checkpoint
   - max_ips:      cap the iteration at this many IPs from the current
                   checkpoint index (0 = scan the full IPv4 space).
                   Wires `--net-max-ips N` so an operator can do a
                   bounded sample scan without committing to a full
                   internet sweep.  Excluded IPs (RFC1918, multicast,
                   loopback, etc.) still count toward the cap because
                   the cap measures iteration progress, not probe count;
                   at any realistic sample size the excluded-ratio is
                   noise.
   Returns 0 on success, 1 on error. */
/* target_base / target_count bound the sweep to a single contiguous IPv4 range
   (a CIDR): target_base is the masked network address (host order) and
   target_count is the number of addresses (a power of two, = 2^(32-prefix)).
   When target_count is 0 the scan covers the full IPv4 space (the internet
   sweep).  A bounded scan walks its range sequentially; the randomized
   permutation is only used for the full-space sweep where ordering matters for
   politeness. */
int fast_syn_scan(const char *data_dir,
                  const std::vector<int> &ports,
                  int rate_pps,
                  const std::vector<ExcludeRange> &excludes,
                  bool resume,
                  uint64_t max_ips = 0,
                  uint32_t target_base = 0,
                  uint64_t target_count = 0);

/* Parse a port specification string like "22,80,443" or "1-1024".
   Returns sorted, deduplicated list of port numbers. */
std::vector<int> parse_port_spec(const char *spec);

#endif /* FAST_SYN_H */
