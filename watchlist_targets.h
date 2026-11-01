#ifndef KMAP_WATCHLIST_TARGETS_H
#define KMAP_WATCHLIST_TARGETS_H

#include "net_db.h"
#include <cstdlib>

enum class WatchlistTargetStatus { Added, InvalidAddress, InvalidPrefix, TooLarge };

// The caller trims whitespace and removes comments. Invalid entries must never
// turn into a different address range, and must leave the target list intact.
static inline WatchlistTargetStatus watchlist_expand_target(
    const std::string &line, std::vector<uint32_t> &targets) {
  const size_t slash = line.find('/');
  if (slash == std::string::npos) {
    const uint32_t ip = ip_to_u32(line.c_str());
    if (ip == 0) return WatchlistTargetStatus::InvalidAddress;
    targets.push_back(ip);
    return WatchlistTargetStatus::Added;
  }
  const std::string token = line.substr(slash + 1);
  char *end = nullptr;
  const long prefix = std::strtol(token.c_str(), &end, 10);
  if (token.empty() || end == token.c_str() || *end || prefix < 0 || prefix > 32)
    return WatchlistTargetStatus::InvalidPrefix;
  const std::string host = line.substr(0, slash);
  uint32_t base = ip_to_u32(host.c_str());
  // ip_to_u32 returns zero on failure. Check before masking or expansion:
  // malformed hosts must not become probes for 0.0.0.0 or its neighbours.
  if (base == 0 && host != "0.0.0.0")
    return WatchlistTargetStatus::InvalidAddress;
  if (prefix < 16) return WatchlistTargetStatus::TooLarge;
  const uint32_t count = 1u << (32 - prefix);
  base &= ~(count - 1);
  const uint32_t first = prefix <= 30 ? 1 : 0;
  const uint32_t last = prefix <= 30 ? count - 1 : count;
  for (uint32_t i = first; i < last; ++i) targets.push_back(base + i);
  return WatchlistTargetStatus::Added;
}

#endif
