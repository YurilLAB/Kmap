// Exercise the production watchlist expansion without making any connections.
#include "watchlist_targets.h"
#include <cstdio>

static int checks = 0, failures = 0;
#define CHECK(value) do { ++checks; if (!(value)) { ++failures; \
  std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #value); } } while (0)

int main() {
  const uint32_t sentinel = 0x7f000001;
  for (const char *invalid : {"not-an-ip/32", "127.0.0.999/24", "/16",
                            "127.0.0/31", "127.0.0.1junk/32"}) {
    std::vector<uint32_t> targets{sentinel};
    CHECK(watchlist_expand_target(invalid, targets) == WatchlistTargetStatus::InvalidAddress);
    CHECK(targets == std::vector<uint32_t>{sentinel});
  }
  for (const char *invalid : {"127.0.0.1/", "127.0.0.1/x", "127.0.0.1/33",
                            "127.0.0.1/-1", "127.0.0.1/24/32"}) {
    std::vector<uint32_t> targets{sentinel};
    CHECK(watchlist_expand_target(invalid, targets) == WatchlistTargetStatus::InvalidPrefix);
    CHECK(targets == std::vector<uint32_t>{sentinel});
  }
  std::vector<uint32_t> targets;
  CHECK(watchlist_expand_target("127.0.0.1", targets) == WatchlistTargetStatus::Added);
  CHECK(targets == std::vector<uint32_t>{sentinel});
  targets.clear();
  CHECK(watchlist_expand_target("127.0.0.7/30", targets) == WatchlistTargetStatus::Added);
  CHECK(targets == (std::vector<uint32_t>{0x7f000005, 0x7f000006}));
  targets.clear();
  CHECK(watchlist_expand_target("127.0.0.7/31", targets) == WatchlistTargetStatus::Added);
  CHECK(targets == (std::vector<uint32_t>{0x7f000006, 0x7f000007}));
  targets.clear();
  CHECK(watchlist_expand_target("127.0.0.7/32", targets) == WatchlistTargetStatus::Added);
  CHECK(targets == std::vector<uint32_t>{0x7f000007});
  targets.clear();
  CHECK(watchlist_expand_target("127.0.1.7/16", targets) == WatchlistTargetStatus::Added);
  CHECK(targets.size() == 65534 && targets.front() == sentinel && targets.back() == 0x7f00fffe);
  targets.clear();
  CHECK(watchlist_expand_target("127.0.0.1/15", targets) == WatchlistTargetStatus::TooLarge);
  CHECK(targets.empty());
  std::printf("watchlist targets: checks=%d failures=%d\n", checks, failures);
  return failures ? 1 : 0;
}
