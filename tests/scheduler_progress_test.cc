/* Deterministic offline schedule: snapshot while both workers are alive.
 * Includes the production coordination helper; no scanner/socket code. */
#ifndef KMAP_PROGRESS_HEADER
#define KMAP_PROGRESS_HEADER "../work_progress.h"
#endif
#include KMAP_PROGRESS_HEADER
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <exception>
#include <mutex>
#include <thread>

struct Gate {
  std::mutex mutex;
  std::condition_variable changed;
  bool claimed = false, peer_done = false, allow_publish = false;
  bool published = false, allow_complete = false, release_peer = false;
  bool wait(bool &flag) {
    std::unique_lock<std::mutex> lock(mutex);
    return changed.wait_for(lock, std::chrono::seconds(3), [&] { return flag; });
  }
  void set(bool &flag) {
    std::lock_guard<std::mutex> lock(mutex);
    flag = true;
    changed.notify_all();
  }
};

static int claim_gap(uint64_t initial, unsigned prefix) {
  const uint64_t begin = initial + prefix, end = begin + 32;
  std::atomic<uint64_t> next{initial};
  KmapWorkProgress progress(next, initial, end, 2);
  for (unsigned i = 0; i < prefix; ++i) {
    uint64_t index = end;
    if (!progress.claim(0, index) || index != initial + i) return 1;
    progress.complete(0);
  }
  Gate gate;
  std::atomic<int> errors{0};
  std::atomic<uint64_t> unfinished{end};
  std::atomic<unsigned> completed{0};
  std::thread delayed([&] {
    try {
      uint64_t index = end;
      bool claimed = progress.claim(0, index, [&](uint64_t value) {
        unfinished.store(value);
        gate.set(gate.claimed);
        if (!gate.wait(gate.allow_publish)) throw std::runtime_error("publish barrier timed out");
      });
      if (!claimed || index != begin) ++errors;
      gate.set(gate.published);
      if (!gate.wait(gate.allow_complete)) throw std::runtime_error("completion barrier timed out");
      progress.complete(0);
      ++completed;
    } catch (...) { ++errors; }
  });
  if (!gate.wait(gate.claimed)) ++errors;
  std::thread peer([&] {
    try {
      for (uint64_t expected = begin + 1; expected < end; ++expected) {
        uint64_t index = end;
        if (!progress.claim(1, index) || index != expected) ++errors;
        progress.complete(1);
        ++completed;
      }
      gate.set(gate.peer_done);
      if (!gate.wait(gate.release_peer)) throw std::runtime_error("peer barrier timed out");
    } catch (...) { ++errors; }
  });
  if (!gate.wait(gate.peer_done)) ++errors;

  // Neither thread has been joined; the first holds a claimed but not yet
  // published index, while the peer completed 31 later offline jobs.
  const uint64_t gap_low_water = progress.low_water();
  const uint64_t pending = unfinished.load();
  const bool gap_safe = gap_low_water <= pending;
  if (!gap_safe || completed.load() != end - begin - 1) ++errors;
  if (prefix && gap_low_water != pending) ++errors;
  std::printf("claim gap: next=%llu unfinished=%llu checkpoint=%llu peer_completed=%u completed_prefix=%u snapshot_before_join=true safe=%s\n",
      (unsigned long long)next.load(), (unsigned long long)pending,
      (unsigned long long)gap_low_water, completed.load(), prefix, gap_safe ? "true" : "false");

  gate.set(gate.allow_publish);
  if (!gate.wait(gate.published)) ++errors;
  if (progress.low_water() > pending) ++errors;
  gate.set(gate.allow_complete);
  gate.set(gate.release_peer);
  delayed.join();
  peer.join();
  if (completed.load() != end - begin) ++errors;
  return errors.load();
}

int main() {
  int errors = claim_gap(100, 0) + claim_gap(500, 16);

  // Abandonment retains the pending index; a resumed nonzero range never
  // accidentally rewinds before its own beginning.
  std::atomic<uint64_t> cancelled_next{500};
  KmapWorkProgress cancelled(cancelled_next, 500, 504, 1);
  uint64_t cancelled_index = 0;
  if (!cancelled.claim(0, cancelled_index) || cancelled.low_water() > cancelled_index) ++errors;
  cancelled.complete(0);
  while (cancelled.claim(0, cancelled_index)) cancelled.complete(0);

  std::printf("scheduler progress: %d failure(s)\n", errors);
  return errors ? 1 : 0;
}
