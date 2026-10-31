/* Checkpoint-safe ownership of bounded integer work items. No I/O. */
#ifndef KMAP_WORK_PROGRESS_H
#define KMAP_WORK_PROGRESS_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

class KmapWorkProgress {
  static constexpr uint64_t none = std::numeric_limits<uint64_t>::max();
  std::atomic<uint64_t> &next_;
  const uint64_t end_;
  std::vector<std::atomic<uint64_t>> inflight_;

  struct NoPause { void operator()(uint64_t) const {} };

public:
  KmapWorkProgress(std::atomic<uint64_t> &next, uint64_t begin,
                   uint64_t end, size_t workers)
      : next_(next), end_(end), inflight_(workers) {
    // A worker stops after its first out-of-range claim. Reserve room for
    // those final claims as well as the idle sentinel.
    if (!workers || begin > end || workers >= none ||
        end > none - workers || next.load() != begin)
      throw std::invalid_argument("invalid bounded work progress range");
    for (auto &slot : inflight_) slot.store(none, std::memory_order_relaxed);
  }

  // after_claim is a scheduling seam for offline tests; production uses the
  // no-op default. A throwing/abandoned claim remains conservatively pending.
  // Contract: only this helper increments next_; each stable worker slot has
  // one owner, is completed before another claim, and stops after false.
  template<class AfterClaim = NoPause>
  bool claim(size_t worker, uint64_t &index, AfterClaim after_claim = AfterClaim()) {
    // Reserve a conservative bound BEFORE incrementing the claim counter.
    // Other workers may advance next_ in this gap, so reservation <= claimed.
    const uint64_t reservation = next_.load();
    inflight_.at(worker).store(reservation);
    const uint64_t claimed = next_.fetch_add(1);
    if (claimed >= end_) {
      inflight_[worker].store(none);
      return false;
    }
    after_claim(claimed);
    inflight_[worker].store(claimed);
    index = claimed;
    return true;
  }

  // Call only after the item is fully handled. Cancellation/failure must
  // leave the slot pending so a checkpoint never skips that item.
  void complete(size_t worker) { inflight_.at(worker).store(none); }

  uint64_t low_water() const {
    const uint64_t next = next_.load();
    uint64_t low = next < end_ ? next : end_;
    for (const auto &slot : inflight_) {
      const uint64_t value = slot.load();
      if (value != none && value < low) low = value;
    }
    return low;
  }

  // All live coordination operations are sequentially consistent: if a
  // snapshot observes a claim's counter increment, its later slot load sees
  // either the reservation, published index, or completed/later work. A claim
  // after the counter snapshot has index >= that snapshot and cannot be lost.
  // A preempted reservation can conservatively replay completed work, but
  // does not routinely rewind an active slice to its original beginning.
};

#endif
