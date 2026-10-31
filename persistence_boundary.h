#ifndef KMAP_PERSISTENCE_BOUNDARY_H
#define KMAP_PERSISTENCE_BOUNDARY_H

#include <atomic>
#include <cstddef>

// An error is sticky for the lifetime of this run. The same flag also lets
// producers stop cooperatively before their storage handles are closed.
class KmapPersistenceState {
  std::atomic<bool> failed_{false};
public:
  bool failed() const noexcept { return failed_.load(); }
  bool fail() noexcept { return !failed_.exchange(true); }
};

// The caller serializes writers across this whole boundary. A checkpoint may
// advance only after every commit and (for periodic boundaries) reopen succeeds.
// Shards already committed before another fails cannot be rolled back; leaving
// the old checkpoint allows replay instead of silently skipping missing data.
template<class Commit, class Begin, class Save>
bool kmap_persistence_boundary(KmapPersistenceState &state, size_t shards,
                               bool reopen, Commit commit, Begin begin,
                               Save save) {
  if (state.failed()) return false;
  for (size_t i = 0; i < shards; ++i) {
    if (state.failed()) return false;
    if (!commit(i)) { state.fail(); return false; }
  }
  if (reopen) {
    for (size_t i = 0; i < shards; ++i) {
      if (state.failed()) return false;
      if (!begin(i)) { state.fail(); return false; }
    }
  }
  if (state.failed()) return false;
  if (!save()) { state.fail(); return false; }
  return true;
}

#endif
