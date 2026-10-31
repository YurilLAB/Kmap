#ifndef KMAP_SCAN_CHECKPOINT_H
#define KMAP_SCAN_CHECKPOINT_H

// The five-line checkpoint format, shared by production and offline tests.
// A single writer owns this path. File replacement protects against process
// interruption; fflush/close do not promise durability across power loss.
#include <cstdio>
#include <cstdint>
#include <ctime>
#include <limits>
#include <string>
#include <cerrno>
#include <sys/stat.h>

#if defined(_WIN32) || defined(WIN32)
// Avoid importing the legacy Winsock header before the scanner's winsock2.h.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#define KMAP_CHECKPOINT_UNDEF_LEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#define KMAP_CHECKPOINT_UNDEF_NOMINMAX
#endif
#include <windows.h>
#ifdef KMAP_CHECKPOINT_UNDEF_LEAN
#undef WIN32_LEAN_AND_MEAN
#undef KMAP_CHECKPOINT_UNDEF_LEAN
#endif
#ifdef KMAP_CHECKPOINT_UNDEF_NOMINMAX
#undef NOMINMAX
#undef KMAP_CHECKPOINT_UNDEF_NOMINMAX
#endif
#endif

struct ScanCheckpoint {
  uint64_t next_index;
  uint64_t packets_sent;
  uint64_t hosts_found;
  uint64_t seed;
  time_t last_save;
};

static inline std::string checkpoint_path(const char *data_dir) {
  return std::string(data_dir) + "/.net-scan-checkpoint";
}

namespace checkpoint_detail {

// Bound every field before converting it. A final newline is part of the
// written format: otherwise a torn timestamp prefix could look valid.
static inline bool read_line(FILE *f, std::string &line) {
  line.clear();
  int c;
  while ((c = std::fgetc(f)) != '\n') {
    if (c == EOF || line.size() == 23) return false;
    line.push_back(static_cast<char>(c));
  }
  if (!line.empty() && line.back() == '\r') line.pop_back();
  return !line.empty();
}

static inline bool decimal(const std::string &line, uint64_t &value,
                           size_t first = 0) {
  if (first == line.size()) return false;
  uint64_t result = 0;
  for (size_t i = first; i < line.size(); ++i) {
    if (line[i] < '0' || line[i] > '9') return false;
    const unsigned digit = static_cast<unsigned>(line[i] - '0');
    if (result > (UINT64_MAX - digit) / 10) return false;
    result = result * 10 + digit;
  }
  value = result;
  return true;
}

static inline bool timestamp(const std::string &line, time_t &value) {
  static_assert(sizeof(time_t) <= sizeof(uint64_t), "unsupported time_t width");
  const bool negative = !line.empty() && line[0] == '-';
  uint64_t magnitude;
  if (!decimal(line, magnitude, negative ? 1 : 0)) return false;
  if (negative) {
    if (!std::numeric_limits<time_t>::is_signed) return false;
    const time_t minimum = (std::numeric_limits<time_t>::min)();
    const uint64_t limit = static_cast<uint64_t>(-(minimum + 1)) + 1;
    if (magnitude > limit) return false;
    value = magnitude == limit ? minimum
                              : static_cast<time_t>(-static_cast<int64_t>(magnitude));
  } else {
    if (magnitude > static_cast<uint64_t>((std::numeric_limits<time_t>::max)()))
      return false;
    value = static_cast<time_t>(magnitude);
  }
  return true;
}

static inline bool read_file(const std::string &path, ScanCheckpoint &cp) {
  FILE *f = std::fopen(path.c_str(), "rb");
  if (!f) return false;
  ScanCheckpoint parsed{};
  std::string line;
  bool ok = read_line(f, line) && decimal(line, parsed.next_index)
         && read_line(f, line) && decimal(line, parsed.packets_sent)
         && read_line(f, line) && decimal(line, parsed.hosts_found)
         && read_line(f, line) && decimal(line, parsed.seed)
         && read_line(f, line) && timestamp(line, parsed.last_save);
  if (ok) ok = std::fgetc(f) == EOF && !std::ferror(f);
  if (std::fclose(f) != 0) ok = false;
  if (ok) cp = parsed; // A failed load must not partially change caller state.
  return ok;
}

struct FileOps {
  FILE *open(const char *path) { return std::fopen(path, "w"); }
  int write(FILE *f, const ScanCheckpoint &cp) {
    return std::fprintf(f, "%llu\n%llu\n%llu\n%llu\n%lld\n",
        static_cast<unsigned long long>(cp.next_index),
        static_cast<unsigned long long>(cp.packets_sent),
        static_cast<unsigned long long>(cp.hosts_found),
        static_cast<unsigned long long>(cp.seed),
        static_cast<long long>(cp.last_save));
  }
  int flush(FILE *f) { return std::fflush(f); }
  int close(FILE *f) { return std::fclose(f); }
  int remove(const char *path) { return std::remove(path); }
  int replace(const char *from, const char *to) {
#if defined(_WIN32) || defined(WIN32)
    // rename() cannot replace an existing file on Windows. Do not delete the
    // destination first: a failed move must leave the old checkpoint intact.
    return MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
#else
    return std::rename(from, to);
#endif
  }
};

// The same save implementation runs with real operations in production and
// deterministic I/O failures in tests; no scanner or network dependency.
template <typename Ops>
static bool save(const char *data_dir, const ScanCheckpoint &cp, Ops &ops) {
  const std::string path = checkpoint_path(data_dir);
  const std::string tmp = path + ".tmp";
  ScanCheckpoint previous{};
  // A surviving .tmp can be the only complete checkpoint after interruption.
  // Preserve it as the main file before opening .tmp with truncation again.
  if (!read_file(path, previous) && read_file(tmp, previous)
      && ops.replace(tmp.c_str(), path.c_str()) != 0)
    return false;

  FILE *f = ops.open(tmp.c_str());
  if (!f) return false;
  const bool wrote = ops.write(f, cp) >= 0 && ops.flush(f) == 0;
  const bool closed = ops.close(f) == 0;
  if (!wrote || !closed) {
    ops.remove(tmp.c_str());
    return false;
  }
  // Keep a complete .tmp on replacement failure so a first-ever checkpoint
  // remains recoverable too. A valid main file always has priority on load.
  return ops.replace(tmp.c_str(), path.c_str()) == 0;
}

} // namespace checkpoint_detail

static inline bool save_checkpoint(const char *data_dir, const ScanCheckpoint &cp) {
  checkpoint_detail::FileOps ops;
  return checkpoint_detail::save(data_dir, cp, ops);
}

static inline bool load_checkpoint(const char *data_dir, ScanCheckpoint &cp) {
  const std::string path = checkpoint_path(data_dir);
  return checkpoint_detail::read_file(path, cp)
      || checkpoint_detail::read_file(path + ".tmp", cp);
}

enum class CheckpointLoadStatus { Loaded, Missing, Invalid };

static inline CheckpointLoadStatus load_checkpoint_status(const char *data_dir,
                                                         ScanCheckpoint &cp) {
  if (load_checkpoint(data_dir, cp)) return CheckpointLoadStatus::Loaded;
  const std::string path = checkpoint_path(data_dir);
  for (const std::string &candidate : {path, path + ".tmp"}) {
#if defined(_WIN32) || defined(WIN32)
    struct _stat64 info;
    const int result = _stat64(candidate.c_str(), &info);
#else
    struct stat info;
    const int result = stat(candidate.c_str(), &info);
#endif
    // Only ENOENT means genuinely absent. Permissions and other I/O errors
    // must not turn an explicit resume request into a fresh overwrite.
    if (result == 0 || errno != ENOENT) return CheckpointLoadStatus::Invalid;
  }
  return CheckpointLoadStatus::Missing;
}

#endif
