// Offline production checkpoint I/O: no scanner, sockets, DNS or privileges.
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <cstdlib>
#include "../scan_checkpoint.h"

namespace fs = std::filesystem;
static int failures = 0, checks = 0;
#define CHECK(c) do { ++checks; if (!(c)) { ++failures; \
  std::cerr << "FAIL line " << __LINE__ << ": " #c "\n"; } } while (0)

static const ScanCheckpoint OLD{17, 33, 5, 777, 1700000000};
static const ScanCheckpoint NEW{29, 61, 9, 888, 1700000001};
static const ScanCheckpoint SENTINEL{41, 42, 43, 44, 45};
static bool same(const ScanCheckpoint &a, const ScanCheckpoint &b) {
  return a.next_index == b.next_index && a.packets_sent == b.packets_sent
      && a.hosts_found == b.hosts_found && a.seed == b.seed
      && a.last_save == b.last_save;
}
static std::string record(const ScanCheckpoint &cp, const char *eol = "\n") {
  std::ostringstream out;
  out << cp.next_index << eol << cp.packets_sent << eol << cp.hosts_found << eol
      << cp.seed << eol << cp.last_save << eol;
  return out.str();
}
static void raw(const fs::path &path, const std::string &bytes) {
  std::ofstream out(path, std::ios::binary); out << bytes; out.close();
  if (!out) throw std::runtime_error("fixture write failed");
}
static std::string dir(const fs::path &root, const std::string &name) {
  const auto path = root / name;
  if (!fs::create_directory(path)) throw std::runtime_error("fixture directory exists");
  return path.string();
}
static bool loaded(const std::string &directory, const ScanCheckpoint &want) {
  ScanCheckpoint got = SENTINEL;
  return load_checkpoint(directory.c_str(), got) && same(got, want);
}

struct FaultOps : checkpoint_detail::FileOps {
  std::string fail;
  int opened = 0, closed = 0, replacements = 0;
  explicit FaultOps(const std::string &fault) : fail(fault) {}
  FILE *open(const char *path) {
    if (fail == "open") return nullptr;
    FILE *f = FileOps::open(path); if (f) ++opened; return f;
  }
  int write(FILE *f, const ScanCheckpoint &cp) {
    if (fail == "write") { std::fputs("12", f); return -1; }
    return FileOps::write(f, cp);
  }
  int flush(FILE *f) { return fail == "flush" ? EOF : FileOps::flush(f); }
  int close(FILE *f) {
    ++closed;
    const int result = FileOps::close(f);
    return fail == "close" ? EOF : result;
  }
  int replace(const char *from, const char *to) {
    ++replacements;
    return fail == "replace" ? -1 : FileOps::replace(from, to);
  }
};

struct CrashOps : checkpoint_detail::FileOps {
  std::string stage;
  explicit CrashOps(const std::string &point) : stage(point) {}
  int write(FILE *f, const ScanCheckpoint &cp) {
    if (stage == "partial-write") {
      std::fputs("29\n61\n", f); std::fflush(f); std::_Exit(73);
    }
    return FileOps::write(f, cp);
  }
  int flush(FILE *f) {
    const int result = FileOps::flush(f);
    if (stage == "after-flush") std::_Exit(73);
    return result;
  }
  int close(FILE *f) {
    const int result = FileOps::close(f);
    if (stage == "after-close") std::_Exit(73);
    return result;
  }
  int replace(const char *from, const char *to) {
    if (stage == "before-replace") std::_Exit(73);
    const int result = FileOps::replace(from, to);
    if (stage == "after-replace") std::_Exit(73);
    return result;
  }
};

static void test_load(const fs::path &root) {
  const std::string d = dir(root, "load");
  const std::string path = checkpoint_path(d.c_str());
  for (const char *eol : {"\n", "\r\n"}) {
    raw(path, record(OLD, eol)); CHECK(loaded(d, OLD));
  }
  const ScanCheckpoint extremes{
    UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
    (std::numeric_limits<time_t>::max)()};
  CHECK(save_checkpoint(d.c_str(), extremes)); CHECK(loaded(d, extremes));
  ScanCheckpoint minimum{};
  minimum.last_save = (std::numeric_limits<time_t>::min)();
  CHECK(save_checkpoint(d.c_str(), minimum)); CHECK(loaded(d, minimum));
  ScanCheckpoint zero{};
  CHECK(save_checkpoint(d.c_str(), zero)); CHECK(loaded(d, zero));

  // All cuts of an actual generated record, including partial timestamps.
  const std::string full = record(OLD);
  for (size_t length = 0; length < full.size(); ++length) {
    raw(path, full.substr(0, length));
    ScanCheckpoint got = SENTINEL;
    CHECK(!load_checkpoint(d.c_str(), got)); CHECK(same(got, SENTINEL));
  }
  const char *bad_unsigned[] = {"-1", "+1", "18446744073709551616", "1x",
                               "", " 1", "1 ", "999999999999999999999999999"};
  for (unsigned field = 0; field < 4; ++field) {
    for (const char *bad : bad_unsigned) {
      std::string values[] = {"17", "33", "5", "777", "1700000000"};
      values[field] = bad;
      std::string text;
      for (const auto &value : values) text += value + "\n";
      raw(path, text);
      ScanCheckpoint got = SENTINEL;
      CHECK(!load_checkpoint(d.c_str(), got)); CHECK(same(got, SENTINEL));
    }
  }
  const char *bad_times[] = {"9223372036854775808", "-9223372036854775809",
                           "18446744073709551616", "5junk", "-", "+5"};
  for (const char *bad : bad_times) {
    raw(path, "17\n33\n5\n777\n" + std::string(bad) + "\n");
    ScanCheckpoint got = SENTINEL;
    CHECK(!load_checkpoint(d.c_str(), got)); CHECK(same(got, SENTINEL));
  }
  const char embedded_null[] = "17\0junk\n33\n5\n777\n1700000000\n";
  for (const std::string &bad : {full + "6\n", full + "junk",
                               std::string(embedded_null, sizeof(embedded_null) - 1),
                               std::string(1024 * 1024, '9')}) {
    raw(path, bad);
    ScanCheckpoint got = SENTINEL;
    CHECK(!load_checkpoint(d.c_str(), got)); CHECK(same(got, SENTINEL));
  }
  fs::remove(path);
  ScanCheckpoint got = SENTINEL;
  CHECK(!load_checkpoint(d.c_str(), got)); CHECK(same(got, SENTINEL));
}

static void test_recovery(const fs::path &root) {
  const std::string d = dir(root, "recovery");
  const std::string path = checkpoint_path(d.c_str());
  raw(path + ".tmp", record(OLD)); CHECK(loaded(d, OLD));
  raw(path, "truncated\n"); CHECK(loaded(d, OLD));
  raw(path, record(NEW)); CHECK(loaded(d, NEW)); // Main wins over stale .tmp.
  raw(path, "bad\n"); raw(path + ".tmp", "bad\n");
  ScanCheckpoint got = SENTINEL;
  CHECK(!load_checkpoint(d.c_str(), got)); CHECK(same(got, SENTINEL));

  for (const char *failure : {"open", "write", "flush", "close", "replace"}) {
    const std::string sub = dir(root, std::string("recover-") + failure);
    raw(checkpoint_path(sub.c_str()) + ".tmp", record(OLD));
    FaultOps ops(failure);
    CHECK(!checkpoint_detail::save(sub.c_str(), NEW, ops));
    CHECK(loaded(sub, OLD)); CHECK(ops.opened == ops.closed);
  }
  // A failed first-ever replacement leaves the complete temporary record.
  const std::string first = dir(root, "first-replace-failure");
  FaultOps ops("replace");
  CHECK(!checkpoint_detail::save(first.c_str(), NEW, ops));
  CHECK(loaded(first, NEW)); CHECK(ops.opened == ops.closed);
}

static void test_load_status(const fs::path &root) {
  const std::string d = dir(root, "load-status");
  const std::string path = checkpoint_path(d.c_str());
  ScanCheckpoint got = SENTINEL;
  CHECK(load_checkpoint_status(d.c_str(), got) == CheckpointLoadStatus::Missing);
  CHECK(same(got, SENTINEL));
  raw(path, "malformed\n");
  CHECK(load_checkpoint_status(d.c_str(), got) == CheckpointLoadStatus::Invalid);
  CHECK(same(got, SENTINEL));
  raw(path + ".tmp", record(OLD));
  CHECK(load_checkpoint_status(d.c_str(), got) == CheckpointLoadStatus::Loaded);
  CHECK(same(got, OLD));
  fs::remove(path + ".tmp");
  raw(path, record(NEW));
#if defined(_WIN32) || defined(WIN32)
  HANDLE locked = CreateFileA(path.c_str(), GENERIC_READ, 0, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  CHECK(locked != INVALID_HANDLE_VALUE);
  if (locked != INVALID_HANDLE_VALUE) {
    got = SENTINEL;
    CHECK(load_checkpoint_status(d.c_str(), got) == CheckpointLoadStatus::Invalid);
    CHECK(same(got, SENTINEL)); CHECK(CloseHandle(locked) != 0);
  }
#endif
  CHECK(load_checkpoint_status(d.c_str(), got) == CheckpointLoadStatus::Loaded);
  CHECK(same(got, NEW));
}

static void test_failures(const fs::path &root) {
  for (const char *failure : {"open", "write", "flush", "close", "replace"}) {
    const std::string d = dir(root, std::string("save-") + failure);
    CHECK(save_checkpoint(d.c_str(), OLD));
    FaultOps ops(failure);
    CHECK(!checkpoint_detail::save(d.c_str(), NEW, ops));
    CHECK(loaded(d, OLD)); CHECK(ops.opened == ops.closed);
    CHECK(save_checkpoint(d.c_str(), NEW)); CHECK(loaded(d, NEW));
    CHECK(!fs::exists(checkpoint_path(d.c_str()) + ".tmp"));
  }
  const std::string d = dir(root, "cycles");
  for (uint64_t i = 0; i < 500; ++i) {
    const ScanCheckpoint cp{i, i * 7, i / 2, 777 + i, static_cast<time_t>(i)};
    CHECK(save_checkpoint(d.c_str(), cp)); CHECK(loaded(d, cp));
    FaultOps ops(i % 2 ? "write" : "close");
    CHECK(!checkpoint_detail::save(d.c_str(), NEW, ops));
    CHECK(loaded(d, cp)); CHECK(ops.opened == 1 && ops.closed == 1);
  }
#if defined(_WIN32) || defined(WIN32)
  // Real Windows sharing denial, in addition to deterministic operation stubs.
  const std::string locked = dir(root, "real-sharing-denial");
  CHECK(save_checkpoint(locked.c_str(), OLD));
  const std::string path = checkpoint_path(locked.c_str());
  HANDLE handle = CreateFileA(path.c_str(), GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL, nullptr);
  CHECK(handle != INVALID_HANDLE_VALUE);
  if (handle != INVALID_HANDLE_VALUE) {
    CHECK(!save_checkpoint(locked.c_str(), NEW));
    CHECK(loaded(locked, OLD));
    CHECK(CloseHandle(handle) != 0);
    CHECK(save_checkpoint(locked.c_str(), NEW)); CHECK(loaded(locked, NEW));
  }
#endif
}

int main(int argc, char **argv) {
  try {
    // The external offline driver uses abrupt child exits at I/O boundaries.
    if (argc == 4 && std::string(argv[1]) == "--crash") {
      CrashOps ops(argv[3]);
      return checkpoint_detail::save(argv[2], NEW, ops) ? 0 : 2;
    }
    if (argc == 4 && std::string(argv[1]) == "--verify") {
      const std::string want = argv[3];
      const bool ok = want == "new" ? loaded(argv[2], NEW) : loaded(argv[2], OLD);
      std::cout << "recovery=" << want << " ok=" << ok << '\n';
      return ok ? 0 : 1;
    }
    const bool retain = argc == 2;
    fs::path root;
    if (retain) {
      root = fs::absolute(argv[1]);
      if (!fs::create_directory(root)) throw std::runtime_error("fixture directory exists");
    } else {
      std::random_device random;
      for (int i = 0; i < 10; ++i) {
        root = fs::temp_directory_path() / ("kmap-checkpoint-" + std::to_string(random()));
        if (fs::create_directory(root)) break;
        root.clear();
      }
      if (root.empty()) throw std::runtime_error("no unique fixture directory");
    }
    std::cout << "fixtures=" << root.string() << '\n';
    test_load(root); test_recovery(root); test_load_status(root); test_failures(root);
    std::cout << "checks=" << checks << " failures=" << failures << '\n';
    if (!retain && failures == 0) fs::remove_all(root);
    return failures == 0 ? 0 : 1;
  } catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n'; return 2;
  }
}
