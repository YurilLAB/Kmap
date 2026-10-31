// Shared production persistence ordering, with inert jobs and owned files only.
#include <filesystem>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>
#include "../persistence_boundary.h"
#include "../scan_checkpoint.h"
#include "../joined_workers.h"

namespace fs = std::filesystem;
static int failures = 0, checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; \
  std::cerr << "FAIL line " << __LINE__ << ": " #x "\n"; } } while (0)
static const ScanCheckpoint OLD{11, 21, 2, 1234, 1700000000};
static const ScanCheckpoint NEW{19, 39, 4, 1234, 1700000001};
static bool is_saved(const std::string &path, const ScanCheckpoint &expected) {
  ScanCheckpoint actual{};
  return load_checkpoint(path.c_str(), actual)
      && actual.next_index == expected.next_index
      && actual.packets_sent == expected.packets_sent
      && actual.hosts_found == expected.hosts_found
      && actual.seed == expected.seed && actual.last_save == expected.last_save;
}

static void boundary_case(const fs::path &root, int fail_at, bool reopen) {
  const auto path = root / (std::string(reopen ? "periodic-" : "final-")
                             + std::to_string(fail_at));
  CHECK(fs::create_directory(path));
  const std::string directory = path.string();
  CHECK(save_checkpoint(directory.c_str(), OLD));
  KmapPersistenceState state;
  std::vector<std::string> observed;
  auto operation = [&](std::string name) {
    observed.push_back(name);
    return static_cast<int>(observed.size() - 1) != fail_at;
  };
  bool result = kmap_persistence_boundary(state, 3, reopen,
      [&](size_t shard) { return operation("commit" + std::to_string(shard)); },
      [&](size_t shard) { return operation("begin" + std::to_string(shard)); },
      [&]() { return operation("save") && save_checkpoint(directory.c_str(), NEW); });
  std::vector<std::string> expected{"commit0", "commit1", "commit2"};
  if (reopen) expected.insert(expected.end(), {"begin0", "begin1", "begin2"});
  expected.push_back("save");
  if (fail_at >= 0) expected.resize(static_cast<size_t>(fail_at + 1));
  CHECK(observed == expected);
  CHECK(result == (fail_at < 0)); CHECK(state.failed() == (fail_at >= 0));
  CHECK(is_saved(directory, fail_at < 0 ? NEW : OLD));
  if (fail_at >= 0) {
    // A later retry in the failed run cannot accidentally publish progress.
    bool invoked = false;
    CHECK(!kmap_persistence_boundary(state, 3, false,
        [&](size_t) { invoked = true; return true; },
        [&](size_t) { invoked = true; return true; },
        [&]() { invoked = true; return true; }));
    CHECK(!invoked); CHECK(is_saved(directory, OLD));
  }
}

static void producer_error_before_save() {
  KmapPersistenceState state;
  int commits = 0, begins = 0, saves = 0;
  CHECK(!kmap_persistence_boundary(state, 2, true,
      [&](size_t) { ++commits; return true; },
      [&](size_t index) { ++begins; if (index == 1) state.fail(); return true; },
      [&]() { ++saves; return true; }));
  CHECK(commits == 2 && begins == 2 && saves == 0);
}

static void worker_cleanup(const fs::path &root, bool throw_monitor) {
  const auto path = root / (throw_monitor ? "monitor-error" : "insert-error");
  CHECK(fs::create_directory(path));
  const std::string directory = path.string();
  CHECK(save_checkpoint(directory.c_str(), OLD));
  KmapPersistenceState state;
  std::atomic<unsigned> active{0}, finished{0};
  std::mutex writer_mutex;
  bool saved = false;
  auto result = kmap_run_joined_workers_with_monitor(2, [&](size_t index) {
    ++active;
    if (!throw_monitor && index == 0) {
      std::lock_guard<std::mutex> lock(writer_mutex);
      state.fail(); // stand-in for checked storage result; no network work
    }
    while (!state.failed()) std::this_thread::yield();
    --active; ++finished;
  }, [&]() noexcept { state.fail(); }, [&]() {
    if (!throw_monitor) {
      while (!state.failed()) std::this_thread::yield();
    }
    std::lock_guard<std::mutex> lock(writer_mutex);
    kmap_persistence_boundary(state, 2, false,
        [&](size_t) -> bool { throw std::runtime_error("offline commit exception"); },
        [&](size_t) { return true; },
        [&]() { saved = true; return save_checkpoint(directory.c_str(), NEW); });
  });
  CHECK(static_cast<bool>(result.error) == throw_monitor);
  CHECK(state.failed()); CHECK(active.load() == 0);
  CHECK(finished.load() == result.started); CHECK(!saved);
  CHECK(is_saved(directory, OLD));
  // Production performs rollback/close at this point, after the helper joins.
  bool safe_to_close = active.load() == 0;
  CHECK(safe_to_close);
}

int main(int argc, char **argv) {
  try {
    fs::path root;
    const bool retain = argc == 2;
    if (retain) {
      root = fs::absolute(argv[1]);
      if (!fs::create_directory(root)) throw std::runtime_error("fixture directory exists");
    } else {
      std::random_device rng;
      for (int i = 0; i < 10; ++i) {
        root = fs::temp_directory_path() / ("kmap-persistence-" + std::to_string(rng()));
        if (fs::create_directory(root)) break;
        root.clear();
      }
      if (root.empty()) throw std::runtime_error("no unique fixture directory");
    }
    std::cout << "fixture_dir=" << root.string() << '\n';
    boundary_case(root, -1, true); boundary_case(root, -1, false);
    for (int fault = 0; fault < 7; ++fault) boundary_case(root, fault, true);
    for (int fault = 0; fault < 4; ++fault) boundary_case(root, fault, false);
    producer_error_before_save();
    worker_cleanup(root, false); worker_cleanup(root, true);
    std::cout << "checks=" << checks << " failures=" << failures << '\n';
    if (!retain && failures == 0) fs::remove_all(root);
    return failures ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n'; return 2;
  }
}
