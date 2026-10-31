/* Actual worker-lifecycle helper with inert jobs and bounded fault injection.
 * No sockets, resource exhaustion, scanner code or external services. */
#include "../joined_workers.h"
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <system_error>

static int failures = 0;
#define CHECK(test) do { if (!(test)) { ++failures; \
  std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #test); } } while (0)

struct FailingLauncher {
  size_t fail_at, calls = 0;
  template<class Body> std::thread operator()(Body body) {
    if (calls++ == fail_at)
      throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again));
    return std::thread(std::move(body));
  }
};

struct WaitingJobs {
  std::atomic<bool> stop{false};
  std::atomic<unsigned> active{0}, finished{0};
  std::mutex mutex;
  std::condition_variable changed;
  struct Active {
    WaitingJobs &owner;
    explicit Active(WaitingJobs &value) : owner(value) {
      {
        std::lock_guard<std::mutex> lock(owner.mutex);
        ++owner.active;
      }
      owner.changed.notify_all();
    }
    ~Active() { --owner.active; ++owner.finished; }
  };
  void request_stop() noexcept {
    {
      std::lock_guard<std::mutex> lock(mutex);
      stop.store(true);
    }
    changed.notify_all();
  }
  void run(size_t index, bool throw_job) {
    Active guard(*this);
    if (throw_job && index == 1) throw std::runtime_error("offline job failed");
    std::unique_lock<std::mutex> lock(mutex);
    if (!changed.wait_for(lock, std::chrono::seconds(2), [&] { return stop.load(); }))
      throw std::runtime_error("cooperative stop deadline exceeded");
  }
};

static void startup_failure(size_t fail_at) {
  WaitingJobs jobs;
  auto result = kmap_run_joined_workers(4,
      [&](size_t index) { jobs.run(index, false); },
      [&]() noexcept { jobs.request_stop(); }, FailingLauncher{fail_at});
  CHECK(result.error != nullptr);
  CHECK(result.started == fail_at);
  CHECK(jobs.active.load() == 0);
  CHECK(jobs.finished.load() == result.started);
  CHECK(jobs.stop.load());
  try {
    if (result.error) std::rethrow_exception(result.error);
  } catch (const std::system_error &error) {
    CHECK(error.code() == std::make_error_code(std::errc::resource_unavailable_try_again));
  } catch (...) { CHECK(false); }
  std::printf("launch failure after %zu workers: joined=%u active=%u\n",
              result.started, jobs.finished.load(), jobs.active.load());
}

int main() {
  // Successful execution preserves every job exactly once.
  std::array<std::atomic<unsigned>, 32> visits;
  for (auto &visit : visits) visit.store(0);
  std::atomic<size_t> next{0};
  std::atomic<bool> stopped{false};
  auto success = kmap_run_joined_workers(4, [&](size_t) {
    for (;;) {
      size_t item = next.fetch_add(1);
      if (item >= visits.size()) return;
      ++visits[item];
    }
  }, [&]() noexcept { stopped.store(true); });
  CHECK(!success.error); CHECK(success.started == 4); CHECK(!stopped.load());
  for (const auto &visit : visits) CHECK(visit.load() == 1);

  startup_failure(0);
  startup_failure(2);

  WaitingJobs jobs;
  auto thrown = kmap_run_joined_workers(4,
      [&](size_t index) { jobs.run(index, true); },
      [&]() noexcept { jobs.request_stop(); });
  CHECK(thrown.error != nullptr); CHECK(thrown.started >= 2);
  CHECK(jobs.active.load() == 0); CHECK(jobs.finished.load() == thrown.started);
  try {
    if (thrown.error) std::rethrow_exception(thrown.error);
  } catch (const std::runtime_error &error) {
    CHECK(std::string(error.what()) == "offline job failed");
  } catch (...) { CHECK(false); }
  std::printf("worker exception: started=%zu joined=%u active=%u\n",
              thrown.started, jobs.finished.load(), jobs.active.load());

  WaitingJobs monitored;
  auto monitor_error = kmap_run_joined_workers_with_monitor(4,
      [&](size_t index) { monitored.run(index, false); },
      [&]() noexcept { monitored.request_stop(); },
      [&] {
        std::unique_lock<std::mutex> lock(monitored.mutex);
        if (!monitored.changed.wait_for(lock, std::chrono::seconds(1),
                                       [&] { return monitored.active.load() == 4; }))
          throw std::runtime_error("monitor start deadline exceeded");
        CHECK(monitored.finished.load() == 0);
        throw std::runtime_error("offline monitor failed");
      });
  CHECK(monitor_error.error != nullptr); CHECK(monitor_error.started == 4);
  CHECK(monitored.active.load() == 0); CHECK(monitored.finished.load() == 4);
  try {
    if (monitor_error.error) std::rethrow_exception(monitor_error.error);
  } catch (const std::runtime_error &error) {
    CHECK(std::string(error.what()) == "offline monitor failed");
  } catch (...) { CHECK(false); }
  std::printf("monitor exception: started=%zu joined=%u active=%u\n",
              monitor_error.started, monitored.finished.load(), monitored.active.load());

  auto empty = kmap_run_joined_workers(0, [](size_t) {}, []() noexcept {});
  CHECK(!empty.error); CHECK(empty.started == 0);
  std::printf("joined workers: %d failure(s)\n", failures);
  return failures ? 1 : 0;
}
