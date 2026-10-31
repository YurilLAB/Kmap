/* Join every started worker before returning, including exceptional paths.
 * Coordination only: callers supply work and a cooperative stop request. */
#ifndef KMAP_JOINED_WORKERS_H
#define KMAP_JOINED_WORKERS_H

#include <atomic>
#include <cstddef>
#include <exception>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

struct KmapWorkerResult {
  size_t started = 0;
  std::exception_ptr error;
};

struct KmapNativeThreadLauncher {
  template<class Body> std::thread operator()(Body &&body) const {
    return std::thread(std::forward<Body>(body));
  }
};

template<class Worker, class RequestStop, class Monitor,
         class Launcher = KmapNativeThreadLauncher>
KmapWorkerResult kmap_run_joined_workers_with_monitor(size_t count, Worker worker,
                                                     RequestStop request_stop,
                                                     Monitor monitor,
                                                     Launcher launch = Launcher()) {
  static_assert(noexcept(request_stop()), "worker stop request must be noexcept");
  KmapWorkerResult result;
  std::vector<std::thread> threads;
  std::mutex failure_mutex;
  std::atomic<bool> failed{false};
  auto record_failure = [&](std::exception_ptr error) {
    {
      std::lock_guard<std::mutex> lock(failure_mutex);
      if (!result.error) result.error = error;
    }
    failed.store(true);
    request_stop();
  };
  try {
    threads.reserve(count);
    for (size_t index = 0; index < count && !failed.load(); ++index) {
      // reserve above makes emplacement of the noexcept-movable std::thread
      // non-allocating. A launch exception leaves all earlier threads owned.
      threads.emplace_back(launch([&, index] {
        try { worker(index); }
        catch (...) { record_failure(std::current_exception()); }
      }));
      ++result.started;
    }
    // A main-thread monitor may snapshot/checkpoint while workers run. It
    // must observe the caller's stop flag; startup failure skips it entirely.
    if (!failed.load()) monitor();
  } catch (...) {
    record_failure(std::current_exception());
  }
  for (auto &thread : threads) thread.join();
  // Joined threads can no longer access worker/cancellation captures or the
  // result. The caller must report error and follow its normal resource cleanup.
  // This does not forcibly interrupt a job: jobs must honor request_stop and
  // keep their own blocking operations bounded.
  return result;
}

template<class Worker, class RequestStop, class Launcher = KmapNativeThreadLauncher>
KmapWorkerResult kmap_run_joined_workers(size_t count, Worker worker,
                                        RequestStop request_stop,
                                        Launcher launch = Launcher()) {
  return kmap_run_joined_workers_with_monitor(count, std::move(worker),
      std::move(request_stop), [] {}, std::move(launch));
}

#endif
