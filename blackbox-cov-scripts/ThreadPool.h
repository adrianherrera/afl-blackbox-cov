#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "debug.h"

// Adapted from https://github.com/progschj/ThreadPool/blob/master/ThreadPool.h
class ThreadPool {
private:
  /** Threads */
  std::vector<std::thread> Workers;

  /** Task queue */
  std::queue<std::function<void()>> Tasks;

  // Synchronization
  std::mutex QueueMutex;
  std::condition_variable Condition;
  bool Stop;

public:
  ThreadPool(size_t N) {
    for (size_t I = 0; I < N; ++I) {
      Workers.emplace_back([this] {
        while (true) {
          std::function<void()> Task;
          {
            std::unique_lock<std::mutex> Lock(this->QueueMutex);
            this->Condition.wait(
                Lock, [this] { return this->Stop || !this->Tasks.empty(); });
            if (this->Stop && this->Tasks.empty())
              return;
            Task = std::move(this->Tasks.front());
            this->Tasks.pop();
          }

          Task();
        }
      });
    }
  }

  /** Add a new task to the thread pool */
  template <typename F, typename... Args>
  std::future<typename std::result_of<F(Args...)>::type> Enqueue(F &&Func,
                                                                 Args &&... A) {
    using ReturnType = typename std::result_of<F(Args...)>::type;
    auto Task = std::make_shared<std::packaged_task<ReturnType()>>(
        std::bind(std::forward<F>(Func), std::forward<Args>(A)...));
    std::future<ReturnType> Res = Task->get_future();
    {
      std::unique_lock<std::mutex> Lock(this->QueueMutex);
      if (this->Stop)
        FATAL("Enqueuing on stoppped thread pool");
      this->Tasks.emplace([Task]() { (*Task)(); });
    }

    Condition.notify_one();
    return Res;
  }

  ~ThreadPool() {
    {
      std::unique_lock<std::mutex> Lock(this->QueueMutex);
      this->Stop = true;
    }
    this->Condition.notify_all();
    for (std::thread &Worker : this->Workers)
      Worker.join();
  }
};

#endif