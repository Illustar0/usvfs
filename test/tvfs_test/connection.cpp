#include "pch.h"

#include <atomic>
#include <format>
#include <gtest/gtest.h>
#include <latch>
#include <thread>
#include <usvfs.h>
#include <vector>

TEST(Connection, ThreadsConnectAndDisconnectConcurrently)
{
  auto params = std::unique_ptr<usvfsParameters, decltype(&usvfsFreeParameters)>(
      usvfsCreateParameters(), &usvfsFreeParameters);
  const auto instance =
      std::format("usvfs_connection_{}_instance", ::GetCurrentProcessId());
  usvfsSetInstanceName(params.get(), instance.c_str());
  usvfsSetLogLevel(params.get(), LogLevel::Warning);
  usvfsInitLogging(false);

  constexpr int threadCount = 8;
  constexpr int roundCount  = 25;
  std::latch start(threadCount);
  std::atomic<int> failedConnects = 0;
  {
    std::vector<std::jthread> threads;
    for (int i = 0; i < threadCount; ++i) {
      threads.emplace_back([&] {
        start.arrive_and_wait();
        for (int round = 0; round < roundCount; ++round) {
          if (!usvfsConnectVFS(params.get())) {
            ++failedConnects;
          }
          usvfsDisconnectVFS();
        }
      });
    }
  }

  EXPECT_EQ(failedConnects, 0);
}
