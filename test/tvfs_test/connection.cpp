#include "pch.h"

#include <atomic>
#include <cstdlib>
#include <format>
#include <gtest/gtest.h>
#include <latch>
#include <thread>
#include <usvfs.h>
#include <vector>

namespace
{

// Connects to and disconnects from the instance from several threads at once, and
// returns how many of the connects failed.
int connectAndDisconnectFromThreads()
{
  auto params = std::unique_ptr<usvfsParameters, decltype(&usvfsFreeParameters)>(
      usvfsCreateParameters(), &usvfsFreeParameters);
  const auto instance =
      std::format("usvfs_connection_{}_instance", ::GetCurrentProcessId());
  usvfsSetInstanceName(params.get(), instance.c_str());
  usvfsSetLogLevel(params.get(), LogLevel::Warning);

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
  return failedConnects;
}

}  // namespace

// Runs in a process of its own, the way a death test does, rather than to check that
// the process dies: there the connects are the first calls into the DLL, so they also
// race to register the fallback logger. The exit code is how many of them failed.
TEST(ConnectionDeathTest, ThreadsConnectAndDisconnectConcurrently)
{
  EXPECT_EXIT(std::exit(connectAndDisconnectFromThreads()), testing::ExitedWithCode(0),
              "");
}
