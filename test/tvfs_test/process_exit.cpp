#include "pch.h"

#include <exceptionex.h>
#include <gtest/gtest.h>
#include <test_helpers.h>
#include <usvfs.h>

class ProcessExit : public testing::TestWithParam<bool>
{};

TEST_P(ProcessExit, HostReapsSignaledProcess)
{
  auto params = std::unique_ptr<usvfsParameters, decltype(&usvfsFreeParameters)>(
      usvfsCreateParameters(), &usvfsFreeParameters);
  const auto instance = std::format("usvfs_exit_{}_instance", ::GetCurrentProcessId());
  usvfsSetInstanceName(params.get(), instance.c_str());
  usvfsSetLogLevel(params.get(), LogLevel::Warning);
  usvfsInitLogging(false);
  ASSERT_TRUE(usvfsCreateVFS(params.get()));
  ON_BLOCK_EXIT([]() {
    usvfsDisconnectVFS();
  });

  const auto exe =
      test::path_of_test_bin(test::platform_dependant_executable("usvfs_exit_child"));
  const auto virtualPath = exe.parent_path() / (instance + ".exe");
  ASSERT_EQ(::GetFileAttributesW(virtualPath.c_str()), INVALID_FILE_ATTRIBUTES);
  ASSERT_TRUE(usvfsVirtualLinkFile(exe.c_str(), virtualPath.c_str(), 0));

  SECURITY_ATTRIBUTES inheritance{sizeof(inheritance), nullptr, TRUE};
  using Event = std::unique_ptr<void, decltype(&::CloseHandle)>;
  Event started(::CreateEventW(&inheritance, TRUE, FALSE, nullptr), &::CloseHandle);
  Event exitAllowed(::CreateEventW(&inheritance, TRUE, FALSE, nullptr), &::CloseHandle);
  Event nativePathObserved(::CreateEventW(&inheritance, TRUE, FALSE, nullptr),
                           &::CloseHandle);
  ASSERT_TRUE(started && exitAllowed && nativePathObserved);

  constexpr DWORD timeout = 10'000;
  auto command = std::format(L"\"{}\" {} {} {} \"{}\"", exe.wstring(),
                             reinterpret_cast<std::uintptr_t>(started.get()),
                             reinterpret_cast<std::uintptr_t>(exitAllowed.get()),
                             reinterpret_cast<std::uintptr_t>(nativePathObserved.get()),
                             virtualPath.wstring());
  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION child{};
  ASSERT_TRUE(usvfsCreateProcessHooked(exe.c_str(), command.data(), nullptr, nullptr,
                                       TRUE, 0, nullptr, nullptr, &startup, &child));
  ON_BLOCK_EXIT([&]() {
    if (::WaitForSingleObject(child.hProcess, 0) == WAIT_TIMEOUT) {
      ::TerminateProcess(child.hProcess, 1);
    }
    ::CloseHandle(child.hProcess);
    ::CloseHandle(child.hThread);
  });

  ASSERT_EQ(::WaitForSingleObject(started.get(), timeout), WAIT_OBJECT_0);
  DWORD pid    = 0;
  size_t count = 1;
  ASSERT_TRUE(usvfsGetVFSProcessList(&count, &pid));
  EXPECT_EQ(count, 1);
  EXPECT_EQ(pid, child.dwProcessId);

  const bool forceExit = GetParam();
  if (forceExit) {
    ASSERT_TRUE(::TerminateProcess(child.hProcess, STILL_ACTIVE));
  } else {
    ASSERT_TRUE(::SetEvent(exitAllowed.get()));
  }
  ASSERT_EQ(::WaitForSingleObject(child.hProcess, timeout), WAIT_OBJECT_0);
  DWORD exitCode = 0;
  ASSERT_TRUE(::GetExitCodeProcess(child.hProcess, &exitCode));
  EXPECT_EQ(exitCode, STILL_ACTIVE);
  // TerminateProcess skips the loader shutdown, so the child's FLS callback never runs.
  EXPECT_EQ(::WaitForSingleObject(nativePathObserved.get(), 0),
            forceExit ? WAIT_TIMEOUT : WAIT_OBJECT_0);

  // The child has exited even though its handle remains open and its exit code is 259.
  DWORD* pids = nullptr;
  ASSERT_TRUE(usvfsGetVFSProcessList2(&count, &pids));
  EXPECT_EQ(count, 0);
  std::free(pids);
}

INSTANTIATE_TEST_SUITE_P(SegmentHeap, ProcessExit, testing::Values(false, true),
                         [](const testing::TestParamInfo<bool>& info) {
                           return info.param ? "Terminated" : "Exited";
                         });
