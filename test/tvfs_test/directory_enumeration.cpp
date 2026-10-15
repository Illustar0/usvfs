// this file depends on so many stuff that the easiest way is to include
// pch.h from shared
#include "pch.h"

#include <algorithm>
#include <latch>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <hookcontext.h>
#include <hooks/ntdll.h>
#include <unicodestring.h>

#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include "tvfs_test.h"

TEST_F(USVFSTest, NtQueryDirectoryFileRegularFile)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));

  HANDLE hdl =
      hooked_NtOpenFile(L"C:\\", FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
  ASSERT_NE(INVALID_HANDLE_VALUE, hdl);

  IO_STATUS_BLOCK status;
  char buffer[1024];

  usvfs::hook_NtQueryDirectoryFile(hdl, nullptr, nullptr, nullptr, &status, buffer,
                                   1024, FileDirectoryInformation, TRUE, nullptr, TRUE);

  ASSERT_EQ(STATUS_SUCCESS, status.Status);

  usvfs::hook_NtClose(hdl);
}

TEST_F(USVFSTest, NtQueryDirectoryFileFindsVirtualFile)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  usvfs::RedirectionTreeContainer& tree = ctx->redirectionTable();

  tree.addFile(L"C:\\np.exe", usvfs::RedirectionDataLocal(REAL_FILEA));

  HANDLE hdl =
      hooked_NtOpenFile(L"C:\\", FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
  ASSERT_NE(INVALID_HANDLE_VALUE, hdl);

  IO_STATUS_BLOCK status;
  char buffer[1024];

  usvfs::UnicodeString fileName(L"np.exe");

  usvfs::hook_NtQueryDirectoryFile(hdl, nullptr, nullptr, nullptr, &status, buffer,
                                   1024, FileDirectoryInformation, TRUE,
                                   static_cast<PUNICODE_STRING>(fileName), TRUE);

  FILE_DIRECTORY_INFORMATION* info =
      reinterpret_cast<FILE_DIRECTORY_INFORMATION*>(buffer);
  ASSERT_EQ(STATUS_SUCCESS, status.Status);
  ASSERT_EQ(0, wcscmp(info->FileName, L"np.exe"));

  usvfs::hook_NtClose(hdl);
}

TEST_F(USVFSTest, NtQueryDirectoryFileHonorsFileNameLength)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  usvfs::RedirectionTreeContainer& tree = ctx->redirectionTable();

  tree.addFile(L"C:\\np.exe", usvfs::RedirectionDataLocal(REAL_FILEA));

  HANDLE hdl =
      hooked_NtOpenFile(L"C:\\", FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
  ASSERT_NE(INVALID_HANDLE_VALUE, hdl);

  // the pattern is "np.exe": the characters past Length must be ignored
  WCHAR patternBuffer[] = L"np.exe.bak";
  UNICODE_STRING pattern;
  pattern.Buffer        = patternBuffer;
  pattern.Length        = static_cast<USHORT>(wcslen(L"np.exe") * sizeof(WCHAR));
  pattern.MaximumLength = sizeof(patternBuffer);

  IO_STATUS_BLOCK status;
  char buffer[1024];

  usvfs::hook_NtQueryDirectoryFile(hdl, nullptr, nullptr, nullptr, &status, buffer,
                                   1024, FileDirectoryInformation, TRUE, &pattern,
                                   TRUE);

  const auto* info = reinterpret_cast<FILE_DIRECTORY_INFORMATION*>(buffer);
  ASSERT_EQ(STATUS_SUCCESS, status.Status);
  ASSERT_EQ(L"np.exe",
            std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR)));

  usvfs::hook_NtClose(hdl);
}

TEST_F(USVFSTest, NtQueryDirectoryFileForwardsUnsupportedInformationClass)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));

  HANDLE hdl =
      hooked_NtOpenFile(L"C:\\", FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
  ASSERT_NE(INVALID_HANDLE_VALUE, hdl);

  IO_STATUS_BLOCK status;
  char buffer[1024];

  // not a directory information class; ntdll rejects it with a status that differs
  // between architectures, so compare against a direct call
  const auto nativeQuery = reinterpret_cast<NtQueryDirectoryFile_type>(
      ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile"));
  const auto hookedQuery = &usvfs::hook_NtQueryDirectoryFile;

  const NTSTATUS expected =
      nativeQuery(hdl, nullptr, nullptr, nullptr, &status, buffer, 1024,
                  FileStandardInformation, TRUE, nullptr, TRUE);
  const NTSTATUS actual =
      hookedQuery(hdl, nullptr, nullptr, nullptr, &status, buffer, 1024,
                  FileStandardInformation, TRUE, nullptr, TRUE);

  ASSERT_LT(expected, 0);
  ASSERT_EQ(expected, actual);

  usvfs::hook_NtClose(hdl);
}

TEST_F(USVFSTest, NtQueryDirectoryFileExVirtualFile)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  usvfs::RedirectionTreeContainer& tree = ctx->redirectionTable();

  tree.addFile(L"C:\\0123456789.txt", usvfs::RedirectionDataLocal(REAL_FILEA));
  tree.addFile(L"C:\\123456", usvfs::RedirectionDataLocal(REAL_FILEA));
  tree.addFile(L"C:\\abcdef", usvfs::RedirectionDataLocal(REAL_FILEA));
  tree.addFile(L"C:\\abcdefghijklmnopqrstuvwxyz.txt",
               usvfs::RedirectionDataLocal(REAL_FILEA));

  HANDLE hdl =
      hooked_NtOpenFile(L"C:\\", FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
  ASSERT_NE(INVALID_HANDLE_VALUE, hdl);

  IO_STATUS_BLOCK status;

  constexpr size_t BUFFER_SIZE = 2048;
  char buffer[BUFFER_SIZE];

  std::vector<std::wstring> foundFiles;
  while (usvfs::hook_NtQueryDirectoryFileEx(
             hdl, nullptr, nullptr, nullptr, &status, buffer, BUFFER_SIZE,
             FileFullDirectoryInformation, 0, nullptr) == STATUS_SUCCESS) {
    std::size_t offset = 0;
    while (offset < BUFFER_SIZE) {
      const auto* info = reinterpret_cast<FILE_FULL_DIR_INFORMATION*>(buffer + offset);
      foundFiles.emplace_back(info->FileName, info->FileNameLength / sizeof(wchar_t));

      if (info->NextEntryOffset == 0) {
        break;  // no more entries
      }

      offset += info->NextEntryOffset;
    }
  }

  ASSERT_THAT(foundFiles,
              ::testing::IsSupersetOf({L"0123456789.txt", L"123456", L"abcdef",
                                       L"abcdefghijklmnopqrstuvwxyz.txt"}));

  usvfs::hook_NtClose(hdl);
}

TEST_F(USVFSTest, NtQueryDirectoryFileRestartClosesReopenedHandle)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));

  // backup intent makes the scan reopen the directory into a handle of its own
  HANDLE hdl = hooked_NtOpenFile(
      L"C:\\", FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
      FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
  ASSERT_NE(INVALID_HANDLE_VALUE, hdl);

  IO_STATUS_BLOCK status;
  char buffer[1024];

  // a single entry leaves the regular phase, and so the reopened handle, open
  usvfs::hook_NtQueryDirectoryFile(hdl, nullptr, nullptr, nullptr, &status, buffer,
                                   sizeof(buffer), FileDirectoryInformation, TRUE,
                                   nullptr, FALSE);
  ASSERT_EQ(STATUS_SUCCESS, status.Status);

  DWORD handleCountBefore = 0;
  ASSERT_TRUE(::GetProcessHandleCount(::GetCurrentProcess(), &handleCountBefore));

  for (int restart = 0; restart < 10; ++restart) {
    usvfs::hook_NtQueryDirectoryFile(hdl, nullptr, nullptr, nullptr, &status, buffer,
                                     sizeof(buffer), FileDirectoryInformation, TRUE,
                                     nullptr, TRUE);
    ASSERT_EQ(STATUS_SUCCESS, status.Status);
  }

  DWORD handleCountAfter = 0;
  ASSERT_TRUE(::GetProcessHandleCount(::GetCurrentProcess(), &handleCountAfter));
  EXPECT_EQ(handleCountBefore, handleCountAfter);

  usvfs::hook_NtClose(hdl);
}

namespace
{

// Lists a directory one entry per call, as long as the query succeeds.
std::vector<std::wstring> listSingleEntries(HANDLE directory)
{
  std::vector<std::wstring> names;
  IO_STATUS_BLOCK status;
  char buffer[1024];
  while (usvfs::hook_NtQueryDirectoryFile(
             directory, nullptr, nullptr, nullptr, &status, buffer, sizeof(buffer),
             FileDirectoryInformation, TRUE, nullptr, FALSE) == STATUS_SUCCESS) {
    const auto* info = reinterpret_cast<FILE_DIRECTORY_INFORMATION*>(buffer);
    names.emplace_back(info->FileName, info->FileNameLength / sizeof(WCHAR));
  }
  return names;
}

}  // namespace

TEST_F(USVFSTest, NtQueryDirectoryFileSerializesConcurrentQueries)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  usvfs::RedirectionTreeContainer& tree = ctx->redirectionTable();

  // virtual entries make each call long enough for the threads to overlap
  for (int file = 0; file < 64; ++file) {
    tree.addFile((L"C:\\usvfs_concurrent_" + std::to_wstring(file) + L".txt").c_str(),
                 usvfs::RedirectionDataLocal(REAL_FILEA));
  }

  const auto openRoot = [] {
    return hooked_NtOpenFile(L"C:\\", FILE_GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
  };

  HANDLE serialHandle = openRoot();
  ASSERT_NE(INVALID_HANDLE_VALUE, serialHandle);
  std::vector<std::wstring> expected = listSingleEntries(serialHandle);
  usvfs::hook_NtClose(serialHandle);
  std::sort(expected.begin(), expected.end());
  ASSERT_TRUE(std::binary_search(expected.begin(), expected.end(),
                                 std::wstring(L"usvfs_concurrent_63.txt")))
      << "the virtual entries must be listed, " << expected.size() << " names found";

  for (int attempt = 0; attempt < 10; ++attempt) {
    HANDLE sharedHandle = openRoot();
    ASSERT_NE(INVALID_HANDLE_VALUE, sharedHandle);

    constexpr int THREAD_COUNT = 8;
    std::latch start(THREAD_COUNT);
    std::mutex namesMutex;
    std::vector<std::wstring> names;
    std::vector<std::thread> threads;
    for (int thread = 0; thread < THREAD_COUNT; ++thread) {
      threads.emplace_back([&] {
        start.arrive_and_wait();
        std::vector<std::wstring> threadNames = listSingleEntries(sharedHandle);
        std::lock_guard lock(namesMutex);
        names.insert(names.end(), threadNames.begin(), threadNames.end());
      });
    }
    for (std::thread& thread : threads) {
      thread.join();
    }
    usvfs::hook_NtClose(sharedHandle);

    // every entry exactly once across all threads, like a single caller sees them
    std::sort(names.begin(), names.end());
    ASSERT_EQ(expected, names) << "attempt " << attempt;
  }
}
