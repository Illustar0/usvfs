// this file depends on so many stuff that the easiest way is to include
// pch.h from shared
#include "pch.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <latch>
#include <mutex>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <hookcontext.h>
#include <hooks/directory_records.h>
#include <hooks/ntdll.h>
#include <unicodestring.h>

#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>
#include <test_helpers.h>

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

  // FileName is not terminated: FileNameLength tells where it ends
  const auto* info = reinterpret_cast<FILE_DIRECTORY_INFORMATION*>(buffer);
  ASSERT_EQ(STATUS_SUCCESS, status.Status);
  ASSERT_EQ(L"np.exe",
            std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR)));

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

namespace
{

enum class CompletionNotification
{
  Event,
  Apc,
  CompletionPort,
};

const auto QUERY_CONTEXT                  = reinterpret_cast<PVOID>(0x5A5A);
constexpr ULONG_PTR COMPLETION_KEY        = 0x1234;
constexpr DWORD COMPLETION_TIMEOUT        = 5000;
const auto UNWRITTEN_STATUS               = static_cast<NTSTATUS>(0xDEADBEEF);
constexpr ULONG_PTR UNWRITTEN_INFORMATION = 0xDEADBEEF;

struct ApcRecord
{
  int count;
  PVOID context;
  PIO_STATUS_BLOCK statusBlock;
};

ApcRecord apcRecord;

VOID NTAPI recordApc(PVOID context, PIO_STATUS_BLOCK statusBlock, ULONG)
{
  ++apcRecord.count;
  apcRecord.context     = context;
  apcRecord.statusBlock = statusBlock;
}

// How one query completed, in terms that do not depend on the entries it returned,
// so that listings of different directories can be compared call by call.
struct CompletionRecord
{
  // from the status block, or the returned status if the query left it alone
  NTSTATUS status;
  bool isStatusBlockWritten;
  // returning STATUS_PENDING instead is consistent too: a query may pend or not
  bool isReturnedStatusFinal;
  bool isEventSignaled;
  int apcCount;
  bool isApcForQuery;
  int packetCount;
  bool isPacketForQuery;
  bool isPacketByteCountInformation;

  bool operator==(const CompletionRecord&) const = default;
};

std::ostream& operator<<(std::ostream& out, const CompletionRecord& record)
{
  return out << "{status " << std::hex << static_cast<ULONG>(record.status) << std::dec
             << ", status block written " << record.isStatusBlockWritten
             << ", returned status final " << record.isReturnedStatusFinal
             << ", event signaled " << record.isEventSignaled << ", APCs "
             << record.apcCount << ", APC for query " << record.isApcForQuery
             << ", packets " << record.packetCount << ", packet for query "
             << record.isPacketForQuery << ", packet byte count is Information "
             << record.isPacketByteCountInformation << "}";
}

// Lists a directory one entry per call, asking to be notified of each completion,
// and records how each call completed, up to the first one that returns nothing.
std::vector<CompletionRecord> recordNotifiedListing(NtQueryDirectoryFile_type query,
                                                    HANDLE directory,
                                                    CompletionNotification notification,
                                                    HANDLE port)
{
  const HANDLE event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  std::vector<CompletionRecord> records;
  for (int call = 0; call < 10000; ++call) {
    IO_STATUS_BLOCK status;
    status.Status      = UNWRITTEN_STATUS;
    status.Information = UNWRITTEN_INFORMATION;
    alignas(8) char buffer[1024];
    ::ResetEvent(event);
    apcRecord = {};

    const NTSTATUS result = query(
        directory, notification == CompletionNotification::Event ? event : nullptr,
        notification == CompletionNotification::Apc ? recordApc : nullptr,
        notification == CompletionNotification::Event ? nullptr : QUERY_CONTEXT,
        &status, buffer, sizeof(buffer), FileDirectoryInformation, TRUE, nullptr,
        FALSE);
    // a query that did not pend has delivered its notifications before returning
    const DWORD timeout = result == STATUS_PENDING ? COMPLETION_TIMEOUT : 0;

    CompletionRecord record{};
    switch (notification) {
    case CompletionNotification::Event:
      record.isEventSignaled = ::WaitForSingleObject(event, timeout) == WAIT_OBJECT_0;
      break;
    case CompletionNotification::Apc: {
      const ULONGLONG deadline = ::GetTickCount64() + timeout;
      while (apcRecord.count == 0 && ::GetTickCount64() < deadline) {
        ::SleepEx(10, TRUE);
      }
      ::SleepEx(0, TRUE);
      record.apcCount = apcRecord.count;
      record.isApcForQuery =
          apcRecord.context == QUERY_CONTEXT && apcRecord.statusBlock == &status;
      break;
    }
    case CompletionNotification::CompletionPort: {
      // a packet of a warning or error dequeues as a failure, so look at the
      // context to tell a packet from a timeout
      DWORD bytes = 0;
      for (DWORD packetTimeout = timeout;; packetTimeout = 0) {
        ULONG_PTR key        = 0;
        LPOVERLAPPED context = nullptr;
        ::GetQueuedCompletionStatus(port, &bytes, &key, &context, packetTimeout);
        if (context == nullptr) {
          break;
        }
        ++record.packetCount;
        record.isPacketForQuery = key == COMPLETION_KEY && context == QUERY_CONTEXT;
      }
      record.isPacketByteCountInformation =
          record.packetCount != 0 && bytes == status.Information;
      break;
    }
    }

    record.isStatusBlockWritten  = status.Status != UNWRITTEN_STATUS;
    record.status                = record.isStatusBlockWritten ? status.Status : result;
    record.isReturnedStatusFinal = result == STATUS_PENDING || result == record.status;
    records.push_back(record);
    if (record.status != STATUS_SUCCESS) {
      break;
    }
  }
  ::CloseHandle(event);
  return records;
}

// The virtual entries make the listing reach the virtual phase, which completes
// the queries itself.
void addVirtualEntries(usvfs::RedirectionTreeContainer& tree)
{
  tree.addFile(L"C:\\usvfs_notified_a.txt", usvfs::RedirectionDataLocal(REAL_FILEA));
  tree.addFile(L"C:\\usvfs_notified_b.txt", usvfs::RedirectionDataLocal(REAL_FILEA));
}

HANDLE openRootDirectory(bool isSynchronous)
{
  return hooked_NtOpenFile(
      L"C:\\", FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
      FILE_DIRECTORY_FILE | (isSynchronous ? FILE_SYNCHRONOUS_IO_NONALERT : 0));
}

NtQueryDirectoryFile_type nativeQueryDirectoryFile()
{
  return reinterpret_cast<NtQueryDirectoryFile_type>(
      ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile"));
}

// Lists the root directory through ntdll and through the hook, each with a handle
// of its own, and expects every call under the hook to complete the way ntdll
// completes a call with the same result.
void expectNativeCompletions(bool isSynchronous, CompletionNotification notification)
{
  // a query moves its handle through the directory and completes to the port of
  // its handle, so each listing gets a handle and a port of its own
  HANDLE nativeHandle = openRootDirectory(isSynchronous);
  HANDLE hookedHandle = openRootDirectory(isSynchronous);
  ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
  ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);
  HANDLE nativePort = nullptr;
  HANDLE hookedPort = nullptr;
  if (notification == CompletionNotification::CompletionPort) {
    nativePort = ::CreateIoCompletionPort(nativeHandle, nullptr, COMPLETION_KEY, 0);
    hookedPort = ::CreateIoCompletionPort(hookedHandle, nullptr, COMPLETION_KEY, 0);
    ASSERT_NE(nullptr, nativePort);
    ASSERT_NE(nullptr, hookedPort);
  }

  const std::vector<CompletionRecord> expected = recordNotifiedListing(
      nativeQueryDirectoryFile(), nativeHandle, notification, nativePort);
  const std::vector<CompletionRecord> actual = recordNotifiedListing(
      &usvfs::hook_NtQueryDirectoryFile, hookedHandle, notification, hookedPort);

  ASSERT_LE(2u, expected.size());
  ASSERT_EQ(STATUS_SUCCESS, expected.front().status);
  ASSERT_EQ(STATUS_NO_MORE_FILES, expected.back().status);
  for (size_t call = 0; call + 1 < actual.size(); ++call) {
    ASSERT_EQ(expected.front(), actual[call]) << "call " << call;
  }
  ASSERT_EQ(expected.back(), actual.back()) << "the end of the listing";

  usvfs::hook_NtClose(nativeHandle);
  usvfs::hook_NtClose(hookedHandle);
  if (notification == CompletionNotification::CompletionPort) {
    ::CloseHandle(nativePort);
    ::CloseHandle(hookedPort);
  }
}

}  // namespace

TEST_F(USVFSTest, NtQueryDirectoryFileSignalsEventOnSynchronousHandle)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  addVirtualEntries(ctx->redirectionTable());
  expectNativeCompletions(true, CompletionNotification::Event);
}

TEST_F(USVFSTest, NtQueryDirectoryFileSignalsEventOnAsynchronousHandle)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  addVirtualEntries(ctx->redirectionTable());
  expectNativeCompletions(false, CompletionNotification::Event);
}

TEST_F(USVFSTest, NtQueryDirectoryFileQueuesApcOnAsynchronousHandle)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  addVirtualEntries(ctx->redirectionTable());
  expectNativeCompletions(false, CompletionNotification::Apc);
}

TEST_F(USVFSTest, NtQueryDirectoryFilePostsCompletionPackets)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  addVirtualEntries(ctx->redirectionTable());
  expectNativeCompletions(false, CompletionNotification::CompletionPort);
}

namespace
{

struct QueryOutcome
{
  NTSTATUS result;
  IO_STATUS_BLOCK statusBlock;
};

// Queries a directory with a status block that shows whether the query wrote it.
QueryOutcome queryWithMarkedStatusBlock(NtQueryDirectoryFile_type query,
                                        HANDLE directory, PUNICODE_STRING fileName)
{
  QueryOutcome outcome;
  outcome.statusBlock.Status      = UNWRITTEN_STATUS;
  outcome.statusBlock.Information = UNWRITTEN_INFORMATION;
  alignas(8) char buffer[1024];
  outcome.result =
      query(directory, nullptr, nullptr, nullptr, &outcome.statusBlock, buffer,
            sizeof(buffer), FileDirectoryInformation, FALSE, fileName, FALSE);
  return outcome;
}

// Lists a directory until it reports its end, then queries it once more, and
// returns the outcomes of these two queries.
std::vector<QueryOutcome> queryPastTheLastEntry(NtQueryDirectoryFile_type query,
                                                HANDLE directory)
{
  std::vector<QueryOutcome> endOutcomes;
  for (int call = 0; endOutcomes.size() < 2 && call < 10000; ++call) {
    const QueryOutcome outcome = queryWithMarkedStatusBlock(query, directory, nullptr);
    if (outcome.result != STATUS_SUCCESS) {
      endOutcomes.push_back(outcome);
    }
  }
  return endOutcomes;
}

void expectSameOutcome(const QueryOutcome& expected, const QueryOutcome& actual)
{
  EXPECT_EQ(expected.result, actual.result);
  EXPECT_EQ(expected.statusBlock.Status, actual.statusBlock.Status);
  EXPECT_EQ(expected.statusBlock.Information, actual.statusBlock.Information);
}

}  // namespace

TEST_F(USVFSTest, NtQueryDirectoryFileLeavesStatusBlockWhenNothingMatches)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  addVirtualEntries(ctx->redirectionTable());
  usvfs::UnicodeString pattern(L"usvfs_no_such_file_*");

  // a query moves its handle through the directory, so ntdll and the hook each
  // list through a handle of their own
  HANDLE nativeHandle = openRootDirectory(true);
  HANDLE hookedHandle = openRootDirectory(true);
  ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
  ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

  const QueryOutcome expected = queryWithMarkedStatusBlock(
      nativeQueryDirectoryFile(), nativeHandle, static_cast<PUNICODE_STRING>(pattern));
  const QueryOutcome actual =
      queryWithMarkedStatusBlock(&usvfs::hook_NtQueryDirectoryFile, hookedHandle,
                                 static_cast<PUNICODE_STRING>(pattern));

  ASSERT_EQ(STATUS_NO_SUCH_FILE, expected.result);
  expectSameOutcome(expected, actual);

  usvfs::hook_NtClose(nativeHandle);
  usvfs::hook_NtClose(hookedHandle);
}

TEST_F(USVFSTest, NtQueryDirectoryFileReportsNoBytesPastTheLastEntry)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  addVirtualEntries(ctx->redirectionTable());

  HANDLE nativeHandle = openRootDirectory(true);
  HANDLE hookedHandle = openRootDirectory(true);
  ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
  ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

  const std::vector<QueryOutcome> expected =
      queryPastTheLastEntry(nativeQueryDirectoryFile(), nativeHandle);
  const std::vector<QueryOutcome> actual =
      queryPastTheLastEntry(&usvfs::hook_NtQueryDirectoryFile, hookedHandle);

  ASSERT_EQ(2u, expected.size());
  ASSERT_EQ(STATUS_NO_MORE_FILES, expected.front().result);
  ASSERT_EQ(expected.size(), actual.size()) << "the listing does not end";
  for (size_t query = 0; query < expected.size(); ++query) {
    SCOPED_TRACE(query);
    expectSameOutcome(expected[query], actual[query]);
  }

  usvfs::hook_NtClose(nativeHandle);
  usvfs::hook_NtClose(hookedHandle);
}

namespace
{

const FILE_INFORMATION_CLASS DIRECTORY_INFORMATION_CLASSES[] = {
    FileDirectoryInformation,          FileFullDirectoryInformation,
    FileBothDirectoryInformation,      FileNamesInformation,
    FileIdBothDirectoryInformation,    FileIdFullDirectoryInformation,
    FileIdExtdDirectoryInformation,    FileIdExtdBothDirectoryInformation,
    FileId64ExtdDirectoryInformation,  FileId64ExtdBothDirectoryInformation,
    FileIdAllExtdDirectoryInformation, FileIdAllExtdBothDirectoryInformation,
};

struct BufferQuery
{
  FILE_INFORMATION_CLASS informationClass;
  bool isEx;
  // bytes past an 8-byte boundary
  size_t offset;
  ULONG length;
};

std::string describe(const BufferQuery& query)
{
  return std::format("class {}, {} entry point, offset {}, length {:#x}",
                     static_cast<int>(query.informationClass),
                     query.isEx ? "Ex" : "legacy", query.offset, query.length);
}

// Queries through the entry point of the query, restarting the scan so that every
// query starts from the same state.
QueryOutcome queryBuffer(bool isNative, HANDLE directory, const BufferQuery& query,
                         PUNICODE_STRING fileName)
{
  QueryOutcome outcome;
  outcome.statusBlock.Status      = UNWRITTEN_STATUS;
  outcome.statusBlock.Information = UNWRITTEN_INFORMATION;
  alignas(8) char storage[0x1000 + 8];
  PVOID buffer = storage + query.offset;

  if (query.isEx) {
    const auto exQuery =
        isNative ? reinterpret_cast<NtQueryDirectoryFileEx_type>(::GetProcAddress(
                       ::GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFileEx"))
                 : &usvfs::hook_NtQueryDirectoryFileEx;
    outcome.result =
        exQuery(directory, nullptr, nullptr, nullptr, &outcome.statusBlock, buffer,
                query.length, query.informationClass, SL_RESTART_SCAN, fileName);
  } else {
    const auto legacyQuery =
        isNative ? nativeQueryDirectoryFile() : &usvfs::hook_NtQueryDirectoryFile;
    outcome.result =
        legacyQuery(directory, nullptr, nullptr, nullptr, &outcome.statusBlock, buffer,
                    query.length, query.informationClass, FALSE, fileName, TRUE);
  }
  return outcome;
}

// Expects the hook to reject a buffer that ntdll rejects, with the same result,
// and, if asked to, to list the virtual entries into a buffer that ntdll accepts.
void expectBufferHandledLikeNtdll(const BufferQuery& query, bool shouldListIfAccepted)
{
  SCOPED_TRACE(describe(query));
  HANDLE nativeHandle = openRootDirectory(true);
  HANDLE hookedHandle = openRootDirectory(true);
  ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
  ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

  const QueryOutcome expected = queryBuffer(true, nativeHandle, query, nullptr);
  // ntdll leaves the status block alone when it rejects the buffer, and fills it
  // for a buffer it accepts, the root directory not being empty
  if (expected.statusBlock.Status == UNWRITTEN_STATUS) {
    expectSameOutcome(expected, queryBuffer(false, hookedHandle, query, nullptr));
  } else if (shouldListIfAccepted) {
    usvfs::UnicodeString pattern(L"usvfs_notified_a.txt");
    const QueryOutcome actual =
        queryBuffer(false, hookedHandle, query, static_cast<PUNICODE_STRING>(pattern));
    EXPECT_EQ(STATUS_SUCCESS, actual.result) << "the virtual entry is not listed";
  }

  usvfs::hook_NtClose(nativeHandle);
  usvfs::hook_NtClose(hookedHandle);
}

}  // namespace

TEST_F(USVFSTest, NtQueryDirectoryFileRejectsUndersizedBuffersLikeNtdll)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  addVirtualEntries(ctx->redirectionTable());

  // every length up to past the largest minimum, 0x80; whether a small buffer that
  // ntdll accepts lists the virtual entries is up to how the hook fills it
  for (const FILE_INFORMATION_CLASS informationClass : DIRECTORY_INFORMATION_CLASSES) {
    for (const bool isEx : {false, true}) {
      for (ULONG length = 0; length <= 0x88; ++length) {
        expectBufferHandledLikeNtdll({informationClass, isEx, 0, length}, false);
      }
    }
  }
}

TEST_F(USVFSTest, NtQueryDirectoryFileRejectsMisalignedBuffersLikeNtdll)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  addVirtualEntries(ctx->redirectionTable());

  for (const FILE_INFORMATION_CLASS informationClass : DIRECTORY_INFORMATION_CLASSES) {
    for (const bool isEx : {false, true}) {
      for (size_t offset = 0; offset < 8; ++offset) {
        expectBufferHandledLikeNtdll({informationClass, isEx, offset, 0x1000}, true);
      }
    }
  }
}

namespace
{

template <FILE_INFORMATION_CLASS InformationClass, typename Record>
struct RecordType
{
  static constexpr FILE_INFORMATION_CLASS informationClass = InformationClass;
  using Type                                               = Record;
};

using RecordTypes = ::testing::Types<
    RecordType<FileDirectoryInformation, FILE_DIRECTORY_INFORMATION>,
    RecordType<FileFullDirectoryInformation, FILE_FULL_DIR_INFORMATION>,
    RecordType<FileBothDirectoryInformation, FILE_BOTH_DIR_INFORMATION>,
    RecordType<FileNamesInformation, FILE_NAMES_INFORMATION>,
    RecordType<FileIdBothDirectoryInformation, FILE_ID_BOTH_DIR_INFORMATION>,
    RecordType<FileIdFullDirectoryInformation, FILE_ID_FULL_DIR_INFORMATION>,
    RecordType<FileIdExtdDirectoryInformation, FILE_ID_EXTD_DIR_INFORMATION>,
    RecordType<FileIdExtdBothDirectoryInformation, FILE_ID_EXTD_BOTH_DIR_INFORMATION>,
    RecordType<FileId64ExtdDirectoryInformation, FILE_ID_64_EXTD_DIR_INFORMATION>,
    RecordType<FileId64ExtdBothDirectoryInformation,
               FILE_ID_64_EXTD_BOTH_DIR_INFORMATION>,
    RecordType<FileIdAllExtdDirectoryInformation, FILE_ID_ALL_EXTD_DIR_INFORMATION>,
    RecordType<FileIdAllExtdBothDirectoryInformation,
               FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION>>;

// A record built through the fields of its declared structure, so that it does not
// depend on the offsets in the layout table it is read with.
template <typename Record>
struct SyntheticRecord
{
  alignas(Record) std::array<std::byte, 0x400> storage{};
  size_t size = 0;

  SyntheticRecord(std::wstring_view name, ULONG nextEntryOffset)
  {
    fields().NextEntryOffset = nextEntryOffset;
    fields().FileNameLength  = static_cast<ULONG>(name.size() * sizeof(WCHAR));
    std::memcpy(storage.data() + offsetof(Record, FileName), name.data(),
                fields().FileNameLength);
    size = offsetof(Record, FileName) + fields().FileNameLength;
  }

  Record& fields() { return *reinterpret_cast<Record*>(storage.data()); }
  std::span<const std::byte> bytes() const { return std::span(storage).first(size); }
};

template <typename T>
class DirectoryRecordTest : public ::testing::Test
{
protected:
  using Record = typename T::Type;

  static DirectoryRecordLayout layout()
  {
    return findDirectoryRecordLayout(T::informationClass).value();
  }
};

// A directory on the volume the tests run from, which differs from the system one on
// a ReFS Dev Drive. Its names take every length up to 64 characters, so that records
// end at every offset modulo 8.
std::filesystem::path generatedListingDirectory()
{
  const std::filesystem::path directory = test::path_of_test_temp(L"directory_records");
  std::filesystem::create_directories(directory);
  for (size_t length = 1; length <= 64; ++length) {
    std::ofstream(directory / std::wstring(length, L'n'));
  }
  return directory;
}

// The directories whose native listings the records are checked against, one per
// filesystem when the tests run from a volume other than NTFS.
std::vector<std::filesystem::path> nativeListingDirectories()
{
  return {L"C:\\Windows", generatedListingDirectory()};
}

std::wstring fileSystemOf(const std::filesystem::path& path)
{
  std::wstring volume(MAX_PATH, L'\0');
  std::wstring fileSystem(MAX_PATH, L'\0');
  if (!::GetVolumePathNameW(path.c_str(), volume.data(), MAX_PATH) ||
      !::GetVolumeInformationW(volume.c_str(), nullptr, 0, nullptr, nullptr, nullptr,
                               fileSystem.data(), MAX_PATH)) {
    return L"unknown";
  }
  return fileSystem.c_str();
}

std::string describeDirectory(const std::filesystem::path& path)
{
  return std::format("{} ({})", path.string(),
                     std::filesystem::path(fileSystemOf(path)).string());
}

// Lists a directory through ntdll and reads the names with DirectoryRecord.
std::vector<std::wstring> listWithDirectoryRecords(const std::filesystem::path& path,
                                                   const DirectoryRecordLayout& layout)
{
  const HANDLE directory = ::CreateFileW(
      path.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  EXPECT_NE(INVALID_HANDLE_VALUE, directory);

  std::vector<std::wstring> names;
  std::vector<std::byte> buffer(0x10000);
  IO_STATUS_BLOCK statusBlock;
  while (nativeQueryDirectoryFile()(directory, nullptr, nullptr, nullptr, &statusBlock,
                                    buffer.data(), static_cast<ULONG>(buffer.size()),
                                    layout.informationClass, FALSE, nullptr,
                                    FALSE) == STATUS_SUCCESS) {
    std::span<const std::byte> data(buffer.data(), statusBlock.Information);
    for (;;) {
      const DirectoryRecord record(layout, data);
      EXPECT_FALSE(record.isTruncated());
      names.push_back(record.fileName());
      if (record.nextEntryOffset() == 0) {
        break;
      }
      data = data.subspan(record.nextEntryOffset());
    }
  }
  ::CloseHandle(directory);
  std::ranges::sort(names);
  return names;
}

std::vector<std::wstring> listWithFindFirstFile(const std::filesystem::path& path)
{
  std::vector<std::wstring> names;
  WIN32_FIND_DATAW data;
  const HANDLE search = ::FindFirstFileW((path / L"*").c_str(), &data);
  EXPECT_NE(INVALID_HANDLE_VALUE, search);
  do {
    names.emplace_back(data.cFileName);
  } while (::FindNextFileW(search, &data));
  ::FindClose(search);
  std::ranges::sort(names);
  return names;
}

}  // namespace

TYPED_TEST_SUITE(DirectoryRecordTest, RecordTypes);

TYPED_TEST(DirectoryRecordTest, ReadsTheFieldsOfARecord)
{
  const SyntheticRecord<typename TestFixture::Record> synthetic(L"usvfs.txt", 0x100);
  const DirectoryRecord record(TestFixture::layout(), synthetic.bytes());

  EXPECT_EQ(0x100u, record.nextEntryOffset());
  EXPECT_EQ(synthetic.size, record.size());
  EXPECT_FALSE(record.isTruncated());
  EXPECT_EQ(L"usvfs.txt", record.fileName());
}

TYPED_TEST(DirectoryRecordTest, ReadsACutRecordAsTruncated)
{
  const SyntheticRecord<typename TestFixture::Record> synthetic(L"usvfs.txt", 0);
  const DirectoryRecord record(TestFixture::layout(),
                               synthetic.bytes().first(synthetic.size - sizeof(WCHAR)));

  EXPECT_EQ(synthetic.size, record.size());
  EXPECT_TRUE(record.isTruncated());
  EXPECT_EQ(L"usvfs.tx", record.fileName());
}

TYPED_TEST(DirectoryRecordTest, ReadsBytesShortOfTheFixedFieldsAsTruncated)
{
  const SyntheticRecord<typename TestFixture::Record> synthetic(L"usvfs.txt", 0x100);
  const DirectoryRecord record(TestFixture::layout(), synthetic.bytes().first(2));

  EXPECT_EQ(0u, record.nextEntryOffset());
  EXPECT_TRUE(record.isTruncated());
  EXPECT_EQ(L"", record.fileName());
}

// ntdll is the reference for the declared structures the layout table derives from
TYPED_TEST(DirectoryRecordTest, ReadsTheNamesNtdllWrites)
{
  for (const std::filesystem::path& directory : nativeListingDirectories()) {
    SCOPED_TRACE(describeDirectory(directory));
    const std::vector<std::wstring> names =
        listWithDirectoryRecords(directory, TestFixture::layout());

    ASSERT_LT(2u, names.size());
    EXPECT_EQ(listWithFindFirstFile(directory), names);
  }
}

TEST(DirectoryRecordLayoutTest, KnowsOnlyClassesWhoseRecordsCarryAFileName)
{
  EXPECT_TRUE(findDirectoryRecordLayout(FileDirectoryInformation).has_value());
  EXPECT_FALSE(findDirectoryRecordLayout(FileStandardInformation).has_value());
  EXPECT_FALSE(findDirectoryRecordLayout(FileObjectIdInformation).has_value());
}

namespace
{

// Returns the data each query of a native listing returned into a buffer of the
// given length.
std::vector<std::vector<std::byte>>
listNativeQueries(const std::filesystem::path& path,
                  FILE_INFORMATION_CLASS informationClass, ULONG length)
{
  const HANDLE directory = ::CreateFileW(
      path.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  EXPECT_NE(INVALID_HANDLE_VALUE, directory);

  std::vector<std::vector<std::byte>> queries;
  std::vector<std::byte> buffer(length);
  IO_STATUS_BLOCK statusBlock;
  while (nativeQueryDirectoryFile()(directory, nullptr, nullptr, nullptr, &statusBlock,
                                    buffer.data(), length, informationClass, FALSE,
                                    nullptr, FALSE) == STATUS_SUCCESS) {
    queries.emplace_back(buffer.begin(), buffer.begin() + statusBlock.Information);
  }
  ::CloseHandle(directory);
  return queries;
}

// Returns where the records in the data of a query start.
std::vector<size_t> recordOffsets(const DirectoryRecordLayout& layout,
                                  std::span<const std::byte> data)
{
  std::vector<size_t> offsets{0};
  for (;;) {
    const ULONG next =
        DirectoryRecord(layout, data.subspan(offsets.back())).nextEntryOffset();
    if (next == 0) {
      return offsets;
    }
    offsets.push_back(offsets.back() + next);
  }
}

}  // namespace

// ntdll is the reference for where records go and for the size reported
TYPED_TEST(DirectoryRecordTest, LaysOutRecordsLikeNtdll)
{
  // small enough for the listing to take several queries
  constexpr ULONG LENGTH             = 0x800;
  const DirectoryRecordLayout layout = TestFixture::layout();
  for (const std::filesystem::path& directory : nativeListingDirectories()) {
    SCOPED_TRACE(describeDirectory(directory));
    const std::vector<std::vector<std::byte>> queries =
        listNativeQueries(directory, layout.informationClass, LENGTH);
    ASSERT_LE(2u, queries.size());

    for (size_t query = 0; query < queries.size(); ++query) {
      SCOPED_TRACE(query);
      const std::span<const std::byte> expected(queries[query]);
      const std::vector<size_t> offsets = recordOffsets(layout, expected);
      std::vector<std::byte> buffer(LENGTH);
      DirectoryOutput output(buffer, layout,
                             {.isSingleEntry = false, .isFirstCall = false});
      for (const size_t offset : offsets) {
        ASSERT_TRUE(output.append(DirectoryRecord(layout, expected.subspan(offset))));
      }

      // the records with their links, and the size; the padding between them is
      // whatever the buffer held
      EXPECT_EQ(expected.size(), output.size());
      for (const size_t offset : offsets) {
        const size_t size = DirectoryRecord(layout, expected.subspan(offset)).size();
        EXPECT_TRUE(std::ranges::equal(expected.subspan(offset, size),
                                       std::span(buffer).subspan(offset, size)))
            << "record at " << offset;
      }
    }
  }
}

// The rule NtfsQueryDirectory and RefsQueryDirectory apply to a record after the
// first: it fits when it ends, without the padding after it, within the buffer.
// Native listings are no reference for it: where a query ends depends on the
// filesystem, on the filters above it, and on how NTFS makes up "." and "..".
TYPED_TEST(DirectoryRecordTest, FitsARecordThatEndsWithTheBuffer)
{
  using Record = typename TestFixture::Record;
  const SyntheticRecord<Record> first(L"usvfs.txt", 0);
  const SyntheticRecord<Record> second(L"usvfs_second.txt", 0);
  const size_t end = (first.size + 7) / 8 * 8 + second.size;

  for (const size_t length : {end, end - 1}) {
    SCOPED_TRACE(length);
    std::vector<std::byte> buffer(length);
    DirectoryOutput output(buffer, TestFixture::layout(),
                           {.isSingleEntry = false, .isFirstCall = false});
    ASSERT_TRUE(output.append(DirectoryRecord(TestFixture::layout(), first.bytes())));

    EXPECT_EQ(length == end,
              output.append(DirectoryRecord(TestFixture::layout(), second.bytes())));
    EXPECT_EQ(length == end ? end : first.size, output.size());
  }
}

TYPED_TEST(DirectoryRecordTest, WritesOneRecordForASingleEntryQuery)
{
  const SyntheticRecord<typename TestFixture::Record> synthetic(L"usvfs.txt", 0);
  const DirectoryRecord record(TestFixture::layout(), synthetic.bytes());
  std::vector<std::byte> buffer(0x400);
  DirectoryOutput output(buffer, TestFixture::layout(),
                         {.isSingleEntry = true, .isFirstCall = false});

  EXPECT_FALSE(output.isSatisfied());
  ASSERT_TRUE(output.append(record));
  EXPECT_TRUE(output.isSatisfied());
  EXPECT_FALSE(output.append(record));
  EXPECT_EQ(synthetic.size, output.size());
}

TYPED_TEST(DirectoryRecordTest, WritesARecordUnderAnotherName)
{
  SyntheticRecord<typename TestFixture::Record> synthetic(L"usvfs.txt", 0x100);
  synthetic.fields().FileIndex = 0x12345678;
  std::vector<std::byte> buffer(0x400);
  DirectoryOutput output(buffer, TestFixture::layout(),
                         {.isSingleEntry = false, .isFirstCall = false});

  ASSERT_TRUE(
      output.appendRenamed(DirectoryRecord(TestFixture::layout(), synthetic.bytes()),
                           L"usvfs_a_longer_name.txt"));

  const DirectoryRecord renamed(TestFixture::layout(),
                                std::span(buffer).first(output.size()));
  EXPECT_EQ(L"usvfs_a_longer_name.txt", renamed.fileName());
  EXPECT_EQ(0u, renamed.nextEntryOffset());
  EXPECT_EQ(output.size(), renamed.size());
  EXPECT_EQ(
      0x12345678u,
      reinterpret_cast<const typename TestFixture::Record*>(buffer.data())->FileIndex);
}

TYPED_TEST(DirectoryRecordTest, RefusesATruncatedRecord)
{
  const SyntheticRecord<typename TestFixture::Record> synthetic(L"usvfs.txt", 0);
  const DirectoryRecord record(TestFixture::layout(),
                               synthetic.bytes().first(synthetic.size - sizeof(WCHAR)));
  std::vector<std::byte> buffer(0x400);
  DirectoryOutput output(buffer, TestFixture::layout(),
                         {.isSingleEntry = false, .isFirstCall = false});

  EXPECT_FALSE(output.append(record));
  EXPECT_FALSE(output.appendRenamed(record, L"usvfs.txt"));
  EXPECT_TRUE(output.isEmpty());
}

namespace
{

struct ListedQuery
{
  QueryOutcome outcome;
  // the bytes the status block reports, for a query that returned records, whole or
  // cut short
  std::vector<std::byte> data;
};

// The queries of a listing, which differ only in where they find the handle.
struct ListingQuery
{
  FILE_INFORMATION_CLASS informationClass;
  ULONG length;
  bool isSingleEntry;
  // nothing for a query without FileName
  std::optional<std::wstring_view> pattern;
  bool isRestart = false;
};

// Queries a directory with a status block that shows whether the query wrote it.
ListedQuery queryOnce(NtQueryDirectoryFile_type query, HANDLE directory,
                      const ListingQuery& listing)
{
  std::optional<usvfs::UnicodeString> fileName;
  if (listing.pattern) {
    fileName.emplace(listing.pattern->data(), listing.pattern->size());
  }
  std::vector<std::byte> buffer(listing.length);
  ListedQuery listed;
  listed.outcome.statusBlock.Status      = UNWRITTEN_STATUS;
  listed.outcome.statusBlock.Information = UNWRITTEN_INFORMATION;
  listed.outcome.result                  = query(
      directory, nullptr, nullptr, nullptr, &listed.outcome.statusBlock, buffer.data(),
      listing.length, listing.informationClass, listing.isSingleEntry,
      fileName ? static_cast<PUNICODE_STRING>(*fileName) : nullptr, listing.isRestart);
  if (listed.outcome.result == STATUS_SUCCESS ||
      listed.outcome.result == STATUS_BUFFER_OVERFLOW) {
    listed.data.assign(buffer.begin(),
                       buffer.begin() + listed.outcome.statusBlock.Information);
  }
  return listed;
}

// Lists a directory as queryOnce queries it, and returns every query up to the first
// that fails.
std::vector<ListedQuery> listQueries(NtQueryDirectoryFile_type query, HANDLE directory,
                                     const ListingQuery& listing)
{
  std::vector<ListedQuery> queries;
  do {
    queries.push_back(queryOnce(query, directory, listing));
  } while (queries.back().outcome.result == STATUS_SUCCESS);
  return queries;
}

// Lists a directory through ntdll, as listQueries does.
std::vector<ListedQuery> listNativeOutcomes(const std::filesystem::path& path,
                                            std::wstring_view pattern, ULONG length)
{
  const HANDLE directory = ::CreateFileW(
      path.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  EXPECT_NE(INVALID_HANDLE_VALUE, directory);
  std::vector<ListedQuery> queries =
      listQueries(nativeQueryDirectoryFile(), directory,
                  {FileDirectoryInformation, length, false, pattern});
  ::CloseHandle(directory);
  return queries;
}

// Writes the records of a native query to a DirectoryOutput that ends with them, and
// completes it with the status a fill of the output ended with.
QueryOutcome replay(const ListedQuery& native, bool isFirstCall, NTSTATUS fillStatus)
{
  const DirectoryRecordLayout layout =
      findDirectoryRecordLayout(FileDirectoryInformation).value();
  std::vector<std::byte> buffer(native.data.size());
  DirectoryOutput output(buffer, layout,
                         {.isSingleEntry = false, .isFirstCall = isFirstCall});
  if (!native.data.empty()) {
    for (const size_t offset : recordOffsets(layout, native.data)) {
      EXPECT_TRUE(output.append(
          DirectoryRecord(layout, std::span(native.data).subspan(offset))));
    }
  }

  QueryOutcome outcome;
  outcome.statusBlock.Status      = UNWRITTEN_STATUS;
  outcome.statusBlock.Information = UNWRITTEN_INFORMATION;
  outcome.result                  = output.complete(fillStatus, outcome.statusBlock);
  return outcome;
}

// Whether the filesystem pends the first query for a pattern instead of completing it
// at once, which only an asynchronous handle shows.
bool isFirstQueryPended(const std::filesystem::path& path, std::wstring_view pattern)
{
  const HANDLE directory = ::CreateFileW(
      path.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
  EXPECT_NE(INVALID_HANDLE_VALUE, directory);
  const HANDLE event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  usvfs::UnicodeString fileName(pattern.data(), pattern.size());

  IO_STATUS_BLOCK statusBlock;
  alignas(8) std::array<std::byte, 0x800> buffer;
  const NTSTATUS status = nativeQueryDirectoryFile()(
      directory, event, nullptr, nullptr, &statusBlock, buffer.data(),
      static_cast<ULONG>(buffer.size()), FileDirectoryInformation, FALSE,
      static_cast<PUNICODE_STRING>(fileName), FALSE);
  if (status == STATUS_PENDING) {
    // the query writes the buffer and status block until it completes
    ::WaitForSingleObject(event, INFINITE);
  }
  ::CloseHandle(event);
  ::CloseHandle(directory);
  return status == STATUS_PENDING;
}

}  // namespace

// ntdll is the reference for how the queries of a listing complete: a query reports
// its records whether its fill ran out of room or of records, and the end of the
// listing comes with the query after the last records.
TEST(DirectoryOutputTest, CompletesTheQueriesOfAListingLikeNtdll)
{
  for (const std::filesystem::path& directory : nativeListingDirectories()) {
    SCOPED_TRACE(describeDirectory(directory));
    const std::vector<ListedQuery> queries = listNativeOutcomes(directory, L"*", 0x800);
    ASSERT_LE(3u, queries.size());
    ASSERT_EQ(STATUS_NO_MORE_FILES, queries.back().outcome.result);

    for (size_t query = 0; query + 1 < queries.size(); ++query) {
      SCOPED_TRACE(query);
      for (const NTSTATUS fillStatus : {STATUS_SUCCESS, STATUS_NO_MORE_FILES}) {
        SCOPED_TRACE(fillStatus);
        expectSameOutcome(queries[query].outcome,
                          replay(queries[query], query == 0, fillStatus));
      }
    }
    expectSameOutcome(queries.back().outcome,
                      replay(queries.back(), false, STATUS_NO_MORE_FILES));
  }
}

// ntdll is the reference for a query that fails at once, as the queries of the hook
// do. The I/O manager writes the status block of a failed query only when the
// filesystem pended it (IopCompleteRequest checks Irp->PendingReturned), which ReFS
// does here and NTFS does not, so a pended query is a reference for the result only.
TEST(DirectoryOutputTest, FailsAQueryThatMatchesNothingLikeNtdll)
{
  constexpr std::wstring_view PATTERN = L"usvfs_no_such_file_*";
  for (const std::filesystem::path& directory : nativeListingDirectories()) {
    SCOPED_TRACE(describeDirectory(directory));
    const std::vector<ListedQuery> queries =
        listNativeOutcomes(directory, PATTERN, 0x800);
    ASSERT_EQ(1u, queries.size());
    const QueryOutcome actual = replay(queries.front(), true, STATUS_NO_MORE_FILES);

    if (isFirstQueryPended(directory, PATTERN)) {
      EXPECT_EQ(queries.front().outcome.result, actual.result);
      continue;
    }
    expectSameOutcome(queries.front().outcome, actual);
  }
}

TEST(DirectoryOutputTest, PassesAnErrorOnLikeNtdll)
{
  for (const std::filesystem::path& directory : nativeListingDirectories()) {
    SCOPED_TRACE(describeDirectory(directory));
    // shorter than any record, which ntdll rejects before the filesystem sees it
    const std::vector<ListedQuery> queries = listNativeOutcomes(directory, L"*", 1);
    ASSERT_EQ(1u, queries.size());
    ASSERT_EQ(STATUS_INFO_LENGTH_MISMATCH, queries.front().outcome.result);

    expectSameOutcome(queries.front().outcome,
                      replay(queries.front(), true, queries.front().outcome.result));
  }
}

// ntdll is the reference for a record that does not fit an empty buffer: it returns
// as many bytes of it as the buffer holds, with the full FileNameLength, whether the
// buffer ends within a character of the name or not
TYPED_TEST(DirectoryRecordTest, CutsARecordThatDoesNotFitLikeNtdll)
{
  const DirectoryRecordLayout layout    = TestFixture::layout();
  const std::filesystem::path directory = generatedListingDirectory();
  const std::wstring name(64, L'n');
  const auto queryNative = [&](ULONG length) {
    const HANDLE handle = ::CreateFileW(
        directory.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    EXPECT_NE(INVALID_HANDLE_VALUE, handle);
    const ListedQuery query = queryOnce(nativeQueryDirectoryFile(), handle,
                                        {layout.informationClass, length, false, name});
    ::CloseHandle(handle);
    return query;
  };
  const ListedQuery whole = queryNative(0x1000);
  ASSERT_EQ(STATUS_SUCCESS, whole.outcome.result);

  for (const ULONG length : {layout.minimumLength, layout.minimumLength + 1}) {
    SCOPED_TRACE(length);
    const ListedQuery cut = queryNative(length);
    ASSERT_EQ(STATUS_BUFFER_OVERFLOW, cut.outcome.result);
    std::vector<std::byte> buffer(length);
    DirectoryOutput output(buffer, layout,
                           {.isSingleEntry = false, .isFirstCall = true});

    EXPECT_FALSE(output.append(DirectoryRecord(layout, whole.data)));
    EXPECT_TRUE(output.isOverflowed());
    EXPECT_EQ(cut.outcome.statusBlock.Information, output.size());
    EXPECT_EQ(cut.data, buffer);
  }
}

namespace
{

// Expects the same record at an offset, but for the link to the next one.
void expectSameRecordAt(const DirectoryRecordLayout& layout,
                        std::span<const std::byte> expected,
                        std::span<const std::byte> actual, size_t offset)
{
  // past NextEntryOffset, the first field of every record
  constexpr size_t FIELDS_OFFSET = sizeof(ULONG);
  const size_t size = DirectoryRecord(layout, expected.subspan(offset)).size();
  ASSERT_LE(offset + size, actual.size()) << "record at " << offset;
  EXPECT_TRUE(
      std::ranges::equal(expected.subspan(offset + FIELDS_OFFSET, size - FIELDS_OFFSET),
                         actual.subspan(offset + FIELDS_OFFSET, size - FIELDS_OFFSET)))
      << "record at " << offset;
}

// Expects the same records at the same offsets; the padding between them is whatever
// the buffers held.
void expectSameRecords(const DirectoryRecordLayout& layout,
                       std::span<const std::byte> expected,
                       std::span<const std::byte> actual)
{
  ASSERT_EQ(expected.empty(), actual.empty());
  if (expected.empty()) {
    return;
  }
  const std::vector<size_t> offsets = recordOffsets(layout, expected);
  ASSERT_EQ(offsets, recordOffsets(layout, actual));
  for (const size_t offset : offsets) {
    expectSameRecordAt(layout, expected, actual, offset);
  }
}

HANDLE openHookedDirectory(const std::filesystem::path& path)
{
  return hooked_NtOpenFile(path.c_str(), FILE_GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
}

}  // namespace

// ntdll is the reference for the regular entries of a directory without virtual
// entries: the hook reads them from ntdll and has none to leave out or add
TEST_F(USVFSTest, NtQueryDirectoryFileListsRegularEntriesLikeNtdll)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));

  for (const std::filesystem::path& directory : nativeListingDirectories()) {
    for (const FILE_INFORMATION_CLASS informationClass :
         DIRECTORY_INFORMATION_CLASSES) {
      for (const bool isSingleEntry : {false, true}) {
        SCOPED_TRACE(std::format("{}, class {}, {}", describeDirectory(directory),
                                 static_cast<int>(informationClass),
                                 isSingleEntry ? "single entry" : "full buffer"));
        const ListingQuery listing{informationClass, 0x800, isSingleEntry, L"*"};
        // a query moves its handle through the directory, so ntdll and the hook each
        // list through a handle of their own
        HANDLE nativeHandle = openHookedDirectory(directory);
        HANDLE hookedHandle = openHookedDirectory(directory);
        ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
        ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

        const std::vector<ListedQuery> expected =
            listQueries(nativeQueryDirectoryFile(), nativeHandle, listing);
        const std::vector<ListedQuery> actual =
            listQueries(&usvfs::hook_NtQueryDirectoryFile, hookedHandle, listing);

        ASSERT_LE(2u, expected.size());
        ASSERT_EQ(expected.size(), actual.size());
        const DirectoryRecordLayout layout =
            findDirectoryRecordLayout(informationClass).value();
        for (size_t query = 0; query < expected.size(); ++query) {
          SCOPED_TRACE(query);
          expectSameOutcome(expected[query].outcome, actual[query].outcome);
          expectSameRecords(layout, expected[query].data, actual[query].data);
        }

        usvfs::hook_NtClose(nativeHandle);
        usvfs::hook_NtClose(hookedHandle);
      }
    }
  }
}

// ntdll is the reference for where the data of a query ends: with its last record,
// without the padding after it, also when the hook leaves out the shadowed records
// after it. Every entry but "." and ".." is shadowed here, so the first query holds
// the two, as ntdll returns them into a buffer that holds no more.
TEST_F(USVFSTest, NtQueryDirectoryFileEndsWithTheLastRegularEntryLikeNtdll)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  const std::vector<std::filesystem::path> directories = nativeListingDirectories();
  for (const std::filesystem::path& directory : directories) {
    for (const std::wstring& name : listWithFindFirstFile(directory)) {
      if (name != L"." && name != L"..") {
        ctx->redirectionTable().addFile((directory / name).c_str(),
                                        usvfs::RedirectionDataLocal(REAL_FILEA));
      }
    }
  }

  for (const std::filesystem::path& directory : directories) {
    for (const FILE_INFORMATION_CLASS informationClass :
         DIRECTORY_INFORMATION_CLASSES) {
      SCOPED_TRACE(std::format("{}, class {}", describeDirectory(directory),
                               static_cast<int>(informationClass)));
      const ListingQuery listing{informationClass, 0x800, false, L"*"};
      HANDLE nativeHandle = openHookedDirectory(directory);
      HANDLE hookedHandle = openHookedDirectory(directory);
      ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
      ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

      const ListedQuery native =
          queryOnce(nativeQueryDirectoryFile(), nativeHandle, listing);
      const ListedQuery hooked =
          queryOnce(&usvfs::hook_NtQueryDirectoryFile, hookedHandle, listing);

      const DirectoryRecordLayout layout =
          findDirectoryRecordLayout(informationClass).value();
      const std::vector<size_t> offsets = recordOffsets(layout, native.data);
      ASSERT_LE(3u, offsets.size()) << "no shadowed record follows \"..\"";
      const size_t end =
          offsets[1] +
          DirectoryRecord(layout, std::span(native.data).subspan(offsets[1])).size();
      QueryOutcome expected            = native.outcome;
      expected.statusBlock.Information = end;
      expectSameOutcome(expected, hooked.outcome);
      ASSERT_EQ((std::vector<size_t>{0, offsets[1]}),
                recordOffsets(layout, hooked.data));
      for (const size_t offset : {offsets[0], offsets[1]}) {
        expectSameRecordAt(layout, native.data, hooked.data, offset);
      }

      usvfs::hook_NtClose(nativeHandle);
      usvfs::hook_NtClose(hookedHandle);
    }
  }
}

namespace
{

// Expects the same fields between NextEntryOffset and FileName, but for the name's
// length and the 8.3 name, which a renamed record does not take from its file.
void expectSameFixedFields(const DirectoryRecordLayout& layout,
                           std::span<const std::byte> expected,
                           std::span<const std::byte> actual)
{
  ASSERT_LE(layout.fileNameOffset, expected.size());
  ASSERT_LE(layout.fileNameOffset, actual.size());
  for (size_t offset = sizeof(ULONG); offset < layout.fileNameOffset; ++offset) {
    const bool isFileNameLength = offset >= layout.fileNameLengthOffset &&
                                  offset < layout.fileNameLengthOffset + sizeof(ULONG);
    const bool isShortName = layout.shortName &&
                             offset >= layout.shortName->lengthOffset &&
                             offset < layout.shortName->offset + 12 * sizeof(WCHAR);
    if (!isFileNameLength && !isShortName) {
      EXPECT_EQ(expected[offset], actual[offset]) << "byte " << offset;
    }
  }
}

}  // namespace

// ntdll is the reference for a virtual entry: the record ntdll lists for the file the
// entry maps to, under the virtual name, reported up to the end of that name
TEST_F(USVFSTest, NtQueryDirectoryFileListsAVirtualEntryLikeNtdllListsItsFile)
{
  constexpr std::wstring_view VIRTUAL_NAME = L"usvfs_a_name_longer_than_notepad.exe";
  auto params                              = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  ctx->redirectionTable().addFile((L"C:\\" + std::wstring(VIRTUAL_NAME)).c_str(),
                                  usvfs::RedirectionDataLocal(REAL_FILEA));

  for (const FILE_INFORMATION_CLASS informationClass : DIRECTORY_INFORMATION_CLASSES) {
    SCOPED_TRACE(std::format("class {}", static_cast<int>(informationClass)));
    HANDLE nativeHandle = openHookedDirectory(L"C:\\Windows");
    HANDLE hookedHandle = openHookedDirectory(L"C:\\");
    ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
    ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

    const ListedQuery native =
        queryOnce(nativeQueryDirectoryFile(), nativeHandle,
                  {informationClass, 0x1000, false, L"notepad.exe"});
    const ListedQuery hooked =
        queryOnce(&usvfs::hook_NtQueryDirectoryFile, hookedHandle,
                  {informationClass, 0x1000, false, VIRTUAL_NAME});

    ASSERT_EQ(STATUS_SUCCESS, native.outcome.result);
    const DirectoryRecordLayout layout =
        findDirectoryRecordLayout(informationClass).value();
    QueryOutcome expected = native.outcome;
    expected.statusBlock.Information =
        layout.fileNameOffset + VIRTUAL_NAME.size() * sizeof(WCHAR);
    expectSameOutcome(expected, hooked.outcome);
    const DirectoryRecord record(layout, hooked.data);
    EXPECT_EQ(0u, record.nextEntryOffset());
    EXPECT_EQ(VIRTUAL_NAME, record.fileName());
    expectSameFixedFields(layout, native.data, hooked.data);

    usvfs::hook_NtClose(nativeHandle);
    usvfs::hook_NtClose(hookedHandle);
  }
}

// ntdll is the reference for a virtual entry whose file has a longer name: the record
// ntdll lists for the file, under the virtual name, in a buffer that holds it under
// that name only
TEST_F(USVFSTest, NtQueryDirectoryFileListsAVirtualEntryThatFitsWhereItsFileWouldNot)
{
  constexpr std::wstring_view VIRTUAL_NAME = L"usvfs_v.txt";
  constexpr std::wstring_view FILE_NAME =
      L"usvfs_a_name_longer_than_the_virtual_one.txt";
  const std::filesystem::path directory = test::path_of_test_temp(L"virtual_file");
  std::filesystem::create_directories(directory);
  std::ofstream(directory / FILE_NAME);
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  ctx->redirectionTable().addFile(
      (L"C:\\" + std::wstring(VIRTUAL_NAME)).c_str(),
      usvfs::RedirectionDataLocal((directory / FILE_NAME).string()));

  for (const FILE_INFORMATION_CLASS informationClass : DIRECTORY_INFORMATION_CLASSES) {
    SCOPED_TRACE(std::format("class {}", static_cast<int>(informationClass)));
    const DirectoryRecordLayout layout =
        findDirectoryRecordLayout(informationClass).value();
    const ULONG length =
        layout.fileNameOffset + static_cast<ULONG>(VIRTUAL_NAME.size() * sizeof(WCHAR));
    HANDLE nativeHandle = openHookedDirectory(directory);
    HANDLE hookedHandle = openHookedDirectory(L"C:\\");
    ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
    ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

    const ListedQuery native = queryOnce(nativeQueryDirectoryFile(), nativeHandle,
                                         {informationClass, 0x1000, false, FILE_NAME});
    const ListedQuery hooked =
        queryOnce(&usvfs::hook_NtQueryDirectoryFile, hookedHandle,
                  {informationClass, length, false, VIRTUAL_NAME});

    ASSERT_EQ(STATUS_SUCCESS, native.outcome.result);
    QueryOutcome expected            = native.outcome;
    expected.statusBlock.Information = length;
    expectSameOutcome(expected, hooked.outcome);
    const DirectoryRecord record(layout, hooked.data);
    EXPECT_EQ(0u, record.nextEntryOffset());
    EXPECT_EQ(VIRTUAL_NAME, record.fileName());
    expectSameFixedFields(layout, native.data, hooked.data);

    usvfs::hook_NtClose(nativeHandle);
    usvfs::hook_NtClose(hookedHandle);
  }
}

// ntdll is the reference for a first record that does not fit: it returns as much of
// it as fits, with STATUS_BUFFER_OVERFLOW, again on every query until a buffer holds
// it, and the listing goes on from there
TEST_F(USVFSTest, NtQueryDirectoryFileListsPastAPartialRecordLikeNtdll)
{
  // queries enough to list either directory several times over
  constexpr size_t MAXIMUM_QUERIES = 1000;
  auto params                      = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));

  for (const std::filesystem::path& directory : nativeListingDirectories()) {
    for (const FILE_INFORMATION_CLASS informationClass :
         DIRECTORY_INFORMATION_CLASSES) {
      SCOPED_TRACE(std::format("{}, class {}", describeDirectory(directory),
                               static_cast<int>(informationClass)));
      const DirectoryRecordLayout layout =
          findDirectoryRecordLayout(informationClass).value();
      // a query moves its handle through the directory, so ntdll and the hook each
      // list through a handle of their own
      HANDLE nativeHandle = openHookedDirectory(directory);
      HANDLE hookedHandle = openHookedDirectory(directory);
      ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
      ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

      std::vector<ListedQuery> expected;
      std::vector<ListedQuery> actual;
      const auto queryBoth = [&](ULONG length) {
        const ListingQuery listing{informationClass, length, false, L"*"};
        expected.push_back(
            queryOnce(nativeQueryDirectoryFile(), nativeHandle, listing));
        actual.push_back(
            queryOnce(&usvfs::hook_NtQueryDirectoryFile, hookedHandle, listing));
        return expected.back().outcome.result;
      };
      // the smallest buffer ntdll accepts, which a longer name overflows
      while (queryBoth(layout.minimumLength) == STATUS_SUCCESS &&
             expected.size() < MAXIMUM_QUERIES) {
      }
      ASSERT_EQ(STATUS_BUFFER_OVERFLOW, expected.back().outcome.result);
      queryBoth(layout.minimumLength);
      while (queryBoth(0x1000) == STATUS_SUCCESS && expected.size() < MAXIMUM_QUERIES) {
      }
      ASSERT_EQ(STATUS_NO_MORE_FILES, expected.back().outcome.result);

      for (size_t query = 0; query < expected.size(); ++query) {
        SCOPED_TRACE(query);
        expectSameOutcome(expected[query].outcome, actual[query].outcome);
        if (expected[query].outcome.result == STATUS_BUFFER_OVERFLOW) {
          EXPECT_EQ(expected[query].data, actual[query].data) << "the partial record";
        } else {
          expectSameRecords(layout, expected[query].data, actual[query].data);
        }
      }

      usvfs::hook_NtClose(nativeHandle);
      usvfs::hook_NtClose(hookedHandle);
    }
  }
}

// ntdll is the reference for a virtual entry that does not fit: the record it cuts
// short for a file of the virtual name, with the fields of the file the entry maps to
TEST_F(USVFSTest, NtQueryDirectoryFileCutsAVirtualEntryThatDoesNotFitLikeNtdll)
{
  constexpr std::wstring_view VIRTUAL_NAME = L"usvfs_a_name_longer_than_notepad.exe";
  const std::filesystem::path namesakeDirectory =
      test::path_of_test_temp(L"virtual_namesake");
  std::filesystem::create_directories(namesakeDirectory);
  std::ofstream(namesakeDirectory / VIRTUAL_NAME);
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  ctx->redirectionTable().addFile((L"C:\\" + std::wstring(VIRTUAL_NAME)).c_str(),
                                  usvfs::RedirectionDataLocal(REAL_FILEA));

  for (const FILE_INFORMATION_CLASS informationClass : DIRECTORY_INFORMATION_CLASSES) {
    const DirectoryRecordLayout layout =
        findDirectoryRecordLayout(informationClass).value();
    HANDLE fileHandle = openHookedDirectory(L"C:\\Windows");
    ASSERT_NE(INVALID_HANDLE_VALUE, fileHandle);
    const ListedQuery file =
        queryOnce(nativeQueryDirectoryFile(), fileHandle,
                  {informationClass, 0x1000, false, L"notepad.exe"});
    ASSERT_EQ(STATUS_SUCCESS, file.outcome.result);
    usvfs::hook_NtClose(fileHandle);

    // the first holds neither the record of the file the entry maps to nor the one
    // under the virtual name, the second holds the record of the file only
    for (const ULONG length :
         {layout.minimumLength, static_cast<ULONG>(file.data.size())}) {
      SCOPED_TRACE(std::format("class {}, length {}",
                               static_cast<int>(informationClass), length));
      HANDLE namesakeHandle = openHookedDirectory(namesakeDirectory);
      HANDLE hookedHandle   = openHookedDirectory(L"C:\\");
      ASSERT_NE(INVALID_HANDLE_VALUE, namesakeHandle);
      ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

      const ListedQuery namesake =
          queryOnce(nativeQueryDirectoryFile(), namesakeHandle,
                    {informationClass, length, false, VIRTUAL_NAME});
      const ListedQuery hooked =
          queryOnce(&usvfs::hook_NtQueryDirectoryFile, hookedHandle,
                    {informationClass, length, false, VIRTUAL_NAME});

      ASSERT_EQ(STATUS_BUFFER_OVERFLOW, namesake.outcome.result);
      expectSameOutcome(namesake.outcome, hooked.outcome);
      ASSERT_EQ(namesake.data.size(), hooked.data.size());
      const DirectoryRecord record(layout, hooked.data);
      EXPECT_EQ(0u, record.nextEntryOffset());
      EXPECT_EQ(DirectoryRecord(layout, namesake.data).size(), record.size());
      EXPECT_TRUE(
          std::ranges::equal(std::span(namesake.data).subspan(layout.fileNameOffset),
                             std::span(hooked.data).subspan(layout.fileNameOffset)))
          << "the name, as much of it as fits";
      expectSameFixedFields(layout, file.data, hooked.data);

      usvfs::hook_NtClose(namesakeHandle);
      usvfs::hook_NtClose(hookedHandle);
    }
  }
}

// ntdll is the reference for what follows the partial record of a virtual entry, as
// it lists a file of the virtual name: the same partial record on every query until a
// buffer holds the entry, then the entry, then the end of the listing
TEST_F(USVFSTest, NtQueryDirectoryFileListsPastAVirtualPartialRecordLikeNtdll)
{
  constexpr std::wstring_view VIRTUAL_NAME = L"usvfs_a_name_longer_than_notepad.exe";
  const std::filesystem::path namesakeDirectory =
      test::path_of_test_temp(L"virtual_namesake");
  std::filesystem::create_directories(namesakeDirectory);
  std::ofstream(namesakeDirectory / VIRTUAL_NAME);
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  ctx->redirectionTable().addFile((L"C:\\" + std::wstring(VIRTUAL_NAME)).c_str(),
                                  usvfs::RedirectionDataLocal(REAL_FILEA));

  for (const FILE_INFORMATION_CLASS informationClass : DIRECTORY_INFORMATION_CLASSES) {
    SCOPED_TRACE(std::format("class {}", static_cast<int>(informationClass)));
    const DirectoryRecordLayout layout =
        findDirectoryRecordLayout(informationClass).value();
    // holds the record of the file the entry maps to, and not the one under the
    // virtual name
    const ULONG cutLength = layout.fileNameOffset +
                            static_cast<ULONG>(sizeof(L"notepad.exe") - sizeof(WCHAR));
    // a query moves its handle through the directory, so ntdll and the hook each list
    // through a handle of their own
    HANDLE namesakeHandle = openHookedDirectory(namesakeDirectory);
    HANDLE hookedHandle   = openHookedDirectory(L"C:\\");
    ASSERT_NE(INVALID_HANDLE_VALUE, namesakeHandle);
    ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

    std::vector<ListedQuery> expected;
    std::vector<ListedQuery> actual;
    for (const ULONG length : {cutLength, cutLength, 0x1000ul, 0x1000ul}) {
      const ListingQuery listing{informationClass, length, false, VIRTUAL_NAME};
      expected.push_back(
          queryOnce(nativeQueryDirectoryFile(), namesakeHandle, listing));
      actual.push_back(
          queryOnce(&usvfs::hook_NtQueryDirectoryFile, hookedHandle, listing));
    }
    ASSERT_EQ(STATUS_BUFFER_OVERFLOW, expected[1].outcome.result);
    ASSERT_EQ(STATUS_NO_MORE_FILES, expected.back().outcome.result);

    for (size_t query = 0; query < expected.size(); ++query) {
      SCOPED_TRACE(query);
      expectSameOutcome(expected[query].outcome, actual[query].outcome);
      ASSERT_EQ(expected[query].data.size(), actual[query].data.size());
      if (expected[query].data.empty()) {
        continue;
      }
      // the fields before the name are those of the file the entry maps to
      EXPECT_EQ(DirectoryRecord(layout, expected[query].data).size(),
                DirectoryRecord(layout, actual[query].data).size());
      EXPECT_TRUE(std::ranges::equal(
          std::span(expected[query].data).subspan(layout.fileNameOffset),
          std::span(actual[query].data).subspan(layout.fileNameOffset)))
          << "the name, as much of it as fits";
    }

    usvfs::hook_NtClose(namesakeHandle);
    usvfs::hook_NtClose(hookedHandle);
  }
}

// ntdll is the reference for a directory read that fails, also where virtual entries
// would follow: the error, on every query. The I/O manager refuses a handle without
// FILE_LIST_DIRECTORY before the filesystem sees the query, so every filesystem fails
// it alike.
TEST_F(USVFSTest, NtQueryDirectoryFilePassesAFailedRegularReadOnLikeNtdll)
{
  // from ntstatus.h, which ntdll_declarations.h copies only what usvfs uses of
  constexpr auto STATUS_ACCESS_DENIED = static_cast<NTSTATUS>(0xC0000022L);

  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  const std::vector<std::filesystem::path> directories = nativeListingDirectories();
  for (const std::filesystem::path& directory : directories) {
    ctx->redirectionTable().addFile((directory / L"usvfs_virtual.txt").c_str(),
                                    usvfs::RedirectionDataLocal(REAL_FILEA));
  }

  for (const std::filesystem::path& directory : directories) {
    SCOPED_TRACE(describeDirectory(directory));
    const auto openUnlistable = [&] {
      return hooked_NtOpenFile(directory.c_str(), FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    };
    HANDLE nativeHandle = openUnlistable();
    HANDLE hookedHandle = openUnlistable();
    ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
    ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

    const ListingQuery listing{FileDirectoryInformation, 0x1000, false, L"*"};
    for (int query = 0; query < 2; ++query) {
      SCOPED_TRACE(query);
      const ListedQuery expected =
          queryOnce(nativeQueryDirectoryFile(), nativeHandle, listing);
      const ListedQuery actual =
          queryOnce(&usvfs::hook_NtQueryDirectoryFile, hookedHandle, listing);
      ASSERT_EQ(STATUS_ACCESS_DENIED, expected.outcome.result);
      expectSameOutcome(expected.outcome, actual.outcome);
    }

    usvfs::hook_NtClose(nativeHandle);
    usvfs::hook_NtClose(hookedHandle);
  }
}

// ntdll is the reference for a restart in the middle of a listing: what the scan
// lists from there with the pattern the restart brings, or without one
TEST_F(USVFSTest, NtQueryDirectoryFileRestartsTheRegularEntriesLikeNtdll)
{
  // queries enough to list either directory several times over
  constexpr size_t MAXIMUM_QUERIES = 1000;
  struct Restart
  {
    std::wstring_view firstPattern;
    std::optional<std::wstring_view> restartPattern;
  };
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));

  for (const std::filesystem::path& directory : nativeListingDirectories()) {
    for (const Restart& restart :
         {Restart{L"*", L"*"}, Restart{L"*", L"n*"}, Restart{L"n*", std::nullopt}}) {
      SCOPED_TRACE(std::format(
          "{}, {} then {}", describeDirectory(directory),
          std::filesystem::path(restart.firstPattern).string(),
          std::filesystem::path(restart.restartPattern.value_or(L"<null>")).string()));
      const DirectoryRecordLayout layout =
          findDirectoryRecordLayout(FileDirectoryInformation).value();
      // a query moves its handle through the directory, so ntdll and the hook each
      // list through a handle of their own
      HANDLE nativeHandle = openHookedDirectory(directory);
      HANDLE hookedHandle = openHookedDirectory(directory);
      ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
      ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

      std::vector<ListedQuery> expected;
      std::vector<ListedQuery> actual;
      const auto queryBoth = [&](const ListingQuery& listing) {
        expected.push_back(
            queryOnce(nativeQueryDirectoryFile(), nativeHandle, listing));
        actual.push_back(
            queryOnce(&usvfs::hook_NtQueryDirectoryFile, hookedHandle, listing));
        return expected.back().outcome.result;
      };
      // small enough for the listing to go on after it
      ASSERT_EQ(STATUS_SUCCESS, queryBoth({FileDirectoryInformation, 0x800, false,
                                           restart.firstPattern}));
      NTSTATUS result = queryBoth(
          {FileDirectoryInformation, 0x800, false, restart.restartPattern, true});
      while (result == STATUS_SUCCESS && expected.size() < MAXIMUM_QUERIES) {
        result = queryBoth({FileDirectoryInformation, 0x800, false, L"*"});
      }
      ASSERT_EQ(STATUS_NO_MORE_FILES, result);

      for (size_t query = 0; query < expected.size(); ++query) {
        SCOPED_TRACE(query);
        expectSameOutcome(expected[query].outcome, actual[query].outcome);
        expectSameRecords(layout, expected[query].data, actual[query].data);
      }

      usvfs::hook_NtClose(nativeHandle);
      usvfs::hook_NtClose(hookedHandle);
    }
  }
}

// ntdll is the reference for a restart that matches nothing: STATUS_NO_MORE_FILES,
// as NTFS and ReFS keep STATUS_NO_SUCH_FILE for the first query of a handle. A
// filesystem that pends the query reports it in the status block too (see
// FailsAQueryThatMatchesNothingLikeNtdll), so a pended one is a reference for the
// result only.
TEST_F(USVFSTest, NtQueryDirectoryFileEndsAnEmptyRestartLikeNtdll)
{
  constexpr std::wstring_view NO_MATCH = L"usvfs_no_such_file_*";
  auto params                          = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));

  for (const std::filesystem::path& directory : nativeListingDirectories()) {
    SCOPED_TRACE(describeDirectory(directory));
    HANDLE nativeHandle = openHookedDirectory(directory);
    HANDLE hookedHandle = openHookedDirectory(directory);
    ASSERT_NE(INVALID_HANDLE_VALUE, nativeHandle);
    ASSERT_NE(INVALID_HANDLE_VALUE, hookedHandle);

    const bool isPended = isFirstQueryPended(directory, NO_MATCH);
    for (const ListingQuery& listing :
         {ListingQuery{FileDirectoryInformation, 0x800, false, L"*"},
          ListingQuery{FileDirectoryInformation, 0x800, false, NO_MATCH, true},
          ListingQuery{FileDirectoryInformation, 0x800, false, L"*"}}) {
      SCOPED_TRACE(listing.isRestart ? "restart" : "query");
      const ListedQuery expected =
          queryOnce(nativeQueryDirectoryFile(), nativeHandle, listing);
      const ListedQuery actual =
          queryOnce(&usvfs::hook_NtQueryDirectoryFile, hookedHandle, listing);
      if (listing.isRestart && isPended) {
        EXPECT_EQ(expected.outcome.result, actual.outcome.result);
      } else {
        expectSameOutcome(expected.outcome, actual.outcome);
      }
      EXPECT_EQ(expected.data.size(), actual.data.size());
    }

    usvfs::hook_NtClose(nativeHandle);
    usvfs::hook_NtClose(hookedHandle);
  }
}
