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

struct NativeQuery
{
  QueryOutcome outcome;
  // the bytes the status block reports, for a query that succeeded
  std::vector<std::byte> data;
};

// Lists a directory through ntdll with status blocks that show whether a query wrote
// them, and returns every query up to the first that fails.
std::vector<NativeQuery> listNativeOutcomes(const std::filesystem::path& path,
                                            std::wstring_view pattern, ULONG length)
{
  const HANDLE directory = ::CreateFileW(
      path.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  EXPECT_NE(INVALID_HANDLE_VALUE, directory);
  usvfs::UnicodeString fileName(pattern.data(), pattern.size());

  std::vector<NativeQuery> queries;
  std::vector<std::byte> buffer(length);
  do {
    NativeQuery& query                    = queries.emplace_back();
    query.outcome.statusBlock.Status      = UNWRITTEN_STATUS;
    query.outcome.statusBlock.Information = UNWRITTEN_INFORMATION;
    query.outcome.result                  = nativeQueryDirectoryFile()(
        directory, nullptr, nullptr, nullptr, &query.outcome.statusBlock, buffer.data(),
        length, FileDirectoryInformation, FALSE, static_cast<PUNICODE_STRING>(fileName),
        FALSE);
    if (query.outcome.result == STATUS_SUCCESS) {
      query.data.assign(buffer.begin(),
                        buffer.begin() + query.outcome.statusBlock.Information);
    }
  } while (queries.back().outcome.result == STATUS_SUCCESS);
  ::CloseHandle(directory);
  return queries;
}

// Writes the records of a native query to a DirectoryOutput that ends with them, and
// completes it with the status a fill of the output ended with.
QueryOutcome replay(const NativeQuery& native, bool isFirstCall, NTSTATUS fillStatus)
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
    const std::vector<NativeQuery> queries = listNativeOutcomes(directory, L"*", 0x800);
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
    const std::vector<NativeQuery> queries =
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
    const std::vector<NativeQuery> queries = listNativeOutcomes(directory, L"*", 1);
    ASSERT_EQ(1u, queries.size());
    ASSERT_EQ(STATUS_INFO_LENGTH_MISMATCH, queries.front().outcome.result);

    expectSameOutcome(queries.front().outcome,
                      replay(queries.front(), true, queries.front().outcome.result));
  }
}
