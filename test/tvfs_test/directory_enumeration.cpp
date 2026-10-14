// this file depends on so many stuff that the easiest way is to include
// pch.h from shared
#include "pch.h"

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
