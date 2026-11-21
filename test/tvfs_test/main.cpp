/*
Userspace Virtual Filesystem

Copyright (C) 2015 Sebastian Herbord. All rights reserved.

This file is part of usvfs.

usvfs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

usvfs is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with usvfs. If not, see <http://www.gnu.org/licenses/>.
*/

// this file depends on so many stuff that the easiest way is to include
// pch.h from shared
#include "pch.h"

#include <test_helpers.h>

#include <climits>
#include <fstream>
#include <iostream>

#include <inject.h>
#include <stringutils.h>
#include <windows_sane.h>

#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/spdlog.h>

#include <hookcontext.h>
#include <hooks/kernel32.h>
#include <hooks/ntdll.h>
#include <logging.h>
#include <stringcast.h>
#include <unicodestring.h>
#include <usvfs.h>

#include <gtest/gtest.h>

#include "tvfs_test.h"

namespace spd = spdlog;

namespace ush = usvfs::shared;

// name of a file to be created in the virtual fs. Shouldn't exist on disc but the
// directory must exist
static LPCSTR VIRTUAL_FILEA  = "C:/np.exe";
static LPCWSTR VIRTUAL_FILEW = L"C:/np.exe";

static LPCSTR REAL_DIRA  = "C:/windows/Logs";
static LPCWSTR REAL_DIRW = L"C:/windows/Logs";

static std::shared_ptr<spdlog::logger> logger()
{
  std::shared_ptr<spdlog::logger> result = spdlog::get("test");
  if (result.get() == nullptr) {
    result = spdlog::stdout_logger_mt("test");
  }
  return result;
}

class USVFSTestWithReroute : public testing::Test
{
public:
  void SetUp()
  {
    SHMLogger::create("usvfs");
    // need to initialize logging in the context of the dll
    usvfsInitLogging();

    auto params = defaultUsvfsParams();
    m_Context.reset(usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
    usvfs::RedirectionTreeContainer& tree = m_Context->redirectionTable();
    tree.addFile(
        ush::string_cast<std::string>(VIRTUAL_FILEW, ush::CodePage::UTF8).c_str(),
        usvfs::RedirectionDataLocal(REAL_FILEA));
  }

  void TearDown()
  {
    std::array<char, 1024> buffer;
    while (SHMLogger::instance().tryGet(buffer.data(), buffer.size())) {
      std::cout << buffer.data() << std::endl;
    }
    m_Context.reset();
    SHMLogger::free();
  }

private:
  std::unique_ptr<usvfs::HookContext> m_Context;
};

class USVFSTestAuto : public testing::Test
{
public:
  void SetUp()
  {
    auto params = defaultUsvfsParams();
    usvfsConnectVFS(params.get());
    SHMLogger::create("usvfs");
  }

  void TearDown()
  {
    usvfsDisconnectVFS();

    std::array<char, 1024> buffer;
    while (SHMLogger::instance().tryGet(buffer.data(), buffer.size())) {
      std::cout << buffer.data() << std::endl;
    }
    SHMLogger::free();
  }

private:
};

TEST_F(USVFSTest, CanResizeRedirectiontree)
{
  using usvfs::shared::MissingThrow;
  ASSERT_NO_THROW({
    usvfs::RedirectionTreeContainer container("treetest_shm", 1024);
    for (char i = 'a'; i <= 'z'; ++i) {
      for (char j = 'a'; j <= 'z'; ++j) {
        std::string name = std::string(R"(C:\temp\)") + i + j;
        container.addFile(name, usvfs::RedirectionDataLocal("gaga"), false);
      }
    }

    ASSERT_EQ("gaga", container->node("C:")
                          ->node("temp")
                          ->node("aa", MissingThrow)
                          ->data()
                          .linkTarget);
    ASSERT_EQ("gaga", container->node("C:")
                          ->node("temp")
                          ->node("az", MissingThrow)
                          ->data()
                          .linkTarget);
  });
}

/*
TEST_F(USVFSTest, CreateFileHookReportsCorrectErrorOnMissingFile)
{
  ASSERT_NO_THROW({
    USVFSParameters params;
    USVFSInitParameters(&params, "usvfs_test", true, LogLevel::Debug,
CrashDumpsType::None, ""); std::unique_ptr<usvfs::HookContext>
ctx(CreateHookContext(params, ::GetModuleHandle(nullptr))); HANDLE res =
usvfs::hook_CreateFileW(VIRTUAL_FILEW , GENERIC_READ , FILE_SHARE_READ |
FILE_SHARE_WRITE , nullptr , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , nullptr);

    ASSERT_EQ(INVALID_HANDLE_VALUE, res);
    ASSERT_EQ(ERROR_FILE_NOT_FOUND, ::GetLastError());
  });
}
*/

/*
TEST_F(USVFSTestWithReroute, CreateFileHookRedirectsFile)
{
  ASSERT_NE(INVALID_HANDLE_VALUE
            , usvfs::hook_CreateFileW(VIRTUAL_FILEW
                                  , GENERIC_READ
                                  , FILE_SHARE_READ | FILE_SHARE_WRITE
                                  , nullptr
                                  , OPEN_EXISTING
                                  , FILE_ATTRIBUTE_NORMAL
                                  , nullptr));
}
*/

TEST_F(USVFSTest, GetFileAttributesHookReportsCorrectErrorOnMissingFile)
{
  ASSERT_NO_THROW({
    try {
      auto params = defaultUsvfsParams();
      std::unique_ptr<usvfs::HookContext> ctx(
          usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
      DWORD res = usvfs::hook_GetFileAttributesW(VIRTUAL_FILEW);

      ASSERT_EQ(INVALID_FILE_ATTRIBUTES, res);
      ASSERT_EQ(ERROR_FILE_NOT_FOUND, ::GetLastError());
    } catch (const std::exception& e) {
      logger()->error("Exception: {}", e.what());
      throw;
    }
  });
}

TEST_F(USVFSTest, GetFileAttributesHookRedirectsFile)
{
  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  usvfs::RedirectionTreeContainer& tree = ctx->redirectionTable();

  tree.addFile(
      ush::string_cast<std::string>(VIRTUAL_FILEW, ush::CodePage::UTF8).c_str(),
      usvfs::RedirectionDataLocal(REAL_FILEA));

  ASSERT_EQ(::GetFileAttributesW(REAL_FILEW),
            usvfs::hook_GetFileAttributesW(VIRTUAL_FILEW));
}

TEST_F(USVFSTest, GetCurrentDirectoryAHookReportsRequiredSize)
{
  const DWORD expected = ::GetCurrentDirectoryA(0, nullptr);
  ASSERT_NE(0UL, expected);
  char tooSmall[1];

  EXPECT_EQ(expected, usvfs::hook_GetCurrentDirectoryA(0, nullptr));
  EXPECT_EQ(expected, usvfs::hook_GetCurrentDirectoryA(1, tooSmall));
}

TEST_F(USVFSTest, GetCurrentDirectoryAHookCopiesDirectory)
{
  char expected[MAX_PATH];
  const DWORD expectedLength = ::GetCurrentDirectoryA(MAX_PATH, expected);
  ASSERT_NE(0UL, expectedLength);
  char actual[MAX_PATH];

  EXPECT_EQ(expectedLength, usvfs::hook_GetCurrentDirectoryA(MAX_PATH, actual));
  EXPECT_STREQ(expected, actual);
}

TEST_F(USVFSTest, GetCurrentDirectoryAHookTakesBufferLengthBeyondInt)
{
  char expected[MAX_PATH];
  const DWORD expectedLength = ::GetCurrentDirectoryA(MAX_PATH, expected);
  ASSERT_NE(0UL, expectedLength);
  // the hook writes only the directory and its terminating null
  char actual[MAX_PATH];
  const DWORD beyondInt = static_cast<DWORD>(INT_MAX) + 1;

  EXPECT_EQ(expectedLength, usvfs::hook_GetCurrentDirectoryA(beyondInt, actual));
  EXPECT_STREQ(expected, actual);
}

TEST_F(USVFSTest, GetCurrentDirectoryAHookFailsWithConversionError)
{
  ::SetLastError(ERROR_SUCCESS);

  EXPECT_EQ(0UL, usvfs::hook_GetCurrentDirectoryA(MAX_PATH, nullptr));
  EXPECT_EQ(static_cast<DWORD>(ERROR_INVALID_PARAMETER), ::GetLastError());
}
/*
TEST_F(USVFSTest, GetFullPathNameOnRegularCurrentDirectory)
{
  USVFSParameters params;
  USVFSInitParameters(&params, "usvfs_test", true, LogLevel::Debug,
CrashDumpsType::None, ""); std::unique_ptr<usvfs::HookContext>
ctx(CreateHookContext(params, ::GetModuleHandle(nullptr)));

  std::wstring expected = winapi::wide::getCurrentDirectory() + L"\\filename.txt";

  DWORD bufferLength = 32767;
  std::unique_ptr<wchar_t[]> buffer(new wchar_t[bufferLength]);
  LPWSTR filePart = nullptr;

  DWORD res = usvfs::hook_GetFullPathNameW(L"filename.txt", bufferLength, buffer.get(),
&filePart);

  ASSERT_NE(0UL, res);
  ASSERT_EQ(expected, std::wstring(buffer.get()));
}*/

TEST_F(USVFSTest, NtQueryObjectVirtualFile)
{
  std::wstring c_drive_device;
  {
    // find the device path for C:
    HANDLE hdl = ::CreateFileW(
        L"C:\\", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    ASSERT_NE(INVALID_HANDLE_VALUE, hdl);

    char buffer[2048];
    ASSERT_EQ(STATUS_SUCCESS, ::NtQueryObject(hdl, ObjectNameInformation, buffer,
                                              sizeof(buffer), nullptr));

    OBJECT_NAME_INFORMATION* information =
        reinterpret_cast<OBJECT_NAME_INFORMATION*>(buffer);

    c_drive_device =
        std::wstring(information->Name.Buffer, information->Name.Length / 2);

    ::CloseHandle(hdl);
  }

  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  usvfs::RedirectionTreeContainer& tree = ctx->redirectionTable();

  tree.addFile(L"C:\\np.exe", usvfs::RedirectionDataLocal(REAL_FILEA));

  HANDLE hdl = hooked_NtOpenFile(L"C:\\np.exe", FILE_GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT);
  ASSERT_NE(INVALID_HANDLE_VALUE, hdl) << "last error=" << ::GetLastError();

  {
    char buffer[1024];
    IO_STATUS_BLOCK status;
    const auto res = usvfs::hook_NtQueryInformationFile(
        hdl, &status, buffer, sizeof(buffer), FileNameInformation);
    ASSERT_EQ(STATUS_SUCCESS, res);
    ASSERT_EQ(STATUS_SUCCESS, status.Status);

    FILE_NAME_INFORMATION* fileNameInfo =
        reinterpret_cast<FILE_NAME_INFORMATION*>(buffer);
    ASSERT_EQ(L"\\np.exe",
              std::wstring(fileNameInfo->FileName, fileNameInfo->FileNameLength / 2));
  }

  {
    char buffer[1024];
    IO_STATUS_BLOCK status;
    const auto res = usvfs::hook_NtQueryInformationFile(
        hdl, &status, buffer, sizeof(buffer), FileNormalizedNameInformation);
    ASSERT_EQ(STATUS_SUCCESS, res);
    ASSERT_EQ(STATUS_SUCCESS, status.Status);
    ASSERT_EQ(sizeof(ULONG) + 7 * 2, status.Information);

    FILE_NAME_INFORMATION* fileNameInfo =
        reinterpret_cast<FILE_NAME_INFORMATION*>(buffer);
    ASSERT_EQ(L"\\np.exe",
              std::wstring(fileNameInfo->FileName, fileNameInfo->FileNameLength / 2));
  }

  // buffer of size should be too small for the original path (\Windows\notepad.exe)
  // but not for \np.exe
  {
    // the required size should be sizeof(ULONG) + 7 * 2 but apparently that is
    // not enough for the CI so using 16 * 2 which should be large enough for
    // the hooked version, but still too short for the non-hooked one
    char buffer[sizeof(ULONG) + 7 * 2];
    IO_STATUS_BLOCK status;
    NTSTATUS res;

    res = ::NtQueryInformationFile(hdl, &status, buffer, sizeof(buffer),
                                   FileNameInformation);
    ASSERT_EQ(STATUS_BUFFER_OVERFLOW, res);
    ASSERT_EQ(STATUS_BUFFER_OVERFLOW, status.Status);

    res = usvfs::hook_NtQueryInformationFile(hdl, &status, buffer, sizeof(buffer),
                                             FileNameInformation);
    ASSERT_EQ(STATUS_SUCCESS, res);
    ASSERT_EQ(STATUS_SUCCESS, status.Status);
    ASSERT_EQ(sizeof(ULONG) + 7 * 2, status.Information);

    FILE_NAME_INFORMATION* fileNameInfo =
        reinterpret_cast<FILE_NAME_INFORMATION*>(buffer);
    ASSERT_EQ(L"\\np.exe",
              std::wstring(fileNameInfo->FileName, fileNameInfo->FileNameLength / 2));
  }

  {
    char buffer[2048];
    const auto res = usvfs::hook_NtQueryObject(hdl, ObjectNameInformation, buffer,
                                               sizeof(buffer), nullptr);
    ASSERT_EQ(STATUS_SUCCESS, res);

    OBJECT_NAME_INFORMATION* information =
        reinterpret_cast<OBJECT_NAME_INFORMATION*>(buffer);
    ASSERT_EQ(c_drive_device + L"np.exe",
              std::wstring(information->Name.Buffer,
                           information->Name.Length / sizeof(wchar_t)));
  }

  {
    // expected length is sizeof struct + size of path (in bytes), including the
    // null-character
    const auto expectedLength =
        sizeof(OBJECT_NAME_INFORMATION) + c_drive_device.size() * 2 + 12 + 2;
    ULONG requiredLength;
    NTSTATUS res;
    char buffer[2048];

    res =
        usvfs::hook_NtQueryObject(hdl, ObjectNameInformation, buffer,
                                  sizeof(OBJECT_NAME_INFORMATION) - 1, &requiredLength);
    ASSERT_EQ(STATUS_INFO_LENGTH_MISMATCH, res);
    ASSERT_EQ(expectedLength, requiredLength);

    res = usvfs::hook_NtQueryObject(hdl, ObjectNameInformation, buffer,
                                    sizeof(OBJECT_NAME_INFORMATION), &requiredLength);
    ASSERT_EQ(STATUS_BUFFER_OVERFLOW, res);
    ASSERT_EQ(expectedLength, requiredLength);
  }

  usvfs::hook_NtClose(hdl);
}

namespace
{

std::wstring objectNameOf(HANDLE handle, NtQueryObject_type queryObject)
{
  // room for the longest name a UNICODE_STRING holds and its terminator
  std::vector<char> buffer(sizeof(OBJECT_NAME_INFORMATION) + 65536);
  EXPECT_EQ(STATUS_SUCCESS, queryObject(handle, ObjectNameInformation, buffer.data(),
                                        static_cast<ULONG>(buffer.size()), nullptr));
  const auto* information =
      reinterpret_cast<const OBJECT_NAME_INFORMATION*>(buffer.data());
  return std::wstring(information->Name.Buffer,
                      information->Name.Length / sizeof(wchar_t));
}

}  // namespace

TEST_F(USVFSTest, NtQueryObjectVirtualFileBelowVirtualDirectory)
{
  // the closest existing ancestor is a directory, which the system names without the
  // trailing separator it gives the root of a drive
  const std::wstring existingDirectory = LR"(C:\Users\Public)";
  const HANDLE directory =
      ::CreateFileW(existingDirectory.c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  ASSERT_NE(INVALID_HANDLE_VALUE, directory) << "last error=" << ::GetLastError();
  const std::wstring directoryName = objectNameOf(directory, ::NtQueryObject);
  ::CloseHandle(directory);

  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> context(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  const std::wstring virtualFile =
      existingDirectory + LR"(\tvfs_virtual_dir\virtual.ini)";
  context->redirectionTable().addFile(virtualFile,
                                      usvfs::RedirectionDataLocal(REAL_FILEA));
  const HANDLE file =
      hooked_NtOpenFile(virtualFile.c_str(), FILE_GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE);
  ASSERT_NE(INVALID_HANDLE_VALUE, file) << "last error=" << ::GetLastError();

  EXPECT_EQ(directoryName + LR"(\tvfs_virtual_dir\virtual.ini)",
            objectNameOf(file, usvfs::hook_NtQueryObject));
  usvfs::hook_NtClose(file);
}

namespace
{

// a real directory with an 8.3 alias on most volumes; the tests that need an alias
// skip where it has none
constexpr LPCWSTR ALIASED_DIRW = L"C:\\Program Files";

// a virtual file in ALIASED_DIRW
constexpr LPCWSTR ALIASED_DIR_FILE_NAMEW = L"usvfs_short_name.exe";
constexpr LPCWSTR ALIASED_DIR_FILEW      = L"C:\\Program Files\\usvfs_short_name.exe";

// the 8.3 form of a real path, which is the path itself without aliases
std::wstring shortPathOf(LPCWSTR path)
{
  std::array<wchar_t, MAX_PATH> buffer{};
  const DWORD length =
      ::GetShortPathNameW(path, buffer.data(), static_cast<DWORD>(buffer.size()));
  return length > 0 && length < buffer.size() ? std::wstring(buffer.data(), length)
                                              : std::wstring(path);
}

}  // namespace

TEST_F(USVFSTest, GetFileAttributesHookRedirectsShortNamePath)
{
  const std::wstring shortDirectory = shortPathOf(ALIASED_DIRW);
  if (shortDirectory == ALIASED_DIRW) {
    GTEST_SKIP() << ALIASED_DIRW << " has no 8.3 alias";
  }

  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  ctx->redirectionTable().addFile(ALIASED_DIR_FILEW,
                                  usvfs::RedirectionDataLocal(REAL_FILEA));

  const std::wstring shortFile = shortDirectory + L"\\" + ALIASED_DIR_FILE_NAMEW;
  ASSERT_EQ(::GetFileAttributesW(REAL_FILEW),
            usvfs::hook_GetFileAttributesW(shortFile.c_str()));
}

TEST_F(USVFSTest, NtOpenFileHookRedirectsShortNamePath)
{
  const std::wstring shortDirectory = shortPathOf(ALIASED_DIRW);
  if (shortDirectory == ALIASED_DIRW) {
    GTEST_SKIP() << ALIASED_DIRW << " has no 8.3 alias";
  }

  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  ctx->redirectionTable().addFile(ALIASED_DIR_FILEW,
                                  usvfs::RedirectionDataLocal(REAL_FILEA));

  const std::wstring shortFile = shortDirectory + L"\\" + ALIASED_DIR_FILE_NAMEW;
  HANDLE hdl = hooked_NtOpenFile(shortFile.c_str(), FILE_GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT);
  ASSERT_NE(INVALID_HANDLE_VALUE, hdl);

  usvfs::hook_NtClose(hdl);
}

TEST_F(USVFSTest, NtQueryDirectoryFileFindsVirtualFileThroughShortNamePath)
{
  const std::wstring shortDirectory = shortPathOf(ALIASED_DIRW);
  if (shortDirectory == ALIASED_DIRW) {
    GTEST_SKIP() << ALIASED_DIRW << " has no 8.3 alias";
  }

  auto params = defaultUsvfsParams();
  std::unique_ptr<usvfs::HookContext> ctx(
      usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));
  ctx->redirectionTable().addFile(ALIASED_DIR_FILEW,
                                  usvfs::RedirectionDataLocal(REAL_FILEA));

  HANDLE hdl = hooked_NtOpenFile(shortDirectory.c_str(), FILE_GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
  ASSERT_NE(INVALID_HANDLE_VALUE, hdl);

  IO_STATUS_BLOCK status;
  char buffer[1024];
  usvfs::UnicodeString fileName(ALIASED_DIR_FILE_NAMEW);
  ASSERT_EQ(STATUS_SUCCESS, usvfs::hook_NtQueryDirectoryFile(
                                hdl, nullptr, nullptr, nullptr, &status, buffer,
                                sizeof(buffer), FileDirectoryInformation, TRUE,
                                static_cast<PUNICODE_STRING>(fileName), TRUE));

  const auto* info = reinterpret_cast<FILE_DIRECTORY_INFORMATION*>(buffer);
  ASSERT_EQ(ALIASED_DIR_FILE_NAMEW,
            std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR)));

  usvfs::hook_NtClose(hdl);
}

namespace
{

std::wstring extendedLengthPath(const std::wstring& path)
{
  return LR"(\\?\)" + path;
}

void createDirectories(const std::wstring& path)
{
  for (size_t separator = path.find(L'\\', 3);;
       separator        = path.find(L'\\', separator + 1)) {
    ::CreateDirectoryW(extendedLengthPath(path.substr(0, separator)).c_str(), nullptr);
    if (separator == std::wstring::npos) {
      break;
    }
  }
}

void writeFile(const std::wstring& path, std::string_view content)
{
  HANDLE file = ::CreateFileW(extendedLengthPath(path).c_str(), GENERIC_WRITE, 0,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  ASSERT_NE(INVALID_HANDLE_VALUE, file) << "last error=" << ::GetLastError();
  DWORD written = 0;
  ::WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written,
              nullptr);
  ::CloseHandle(file);
}

void removeTree(const std::wstring& path)
{
  WIN32_FIND_DATAW data;
  HANDLE find = ::FindFirstFileW(extendedLengthPath(path + L"\\*").c_str(), &data);
  if (find != INVALID_HANDLE_VALUE) {
    do {
      const std::wstring name = data.cFileName;
      if (name == L"." || name == L"..") {
        continue;
      }
      if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        removeTree(path + L"\\" + name);
      } else {
        ::DeleteFileW(extendedLengthPath(path + L"\\" + name).c_str());
      }
    } while (::FindNextFileW(find, &data));
    ::FindClose(find);
  }
  ::RemoveDirectoryW(extendedLengthPath(path).c_str());
}

std::string toUtf8(const std::wstring& path)
{
  return ush::string_cast<std::string>(path, ush::CodePage::UTF8);
}

bool findsName(HANDLE find, WIN32_FIND_DATAW& data, std::wstring_view name)
{
  if (find == INVALID_HANDLE_VALUE) {
    return false;
  }
  bool isFound = false;
  do {
    isFound = isFound || name == data.cFileName;
  } while (::FindNextFileW(find, &data));
  ::FindClose(find);
  return isFound;
}

}  // namespace

// Files whose paths exceed MAX_PATH, kept in C:\Users\Public rather than the temporary
// directory, which a filter driver may sit in front of. This process is not long path
// aware, so the file functions take such paths only in their \\?\ form, as they do in
// most processes usvfs hooks.
class USVFSLongPathTest : public testing::Test
{
public:
  void SetUp() override
  {
    SHMLogger::create("usvfs");
    usvfsInitLogging();
    auto params = defaultUsvfsParams();
    m_context.reset(usvfsCreateHookContext(*params, ::GetModuleHandle(nullptr)));

    m_root    = L"C:\\Users\\Public\\tvfs_long_path_" +
                std::to_wstring(::GetCurrentProcessId());
    m_longDir = m_root;
    for (wchar_t letter = L'a'; letter < L'g'; ++letter) {
      m_longDir += L'\\' + std::wstring(48, letter);
    }
    createDirectories(m_longDir);
    createDirectories(dataDir());
    writeFile(longFile(), "[section]\r\nkey=value\r\n");
  }

  void TearDown() override
  {
    removeTree(m_root);
    m_context.reset();

    std::array<char, 1024> buffer;
    while (SHMLogger::instance().tryGet(buffer.data(), buffer.size())) {
      std::cout << buffer.data() << std::endl;
    }
    SHMLogger::free();
  }

protected:
  // a short directory, where the tests map the long files in
  std::wstring dataDir() const { return m_root + L"\\data"; }
  std::wstring longFile() const { return m_longDir + L"\\real.ini"; }

  usvfs::RedirectionTreeContainer& tree() { return m_context->redirectionTable(); }

  std::wstring m_root;
  // more than MAX_PATH characters long
  std::wstring m_longDir;

private:
  std::unique_ptr<usvfs::HookContext> m_context;
};

TEST_F(USVFSLongPathTest, GetFileAttributesHookTakesExtendedLengthPath)
{
  const std::wstring path = extendedLengthPath(longFile());
  const DWORD expected    = ::GetFileAttributesW(path.c_str());
  ASSERT_NE(INVALID_FILE_ATTRIBUTES, expected);

  EXPECT_EQ(expected, usvfs::hook_GetFileAttributesW(path.c_str()));
}

TEST_F(USVFSLongPathTest, GetFileAttributesExHookTakesExtendedLengthPath)
{
  const std::wstring path = extendedLengthPath(longFile());
  WIN32_FILE_ATTRIBUTE_DATA data{};

  ASSERT_TRUE(
      usvfs::hook_GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
      << "last error=" << ::GetLastError();
  EXPECT_EQ(::GetFileAttributesW(path.c_str()), data.dwFileAttributes);
}

TEST_F(USVFSLongPathTest, FindFirstFileExHookTakesExtendedLengthPath)
{
  const std::wstring pattern = extendedLengthPath(m_longDir + L"\\*");
  WIN32_FIND_DATAW data;

  const HANDLE find = usvfs::hook_FindFirstFileExW(
      pattern.c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, 0);

  EXPECT_TRUE(findsName(find, data, L"real.ini")) << "last error=" << ::GetLastError();
}

TEST_F(USVFSLongPathTest, FindFirstFileExHookTakesExtendedLengthPathInShortDirectory)
{
  // a directory short enough for every file function to take it without a prefix,
  // holding a file whose path exceeds MAX_PATH
  const std::wstring directory = m_longDir.substr(0, m_root.size() + 4 * 49);
  const std::wstring name      = std::wstring(64, L'n') + L".ini";
  ASSERT_LT(directory.size(), MAX_PATH - 12);
  ASSERT_GT(directory.size() + 1 + name.size(), MAX_PATH);
  writeFile(directory + L"\\" + name, "");
  WIN32_FIND_DATAW data;

  const HANDLE find = usvfs::hook_FindFirstFileExW(
      extendedLengthPath(directory + L"\\" + name).c_str(), FindExInfoBasic, &data,
      FindExSearchNameMatch, nullptr, 0);

  EXPECT_TRUE(findsName(find, data, name)) << "last error=" << ::GetLastError();
}

TEST_F(USVFSLongPathTest, FindFirstFileExHookFindsVerbatimNameEndingInDot)
{
  writeFile(dataDir() + L"\\name.", "");
  WIN32_FIND_DATAW data;

  const HANDLE find = usvfs::hook_FindFirstFileExW(
      extendedLengthPath(dataDir() + L"\\name.").c_str(), FindExInfoBasic, &data,
      FindExSearchNameMatch, nullptr, 0);

  EXPECT_TRUE(findsName(find, data, L"name.")) << "last error=" << ::GetLastError();
}

TEST_F(USVFSLongPathTest, FindFirstFileExHookMatchesTrailingDotOfPlainPathAsDos)
{
  // the file functions take "*." for the names without an extension only in a path
  // they normalize
  writeFile(dataDir() + L"\\noextension", "");
  writeFile(dataDir() + L"\\extension.ini", "");
  const std::wstring pattern = dataDir() + L"\\*.";
  WIN32_FIND_DATAW data;

  const HANDLE withoutExtension = usvfs::hook_FindFirstFileExW(
      pattern.c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, 0);
  EXPECT_TRUE(findsName(withoutExtension, data, L"noextension"))
      << "last error=" << ::GetLastError();
  const HANDLE withExtension = usvfs::hook_FindFirstFileExW(
      pattern.c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, 0);
  EXPECT_FALSE(findsName(withExtension, data, L"extension.ini"));
}

TEST_F(USVFSLongPathTest, FindFirstFileExHookFindsNoFileLeftOutOfTree)
{
  // the directory maps the long one, whose file the redirection tree leaves out, as the
  // skip lists of usvfsVirtualLinkDirectoryStatic do
  tree().addDirectory(dataDir(), usvfs::RedirectionDataLocal(toUtf8(m_longDir) + "\\"),
                      usvfs::shared::FLAG_DIRECTORY);
  WIN32_FIND_DATAW data;

  const HANDLE find =
      usvfs::hook_FindFirstFileExW((dataDir() + L"\\real.ini").c_str(), FindExInfoBasic,
                                   &data, FindExSearchNameMatch, nullptr, 0);

  EXPECT_FALSE(findsName(find, data, L"real.ini"));
}

TEST_F(USVFSLongPathTest, DeleteFileHookTakesExtendedLengthPath)
{
  const std::wstring path = extendedLengthPath(longFile());

  ASSERT_TRUE(usvfs::hook_DeleteFileW(path.c_str()))
      << "last error=" << ::GetLastError();
  EXPECT_EQ(INVALID_FILE_ATTRIBUTES, ::GetFileAttributesW(path.c_str()));
}

TEST_F(USVFSLongPathTest, HooksTakeVolumeGuidPath)
{
  wchar_t volume[MAX_PATH];
  ASSERT_TRUE(::GetVolumeNameForVolumeMountPointW(L"C:\\", volume, MAX_PATH));
  // "\\?\Volume{GUID}\" followed by the path without its drive
  const std::wstring path = volume + dataDir().substr(3);
  const DWORD expected    = ::GetFileAttributesW(path.c_str());
  ASSERT_NE(INVALID_FILE_ATTRIBUTES, expected);

  EXPECT_EQ(expected, usvfs::hook_GetFileAttributesW(path.c_str()));
  WIN32_FIND_DATAW data;
  const HANDLE find =
      usvfs::hook_FindFirstFileExW((path + L"\\*").c_str(), FindExInfoBasic, &data,
                                   FindExSearchNameMatch, nullptr, 0);
  EXPECT_TRUE(findsName(find, data, L".")) << "last error=" << ::GetLastError();
}

TEST_F(USVFSLongPathTest, GetFileAttributesHookFollowsLongReroute)
{
  const std::wstring virtualFile = dataDir() + L"\\virtual.ini";
  tree().addFile(virtualFile, usvfs::RedirectionDataLocal(toUtf8(longFile())));

  EXPECT_EQ(::GetFileAttributesW(extendedLengthPath(longFile()).c_str()),
            usvfs::hook_GetFileAttributesW(virtualFile.c_str()));
}

TEST_F(USVFSLongPathTest, GetFileAttributesExHookFollowsLongReroute)
{
  const std::wstring virtualFile = dataDir() + L"\\virtual.ini";
  tree().addFile(virtualFile, usvfs::RedirectionDataLocal(toUtf8(longFile())));
  WIN32_FILE_ATTRIBUTE_DATA data{};

  ASSERT_TRUE(usvfs::hook_GetFileAttributesExW(virtualFile.c_str(),
                                               GetFileExInfoStandard, &data))
      << "last error=" << ::GetLastError();
  EXPECT_EQ(::GetFileAttributesW(extendedLengthPath(longFile()).c_str()),
            data.dwFileAttributes);
}

TEST_F(USVFSLongPathTest, NtCreateFileHookOpensLongReroute)
{
  const std::wstring virtualFile = dataDir() + L"\\virtual.ini";
  tree().addFile(virtualFile, usvfs::RedirectionDataLocal(toUtf8(longFile())));
  usvfs::UnicodeString name(LR"(\??\)" + virtualFile);
  OBJECT_ATTRIBUTES attributes{sizeof(OBJECT_ATTRIBUTES), nullptr,
                               static_cast<PUNICODE_STRING>(name)};
  IO_STATUS_BLOCK status;
  HANDLE file = INVALID_HANDLE_VALUE;
  // the FILE_OPEN disposition of winternl.h, which this test does not include
  constexpr ULONG openDisposition = 0x00000001;

  ASSERT_EQ(STATUS_SUCCESS,
            usvfs::hook_NtCreateFile(
                &file, FILE_GENERIC_READ, &attributes, &status, nullptr,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, openDisposition,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0));
  usvfs::hook_NtClose(file);
}

TEST_F(USVFSLongPathTest, GetPrivateProfileStringHookFollowsLongReroute)
{
  const std::wstring virtualFile = dataDir() + L"\\virtual.ini";
  tree().addFile(virtualFile, usvfs::RedirectionDataLocal(toUtf8(longFile())));
  wchar_t value[16]{};

  usvfs::hook_GetPrivateProfileStringW(L"section", L"key", L"", value, 16,
                                       virtualFile.c_str());

  EXPECT_STREQ(L"value", value);
}

TEST_F(USVFSLongPathTest, CopyFileExHookFollowsLongReroute)
{
  const std::wstring virtualFile = dataDir() + L"\\virtual.ini";
  tree().addFile(virtualFile, usvfs::RedirectionDataLocal(toUtf8(longFile())));
  const std::wstring copy = dataDir() + L"\\copy.ini";

  ASSERT_TRUE(usvfs::hook_CopyFileExW(virtualFile.c_str(), copy.c_str(), nullptr,
                                      nullptr, nullptr, 0))
      << "last error=" << ::GetLastError();
  wchar_t value[16]{};
  ::GetPrivateProfileStringW(L"section", L"key", L"", value, 16, copy.c_str());
  EXPECT_STREQ(L"value", value);
}

TEST_F(USVFSLongPathTest, DeleteFileHookFollowsLongReroute)
{
  const std::wstring virtualFile = dataDir() + L"\\deleted.ini";
  tree().addFile(virtualFile, usvfs::RedirectionDataLocal(toUtf8(longFile())));

  ASSERT_TRUE(usvfs::hook_DeleteFileW(virtualFile.c_str()))
      << "last error=" << ::GetLastError();
  EXPECT_EQ(INVALID_FILE_ATTRIBUTES,
            ::GetFileAttributesW(extendedLengthPath(longFile()).c_str()));
}

TEST_F(USVFSLongPathTest, CreateDirectoryHookCreatesInLongCreateTarget)
{
  tree().addDirectory(dataDir(), usvfs::RedirectionDataLocal(toUtf8(m_longDir) + "\\"),
                      usvfs::shared::FLAG_CREATETARGET);

  ASSERT_TRUE(usvfs::hook_CreateDirectoryW((dataDir() + L"\\created").c_str(), nullptr))
      << "last error=" << ::GetLastError();
  const DWORD attributes =
      ::GetFileAttributesW(extendedLengthPath(m_longDir + L"\\created").c_str());
  ASSERT_NE(INVALID_FILE_ATTRIBUTES, attributes);
  EXPECT_NE(0UL, attributes & FILE_ATTRIBUTE_DIRECTORY);
}

TEST_F(USVFSTestAuto, CannotCreateLinkToFileInNonexistantDirectory)
{
  ASSERT_EQ(FALSE, usvfsVirtualLinkFile(
                       REAL_FILEW, L"c:/this_directory_shouldnt_exist/np.exe", FALSE));
}

TEST_F(USVFSTestAuto, CanCreateMultipleLinks)
{
  static LPCWSTR outFile            = LR"(C:\np.exe)";
  static LPCWSTR outDir             = LR"(C:\logs)";
  static LPCWSTR outDirCanonizeTest = LR"(C:\.\not/../logs\.\a\.\b\.\c\..\.\..\.\..\)";
  ASSERT_EQ(TRUE, usvfsVirtualLinkFile(REAL_FILEW, outFile, 0));
  ASSERT_EQ(TRUE, usvfsVirtualLinkDirectoryStatic(REAL_DIRW, outDir, 0));

  // both file and dir exist and have the correct type
  ASSERT_NE(INVALID_FILE_ATTRIBUTES, usvfs::hook_GetFileAttributesW(outFile));
  ASSERT_NE(INVALID_FILE_ATTRIBUTES, usvfs::hook_GetFileAttributesW(outDir));
  ASSERT_EQ(0UL, usvfs::hook_GetFileAttributesW(outFile) & FILE_ATTRIBUTE_DIRECTORY);
  ASSERT_NE(0UL, usvfs::hook_GetFileAttributesW(outDir) & FILE_ATTRIBUTE_DIRECTORY);
  ASSERT_NE(0UL, usvfs::hook_GetFileAttributesW(outDirCanonizeTest) &
                     FILE_ATTRIBUTE_DIRECTORY);
}

int main(int argc, char** argv)
{
  using namespace test;

  auto dllPath = path_of_usvfs_lib(platform_dependant_executable("usvfs", "dll"));
  ScopedLoadLibrary loadDll(dllPath.c_str());
  if (!loadDll) {
    std::wcerr << L"failed to load usvfs dll: " << dllPath.c_str() << L", "
               << GetLastError() << std::endl;
    return 1;
  }

  // note: this makes the logger available only to functions statically linked to the
  // test binary, not those called in the dll
  auto logger = spdlog::stdout_logger_mt("usvfs");
  logger->set_level(spdlog::level::warn);
  testing::InitGoogleTest(&argc, argv);
  int res = RUN_ALL_TESTS();

  return res;
}
