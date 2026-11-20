#include "dos_path.h"

#include "ntdll_declarations.h"

namespace usvfs::shared
{

namespace
{

  constexpr std::wstring_view ntPrefix       = LR"(\??\)";
  constexpr std::wstring_view ntUncPrefix    = LR"(\??\UNC\)";
  constexpr std::wstring_view win32Prefix    = LR"(\\?\)";
  constexpr std::wstring_view win32UncPrefix = LR"(\\?\UNC\)";
  constexpr std::wstring_view uncPrefix      = LR"(\\)";

  // CreateDirectoryW takes the shortest paths of the file functions: MAX_PATH less room
  // for an 8.3 name
  constexpr size_t longestPlainPath = MAX_PATH - 12 - 1;

  bool isSeparator(wchar_t character)
  {
    return character == L'\\' || character == L'/';
  }

  bool isDriveLetter(wchar_t character)
  {
    return (character >= L'a' && character <= L'z') ||
           (character >= L'A' && character <= L'Z');
  }

  bool startsWithIgnoringCase(std::wstring_view text, std::wstring_view prefix)
  {
    return text.size() >= prefix.size() &&
           ::_wcsnicmp(text.data(), prefix.data(), prefix.size()) == 0;
  }

  // "C:\..."
  bool isDrivePath(std::wstring_view path)
  {
    return path.size() >= 3 && isDriveLetter(path[0]) && path[1] == L':' &&
           path[2] == L'\\';
  }

  // "server\share" followed by nothing or a separator
  bool isServerShare(std::wstring_view path)
  {
    const size_t serverEnd = path.find(L'\\');
    if (serverEnd == 0 || serverEnd == std::wstring_view::npos) {
      return false;
    }
    const size_t shareEnd = path.find(L'\\', serverEnd + 1);
    return shareEnd != serverEnd + 1 && serverEnd + 1 < path.size();
  }

  // the length of the root of a fully qualified path, "C:" or "\\server\share"
  size_t rootLength(std::wstring_view fullPath)
  {
    if (fullPath.size() >= 2 && fullPath[1] == L':') {
      return 2;
    }
    const auto separator = [&](size_t from) {
      const size_t found = fullPath.find_first_of(LR"(\/)", from);
      return found == std::wstring_view::npos ? fullPath.size() : found;
    };
    return separator(separator(uncPrefix.size()) + 1);
  }

  std::wstring join(std::wstring_view directory, std::wstring_view relativePath)
  {
    std::wstring result(directory);
    if (!relativePath.empty() && !isSeparator(result.back())) {
      result += L'\\';
    }
    return result.append(relativePath);
  }

  // `path` made fully qualified with `currentDirectory` the way the path parser makes
  // it so with the process's own current directory, or `path` as it is when it is
  // fully qualified, relative to another drive or `currentDirectory` is empty
  std::wstring qualify(std::wstring_view path, std::wstring_view currentDirectory)
  {
    std::wstring pathString(path);
    if (currentDirectory.empty()) {
      return pathString;
    }
    switch (RtlDetermineDosPathNameType_U(pathString.c_str())) {
    case RtlPathTypeRelative:
      return join(currentDirectory, path);
    case RtlPathTypeDriveRelative:
      if (currentDirectory.size() >= 2 && currentDirectory[1] == L':' &&
          ::towupper(path[0]) == ::towupper(currentDirectory[0])) {
        return join(currentDirectory, path.substr(2));
      }
      return pathString;
    case RtlPathTypeRooted:
      // the parser takes a path in the \??\ form as the NT path it is
      if (path.starts_with(ntPrefix)) {
        return pathString;
      }
      return std::wstring(currentDirectory.substr(0, rootLength(currentDirectory))) +
             pathString;
    default:
      return pathString;
    }
  }

  // the NT path the Win32 file functions convert `path` to, nothing for one they reject
  std::optional<std::wstring> toNtPath(const std::wstring& path)
  {
    UNICODE_STRING ntPath{};
    if (RtlDosPathNameToNtPathName_U_WithStatus(path.c_str(), &ntPath, nullptr,
                                                nullptr) < 0) {
      return std::nullopt;
    }
    std::wstring result(ntPath.Buffer, ntPath.Length / sizeof(wchar_t));
    // the parser allocates the string on the process heap, as RtlFreeUnicodeString
    // expects
    ::HeapFree(::GetProcessHeap(), 0, ntPath.Buffer);
    return result;
  }

  std::wstring fullPathName(std::wstring_view path)
  {
    const std::wstring pathString(path);
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
      const ULONG bufferBytes = static_cast<ULONG>(buffer.size() * sizeof(wchar_t));
      const ULONG bytes =
          RtlGetFullPathName_U(pathString.c_str(), bufferBytes, buffer.data(), nullptr);
      if (bytes < bufferBytes) {
        buffer.resize(bytes / sizeof(wchar_t));
        return buffer;
      }
      // the size a buffer too small needs, with or without the null
      buffer.resize(bytes / sizeof(wchar_t) + 1);
    }
  }

}  // namespace

std::optional<DosPath> DosPath::fromWin32(std::wstring_view path,
                                          std::wstring_view currentDirectory)
{
  if (path.empty()) {
    return std::nullopt;
  }
  const auto ntPath = toNtPath(qualify(path, currentDirectory));
  return ntPath ? fromNt(*ntPath) : std::nullopt;
}

std::optional<DosPath> DosPath::fromFullPath(std::wstring_view path)
{
  const std::wstring fullPath = fullPathName(path);
  switch (RtlDetermineDosPathNameType_U(fullPath.c_str())) {
  case RtlPathTypeDriveAbsolute:
    return fromNt(std::wstring(ntPrefix) + fullPath);
  case RtlPathTypeUncAbsolute:
    return fromNt(std::wstring(ntUncPrefix) + fullPath.substr(uncPrefix.size()));
  case RtlPathTypeLocalDevice:
    // a \\?\ prefix keeps the parser from limiting its length
    return fromWin32(fullPath);
  default:
    return std::nullopt;
  }
}

std::optional<DosPath> DosPath::fromNt(std::wstring_view path)
{
  if (!path.starts_with(ntPrefix)) {
    return std::nullopt;
  }
  const std::wstring_view dosDevicePath = path.substr(ntPrefix.size());
  if (isDrivePath(dosDevicePath)) {
    return DosPath(std::wstring(dosDevicePath));
  }
  const std::wstring_view uncDevice = ntUncPrefix.substr(ntPrefix.size());
  if (startsWithIgnoringCase(dosDevicePath, uncDevice) &&
      isServerShare(dosDevicePath.substr(uncDevice.size()))) {
    return DosPath(std::wstring(uncPrefix) +
                   std::wstring(dosDevicePath.substr(uncDevice.size())));
  }
  return std::nullopt;
}

DosPath::DosPath(std::wstring path) : m_path(std::move(path))
{
  // "C:" would name the current directory of the drive rather than its root
  const size_t shortest = isUnc() ? 0 : std::wstring_view(LR"(C:\)").size();
  while (m_path.size() > shortest && m_path.back() == L'\\') {
    m_path.pop_back();
  }
}

std::wstring DosPath::ntPath() const
{
  return isUnc() ? std::wstring(ntUncPrefix) + m_path.substr(uncPrefix.size())
                 : std::wstring(ntPrefix) + m_path;
}

std::wstring DosPath::win32Path() const
{
  // the file functions would normalize a path such as "C:\a\..\b", which only the
  // NT path parser and the \\?\ form take as it is
  if (m_path.size() <= longestPlainPath && toNtPath(m_path) == ntPath()) {
    return m_path;
  }
  return verbatimWin32Path();
}

std::wstring DosPath::verbatimWin32Path() const
{
  return isUnc() ? std::wstring(win32UncPrefix) + m_path.substr(uncPrefix.size())
                 : std::wstring(win32Prefix) + m_path;
}

bool DosPath::isUnc() const
{
  return m_path.starts_with(uncPrefix);
}

std::wstring toWin32Path(std::wstring_view fullPath)
{
  const auto path = DosPath::fromFullPath(fullPath);
  return path ? path->win32Path() : std::wstring(fullPath);
}

bool isVerbatimWin32Path(std::wstring_view path)
{
  return path.starts_with(win32Prefix) || path.starts_with(ntPrefix);
}

}  // namespace usvfs::shared
