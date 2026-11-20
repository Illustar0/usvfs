#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace usvfs::shared
{

// A fully qualified path to a file or directory on a drive or a share, "C:\dir\file" or
// "\\server\share\dir\file", normalized as Windows normalizes a path on its way to a
// file system, and with no trailing separator but that of a drive's root, "C:\". The
// redirection tree is keyed by this form. Each form of path the hooks take converts to
// it, and it converts to each form the functions the hooks call take, at any length:
//
//   const auto path = DosPath::fromWin32(LR"(Data\..\Data\plugin.esp)", LR"(C:\Game)");
//   path->str();        // C:\Game\Data\plugin.esp
//   path->ntPath();     // \??\C:\Game\Data\plugin.esp
//   path->win32Path();  // C:\Game\Data\plugin.esp, or \\?\C:\... beyond MAX_PATH
class DosPath
{
public:
  // The path a Win32 file function takes `path` for, with the ntdll path parser the
  // file functions use. A relative path resolves against `currentDirectory`, the
  // current directory the hooks track for its drive, when that is given, and against
  // the process's own otherwise. Nothing for a path to no drive or share, such as a
  // device, pipe or volume GUID path, or for one the file functions reject, such as a
  // path longer than MAX_PATH without the \\?\ prefix in a process that is not long
  // path aware.
  static std::optional<DosPath> fromWin32(std::wstring_view path,
                                          std::wstring_view currentDirectory = {});

  // The path a fully qualified path usvfs holds itself, such as a link target, names,
  // normalized as GetFullPathNameW normalizes it, which takes a path of any length in
  // any process. Nothing for a path to no drive or share.
  static std::optional<DosPath> fromFullPath(std::wstring_view path);

  // The path an NT path in the DOS device namespace, "\??\C:\dir" or
  // "\??\UNC\server\share\dir", names, taken as it is, as the NT file functions take
  // it. Nothing for any other NT path, such as "\Device\HarddiskVolume1\dir", one
  // relative to a directory handle or a device's.
  static std::optional<DosPath> fromNt(std::wstring_view path);

  // "C:\dir" or "\\server\share\dir"
  const std::wstring& str() const { return m_path; }

  // "\??\C:\dir" or "\??\UNC\server\share\dir", which the NT file functions take at any
  // length
  std::wstring ntPath() const;

  // The form the Win32 file functions take this path in, in any process: str() itself
  // while they take it as it is, else verbatimWin32Path().
  std::wstring win32Path() const;

  // "\\?\C:\dir" or "\\?\UNC\server\share\dir", which the Win32 file functions take
  // verbatim: at any length and without normalizing it again.
  std::wstring verbatimWin32Path() const;

private:
  explicit DosPath(std::wstring path);

  bool isUnc() const;

  std::wstring m_path;
};

// The form of `fullPath`, a fully qualified path usvfs holds itself, that the Win32
// file functions take at any length: DosPath::fromFullPath(fullPath)->win32Path(), or
// `fullPath` as it is for a path to no drive or share.
std::wstring toWin32Path(std::wstring_view fullPath);

// Whether the Win32 file functions take `path` verbatim, without normalizing it: a path
// in the \\?\ form, or an NT path in the \??\ form.
bool isVerbatimWin32Path(std::wstring_view path);

}  // namespace usvfs::shared
