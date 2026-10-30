#pragma once

#include "dos_path.h"
#include "hookcallcontext.h"
#include "hookcontext.h"
#include "stringcast.h"

namespace usvfs
{

// The current directory the hooks track for the drive the relative `path` names, or for
// the current drive; empty while they track none, as the process's own one is current.
std::wstring trackedCurrentDirectory(const wchar_t* path);

// returns true iff the path exists (checks only real paths)
static inline bool pathExists(LPCWSTR fileName)
{
  FunctionGroupLock lock(MutExHookGroup::FILE_ATTRIBUTES);
  DWORD attrib = GetFileAttributesW(fileName);
  return attrib != INVALID_FILE_ATTRIBUTES;
}

// returns true iff the path exists and is a file (checks only real paths)
static inline bool pathIsFile(LPCWSTR fileName)
{
  FunctionGroupLock lock(MutExHookGroup::FILE_ATTRIBUTES);
  DWORD attrib = GetFileAttributesW(fileName);
  return attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// returns true iff the path exists and is a file (checks only real paths)
static inline bool pathIsDirectory(LPCWSTR fileName)
{
  FunctionGroupLock lock(MutExHookGroup::FILE_ATTRIBUTES);
  DWORD attrib = GetFileAttributesW(fileName);
  return attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY);
}

// returns true iff the path does not exist but it parent directory does (checks only
// real paths)
static inline bool pathDirectlyAvailable(LPCWSTR pathName)
{
  FunctionGroupLock lock(MutExHookGroup::FILE_ATTRIBUTES);
  DWORD attrib = GetFileAttributesW(pathName);
  return attrib == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
}

class MapTracker
{
public:
  std::wstring lookup(const std::wstring& fromPath) const
  {
    if (!fromPath.empty()) {
      std::shared_lock<std::shared_mutex> lock(m_mutex);
      auto find = m_map.find(fromPath);
      if (find != m_map.end())
        return find->second;
    }
    return std::wstring();
  }

  bool contains(const std::wstring& fromPath) const
  {
    if (!fromPath.empty()) {
      std::shared_lock<std::shared_mutex> lock(m_mutex);
      auto find = m_map.find(fromPath);
      if (find != m_map.end())
        return true;
    }
    return false;
  }

  void insert(const std::wstring& fromPath, const std::wstring& toPath)
  {
    if (fromPath.empty())
      return;
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_map[fromPath] = toPath;
  }

  bool erase(const std::wstring& fromPath)
  {
    if (fromPath.empty())
      return false;
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    return m_map.erase(fromPath);
  }

private:
  mutable std::shared_mutex m_mutex;
  std::unordered_map<std::wstring, std::wstring> m_map;
};

extern MapTracker k32DeleteTracker;
extern MapTracker k32FakeDirTracker;

class RerouteW
{
  // the caller's path as the file functions resolve it, but with the current directory
  // the hooks track: what the redirection tree and the trackers are keyed by
  std::wstring m_RealPath{};
  // where the caller's path leads in the virtual file system, when that is elsewhere
  std::optional<shared::DosPath> m_ReroutedPath{};
  // what fileName() points to
  std::wstring m_Buffer{};
  bool m_HasFileName{false};
  bool m_PathCreated{false};
  bool m_NewReroute{false};

  RedirectionTree::NodePtrT m_FileNode;

public:
  RerouteW() = default;

  RerouteW(RerouteW&&)            = default;
  RerouteW& operator=(RerouteW&&) = default;

  RerouteW(const RerouteW& reference)  = delete;
  RerouteW& operator=(const RerouteW&) = delete;

  // The path to give the file functions, null for a null path: the rerouted path in the
  // form they take at any length, or the caller's path as it is.
  LPCWSTR fileName() const { return m_HasFileName ? m_Buffer.c_str() : nullptr; }

  // The path of fileName() as a DOS path, for what is not a file function: the caller
  // it is handed back to, the loader or a process to start.
  LPCWSTR plainFileName() const
  {
    return m_ReroutedPath ? m_ReroutedPath->str().c_str() : fileName();
  }

  // where the caller's path leads in the virtual file system, when that is elsewhere
  const std::optional<shared::DosPath>& reroutedPath() const { return m_ReroutedPath; }

  bool wasRerouted() const { return m_ReroutedPath.has_value(); }

  bool newReroute() const { return m_NewReroute; }

  void insertMapping(const HookContext::Ptr& context, bool directory = false)
  {
    const std::wstring& reroutedPath = m_ReroutedPath->str();
    if (directory) {
      addDirectoryMapping(context, m_RealPath, reroutedPath);

      // In case we have just created a "fake" directory, it is no longer fake and need
      // to remove it and all its parent folders from the fake map:
      std::wstring dir = reroutedPath;
      while (k32FakeDirTracker.erase(dir))
        dir = fs::path(dir).parent_path().wstring();
    } else {
      // if (m_PathCreated)
      // addDirectoryMapping(context, fs::path(m_RealPath).parent_path(),
      // fs::path(m_FileName).parent_path());

      spdlog::get("hooks")->info(
          "mapping file in vfs: {}, {}",
          shared::string_cast<std::string>(m_RealPath, shared::CodePage::UTF8),
          shared::string_cast<std::string>(reroutedPath, shared::CodePage::UTF8));
      m_FileNode = context->redirectionTable().addFile(
          m_RealPath, RedirectionDataLocal(shared::string_cast<std::string>(
                          reroutedPath, shared::CodePage::UTF8)));

      k32DeleteTracker.erase(m_RealPath);
    }
  }

  // takes write access, as removing m_FileNode changes the tree even though the node
  // is reached without going through the context
  void removeMapping(const HookContext::Ptr& context, bool directory = false)
  {
    bool addToDelete     = false;
    bool dontAddToDelete = false;

    // We need to track deleted files even if they were not rerouted (i.e. files deleted
    // from the real folder which there is a virtualized mapped folder on top of it).
    // Since we don't want to add, *every* file which is deleted we check this:
    bool found = wasRerouted();
    if (!found) {
      FindCreateTarget visitor;
      RedirectionTree::VisitorFunction visitorWrapper =
          [&](const RedirectionTree::NodePtrT& node) {
            visitor(node);
          };
      context->redirectionTable()->visitPath(m_RealPath, visitorWrapper);
      if (visitor.target.get())
        found = true;
    }
    if (found)
      addToDelete = true;

    if (wasRerouted()) {
      if (m_FileNode.get())
        m_FileNode->removeFromTree();
      else
        spdlog::get("usvfs")->warn("Node not removed: {}",
                                   shared::string_cast<std::string>(plainFileName()));

      if (!directory) {
        // check if this file was the last file inside a "fake" directory then remove it
        // and possibly also its fake empty parent folders:
        std::wstring parent = m_ReroutedPath->str();
        while (true) {
          parent = fs::path(parent).parent_path().wstring();
          if (k32FakeDirTracker.contains(parent)) {
            dontAddToDelete = true;
            if (RemoveDirectoryW(shared::toWin32Path(parent).c_str())) {
              k32FakeDirTracker.erase(parent);
              spdlog::get("usvfs")->info("removed empty fake directory: {}",
                                         shared::string_cast<std::string>(parent));
            } else if (GetLastError() != ERROR_DIR_NOT_EMPTY) {
              auto error = GetLastError();
              spdlog::get("usvfs")->warn("removing fake directory failed: {}, error={}",
                                         shared::string_cast<std::string>(parent),
                                         error);
              break;
            }
          } else
            break;
        }
      }
    }
    if (addToDelete && !dontAddToDelete) {
      k32DeleteTracker.insert(m_RealPath,
                              m_ReroutedPath ? m_ReroutedPath->str() : m_RealPath);
    }
  }

  static bool createFakePath(fs::path path, LPSECURITY_ATTRIBUTES securityAttributes)
  {
    // sanity and guaranteed recursion end:
    if (!path.has_relative_path())
      throw shared::windows_error(
          "createFakePath() refusing to create non-existing top level path: " +
          path.string());

    const std::wstring fileFunctionPath = shared::toWin32Path(path.wstring());
    DWORD attr                          = GetFileAttributesW(fileFunctionPath.c_str());
    DWORD err                           = GetLastError();
    if (attr != INVALID_FILE_ATTRIBUTES) {
      if (attr & FILE_ATTRIBUTE_DIRECTORY)
        return false;  // if directory already exists all is good
      else
        throw shared::windows_error("createFakePath() called on a file: " +
                                    path.string());
    }
    if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
      throw shared::windows_error(
          "createFakePath() GetFileAttributesW failed on: " + path.string(), err);

    if (err != ERROR_FILE_NOT_FOUND)  // ERROR_FILE_NOT_FOUND means parent directory
                                      // already exists
      createFakePath(
          path.parent_path(),
          securityAttributes);  // otherwise create parent directory (recursively)

    BOOL res = CreateDirectoryW(fileFunctionPath.c_str(), securityAttributes);
    if (res)
      k32FakeDirTracker.insert(path.wstring(), std::wstring());
    else {
      err = GetLastError();
      throw shared::windows_error(
          "createFakePath() CreateDirectoryW failed on: " + path.string(), err);
    }
    return true;
  }

  static bool addDirectoryMapping(const HookContext::Ptr& context,
                                  const fs::path& originalPath,
                                  const fs::path& reroutedPath)
  {
    if (originalPath.empty() || reroutedPath.empty()) {
      spdlog::get("hooks")->error("RerouteW::addDirectoryMapping failed: {}, {}",
                                  shared::string_cast<std::string>(
                                      originalPath.wstring(), shared::CodePage::UTF8)
                                      .c_str(),
                                  shared::string_cast<std::string>(
                                      reroutedPath.wstring(), shared::CodePage::UTF8)
                                      .c_str());
      return false;
    }

    auto lookupParent =
        context->redirectionTable()->findNode(originalPath.parent_path());
    if (!lookupParent.get() || lookupParent->data().linkTarget.empty()) {
      if (!addDirectoryMapping(context, originalPath.parent_path(),
                               reroutedPath.parent_path())) {
        spdlog::get("hooks")->error("RerouteW::addDirectoryMapping failed: {}, {}",
                                    shared::string_cast<std::string>(
                                        originalPath.wstring(), shared::CodePage::UTF8)
                                        .c_str(),
                                    shared::string_cast<std::string>(
                                        reroutedPath.wstring(), shared::CodePage::UTF8)
                                        .c_str());
        return false;
      }
    }

    std::string reroutedU8 = shared::string_cast<std::string>(reroutedPath.wstring(),
                                                              shared::CodePage::UTF8);
    if (reroutedU8.empty() || reroutedU8[reroutedU8.size() - 1] != '\\')
      reroutedU8 += "\\";

    spdlog::get("hooks")->info("mapping directory in vfs: {}, {}",
                               shared::string_cast<std::string>(originalPath.wstring(),
                                                                shared::CodePage::UTF8),
                               reroutedU8.c_str());

    context->redirectionTable().addDirectory(
        originalPath, RedirectionDataLocal(reroutedU8),
        shared::FLAG_DIRECTORY | shared::FLAG_CREATETARGET);

    fs::directory_iterator end_itr;

    // cycle through the directory; the tree names its entries after reroutedPath, not
    // after the form the iterator takes it in
    for (fs::directory_iterator itr(shared::toWin32Path(reroutedPath.wstring()));
         itr != end_itr; ++itr) {
      // If it's not a directory, add it to the VFS, if it is recurse into it
      if (is_regular_file(itr->path())) {
        std::string fileReroutedU8 = shared::string_cast<std::string>(
            (reroutedPath / itr->path().filename()).wstring(), shared::CodePage::UTF8);
        spdlog::get("hooks")->info(
            "mapping file in vfs: {}, {}",
            shared::string_cast<std::string>(
                (originalPath / itr->path().filename()).wstring(),
                shared::CodePage::UTF8),
            fileReroutedU8.c_str());
        context->redirectionTable().addFile(
            fs::path(originalPath / itr->path().filename()),
            RedirectionDataLocal(fileReroutedU8));
      } else {
        addDirectoryMapping(context, originalPath / itr->path().filename(),
                            reroutedPath / itr->path().filename());
      }
    }

    return true;
  }

  template <class char_t>
  static bool interestingPathImpl(const char_t* inPath)
  {
    if (!inPath || !inPath[0])
      return false;
    // ignore \\.\ unless its a \\.\?:
    if (inPath[0] == '\\' && inPath[1] == '\\' && inPath[2] == '.' &&
        inPath[3] == '\\' && (!inPath[4] || inPath[5] != ':'))
      return false;
    // ignore L"hid#":
    if ((inPath[0] == 'h' || inPath[0] == 'H') &&
        ((inPath[1] == 'i' || inPath[1] == 'I')) &&
        ((inPath[2] == 'd' || inPath[2] == 'D')) && inPath[3] == '#')
      return false;
    return true;
  }

  static bool interestingPath(const char* inPath)
  {
    return interestingPathImpl(inPath);
  }
  static bool interestingPath(const wchar_t* inPath)
  {
    return interestingPathImpl(inPath);
  }

  // The caller's path as the file functions resolve it, but with the current directory
  // the hooks track; nothing for a null path or one to no drive or share.
  static std::optional<shared::DosPath> resolvePath(const wchar_t* inPath)
  {
    if (inPath == nullptr) {
      return std::nullopt;
    }
    const auto path =
        shared::DosPath::fromWin32(inPath, trackedCurrentDirectory(inPath));
    return path ? localDrivePath(*path) : path;
  }

  static RerouteW create(const HookContext::ConstPtr& context,
                         const HookCallContext& callContext, const wchar_t* inPath,
                         bool inverse = false)
  {
    RerouteW result(inPath);
    if (!interestingPath(inPath) || !callContext.active()) {
      return result;
    }
    const auto path = resolvePath(inPath);
    if (!path) {
      return result;
    }
    result.m_RealPath = path->str();

    std::wstring target = k32DeleteTracker.lookup(result.m_RealPath);
    if (!target.empty()) {
      spdlog::get("hooks")->info("Rerouting file open to location of deleted file: {}",
                                 shared::string_cast<std::string>(target));
      result.rerouteTo(target);
      result.m_NewReroute = result.wasRerouted();
      return result;
    }

    const RedirectionTreeContainer& table =
        inverse ? context->inverseTable() : context->redirectionTable();
    result.m_FileNode = table->findNode(fs::path(result.m_RealPath));
    if (!result.m_FileNode.get()) {
      return result;
    }
    if (!result.m_FileNode->data().linkTarget.empty()) {
      result.rerouteTo(shared::string_cast<std::wstring>(
          result.m_FileNode->data().linkTarget.c_str(), shared::CodePage::UTF8));
    } else if (result.m_FileNode->isDirectory()) {
      result.rerouteTo(result.m_FileNode->path().wstring());
    }
    return result;
  }

  static RerouteW createNew(const HookContext::ConstPtr& context,
                            const HookCallContext& callContext, LPCWSTR inPath,
                            bool createPath                          = true,
                            LPSECURITY_ATTRIBUTES securityAttributes = nullptr)
  {
    RerouteW result(inPath);
    if (!interestingPath(inPath) || !callContext.active()) {
      return result;
    }
    const auto path = resolvePath(inPath);
    if (!path) {
      return result;
    }
    result.m_RealPath = path->str();

    std::wstring target = k32DeleteTracker.lookup(result.m_RealPath);
    if (!target.empty()) {
      spdlog::get("hooks")->info(
          "Rerouting file creation to original location of deleted file: {}",
          shared::string_cast<std::string>(target));
    } else {
      FindCreateTarget visitor;
      RedirectionTree::VisitorFunction visitorWrapper =
          [&](const RedirectionTree::NodePtrT& node) {
            visitor(node);
          };
      const fs::path lookupPath(result.m_RealPath);
      context->redirectionTable()->visitPath(lookupPath, visitorWrapper);
      if (!visitor.target.get()) {
        return result;
      }
      // the visitor has found the last (deepest in the directory hierarchy)
      // create-target
      fs::path relativePath = shared::make_relative(visitor.target->path(), lookupPath);
      target = (fs::path(visitor.target->data().linkTarget.c_str()) / relativePath)
                   .wstring();
    }

    result.rerouteTo(target);
    if (!result.wasRerouted()) {
      return result;
    }
    if (createPath) {
      try {
        FunctionGroupLock lock(MutExHookGroup::ALL_GROUPS);
        result.m_PathCreated = createFakePath(
            fs::path(result.m_ReroutedPath->str()).parent_path(), securityAttributes);
      } catch (const std::exception& e) {
        spdlog::get("hooks")->error("failed to create {}: {}",
                                    shared::string_cast<std::string>(target), e.what());
      }
    }
    result.m_NewReroute = true;
    return result;
  }

  static RerouteW createOrNew(const HookContext::ConstPtr& context,
                              const HookCallContext& callContext, LPCWSTR inPath,
                              bool createPath                          = true,
                              LPSECURITY_ATTRIBUTES securityAttributes = nullptr)
  {
    {
      auto res = create(context, callContext, inPath);
      if (res.wasRerouted() || !interestingPath(inPath) || !callContext.active() ||
          pathExists(inPath))
        return std::move(res);
    }
    return createNew(context, callContext, inPath, createPath, securityAttributes);
  }

  static RerouteW noReroute(LPCWSTR inPath)
  {
    RerouteW result;
    if (inPath)
      result.m_Buffer = inPath;
    if (inPath && inPath[0] && !shared::startswith(inPath, L"hid#"))
      std::replace(result.m_Buffer.begin(), result.m_Buffer.end(), L'/', L'\\');
    result.m_HasFileName = true;
    return result;
  }

private:
  // the caller's path as it is, for fileName() to take until it is rerouted
  explicit RerouteW(const wchar_t* inPath)
      : m_Buffer(inPath != nullptr ? inPath : L""), m_HasFileName(inPath != nullptr)
  {}

  // An administrative share of this machine, "\\localhost\C$\dir", names the path on
  // the drive the redirection tree keys it by.
  static shared::DosPath localDrivePath(const shared::DosPath& path)
  {
    const std::wstring_view text = path.str();
    for (const std::wstring_view host : {LR"(\\localhost\)", LR"(\\127.0.0.1\)"}) {
      if (text.size() < host.size() ||
          _wcsnicmp(text.data(), host.data(), host.size()) != 0) {
        continue;
      }
      // "C$" followed by nothing or the path on the drive
      const std::wstring_view share = text.substr(host.size());
      if (share.size() < 2 || share[1] != L'$' ||
          (share.size() > 2 && share[2] != L'\\')) {
        continue;
      }
      const std::wstring drivePath =
          std::wstring{share[0], L':', L'\\'} +
          std::wstring(share.substr(std::min<size_t>(share.size(), 3)));
      return shared::DosPath::fromFullPath(drivePath).value_or(path);
    }
    return path;
  }

  // reroutes to `target`, a path usvfs holds itself
  void rerouteTo(const std::wstring& target)
  {
    m_ReroutedPath = shared::DosPath::fromFullPath(target);
    if (!m_ReroutedPath) {
      spdlog::get("hooks")->warn("not rerouting to a path to no drive or share: {}",
                                 shared::string_cast<std::string>(target));
      return;
    }
    m_Buffer      = m_ReroutedPath->win32Path();
    m_HasFileName = true;
  }

  struct FindCreateTarget
  {
    RedirectionTree::NodePtrT target;
    void operator()(RedirectionTree::NodePtrT node)
    {
      if (node->hasFlag(shared::FLAG_CREATETARGET)) {
        target = node;
      }
    }
  };
};

class CreateRerouter
{
public:
  bool rerouteCreate(const HookContext::ConstPtr& context,
                     const HookCallContext& callContext, LPCWSTR lpFileName,
                     DWORD& dwCreationDisposition, DWORD dwDesiredAccess,
                     LPSECURITY_ATTRIBUTES lpSecurityAttributes)
  {
    enum class Open
    {
      existing,
      create,
      empty
    };
    Open open = Open::existing;

    // Notice since we are calling our patched GetFileAttributesW here this will also
    // check virtualized paths
    DWORD virtAttr = GetFileAttributesW(lpFileName);
    bool isFile    = virtAttr != INVALID_FILE_ATTRIBUTES &&
                     (virtAttr & FILE_ATTRIBUTE_DIRECTORY) == 0;
    m_isDir =
        virtAttr != INVALID_FILE_ATTRIBUTES && (virtAttr & FILE_ATTRIBUTE_DIRECTORY);

    switch (dwCreationDisposition) {
    case CREATE_ALWAYS:
      open = Open::create;
      if (isFile || m_isDir) {
        m_error = ERROR_ALREADY_EXISTS;
      }
      break;

    case CREATE_NEW:
      if (isFile || m_isDir) {
        m_error = ERROR_FILE_EXISTS;
        return false;
      } else {
        open = Open::create;
      }
      break;

    case OPEN_ALWAYS:
      if (isFile || m_isDir) {
        m_error = ERROR_ALREADY_EXISTS;
      } else {
        open = Open::create;
      }
      break;

    case TRUNCATE_EXISTING:
      if ((dwDesiredAccess & GENERIC_WRITE) == 0) {
        m_error = ERROR_INVALID_PARAMETER;
        return false;
      }
      if (isFile || m_isDir)
        open = Open::empty;
      break;
    }

    if (m_isDir && pathIsDirectory(lpFileName))
      m_reroute = RerouteW::noReroute(lpFileName);
    else
      m_reroute = RerouteW::create(context, callContext, lpFileName);

    if (m_reroute.wasRerouted() && open == Open::create &&
        pathIsDirectory(m_reroute.fileName()))
      m_reroute = RerouteW::createNew(context, callContext, lpFileName, true,
                                      lpSecurityAttributes);

    if (!m_isDir && !isFile && !m_reroute.wasRerouted() &&
        (open == Open::create || open == Open::empty)) {
      m_reroute = RerouteW::createNew(context, callContext, lpFileName, true,
                                      lpSecurityAttributes);

      bool newFile =
          !m_reroute.wasRerouted() && pathDirectlyAvailable(m_reroute.fileName());
      if (newFile && open == Open::empty)
        // TRUNCATE_EXISTING will fail since the new file doesn't exist, so change
        // disposition:
        dwCreationDisposition = CREATE_ALWAYS;
    }

    return true;
  }

  // rerouteNew is used for rerouting the destination of copy/move operations. Assumes
  // that the call will be skipped if false is returned.
  bool rerouteNew(const HookContext::ConstPtr& context, HookCallContext& callContext,
                  LPCWSTR lpFileName, bool replaceExisting, const char* hookName)
  {
    DWORD disposition = replaceExisting ? CREATE_ALWAYS : CREATE_NEW;
    if (!rerouteCreate(context, callContext, lpFileName, disposition, GENERIC_WRITE,
                       nullptr)) {
      spdlog::get("hooks")->info(
          "{} guaranteed failure, skipping original call: {}, replaceExisting={}, "
          "error={}",
          hookName,
          shared::string_cast<std::string>(lpFileName, shared::CodePage::UTF8),
          replaceExisting ? "true" : "false", error());

      callContext.updateLastError(error());
      return false;
    }
    return true;
  }

  void updateResult(HookCallContext& callContext, bool success)
  {
    m_originalError = callContext.lastError();
    if (success) {
      // m_error != ERROR_SUCCESS means we are overriding the error on success
      if (m_error == ERROR_SUCCESS)
        m_error = m_originalError;
    } else if (m_originalError == ERROR_PATH_NOT_FOUND && m_directlyAvailable)
      m_error = ERROR_FILE_NOT_FOUND;
    else
      m_error = m_originalError;
    if (m_error != m_originalError)
      callContext.updateLastError(m_error);
  }

  DWORD error() const { return m_error; }
  DWORD originalError() const { return m_originalError; }
  bool changedError() const { return m_error != m_originalError; }

  bool isDir() const { return m_isDir; }
  bool newReroute() const { return m_reroute.newReroute(); }
  bool wasRerouted() const { return m_reroute.wasRerouted(); }
  LPCWSTR fileName() const { return m_reroute.fileName(); }
  LPCWSTR plainFileName() const { return m_reroute.plainFileName(); }
  const std::optional<shared::DosPath>& reroutedPath() const
  {
    return m_reroute.reroutedPath();
  }

  void insertMapping(const HookContext::Ptr& context, bool directory = false)
  {
    m_reroute.insertMapping(context, directory);
  }

private:
  DWORD m_error            = ERROR_SUCCESS;
  DWORD m_originalError    = ERROR_SUCCESS;
  bool m_directlyAvailable = false;
  bool m_isDir             = false;
  RerouteW m_reroute;
};

}  // namespace usvfs
