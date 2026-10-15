#include "directory_scan.h"

#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <shared_mutex>
#include <unordered_map>
#include <utility>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>

#include <addrtools.h>
#include <loghelpers.h>
#include <stringcast.h>
#include <stringutils.h>
#include <unicodestring.h>

#include "../hookcontext.h"

#include "file_information_utils.h"
#include "handle_tracker.h"
#include "sharedids.h"

namespace ulog = usvfs::log;
namespace ush  = usvfs::shared;
namespace bfs  = boost::filesystem;

using usvfs::UnicodeString;

NTSTATUS addNtSearchData(HANDLE hdl, PUNICODE_STRING FileName,
                         const std::wstring& fakeName,
                         FILE_INFORMATION_CLASS FileInformationClass, PVOID& buffer,
                         ULONG& bufferSize, std::set<std::wstring>& foundFiles,
                         HANDLE event, PIO_APC_ROUTINE apcRoutine, PVOID apcContext,
                         BOOLEAN returnSingleEntry)
{
  NTSTATUS res = STATUS_NO_SUCH_FILE;
  if (hdl != INVALID_HANDLE_VALUE) {
    PVOID lastValidRecord = nullptr;
    PVOID bufferInit      = buffer;
    IO_STATUS_BLOCK status;
    res = NtQueryDirectoryFile(hdl, event, apcRoutine, apcContext, &status, buffer,
                               bufferSize, FileInformationClass, returnSingleEntry,
                               FileName, FALSE);

    if ((res != STATUS_SUCCESS) || (status.Information <= 0)) {
      bufferSize = 0UL;
    } else {
      ULONG totalOffset = 0;
      PVOID lastSkipPos = nullptr;

      while (totalOffset < status.Information) {
        ULONG offset;
        std::wstring fileName;
        GetFileInformationData(FileInformationClass, buffer, offset, fileName);
        // in case this is a single-file search result and the specified
        // filename differs from the file name found, replace it in the
        // information structure
        if ((totalOffset == 0) && (offset == 0) && (fakeName.length() > 0)) {
          // if the fake name is larger than what is in the buffer and there is
          // not enough room, that's a buffer overflow
          if ((fakeName.length() > fileName.length()) &&
              ((fakeName.length() - fileName.length()) >
               (bufferSize - status.Information))) {
            res = STATUS_BUFFER_OVERFLOW;
            break;
          }
          // WARNING for the case where the fake name is longer this needs to
          // move back all further results and update the offset first
          SetFileInformationFileName(FileInformationClass, buffer, fakeName);
          fileName = fakeName;
        }
        bool add = true;
        if (fileName.length() > 0) {
          auto insertRes = foundFiles.insert(ush::to_upper(fileName));
          add = insertRes.second;  // add only if we didn't find this file before
        }
        if (!add) {
          if (lastSkipPos == nullptr) {
            lastSkipPos = buffer;
          }
        } else {
          if (lastSkipPos != nullptr) {
            memmove(lastSkipPos, buffer, status.Information - totalOffset);
            ULONG delta = static_cast<ULONG>(ush::AddrDiff(buffer, lastSkipPos));
            totalOffset -= delta;

            buffer      = lastSkipPos;
            lastSkipPos = nullptr;
          }
          lastValidRecord = buffer;
        }

        if (offset == 0) {
          offset = static_cast<ULONG>(status.Information) - totalOffset;
        }
        buffer = ush::AddrAdd(buffer, offset);
        totalOffset += offset;
      }

      if (lastSkipPos != nullptr) {
        buffer     = lastSkipPos;
        bufferSize = static_cast<ULONG>(ush::AddrDiff(buffer, bufferInit));
        // null out the unused rest if there is some
        memset(lastSkipPos, 0, status.Information - bufferSize);
      } else {
        bufferSize = static_cast<ULONG>(ush::AddrDiff(buffer, bufferInit));
      }
    }
    if (lastValidRecord != nullptr) {
      SetFileInformationOffset(FileInformationClass, lastValidRecord, 0);
    }
  }
  return res;
}

// The state of one scan: the queries on a handle from its first query or restart on.
struct DirectoryScan
{
  struct VirtualMatch
  {
    // full path to where the file/directory actually is
    std::wstring realPath;
    // virtual filename (only filename since it has to be within the searched
    // directory)
    // this is left empty when a folder with all its content is mapped to the
    // search directory
    std::wstring virtualName;
  };

  // Starts the scan: picks the directory the regular entries are read from and
  // gathers the virtual entries matching the pattern of the query.
  explicit DirectoryScan(const DirectoryQuery& query);

  std::set<std::wstring> foundFiles;
  HANDLE currentSearchHandle{INVALID_HANDLE_VALUE};
  std::queue<VirtualMatch> virtualMatches;
  UnicodeString searchPattern;
  bool regularComplete{false};
  // an empty result is STATUS_NO_SUCH_FILE on the first call only
  bool isFirstCall{true};
};

// The scans of all directory handles. The lock is a leaf: nothing else is called
// while holding it, and no scan is destroyed under it.
class DirectoryScans
{
public:
  // Returns the scan serving a query: a new one on the first query of a handle or
  // on a restart, the current one otherwise.
  std::shared_ptr<DirectoryScan> scanFor(const DirectoryQuery& query)
  {
    std::shared_ptr<DirectoryScan> current = find(query.handle);
    if (current && !query.isRestart()) {
      return current;
    }
    // tradeoff time: we store this search status even if no virtual results
    // were found. This causes a little extra cost here and in NtClose every
    // time a non-virtual dir is being searched. However if we don't,
    // whenever NtQueryDirectoryFile is called another time on the same handle,
    // this (expensive) construction would be run again.
    //
    // Constructed without the lock, since construction takes the hook context
    // lock and reenters hooks. Declared before the lock, so that a scan that is
    // unused or replaced is destroyed after unlocking.
    auto scan = std::make_shared<DirectoryScan>(query);
    std::unique_lock lock(m_mutex);
    const auto [entry, isInserted] = m_scans.try_emplace(query.handle, scan);
    if (!isInserted && query.isRestart()) {
      entry->second.swap(scan);
    }
    // concurrent first queries on one handle: the first scan inserted wins
    return entry->second;
  }

  // Removes the scan of a handle and returns it, so that the caller destroys it
  // after the lock is released. Returns an empty pointer if the handle has none.
  std::shared_ptr<DirectoryScan> erase(HANDLE handle)
  {
    std::unique_lock lock(m_mutex);
    auto entry = m_scans.extract(handle);
    return entry ? std::move(entry.mapped()) : nullptr;
  }

private:
  // Returns the scan of a handle, or an empty pointer if it has none.
  std::shared_ptr<DirectoryScan> find(HANDLE handle) const
  {
    std::shared_lock lock(m_mutex);
    const auto entry = m_scans.find(handle);
    return entry != m_scans.end() ? entry->second : nullptr;
  }

  mutable std::shared_mutex m_mutex;
  std::unordered_map<HANDLE, std::shared_ptr<DirectoryScan>> m_scans;
};

// Shared by both query hooks and NtClose. Never destroyed, so that hooks still
// running while the DLL unloads do not touch a destroyed registry.
DirectoryScans& directoryScans = *new DirectoryScans;

void gatherVirtualEntries(const UnicodeString& dirName,
                          const usvfs::RedirectionTreeContainer& redir,
                          PUNICODE_STRING FileName, DirectoryScan& info)
{
  LPCWSTR dirNameW = static_cast<LPCWSTR>(dirName);
  // fix directory name. I'd love to know why microsoft sometimes uses "\??\" vs
  // "\\?\"
  if ((wcsncmp(dirNameW, LR"(\\?\)", 4) == 0) ||
      (wcsncmp(dirNameW, LR"(\??\)", 4) == 0)) {
    dirNameW += 4;
  }
  auto node = redir->findNode(boost::filesystem::path(dirNameW));
  if (node.get() != nullptr) {
    std::string searchPattern =
        FileName != nullptr
            ? ush::string_cast<std::string>(FileName->Buffer, ush::CodePage::UTF8,
                                            FileName->Length / sizeof(WCHAR))
            : "*.*";

    boost::replace_all(searchPattern, "\"", ".");

    for (const auto& subNode : node->find(searchPattern)) {
      if (((subNode->data().linkTarget.length() > 0) || subNode->isDirectory()) &&
          !subNode->hasFlag(usvfs::shared::FLAG_DUMMY)) {
        std::wstring vName =
            ush::string_cast<std::wstring>(subNode->name(), ush::CodePage::UTF8);

        DirectoryScan::VirtualMatch m;
        if (subNode->data().linkTarget.length() > 0) {
          m = {ush::string_cast<std::wstring>(subNode->data().linkTarget.c_str(),
                                              ush::CodePage::UTF8),
               vName};
        } else {
          m = {ush::string_cast<std::wstring>(subNode->path().c_str(),
                                              ush::CodePage::UTF8),
               vName};
        }

        info.virtualMatches.push(m);
        info.foundFiles.insert(ush::to_upper(vName));
      }
    }
  }
}

DirectoryScan::DirectoryScan(const DirectoryQuery& query)
{
  using namespace usvfs;

  HookContext::Ptr context = WRITE_CONTEXT();
  searchPattern.appendPath(query.fileName);

  SearchHandleMap& searchMap     = context->customData<SearchHandleMap>(SearchHandles);
  SearchHandleMap::iterator iter = searchMap.find(query.handle);

  UnicodeString searchPath;
  if (iter != searchMap.end()) {
    searchPath          = UnicodeString(iter->second.c_str());
    currentSearchHandle = CreateFileW(
        iter->second.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  } else {
    searchPath = ntdllHandleTracker.lookup(query.handle);
  }
  gatherVirtualEntries(searchPath, context->redirectionTable(), query.fileName, *this);
}

/**
 * @brief insert a virtual entry into the search result
 * @param FileInformation
 * @param FileInformationClass
 * @param info
 * @param realPath path were the actual file resides
 * @param virtualName virtual file name (without path). will often be the same
 *        as the name component of realpath
 * @param ReturnSingleEntry
 * @param dataRead
 * @return true if a virtual result was added, false if the search handle in the
 *         info object yields no more results
 */
bool addVirtualSearchResult(PVOID& FileInformation,
                            FILE_INFORMATION_CLASS FileInformationClass,
                            DirectoryScan& info, const std::wstring& realPath,
                            const std::wstring& virtualName, BOOLEAN ReturnSingleEntry,
                            ULONG& dataRead)
{
  // this opens a search in the real location, then copies the information about
  // files we care about (the ones being mapped) to the result we intend to
  // return
  bfs::path fullPath(realPath);
  if (fullPath.filename().wstring() == L".") {
    fullPath = fullPath.parent_path();
  }
  if (info.currentSearchHandle == INVALID_HANDLE_VALUE) {
    std::wstring dirName = fullPath.parent_path().wstring();
    if (dirName.length() >= MAX_PATH && !ush::startswith(dirName.c_str(), LR"(\\?\)"))
      dirName = LR"(\\?\)" + dirName;
    info.currentSearchHandle =
        CreateFileW(dirName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  }
  std::wstring fileName =
      ush::string_cast<std::wstring>(fullPath.filename().string(), ush::CodePage::UTF8);
  NTSTATUS subRes = addNtSearchData(
      info.currentSearchHandle,
      (fileName != L".") ? static_cast<PUNICODE_STRING>(UnicodeString(fileName.c_str()))
                         : nullptr,
      virtualName, FileInformationClass, FileInformation, dataRead, info.foundFiles,
      nullptr, nullptr, nullptr, ReturnSingleEntry);
  if (subRes == STATUS_SUCCESS) {
    return true;
  } else {
    // STATUS_NO_MORE_FILES merely means the search ended, everything else is an
    // error message. Either way, the search here is finished and we should
    // resume in the next mapped directory
    if (subRes != STATUS_NO_MORE_FILES) {
      spdlog::get("hooks")->warn("error reported listing files in {0}: {1:x}",
                                 fullPath.string(), static_cast<uint32_t>(subRes));
    }
    return false;
  }
}

NTSTATUS queryNative(const DirectoryQuery& query)
{
  if (query.isEx) {
    return ::NtQueryDirectoryFileEx(query.handle, query.event, query.apcRoutine,
                                    query.apcContext, query.statusBlock, query.buffer,
                                    query.length, query.informationClass, query.flags,
                                    query.fileName);
  }
  return ::NtQueryDirectoryFile(
      query.handle, query.event, query.apcRoutine, query.apcContext, query.statusBlock,
      query.buffer, query.length, query.informationClass, query.isSingleEntry(),
      query.fileName, query.isRestart());
}

// Returns whether the virtual listing can serve this query.
bool shouldVirtualize(const DirectoryQuery& query)
{
  // the virtual listing can only filter and rename records that carry a FileName
  switch (query.informationClass) {
  case FileDirectoryInformation:
  case FileFullDirectoryInformation:
  case FileBothDirectoryInformation:
  case FileNamesInformation:
  case FileIdBothDirectoryInformation:
  case FileIdFullDirectoryInformation:
  case FileIdExtdDirectoryInformation:
  case FileIdExtdBothDirectoryInformation:
  case FileId64ExtdDirectoryInformation:
  case FileId64ExtdBothDirectoryInformation:
  case FileIdAllExtdDirectoryInformation:
  case FileIdAllExtdBothDirectoryInformation:
    return true;
  default:
    return false;
  }
}

// this is quite messy...
// first, this will gather the virtual locations mapping to the iterated one
// then we return results from the real location, skipping those that exist
//   in the virtual locations, as those take precedence
// finally the virtual results are returned, adding each result to a skip
//   list, so they don't get added twice
//
// if we don't add the regular files first, "." and ".." wouldn't be in the
//   first search result of wildcard searches which may confuse the caller
NTSTATUS queryDirectory(const DirectoryQuery& query)
{
  if (!shouldVirtualize(query)) {
    return queryNative(query);
  }

  const std::shared_ptr<DirectoryScan> scan = directoryScans.scanFor(query);
  const bool isFirstCall                    = std::exchange(scan->isFirstCall, false);

  ULONG dataRead               = query.length;
  PVOID FileInformationCurrent = query.buffer;

  // add regular search results, skipping those files we have in a virtual
  // location
  bool moreRegular  = !scan->regularComplete;
  bool dataReturned = false;
  while (moreRegular && !dataReturned) {
    dataRead = query.length;

    HANDLE handle = scan->currentSearchHandle;
    if (handle == INVALID_HANDLE_VALUE) {
      handle = query.handle;
    }
    NTSTATUS subRes =
        addNtSearchData(handle, query.fileName, L"", query.informationClass,
                        FileInformationCurrent, dataRead, scan->foundFiles, query.event,
                        query.apcRoutine, query.apcContext, query.isSingleEntry());
    moreRegular = subRes == STATUS_SUCCESS;
    if (moreRegular) {
      dataReturned = dataRead != 0;
    } else {
      scan->regularComplete = true;
      scan->foundFiles.clear();
      if (scan->currentSearchHandle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(scan->currentSearchHandle);
        scan->currentSearchHandle = INVALID_HANDLE_VALUE;
      }
    }
  }
  if (!moreRegular) {
    // add virtual results
    while (!dataReturned && scan->virtualMatches.size() > 0) {
      auto match = scan->virtualMatches.front();
      if (match.realPath.size() != 0) {
        dataRead = query.length;
        if (addVirtualSearchResult(FileInformationCurrent, query.informationClass,
                                   *scan, match.realPath, match.virtualName,
                                   query.isSingleEntry(), dataRead)) {
          // a positive result here means the call returned data and there may
          // be further objects to be retrieved by repeating the call
          dataReturned = true;
        } else {
          // proceed to next search handle

          // TODO: doesn't append search results from more than one redirection
          // per call. This is bad for performance but otherwise we'd need to
          // re-write the offsets between information objects
          scan->virtualMatches.pop();
          CloseHandle(scan->currentSearchHandle);
          scan->currentSearchHandle = INVALID_HANDLE_VALUE;
        }
      }
    }
  }

  NTSTATUS res;
  if (!dataReturned) {
    if (isFirstCall) {
      res = STATUS_NO_SUCH_FILE;
    } else {
      res = STATUS_NO_MORE_FILES;
    }
  } else {
    res = STATUS_SUCCESS;
  }
  query.statusBlock->Status      = res;
  query.statusBlock->Information = dataRead;

  size_t numVirtualFiles = scan->virtualMatches.size();
  if ((numVirtualFiles > 0)) {
    // log under the hook's name so both entry points stay distinguishable
    ulog::CallLogger(query.isEx ? "hook_NtQueryDirectoryFileEx"
                                : "hook_NtQueryDirectoryFile")
        .addParam("path", ntdllHandleTracker.lookup(query.handle))
        .addParam("FileInformationClass", query.informationClass)
        .addParam("FileName", query.fileName)
        .addParam("QueryFlags", query.flags)
        .PARAM(numVirtualFiles)
        .PARAMWRAP(res);
  }

  return res;
}

bool eraseDirectoryScan(HANDLE handle)
{
  const std::shared_ptr<DirectoryScan> scan = directoryScans.erase(handle);
  if (!scan) {
    return false;
  }
  if (scan->currentSearchHandle != INVALID_HANDLE_VALUE) {
    ::CloseHandle(scan->currentSearchHandle);
  }
  return true;
}
