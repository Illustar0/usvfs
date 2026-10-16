#include "directory_scan.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>

#include <addrtools.h>
#include <loghelpers.h>
#include <stringcast.h>
#include <stringutils.h>
#include <unicodestring.h>

#include "../hookcontext.h"

#include "directory_records.h"
#include "handle_tracker.h"
#include "sharedids.h"

namespace ulog = usvfs::log;
namespace ush  = usvfs::shared;
namespace bfs  = boost::filesystem;

using usvfs::UnicodeString;

// File names compared without regard to case, as shadowing and deduplication
// compare them.
class CaseInsensitiveNameSet
{
public:
  // Returns whether the name was not in the set yet.
  bool insert(const std::wstring& name)
  {
    return m_upperNames.insert(ush::to_upper(name)).second;
  }

  void clear() { m_upperNames.clear(); }

private:
  std::set<std::wstring> m_upperNames;
};

// Gives a record in the buffer another name. Keeps what the stock code did until
// the virtual entries are written through DirectoryOutput: the new name is written
// over the old one even when it is longer, and an 8.3 name, if the record has one,
// is replaced by what GetShortPathNameW makes of the new name, relative to the
// current directory, stored as a count of characters.
void renameRecord(const DirectoryRecordLayout& layout, PVOID record,
                  const std::wstring& name)
{
  auto* bytes = static_cast<std::byte*>(record);
  ULONG fileNameLength;
  std::memcpy(&fileNameLength, bytes + layout.fileNameLengthOffset,
              sizeof(fileNameLength));
  std::memset(bytes + layout.fileNameOffset, 0, fileNameLength);
  fileNameLength = static_cast<ULONG>(name.length() * sizeof(WCHAR));
  std::memcpy(bytes + layout.fileNameLengthOffset, &fileNameLength,
              sizeof(fileNameLength));
  std::memcpy(bytes + layout.fileNameOffset, name.c_str(), fileNameLength);

  if (layout.shortName) {
    CCHAR shortNameLength;
    std::memcpy(&shortNameLength, bytes + layout.shortName->lengthOffset,
                sizeof(shortNameLength));
    if (shortNameLength > 0) {
      shortNameLength = static_cast<CCHAR>(GetShortPathNameW(
          name.c_str(), reinterpret_cast<LPWSTR>(bytes + layout.shortName->offset), 8));
      std::memcpy(bytes + layout.shortName->lengthOffset, &shortNameLength,
                  sizeof(shortNameLength));
    }
  }
}

NTSTATUS addNtSearchData(HANDLE hdl, PUNICODE_STRING FileName,
                         const std::wstring& fakeName,
                         FILE_INFORMATION_CLASS FileInformationClass, PVOID& buffer,
                         ULONG& bufferSize, CaseInsensitiveNameSet& foundFiles,
                         BOOLEAN returnSingleEntry)
{
  NTSTATUS res = STATUS_NO_SUCH_FILE;
  if (hdl != INVALID_HANDLE_VALUE) {
    PVOID lastValidRecord = nullptr;
    PVOID bufferInit      = buffer;
    // the handle completes synchronously and the caller's notifications belong to
    // the caller's query, so this read asks for none
    IO_STATUS_BLOCK status;
    res = NtQueryDirectoryFile(hdl, nullptr, nullptr, nullptr, &status, buffer,
                               bufferSize, FileInformationClass, returnSingleEntry,
                               FileName, FALSE);

    if ((res != STATUS_SUCCESS) || (status.Information <= 0)) {
      bufferSize = 0UL;
    } else {
      // shouldVirtualize lets through only the classes that have a layout
      const DirectoryRecordLayout layout =
          findDirectoryRecordLayout(FileInformationClass).value();
      ULONG totalOffset = 0;
      PVOID lastSkipPos = nullptr;

      while (totalOffset < status.Information) {
        const DirectoryRecord record(layout,
                                     std::span(static_cast<const std::byte*>(buffer),
                                               status.Information - totalOffset));
        ULONG offset          = record.nextEntryOffset();
        std::wstring fileName = record.fileName();
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
          renameRecord(layout, buffer, fakeName);
          fileName = fakeName;
        }
        bool add = true;
        if (fileName.length() > 0) {
          // add only if we didn't find this file before
          add = foundFiles.insert(fileName);
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
      // NextEntryOffset, the first field of every directory record
      const ULONG lastEntryOffset = 0;
      std::memcpy(lastValidRecord, &lastEntryOffset, sizeof(lastEntryOffset));
    }
  }
  return res;
}

// A handle the scan opened itself. Move-only; closes the handle when destroyed, so
// that a scan replaced by a restart or dropped by NtClose does not leak it.
class OwnedHandle
{
public:
  OwnedHandle() = default;
  explicit OwnedHandle(HANDLE handle) : m_handle(handle) {}

  OwnedHandle(OwnedHandle&& other) noexcept
      : m_handle(std::exchange(other.m_handle, INVALID_HANDLE_VALUE))
  {}

  OwnedHandle& operator=(OwnedHandle&& other) noexcept
  {
    if (this != &other) {
      reset();
      m_handle = std::exchange(other.m_handle, INVALID_HANDLE_VALUE);
    }
    return *this;
  }

  ~OwnedHandle() { reset(); }

  HANDLE get() const { return m_handle; }
  bool isValid() const { return isValidHandle(m_handle); }

  // Closes the handle, if there is one.
  void reset()
  {
    if (isValid() && !::CloseHandle(m_handle)) {
      spdlog::get("hooks")->warn("failed to close handle {0:x}: {1}",
                                 reinterpret_cast<std::uintptr_t>(m_handle),
                                 ::GetLastError());
    }
    m_handle = INVALID_HANDLE_VALUE;
  }

private:
  HANDLE m_handle = INVALID_HANDLE_VALUE;
};

// Reads the regular entries of the scanned directory from ntdll and writes those that
// no virtual entry shadows.
class RegularEntryReader
{
public:
  // Reads source, or the handle of the query if source is invalid. The shadowed
  // names are those of the virtual entries, which take precedence.
  RegularEntryReader(OwnedHandle source, CaseInsensitiveNameSet shadowedNames)
      : m_source(std::move(source)), m_names(std::move(shadowedNames))
  {}

  // Writes the entries of the next reads, reading only while the output is empty.
  // Returns STATUS_SUCCESS once it wrote some, and STATUS_NO_MORE_FILES when a read
  // fails.
  NTSTATUS fill(const DirectoryQuery& query, DirectoryOutput& output);

private:
  OwnedHandle m_source;
  // the shadowed names and those of the entries written, so that none is written twice
  CaseInsensitiveNameSet m_names;
  // where a read goes before its entries are filtered; vector storage is aligned for
  // every record, as operator new aligns to 8 bytes or more
  std::vector<std::byte> m_staging;
};

NTSTATUS RegularEntryReader::fill(const DirectoryQuery& query, DirectoryOutput& output)
{
  // shouldVirtualize lets through only the classes that have a layout
  const DirectoryRecordLayout layout =
      findDirectoryRecordLayout(query.informationClass).value();
  const HANDLE source = m_source.isValid() ? m_source.get() : query.handle;
  // as large as the buffer of the query, so that a read returns what a read into that
  // buffer would, and every record it returns fits there too
  m_staging.resize(query.length);

  while (output.isEmpty()) {
    // the handle completes synchronously and the caller's notifications belong to
    // the caller's query, so this read asks for none; like the stock code, it never
    // restarts the native scan
    IO_STATUS_BLOCK status;
    const NTSTATUS result = NtQueryDirectoryFile(
        source, nullptr, nullptr, nullptr, &status, m_staging.data(), query.length,
        query.informationClass, query.isSingleEntry(), query.fileName, FALSE);
    // Kept from the stock code until partial records and errors from ntdll are
    // passed on: any other result ends the regular entries.
    if (result != STATUS_SUCCESS) {
      return STATUS_NO_MORE_FILES;
    }

    std::span<const std::byte> data(m_staging.data(), status.Information);
    while (!data.empty()) {
      const DirectoryRecord record(layout, data);
      if (m_names.insert(record.fileName())) {
        // fits, since the records before it in the output are those before it in
        // the read, or fewer
        output.append(record);
      }
      if (record.nextEntryOffset() == 0) {
        break;
      }
      data = data.subspan(record.nextEntryOffset());
    }
  }
  return STATUS_SUCCESS;
}

// A virtual entry of the scanned directory.
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

// The state of one scan: the queries on a handle from its first query or restart on.
class DirectoryScan
{
public:
  // Starts the scan: picks the directory the regular entries are read from and
  // gathers the virtual entries matching the pattern of the query.
  explicit DirectoryScan(const DirectoryQuery& query);

  // Answers a query with the next entries of the scan. Like ntdll, reports the
  // result both as the return value and in the status block. Queries on the same
  // scan run one at a time, as ntdll runs them on a synchronous handle.
  NTSTATUS query(const DirectoryQuery& query);

private:
  NTSTATUS fill(const DirectoryQuery& query, DirectoryOutput& output, ULONG& dataRead);
  bool addVirtualSearchResult(PVOID& FileInformation,
                              FILE_INFORMATION_CLASS FileInformationClass,
                              const std::wstring& realPath,
                              const std::wstring& virtualName,
                              BOOLEAN ReturnSingleEntry, ULONG& dataRead);

  // whether the queries go straight to ntdll; fixed at construction, so read
  // without the lock
  const bool m_isPassthrough;

  // Guards the state below. Taken after the registry lock is released; nested
  // directory queries made while holding it go straight to ntdll, so it is never
  // taken twice by one thread.
  std::mutex m_mutex;
  // has a value while the scan lists the regular entries, before the virtual ones
  std::optional<RegularEntryReader> m_regular;
  // the names of the virtual entries written, so that none is written twice
  CaseInsensitiveNameSet m_foundFiles;
  // the directory the next virtual entry is read from
  OwnedHandle m_currentSearchHandle;
  std::vector<VirtualMatch> m_virtualMatches;
  // index of the next match to return; the ones before it are done
  size_t m_nextVirtualMatch{0};
  // an empty result is STATUS_NO_SUCH_FILE on the first call only
  bool m_isFirstCall{true};
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

// Returns the virtual entries of a directory that match the pattern of a query.
std::vector<VirtualMatch>
gatherVirtualEntries(const UnicodeString& dirName,
                     const usvfs::RedirectionTreeContainer& redir,
                     PUNICODE_STRING FileName)
{
  std::vector<VirtualMatch> matches;
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

        VirtualMatch m;
        if (subNode->data().linkTarget.length() > 0) {
          m = {ush::string_cast<std::wstring>(subNode->data().linkTarget.c_str(),
                                              ush::CodePage::UTF8),
               vName};
        } else {
          m = {ush::string_cast<std::wstring>(subNode->path().c_str(),
                                              ush::CodePage::UTF8),
               vName};
        }

        matches.push_back(std::move(m));
      }
    }
  }
  return matches;
}

// Opens the directory the regular entries are read from: the search path a hook
// stored for the handle. Returns an invalid handle if there is none or opening it
// fails, in which case the caller's handle is read instead.
OwnedHandle openRegularSource(const std::optional<std::wstring>& storedSearchPath)
{
  if (!storedSearchPath) {
    return OwnedHandle();
  }
  return OwnedHandle(CreateFileW(storedSearchPath->c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
}

// Returns whether every I/O on the handle completes before returning. Only then may
// the virtual listing read regular entries through it and complete the query
// itself. A read on an asynchronous handle can pend, and is not waited for: ntdll
// writes its status block after the read returned, into a stack frame that is
// gone. And the handle may be bound to a completion port, whose packets the
// virtual listing does not post.
bool isSynchronousHandle(HANDLE handle)
{
  FILE_MODE_INFORMATION mode{};
  IO_STATUS_BLOCK status;
  const NTSTATUS result = ::NtQueryInformationFile(handle, &status, &mode, sizeof(mode),
                                                   FileModeInformation);
  return result >= 0 &&
         (mode.Mode & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) != 0;
}

// An asynchronous handle gets a scan that only forwards its queries, so that the
// handle is checked once rather than on every query.
DirectoryScan::DirectoryScan(const DirectoryQuery& query)
    : m_isPassthrough(!isSynchronousHandle(query.handle))
{
  using namespace usvfs;

  if (m_isPassthrough) {
    return;
  }

  // The stored search path also names the virtual directory, so it is looked up
  // under the same context lock as the virtual entries.
  std::optional<std::wstring> storedSearchPath;
  {
    HookContext::Ptr context = WRITE_CONTEXT();

    const SearchHandleMap& searchMap =
        context->customData<SearchHandleMap>(SearchHandles);
    if (const auto iter = searchMap.find(query.handle); iter != searchMap.end()) {
      storedSearchPath = iter->second;
    }
    const UnicodeString searchPath = storedSearchPath
                                         ? UnicodeString(storedSearchPath->c_str())
                                         : ntdllHandleTracker.lookup(query.handle);
    m_virtualMatches =
        gatherVirtualEntries(searchPath, context->redirectionTable(), query.fileName);
  }
  CaseInsensitiveNameSet shadowedNames;
  for (const VirtualMatch& match : m_virtualMatches) {
    shadowedNames.insert(match.virtualName);
  }
  // opened without the context lock, since CreateFileW reenters the hooks
  m_regular.emplace(openRegularSource(storedSearchPath), std::move(shadowedNames));
}

/**
 * @brief insert a virtual entry into the search result
 * @param FileInformation
 * @param FileInformationClass
 * @param realPath path were the actual file resides
 * @param virtualName virtual file name (without path). will often be the same
 *        as the name component of realpath
 * @param ReturnSingleEntry
 * @param dataRead
 * @return true if a virtual result was added, false if the current search handle
 *         yields no more results
 */
bool DirectoryScan::addVirtualSearchResult(PVOID& FileInformation,
                                           FILE_INFORMATION_CLASS FileInformationClass,
                                           const std::wstring& realPath,
                                           const std::wstring& virtualName,
                                           BOOLEAN ReturnSingleEntry, ULONG& dataRead)
{
  // this opens a search in the real location, then copies the information about
  // files we care about (the ones being mapped) to the result we intend to
  // return
  bfs::path fullPath(realPath);
  if (fullPath.filename().wstring() == L".") {
    fullPath = fullPath.parent_path();
  }
  if (!m_currentSearchHandle.isValid()) {
    std::wstring dirName = fullPath.parent_path().wstring();
    if (dirName.length() >= MAX_PATH && !ush::startswith(dirName.c_str(), LR"(\\?\)"))
      dirName = LR"(\\?\)" + dirName;
    m_currentSearchHandle = OwnedHandle(
        CreateFileW(dirName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  }
  std::wstring fileName =
      ush::string_cast<std::wstring>(fullPath.filename().string(), ush::CodePage::UTF8);
  NTSTATUS subRes = addNtSearchData(
      m_currentSearchHandle.get(),
      (fileName != L".") ? static_cast<PUNICODE_STRING>(UnicodeString(fileName.c_str()))
                         : nullptr,
      virtualName, FileInformationClass, FileInformation, dataRead, m_foundFiles,
      ReturnSingleEntry);
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

// Returns the alignment ntdll requires of the buffer of a query.
ULONG requiredBufferAlignment(const DirectoryQuery& query,
                              const DirectoryRecordLayout& layout)
{
  if constexpr (sizeof(void*) == 8) {
    return layout.alignment;
  } else {
    // usvfs_x86 runs under WOW64, where the kernel requires only 4-byte alignment,
    // and wow64.dll copies a legacy query whose buffer is not 8-byte aligned through
    // an aligned buffer of its own; it passes the buffer of an Ex query on as it is
    return query.isEx ? 4 : 1;
  }
}

// Returns whether the virtual listing can serve this query.
bool shouldVirtualize(const DirectoryQuery& query)
{
  // A query asking for an event, an APC or a completion packet is left to ntdll:
  // the virtual listing completes the query itself and delivers none of them.
  // Passing them on to the internal reads does not work either. The notifications
  // then report the internal read instead of the query: the APC gets the read's
  // status block on our stack, the packet the read's byte count. And an internal
  // read can pend, as NTFS does at the end of a directory on a handle bound to a
  // completion port; ntdll then writes its status block after the read returned,
  // into a stack frame that is gone.
  //
  // TODO: virtualize these queries and those on asynchronous handles too, by
  // delivering the notifications ourselves after completing the query: NtSetEvent,
  // NtQueueApcThread(ApcRoutine, ApcContext, IoStatusBlock), and NtSetIoCompletion
  // with the port and key a NtSetInformationFile hook recorded for the handle (they
  // cannot be queried). Until then, these callers see only the physical directory.
  if (query.event || query.apcRoutine || query.apcContext) {
    return false;
  }
  const std::optional<DirectoryRecordLayout> layout =
      findDirectoryRecordLayout(query.informationClass);
  if (!layout) {
    return false;
  }
  // ntdll rejects a buffer that cannot hold a record or is misaligned, so it is left
  // to: the internal reads into that buffer would fail too, and the virtual listing
  // would then report an empty directory instead of the error
  return query.length >= layout->minimumLength &&
         reinterpret_cast<uintptr_t>(query.buffer) %
                 requiredBufferAlignment(query, *layout) ==
             0;
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
//
// Writes the next entries, the regular ones into the output and the virtual ones
// still straight into the buffer of the query, and their size into dataRead.
// Returns STATUS_SUCCESS if it wrote any, and STATUS_NO_MORE_FILES once both the
// regular and the virtual entries are exhausted.
NTSTATUS DirectoryScan::fill(const DirectoryQuery& query, DirectoryOutput& output,
                             ULONG& dataRead)
{
  if (m_regular) {
    if (m_regular->fill(query, output) == STATUS_SUCCESS) {
      dataRead = output.size();
      return STATUS_SUCCESS;
    }
    // the regular entries are done, and the reader's handle and staging area with them
    m_regular.reset();
  }

  // add virtual results, into the buffer the regular entries left empty
  PVOID FileInformationCurrent = query.buffer;
  bool dataReturned            = false;
  while (!dataReturned && m_nextVirtualMatch < m_virtualMatches.size()) {
    const VirtualMatch& match = m_virtualMatches[m_nextVirtualMatch];
    if (match.realPath.size() != 0) {
      dataRead = query.length;
      if (addVirtualSearchResult(FileInformationCurrent, query.informationClass,
                                 match.realPath, match.virtualName,
                                 query.isSingleEntry(), dataRead)) {
        // a positive result here means the call returned data and there may
        // be further objects to be retrieved by repeating the call
        dataReturned = true;
      } else {
        // proceed to next search handle

        // TODO: doesn't append search results from more than one redirection
        // per call. This is bad for performance but otherwise we'd need to
        // re-write the offsets between information objects
        ++m_nextVirtualMatch;
        m_currentSearchHandle.reset();
      }
    }
  }
  if (!dataReturned) {
    // the read of a virtual entry whose source did not open leaves the capacity in
    // dataRead
    dataRead = 0;
    return STATUS_NO_MORE_FILES;
  }
  return STATUS_SUCCESS;
}

NTSTATUS DirectoryScan::query(const DirectoryQuery& query)
{
  if (m_isPassthrough) {
    return queryNative(query);
  }
  std::lock_guard lock(m_mutex);
  const bool isFirstCall = std::exchange(m_isFirstCall, false);

  // shouldVirtualize lets through only the classes that have a layout
  DirectoryOutput output(
      std::span(static_cast<std::byte*>(query.buffer), query.length),
      findDirectoryRecordLayout(query.informationClass).value(),
      {.isSingleEntry = query.isSingleEntry(), .isFirstCall = isFirstCall});
  ULONG dataRead;
  const NTSTATUS res = fill(query, output, dataRead);
  // an empty first result is an error, and ntdll leaves the status block of a
  // failed query alone
  if (res == STATUS_NO_MORE_FILES && isFirstCall) {
    return STATUS_NO_SUCH_FILE;
  }
  query.statusBlock->Status      = res;
  query.statusBlock->Information = dataRead;

  size_t numVirtualFiles = m_virtualMatches.size() - m_nextVirtualMatch;
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

NTSTATUS queryDirectory(const DirectoryQuery& query)
{
  if (!shouldVirtualize(query)) {
    return queryNative(query);
  }
  return directoryScans.scanFor(query)->query(query);
}

bool eraseDirectoryScan(HANDLE handle)
{
  // a query still running on the scan keeps it, and its handle, open until it returns
  return directoryScans.erase(handle) != nullptr;
}
