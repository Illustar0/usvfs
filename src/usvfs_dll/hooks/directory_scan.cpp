#include "directory_scan.h"

#include <cstddef>
#include <cstdint>
#include <cwchar>
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

  bool contains(const std::wstring& name) const
  {
    return m_upperNames.contains(ush::to_upper(name));
  }

private:
  std::set<std::wstring> m_upperNames;
};

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
  // names are those of the virtual entries, which take precedence. A reader for a
  // restarted scan restarts the native scan with its first read.
  RegularEntryReader(OwnedHandle source, CaseInsensitiveNameSet shadowedNames,
                     bool isRestart)
      : m_source(std::move(source)), m_names(std::move(shadowedNames)),
        m_isRestartPending(isRestart)
  {}

  // Writes the entries of the next reads, reading only while the output is empty.
  // Returns STATUS_SUCCESS once it wrote some, STATUS_BUFFER_OVERFLOW once it wrote
  // the partial record of a read, STATUS_NO_MORE_FILES once the entries are done, and
  // the error of a read that fails otherwise.
  NTSTATUS fill(const DirectoryQuery& query, DirectoryOutput& output);

private:
  OwnedHandle m_source;
  // the shadowed names and those of the entries written, so that none is written twice
  CaseInsensitiveNameSet m_names;
  bool m_isRestartPending;
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
    // The handle completes synchronously and the caller's notifications belong to
    // the caller's query, so this read asks for none. A restart goes on to the native
    // scan of the caller's handle, which would go on from where it was otherwise;
    // ntdll then lists with the pattern of the restart, or the one it latched when
    // the restart brings none. A reopened source starts at its first entry anyway.
    IO_STATUS_BLOCK status;
    const NTSTATUS result = NtQueryDirectoryFile(
        source, nullptr, nullptr, nullptr, &status, m_staging.data(), query.length,
        query.informationClass, query.isSingleEntry(), query.fileName,
        std::exchange(m_isRestartPending, false));
    // ntdll cuts a first record that does not fit short, and returns it again on
    // every query until a buffer holds it, so the regular entries do not end here.
    // Its name may be cut short too, which leaves no telling whether a virtual entry
    // shadows it: it is passed on either way, and filtered once it comes whole.
    if (result == STATUS_BUFFER_OVERFLOW) {
      output.mirror(std::span(m_staging).first(status.Information));
      return result;
    }
    // a pattern that matches nothing ends the entries on the first read already
    if (result == STATUS_NO_MORE_FILES || result == STATUS_NO_SUCH_FILE) {
      return STATUS_NO_MORE_FILES;
    }
    if (result != STATUS_SUCCESS) {
      return result;
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

// Reads each virtual entry from the directory its file or directory lies in, and
// writes it under its virtual name.
class VirtualEntryReader
{
public:
  VirtualEntryReader() = default;
  explicit VirtualEntryReader(std::vector<VirtualMatch> matches)
      : m_matches(std::move(matches))
  {}

  // Writes the next entry that reads and is not written yet. An entry that does not
  // fit is left for the next call. Returns STATUS_SUCCESS once it wrote one or the
  // output holds no more, STATUS_BUFFER_OVERFLOW once it wrote the partial record of
  // one, and STATUS_NO_MORE_FILES when none is left.
  NTSTATUS fill(const DirectoryQuery& query, DirectoryOutput& output);

private:
  // Reads the record of what a match maps to from the directory it lies in. Returns
  // nothing when the read fails.
  std::optional<DirectoryRecord> read(const VirtualMatch& match,
                                      const DirectoryQuery& query);

  std::vector<VirtualMatch> m_matches;
  // index of the next match to try; the ones before it are done
  size_t m_nextMatch = 0;
  // the names of the entries written, so that none is written twice
  CaseInsensitiveNameSet m_names;
  // where a read goes before its entry is written, aligned as the regular reader's
  std::vector<std::byte> m_staging;
};

NTSTATUS VirtualEntryReader::fill(const DirectoryQuery& query, DirectoryOutput& output)
{
  // Kept from the stock code: a query gets one entry at most, and an entry that does
  // not read or is written already is dropped.
  for (; m_nextMatch < m_matches.size(); ++m_nextMatch) {
    const VirtualMatch& match                   = m_matches[m_nextMatch];
    const std::optional<DirectoryRecord> record = read(match, query);
    if (!record) {
      continue;
    }
    const std::wstring name =
        match.virtualName.empty() ? record->fileName() : match.virtualName;
    if (m_names.contains(name)) {
      continue;
    }
    const bool isWritten = match.virtualName.empty()
                               ? output.append(*record)
                               : output.appendRenamed(*record, name);
    // like ntdll, an entry that does not fit stays for the next call to return, be it
    // after its partial record or after the entries the output holds
    if (!isWritten) {
      return output.isOverflowed() ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
    }
    m_names.insert(name);
    ++m_nextMatch;
    return STATUS_SUCCESS;
  }
  return STATUS_NO_MORE_FILES;
}

std::optional<DirectoryRecord> VirtualEntryReader::read(const VirtualMatch& match,
                                                        const DirectoryQuery& query)
{
  // the path of a directory mapped with all its content ends with a separator, which
  // leaves "." as its file name
  bfs::path fullPath(match.realPath);
  if (fullPath.filename().wstring() == L".") {
    fullPath = fullPath.parent_path();
  }
  std::wstring directoryPath = fullPath.parent_path().wstring();
  if (directoryPath.length() >= MAX_PATH &&
      !ush::startswith(directoryPath.c_str(), LR"(\\?\)")) {
    directoryPath = LR"(\\?\)" + directoryPath;
  }
  const OwnedHandle directory(CreateFileW(
      directoryPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (!directory.isValid()) {
    spdlog::get("hooks")->warn("failed to open the directory of {0} to list it: {1}",
                               fullPath.string(), ::GetLastError());
    return std::nullopt;
  }

  // shouldVirtualize lets through only the classes that have a layout
  const DirectoryRecordLayout layout =
      findDirectoryRecordLayout(query.informationClass).value();
  const std::wstring fileName =
      ush::string_cast<std::wstring>(fullPath.filename().string(), ush::CodePage::UTF8);
  UnicodeString pattern(fileName.c_str());
  // holds a record with the longest name there is, as the record goes out under the
  // virtual name, whose length alone decides whether it fits the buffer of the query
  m_staging.resize(layout.fileNameOffset + UNICODE_STRING_MAX_BYTES);
  IO_STATUS_BLOCK status;
  const NTSTATUS result = NtQueryDirectoryFile(
      directory.get(), nullptr, nullptr, nullptr, &status, m_staging.data(),
      static_cast<ULONG>(m_staging.size()), query.informationClass,
      query.isSingleEntry(),
      fileName != L"." ? static_cast<PUNICODE_STRING>(pattern) : nullptr, FALSE);
  if (result != STATUS_SUCCESS) {
    spdlog::get("hooks")->warn("error reported listing files in {0}: {1:x}",
                               fullPath.string(), static_cast<uint32_t>(result));
    return std::nullopt;
  }

  // the pattern is the name of the file, so the read starts with its record
  return DirectoryRecord(layout, std::span(m_staging).first(status.Information));
}

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
  NTSTATUS fill(const DirectoryQuery& query, DirectoryOutput& output);

  // whether the queries go straight to ntdll; fixed at construction, so read
  // without the lock
  const bool m_isPassthrough;

  // Guards the state below. Taken after the registry lock is released; nested
  // directory queries made while holding it go straight to ntdll, so it is never
  // taken twice by one thread.
  std::mutex m_mutex;
  // has a value while the scan lists the regular entries, before the virtual ones
  std::optional<RegularEntryReader> m_regular;
  VirtualEntryReader m_virtual;
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
  UnicodeString searchPath;
  std::vector<VirtualMatch> virtualMatches;
  {
    HookContext::Ptr context = WRITE_CONTEXT();

    const SearchHandleMap& searchMap =
        context->customData<SearchHandleMap>(SearchHandles);
    if (const auto iter = searchMap.find(query.handle); iter != searchMap.end()) {
      storedSearchPath = iter->second;
    }
    searchPath = storedSearchPath ? UnicodeString(storedSearchPath->c_str())
                                  : ntdllHandleTracker.lookup(query.handle);
    virtualMatches =
        gatherVirtualEntries(searchPath, context->redirectionTable(), query.fileName);
  }
  // opened without the context lock, since CreateFileW reenters the hooks
  OwnedHandle regularSource = openRegularSource(storedSearchPath);

  // logged once per scan, under the hook's name so that both entry points stay
  // distinguishable
  ulog::CallLogger(query.isEx ? "hook_NtQueryDirectoryFileEx"
                              : "hook_NtQueryDirectoryFile")
      .addParam("path", searchPath)
      .addParam("FileName", query.fileName != nullptr
                                ? std::wstring(query.fileName->Buffer,
                                               query.fileName->Length / sizeof(WCHAR))
                                : std::wstring(L"<null>"))
      .addParam("regularSource", regularSource.isValid()
                                     ? *storedSearchPath
                                     : std::wstring(L"<queried handle>"))
      .addParam("numVirtualFiles", virtualMatches.size());

  CaseInsensitiveNameSet shadowedNames;
  for (const VirtualMatch& match : virtualMatches) {
    shadowedNames.insert(match.virtualName);
  }
  m_regular.emplace(std::move(regularSource), std::move(shadowedNames),
                    query.isRestart());
  m_virtual = VirtualEntryReader(std::move(virtualMatches));
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

// Writes the next entries of the scan: the regular ones first, so that "." and ".."
// come with the first query of a wildcard search as callers expect, then the virtual
// ones. Returns STATUS_SUCCESS if it wrote any, STATUS_BUFFER_OVERFLOW if it passed
// on a partial record from ntdll, STATUS_NO_MORE_FILES once both are exhausted, and
// the error of a regular read that fails, after which the next query reads again.
NTSTATUS DirectoryScan::fill(const DirectoryQuery& query, DirectoryOutput& output)
{
  if (m_regular) {
    const NTSTATUS status = m_regular->fill(query, output);
    if (status != STATUS_NO_MORE_FILES) {
      return status;
    }
    // the regular entries are done, and the reader's handle and staging area with them
    m_regular.reset();
  }
  return m_virtual.fill(query, output);
}

NTSTATUS DirectoryScan::query(const DirectoryQuery& query)
{
  if (m_isPassthrough) {
    return queryNative(query);
  }
  std::lock_guard lock(m_mutex);
  // shouldVirtualize lets through only the classes that have a layout
  DirectoryOutput output(std::span(static_cast<std::byte*>(query.buffer), query.length),
                         findDirectoryRecordLayout(query.informationClass).value(),
                         {.isSingleEntry = query.isSingleEntry(),
                          .isFirstCall   = std::exchange(m_isFirstCall, false)});
  return output.complete(fill(query, output), *query.statusBlock);
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
