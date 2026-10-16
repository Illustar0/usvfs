#include "directory_scan.h"

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/filesystem.hpp>

#include <loghelpers.h>
#include <stringcast.h>
#include <stringutils.h>
#include <unicodestring.h>

#include "../hookcallcontext.h"
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

// Opens a directory for synchronous enumeration, with the usvfs hooks suppressed.
//
// The legacy implementation opened mapping source directories with CreateFileW
// without suppressing the hooks, so every internal directory open re-entered the
// NtCreateFile and attribute hooks of usvfs and incurred substantial redundant path
// rerouting and lock overhead.
//
// Suppressing the hooks means that a mapping source directory that only exists
// virtually (a chained virtual-to-virtual mapping) is no longer redirected a second
// time during directory enumeration. However, the file-open hooks only perform a
// single-hop reroute anyway, so such second-hop virtual files could never actually be
// opened (ERROR_PATH_NOT_FOUND); preserving that accidental enumeration behavior has
// little practical value while significantly hurting performance for normal physical
// source directories.
//
// The hooks still track the handle, as they see it closed.
OwnedHandle openScanDirectory(const std::wstring& path)
{
  // the hooks pass a call straight to ntdll while any group of theirs is held
  const usvfs::FunctionGroupLock unhooked(usvfs::MutExHookGroup::ALL_GROUPS);
  return OwnedHandle(CreateFileW(path.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
}

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
      : m_source(std::move(source)), m_shadowedNames(std::move(shadowedNames)),
        m_isRestartPending(isRestart)
  {}

  // Writes the entries of the next reads, reading only while the output is empty.
  // Returns STATUS_SUCCESS once it wrote some, STATUS_BUFFER_OVERFLOW once it wrote
  // the partial record of a read, STATUS_NO_MORE_FILES once the entries are done, and
  // the error of a read that fails otherwise.
  NTSTATUS fill(const DirectoryQuery& query, DirectoryOutput& output);

private:
  OwnedHandle m_source;
  // Only these are left out: ntdll lists every entry once, and names that differ in
  // case only are different entries in a case-sensitive directory.
  CaseInsensitiveNameSet m_shadowedNames;
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
      if (!m_shadowedNames.contains(record.fileName())) {
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

// Reads the records of a directory through a handle of its own, for a query that
// usvfs makes itself rather than one of the caller. Closes the handle when destroyed.
class NativeDirectoryReader
{
public:
  // Scans directory for the entries that match pattern, or for all of them without
  // one, in the information class of layout. Reads into buffer, which it sizes to
  // hold a record with the longest name there is; a record returned stays valid in
  // the buffer until the reader reads again.
  NativeDirectoryReader(OwnedHandle directory, const DirectoryRecordLayout& layout,
                        std::optional<std::wstring_view> pattern,
                        std::vector<std::byte>& buffer);

  // Returns the next record of the scan, or nothing once the scan ends.
  std::optional<DirectoryRecord> next();
  // what ended the scan, STATUS_SUCCESS while it goes on
  NTSTATUS endStatus() const { return m_endStatus; }

private:
  OwnedHandle m_directory;
  DirectoryRecordLayout m_layout;
  std::optional<UnicodeString> m_pattern;
  std::vector<std::byte>& m_buffer;
  // the records of the last read that next has not returned yet
  std::span<const std::byte> m_records;
  NTSTATUS m_endStatus = STATUS_SUCCESS;
};

NativeDirectoryReader::NativeDirectoryReader(OwnedHandle directory,
                                             const DirectoryRecordLayout& layout,
                                             std::optional<std::wstring_view> pattern,
                                             std::vector<std::byte>& buffer)
    : m_directory(std::move(directory)), m_layout(layout), m_buffer(buffer)
{
  if (pattern) {
    m_pattern.emplace(pattern->data(), pattern->size());
  }
  m_buffer.resize(m_layout.fileNameOffset + UNICODE_STRING_MAX_BYTES);
}

std::optional<DirectoryRecord> NativeDirectoryReader::next()
{
  if (m_records.empty()) {
    if (m_endStatus != STATUS_SUCCESS) {
      return std::nullopt;
    }
    IO_STATUS_BLOCK status;
    const NTSTATUS result = NtQueryDirectoryFile(
        m_directory.get(), nullptr, nullptr, nullptr, &status, m_buffer.data(),
        static_cast<ULONG>(m_buffer.size()), m_layout.informationClass, FALSE,
        m_pattern ? static_cast<PUNICODE_STRING>(*m_pattern) : nullptr, FALSE);
    if (result != STATUS_SUCCESS) {
      m_endStatus = result;
      return std::nullopt;
    }
    m_records = std::span(m_buffer).first(status.Information);
  }
  const DirectoryRecord record(m_layout, m_records);
  m_records = record.nextEntryOffset() == 0
                  ? std::span<const std::byte>()
                  : m_records.subspan(record.nextEntryOffset());
  return record;
}

// A directory that virtual entries map files or directories of. Read the first time an
// entry needs it, keeping the records of what the entries map, so that it is read
// once rather than once per entry, and its handle closes before the query that reads
// it returns. Read whole, or queried by name when it has one file mapped: a mapping
// of one file out of a large directory, such as C:\Windows, would read it all.
class SourceDirectory
{
public:
  explicit SourceDirectory(std::wstring path) : m_path(std::move(path)) {}

  // Adds the name of a file or directory that an entry maps.
  void addFileName(std::wstring fileName) { m_fileNames.insert(std::move(fileName)); }

  // Returns the record of a file or directory in the information class of layout, or
  // nothing when it cannot be read. Reads through buffer, as NativeDirectoryReader
  // does; the record stays valid until the next call.
  std::optional<DirectoryRecord> find(const std::wstring& fileName,
                                      const DirectoryRecordLayout& layout,
                                      std::vector<std::byte>& buffer);

private:
  // Reads the directory and keeps the records of the file names.
  void read(const DirectoryRecordLayout& layout, std::vector<std::byte>& buffer);
  // Queries the directory for a file name.
  std::optional<DirectoryRecord> query(const std::wstring& fileName,
                                       const DirectoryRecordLayout& layout,
                                       std::vector<std::byte>& buffer);
  void keep(std::wstring fileName, const DirectoryRecord& record);

  // where a kept record lies in m_records
  struct RecordPlace
  {
    size_t offset;
    size_t size;
  };

  std::wstring m_path;
  std::unordered_set<std::wstring> m_fileNames;
  // the information class of the records kept, nothing before the first read
  std::optional<FILE_INFORMATION_CLASS> m_recordClass;
  // the records kept, one after another, without the padding between them
  std::vector<std::byte> m_records;
  std::unordered_map<std::wstring, RecordPlace> m_recordPlaces;
};

std::optional<DirectoryRecord>
SourceDirectory::find(const std::wstring& fileName, const DirectoryRecordLayout& layout,
                      std::vector<std::byte>& buffer)
{
  if (m_recordClass != layout.informationClass) {
    read(layout, buffer);
  }
  if (const auto place = m_recordPlaces.find(fileName); place != m_recordPlaces.end()) {
    return DirectoryRecord(
        layout, std::span(m_records).subspan(place->second.offset, place->second.size));
  }
  if (m_fileNames.size() == 1) {
    // queried by name already
    return std::nullopt;
  }
  // The file is missing, or the mapping names it in another case or by its 8.3 name,
  // which a query by name leaves to the filesystem to match.
  return query(fileName, layout, buffer);
}

void SourceDirectory::read(const DirectoryRecordLayout& layout,
                           std::vector<std::byte>& buffer)
{
  // set before the read, so that a directory that fails to read is not read again
  // for every entry
  m_recordClass = layout.informationClass;
  m_records.clear();
  m_recordPlaces.clear();
  if (m_fileNames.size() == 1) {
    const std::wstring& fileName = *m_fileNames.begin();
    if (const std::optional<DirectoryRecord> record = query(fileName, layout, buffer)) {
      keep(fileName, *record);
    }
    return;
  }
  OwnedHandle directory = openScanDirectory(m_path);
  if (!directory.isValid()) {
    spdlog::get("hooks")->warn(
        "failed to open {0} to list it: {1}",
        ush::string_cast<std::string>(m_path, ush::CodePage::UTF8), ::GetLastError());
    return;
  }
  NativeDirectoryReader reader(std::move(directory), layout, std::nullopt, buffer);
  while (const std::optional<DirectoryRecord> record = reader.next()) {
    std::wstring fileName = record->fileName();
    if (m_fileNames.contains(fileName)) {
      keep(std::move(fileName), *record);
    }
  }
  if (reader.endStatus() != STATUS_NO_MORE_FILES) {
    spdlog::get("hooks")->warn(
        "error reported listing files in {0}: {1:x}",
        ush::string_cast<std::string>(m_path, ush::CodePage::UTF8),
        static_cast<uint32_t>(reader.endStatus()));
  }
}

std::optional<DirectoryRecord>
SourceDirectory::query(const std::wstring& fileName,
                       const DirectoryRecordLayout& layout,
                       std::vector<std::byte>& buffer)
{
  const std::string filePath =
      ush::string_cast<std::string>(m_path + L"\\" + fileName, ush::CodePage::UTF8);
  OwnedHandle directory = openScanDirectory(m_path);
  if (!directory.isValid()) {
    spdlog::get("hooks")->warn("failed to open the directory of {0} to list it: {1}",
                               filePath, ::GetLastError());
    return std::nullopt;
  }
  NativeDirectoryReader reader(
      std::move(directory), layout,
      fileName != L"." ? std::optional<std::wstring_view>(fileName) : std::nullopt,
      buffer);
  // the pattern is the name of the file, so the scan starts with its record
  const std::optional<DirectoryRecord> record = reader.next();
  if (!record) {
    spdlog::get("hooks")->warn("error reported listing files in {0}: {1:x}", filePath,
                               static_cast<uint32_t>(reader.endStatus()));
  }
  return record;
}

void SourceDirectory::keep(std::wstring fileName, const DirectoryRecord& record)
{
  const std::span<const std::byte> bytes = record.bytes();
  m_recordPlaces.try_emplace(std::move(fileName),
                             RecordPlace{m_records.size(), bytes.size()});
  m_records.insert(m_records.end(), bytes.begin(), bytes.end());
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
  explicit VirtualEntryReader(const std::vector<VirtualMatch>& matches);

  // Writes the entries left to list, as many as the output takes; the first that does
  // not fit stays for the next call. Skips an entry whose record cannot be read or
  // whose name is written already. Returns STATUS_SUCCESS once it wrote some,
  // STATUS_BUFFER_OVERFLOW once it wrote the partial record of one, and
  // STATUS_NO_MORE_FILES when none is left.
  NTSTATUS fill(const DirectoryQuery& query, DirectoryOutput& output);

private:
  // A file or directory of a source directory, listed under its virtual name.
  struct Entry
  {
    // index into m_sources
    size_t source;
    std::wstring fileName;
    // empty for an entry listed under the name of its file
    std::wstring virtualName;
  };

  // a deque, as a vector that grows copies them: the move constructors of the MSVC
  // unordered containers allocate, so they are not noexcept
  std::deque<SourceDirectory> m_sources;
  // in the order of the matches, which is the order they are listed in
  std::vector<Entry> m_entries;
  // index of the next entry to try; the ones before it are done
  size_t m_nextEntry = 0;
  // the names of the entries written, so that none is written twice
  CaseInsensitiveNameSet m_names;
  // where the source directories read, aligned as the regular reader's staging area.
  // A read holds a record whole, whatever the length of its name: the entry goes out
  // under its virtual name, whose length alone decides whether it fits the query.
  std::vector<std::byte> m_staging;
};

VirtualEntryReader::VirtualEntryReader(const std::vector<VirtualMatch>& matches)
{
  std::unordered_map<std::wstring, size_t> sourceIndexes;
  for (const VirtualMatch& match : matches) {
    // the path of a directory mapped with all its content ends with a separator,
    // which leaves "." as its file name
    bfs::path fullPath(match.realPath);
    if (fullPath.filename().wstring() == L".") {
      fullPath = fullPath.parent_path();
    }
    std::wstring sourcePath = fullPath.parent_path().wstring();
    if (sourcePath.length() >= MAX_PATH &&
        !ush::startswith(sourcePath.c_str(), LR"(\\?\)")) {
      sourcePath = LR"(\\?\)" + sourcePath;
    }
    const auto [sourceIndex, isNew] =
        sourceIndexes.try_emplace(sourcePath, m_sources.size());
    if (isNew) {
      m_sources.emplace_back(sourcePath);
    }
    std::wstring fileName = ush::string_cast<std::wstring>(fullPath.filename().string(),
                                                           ush::CodePage::UTF8);
    m_sources[sourceIndex->second].addFileName(fileName);
    m_entries.push_back({sourceIndex->second, std::move(fileName), match.virtualName});
  }
}

NTSTATUS VirtualEntryReader::fill(const DirectoryQuery& query, DirectoryOutput& output)
{
  // shouldVirtualize lets through only the classes that have a layout
  const DirectoryRecordLayout layout =
      findDirectoryRecordLayout(query.informationClass).value();
  // the skipped entries are dropped as the stock code dropped them; a single-entry
  // query stops before reading an entry it would not take
  for (; m_nextEntry < m_entries.size() && !output.isSatisfied(); ++m_nextEntry) {
    const Entry& entry = m_entries[m_nextEntry];
    const std::optional<DirectoryRecord> record =
        m_sources[entry.source].find(entry.fileName, layout, m_staging);
    if (!record) {
      continue;
    }
    const std::wstring name =
        entry.virtualName.empty() ? record->fileName() : entry.virtualName;
    if (m_names.contains(name)) {
      continue;
    }
    const bool isWritten = entry.virtualName.empty()
                               ? output.append(*record)
                               : output.appendRenamed(*record, name);
    // like ntdll, an entry that does not fit stays for the next call to return, be it
    // after its partial record or after the entries the output holds
    if (!isWritten) {
      return output.isOverflowed() ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
    }
    m_names.insert(name);
  }
  return output.isEmpty() ? STATUS_NO_MORE_FILES : STATUS_SUCCESS;
}

// The state of one scan: the queries on a handle from its first query or restart on.
class DirectoryScan
{
public:
  // Starts the scan: picks the directory the regular entries are read from and
  // gathers the virtual entries matching the pattern of the query. The first scan of
  // a handle is the one its first query starts; a restart starts the others.
  DirectoryScan(const DirectoryQuery& query, bool isFirstOfHandle);

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
  // An empty result is STATUS_NO_SUCH_FILE on the first query of a handle only, as
  // NTFS and ReFS tell it by whether the handle has a pattern yet, which a restart
  // does not drop.
  bool m_isFirstCall;
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
    auto scan = std::make_shared<DirectoryScan>(query, current == nullptr);
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
    // looked up under the shared lock first, as every handle opened and closed comes
    // here and few have a scan
    if (!find(handle)) {
      return nullptr;
    }
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
  if (node.get() == nullptr) {
    return matches;
  }

  // ntdll lists every entry for a pattern that is null or empty. RtlIsNameInExpression
  // wants the pattern upcased, as it ignores case; it reads the DOS wildcards as the
  // filesystem does.
  std::optional<std::wstring> upcasedPattern;
  UNICODE_STRING expression{};
  if (FileName != nullptr && FileName->Length > 0) {
    upcasedPattern.emplace(FileName->Length / sizeof(WCHAR), L'\0');
    expression = {FileName->Length, FileName->Length, upcasedPattern->data()};
    RtlUpcaseUnicodeString(&expression, FileName, FALSE);
  }

  for (auto child = node->filesBegin(); child != node->filesEnd(); ++child) {
    const auto& subNode = child->second;
    if (((subNode->data().linkTarget.length() == 0) && !subNode->isDirectory()) ||
        subNode->hasFlag(usvfs::shared::FLAG_DUMMY)) {
      continue;
    }
    std::wstring vName =
        ush::string_cast<std::wstring>(subNode->name(), ush::CodePage::UTF8);
    if (upcasedPattern) {
      UNICODE_STRING name{static_cast<USHORT>(vName.size() * sizeof(WCHAR)),
                          static_cast<USHORT>(vName.size() * sizeof(WCHAR)),
                          vName.data()};
      if (!RtlIsNameInExpression(&expression, &name, TRUE, nullptr)) {
        continue;
      }
    }

    if (subNode->data().linkTarget.length() > 0) {
      matches.push_back({ush::string_cast<std::wstring>(
                             subNode->data().linkTarget.c_str(), ush::CodePage::UTF8),
                         std::move(vName)});
    } else {
      matches.push_back(
          {ush::string_cast<std::wstring>(subNode->path().c_str(), ush::CodePage::UTF8),
           std::move(vName)});
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
DirectoryScan::DirectoryScan(const DirectoryQuery& query, bool isFirstOfHandle)
    : m_isPassthrough(!isSynchronousHandle(query.handle)),
      m_isFirstCall(isFirstOfHandle)
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
  m_virtual = VirtualEntryReader(virtualMatches);
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
