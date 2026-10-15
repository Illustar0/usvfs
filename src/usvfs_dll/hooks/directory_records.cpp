#include "directory_records.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace
{

template <typename Record>
constexpr std::optional<ShortNameFields> shortNameFieldsOf()
{
  if constexpr (requires(Record record) { record.ShortName; }) {
    return ShortNameFields{.lengthOffset = offsetof(Record, ShortNameLength),
                           .offset       = offsetof(Record, ShortName)};
  } else {
    return std::nullopt;
  }
}

template <typename Record>
constexpr DirectoryRecordLayout layoutOf(FILE_INFORMATION_CLASS informationClass)
{
  return {.informationClass     = informationClass,
          .minimumLength        = sizeof(Record),
          .alignment            = alignof(Record),
          .fileNameLengthOffset = offsetof(Record, FileNameLength),
          .fileNameOffset       = offsetof(Record, FileName),
          .shortName            = shortNameFieldsOf<Record>()};
}

// The minimum lengths and alignments are those BuildQueryDirectoryIrp in ntoskrnl
// checks the buffer against: it keeps its own tables, which match these records.
constexpr std::array DIRECTORY_RECORD_LAYOUTS{
    layoutOf<FILE_DIRECTORY_INFORMATION>(FileDirectoryInformation),
    layoutOf<FILE_FULL_DIR_INFORMATION>(FileFullDirectoryInformation),
    layoutOf<FILE_BOTH_DIR_INFORMATION>(FileBothDirectoryInformation),
    layoutOf<FILE_NAMES_INFORMATION>(FileNamesInformation),
    layoutOf<FILE_ID_BOTH_DIR_INFORMATION>(FileIdBothDirectoryInformation),
    layoutOf<FILE_ID_FULL_DIR_INFORMATION>(FileIdFullDirectoryInformation),
    layoutOf<FILE_ID_EXTD_DIR_INFORMATION>(FileIdExtdDirectoryInformation),
    layoutOf<FILE_ID_EXTD_BOTH_DIR_INFORMATION>(FileIdExtdBothDirectoryInformation),
    layoutOf<FILE_ID_64_EXTD_DIR_INFORMATION>(FileId64ExtdDirectoryInformation),
    layoutOf<FILE_ID_64_EXTD_BOTH_DIR_INFORMATION>(
        FileId64ExtdBothDirectoryInformation),
    layoutOf<FILE_ID_ALL_EXTD_DIR_INFORMATION>(FileIdAllExtdDirectoryInformation),
    layoutOf<FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION>(
        FileIdAllExtdBothDirectoryInformation),
};

}  // namespace

std::optional<DirectoryRecordLayout>
findDirectoryRecordLayout(FILE_INFORMATION_CLASS informationClass)
{
  const auto layout = std::ranges::find(DIRECTORY_RECORD_LAYOUTS, informationClass,
                                        &DirectoryRecordLayout::informationClass);
  if (layout == DIRECTORY_RECORD_LAYOUTS.end()) {
    return std::nullopt;
  }
  return *layout;
}

DirectoryRecord::DirectoryRecord(const DirectoryRecordLayout& layout,
                                 std::span<const std::byte> bytes)
    : m_layout(layout), m_bytes(bytes)
{}

ULONG DirectoryRecord::nextEntryOffset() const
{
  // the first field of every directory record
  return readField(0);
}

ULONG DirectoryRecord::size() const
{
  return m_layout.fileNameOffset + readField(m_layout.fileNameLengthOffset);
}

bool DirectoryRecord::isTruncated() const
{
  return size() > m_bytes.size();
}

std::wstring DirectoryRecord::fileName() const
{
  const size_t end = std::min<size_t>(size(), m_bytes.size());
  if (end <= m_layout.fileNameOffset) {
    return {};
  }
  std::wstring name((end - m_layout.fileNameOffset) / sizeof(WCHAR), L'\0');
  std::memcpy(name.data(), m_bytes.data() + m_layout.fileNameOffset,
              name.size() * sizeof(WCHAR));
  return name;
}

ULONG DirectoryRecord::readField(ULONG offset) const
{
  ULONG value = 0;
  if (offset + sizeof(value) <= m_bytes.size()) {
    std::memcpy(&value, m_bytes.data() + offset, sizeof(value));
  }
  return value;
}
