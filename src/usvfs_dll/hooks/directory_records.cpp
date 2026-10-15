#include "directory_records.h"

#include <algorithm>
#include <array>

namespace
{

template <typename Record>
constexpr DirectoryRecordLayout layoutOf(FILE_INFORMATION_CLASS informationClass)
{
  return {informationClass, sizeof(Record), alignof(Record)};
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
