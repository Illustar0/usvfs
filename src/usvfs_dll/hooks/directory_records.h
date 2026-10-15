#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>

#include <ntdll_declarations.h>

// The 8.3 name of a record: a CCHAR byte count and a WCHAR[12] array.
struct ShortNameFields
{
  ULONG lengthOffset;
  ULONG offset;
};

// The records one directory information class returns.
struct DirectoryRecordLayout
{
  FILE_INFORMATION_CLASS informationClass;
  // the size of a record with a one-character name; ntdll rejects shorter buffers
  ULONG minimumLength;
  // the alignment of a record, which x64 ntdll requires of the buffer
  ULONG alignment;
  ULONG fileNameLengthOffset;
  ULONG fileNameOffset;
  // only the classes with "Both" in their name carry an 8.3 name
  std::optional<ShortNameFields> shortName;
};

// Returns the layout of the records of a directory information class whose records
// carry a FileName, the only ones the virtual listing can filter and rename.
std::optional<DirectoryRecordLayout>
findDirectoryRecordLayout(FILE_INFORMATION_CLASS informationClass);

// A record that a directory query returned, read where it lies. The bytes run from
// the start of the record to the end of the data the query returned, so that a
// record cut short by the end of the buffer reads as truncated instead of past it.
class DirectoryRecord
{
public:
  DirectoryRecord(const DirectoryRecordLayout& layout,
                  std::span<const std::byte> bytes);

  // the offset of the next record, 0 for the last one
  ULONG nextEntryOffset() const;
  // the size of the record without the padding up to the next one
  ULONG size() const;
  // whether the record runs past the bytes, as the partial record that comes with
  // STATUS_BUFFER_OVERFLOW does
  bool isTruncated() const;
  // The name, or as much of it as the bytes hold. Copied rather than viewed in
  // place: WOW64 accepts the buffer of a legacy query at any address, so the name
  // need not be aligned for WCHAR.
  std::wstring fileName() const;

private:
  // reads 0 for a field past the bytes
  ULONG readField(ULONG offset) const;

  DirectoryRecordLayout m_layout;
  std::span<const std::byte> m_bytes;
};
