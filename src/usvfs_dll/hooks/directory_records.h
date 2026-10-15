#pragma once

#include <optional>

#include <ntdll_declarations.h>

// The records one directory information class returns.
struct DirectoryRecordLayout
{
  FILE_INFORMATION_CLASS informationClass;
  // the size of a record with a one-character name; ntdll rejects shorter buffers
  ULONG minimumLength;
  // the alignment of a record, which x64 ntdll requires of the buffer
  ULONG alignment;
};

// Returns the layout of the records of a directory information class whose records
// carry a FileName, the only ones the virtual listing can filter and rename.
std::optional<DirectoryRecordLayout>
findDirectoryRecordLayout(FILE_INFORMATION_CLASS informationClass);
