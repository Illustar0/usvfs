#pragma once

#include <ntdll_declarations.h>

// A call to either directory query entry point. The BOOLEAN arguments of the
// legacy entry point are folded into SL_* flags.
struct DirectoryQuery
{
  HANDLE handle;
  HANDLE event;
  PIO_APC_ROUTINE apcRoutine;
  PVOID apcContext;
  PIO_STATUS_BLOCK statusBlock;
  PVOID buffer;
  ULONG length;
  FILE_INFORMATION_CLASS informationClass;
  PUNICODE_STRING fileName;
  ULONG flags;
  bool isEx;

  bool isRestart() const { return (flags & SL_RESTART_SCAN) != 0; }
  bool isSingleEntry() const { return (flags & SL_RETURN_SINGLE_ENTRY) != 0; }
};

NTSTATUS queryNative(const DirectoryQuery& query);
// Routes a query: virtualizes it when shouldVirtualize allows, and forwards it to
// ntdll otherwise. Like ntdll, reports the result both as the return value and in
// the status block.
NTSTATUS queryDirectory(const DirectoryQuery& query);

// Releases the scan of a closed handle, or of a handle value just opened again, as a
// handle closed where the hooks do not see it leaves its scan behind:
// DuplicateHandle with DUPLICATE_CLOSE_SOURCE into another process closes it in the
// kernel. Returns whether the handle had a scan.
bool eraseDirectoryScan(HANDLE handle);
