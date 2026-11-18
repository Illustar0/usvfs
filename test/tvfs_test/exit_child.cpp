#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <cwchar>

namespace
{

/// Exit codes that tell which step failed before the test allowed the exit.
enum FailureExitCode
{
  /// The arguments are wrong, or the virtual path is not visible through the VFS.
  INVALID_STARTUP = 1,
  /// The shutdown check could not be registered as an FLS callback.
  FLS_SETUP_FAILED = 2,
  /// The test did not allow the exit in time.
  EXIT_NOT_ALLOWED = 3,
};

/// The virtual path to look up again while the loader shuts the process down.
struct ShutdownCheck
{
  const wchar_t* virtualPath;
  HANDLE nativePathObserved;
};

/// Signals `nativePathObserved` when the virtual path is not visible. The loader runs
/// FLS callbacks while it shuts the process down, when hooks must go straight to the
/// original functions, so this lookup must see the native file system.
void NTAPI checkPathAtShutdown(void* value)
{
  const auto& check = *static_cast<const ShutdownCheck*>(value);
  if (::GetFileAttributesW(check.virtualPath) == INVALID_FILE_ATTRIBUTES) {
    ::SetEvent(check.nativePathObserved);
  }
}

/// Parses a handle value that the test passed on the command line.
HANDLE inheritedHandle(const wchar_t* value)
{
  return reinterpret_cast<HANDLE>(
      static_cast<std::uintptr_t>(std::wcstoull(value, nullptr, 10)));
}

}  // namespace

/// Runs as the hooked child of the ProcessExit test. The arguments are the inherited
/// "started", "exit allowed" and "native path observed" events, then the virtual path.
/// Exits with STILL_ACTIVE (259) so the test can check that the host judges whether a
/// process has ended by its handle, not by its exit code.
int wmain(int argc, wchar_t** argv)
{
  if (argc != 5 || ::GetFileAttributesW(argv[4]) == INVALID_FILE_ATTRIBUTES) {
    return INVALID_STARTUP;
  }

  // Static, since the FLS callback also runs after an early return from wmain.
  static ShutdownCheck shutdownCheck{argv[4], inheritedHandle(argv[3])};
  const DWORD slot = ::FlsAlloc(checkPathAtShutdown);
  if (slot == FLS_OUT_OF_INDEXES || !::FlsSetValue(slot, &shutdownCheck)) {
    return FLS_SETUP_FAILED;
  }

  ::SetEvent(inheritedHandle(argv[1]));
  if (::WaitForSingleObject(inheritedHandle(argv[2]), 10'000) != WAIT_OBJECT_0) {
    return EXIT_NOT_ALLOWED;
  }
  ::ExitProcess(STILL_ACTIVE);
}
