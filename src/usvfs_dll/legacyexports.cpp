/*
Userspace Virtual Filesystem

Copyright (C) 2015 Sebastian Herbord. All rights reserved.

This file is part of usvfs.

usvfs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

usvfs is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with usvfs. If not, see <http://www.gnu.org/licenses/>.
*/

// usvfs 0.5 prefixed every exported function with "usvfs" and dropped the
// deprecated ones, so binaries built against 0.4 no longer find their imports.
// This file exports the 0.4 names again, each forwarding to its 0.5 equivalent.
//
// The signatures are copied from the 0.4 headers and must stay that way: on x86
// the exported name encodes the size of the arguments (_VirtualLinkFile@12), so
// any change to a parameter list breaks the import again.

#include "usvfs.h"
#include "usvfsparametersprivate.h"

extern "C"
{

  DLLEXPORT void WINAPI ClearVirtualMappings()
  {
    usvfsClearVirtualMappings();
  }

  DLLEXPORT BOOL WINAPI VirtualLinkFile(LPCWSTR source, LPCWSTR destination,
                                        unsigned int flags)
  {
    return usvfsVirtualLinkFile(source, destination, flags);
  }

  DLLEXPORT BOOL WINAPI VirtualLinkDirectoryStatic(LPCWSTR source, LPCWSTR destination,
                                                   unsigned int flags)
  {
    return usvfsVirtualLinkDirectoryStatic(source, destination, flags);
  }

  DLLEXPORT BOOL WINAPI ConnectVFS(const USVFSParameters* parameters)
  {
    const usvfsParameters p(*parameters);
    return usvfsConnectVFS(&p);
  }

  DLLEXPORT BOOL WINAPI CreateVFS(const USVFSParameters* parameters)
  {
    const usvfsParameters p(*parameters);
    return usvfsCreateVFS(&p);
  }

  DLLEXPORT void WINAPI DisconnectVFS()
  {
    usvfsDisconnectVFS();
  }

  DLLEXPORT void WINAPI GetCurrentVFSName(char* buffer, size_t size)
  {
    usvfsGetCurrentVFSName(buffer, size);
  }

  DLLEXPORT BOOL WINAPI GetVFSProcessList(size_t* count, LPDWORD processIDs)
  {
    return usvfsGetVFSProcessList(count, processIDs);
  }

  DLLEXPORT BOOL WINAPI GetVFSProcessList2(size_t* count, DWORD** buffer)
  {
    return usvfsGetVFSProcessList2(count, buffer);
  }

  DLLEXPORT BOOL WINAPI CreateProcessHooked(
      LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes,
      LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
      DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
      LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
  {
    return usvfsCreateProcessHooked(
        lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);
  }

  DLLEXPORT bool WINAPI GetLogMessages(LPSTR buffer, size_t size, bool blocking)
  {
    return usvfsGetLogMessages(buffer, size, blocking);
  }

  DLLEXPORT BOOL WINAPI CreateVFSDump(LPSTR buffer, size_t* size)
  {
    return usvfsCreateVFSDump(buffer, size);
  }

  DLLEXPORT VOID WINAPI BlacklistExecutable(LPWSTR executableName)
  {
    usvfsBlacklistExecutable(executableName);
  }

  DLLEXPORT VOID WINAPI ClearExecutableBlacklist()
  {
    usvfsClearExecutableBlacklist();
  }

  DLLEXPORT VOID WINAPI ForceLoadLibrary(LPWSTR processName, LPWSTR libraryPath)
  {
    usvfsForceLoadLibrary(processName, libraryPath);
  }

  DLLEXPORT VOID WINAPI ClearLibraryForceLoads()
  {
    usvfsClearLibraryForceLoads();
  }

  DLLEXPORT VOID WINAPI PrintDebugInfo()
  {
    usvfsPrintDebugInfo();
  }

  DLLEXPORT void WINAPI InitLogging(bool toLocal)
  {
    usvfsInitLogging(toLocal);
  }

  // an invalid or too long crash dump path disables crash dumps, as in 0.4
  DLLEXPORT void WINAPI USVFSInitParameters(USVFSParameters* parameters,
                                            const char* instanceName, bool debugMode,
                                            LogLevel logLevel,
                                            CrashDumpsType crashDumpsType,
                                            const char* crashDumpsPath)
  {
    parameters->debugMode      = debugMode;
    parameters->logLevel       = logLevel;
    parameters->crashDumpsType = crashDumpsType;

    strncpy_s(parameters->instanceName, instanceName, _TRUNCATE);
    if (crashDumpsPath && *crashDumpsPath &&
        strlen(crashDumpsPath) < _countof(parameters->crashDumpsPath)) {
      memcpy(parameters->crashDumpsPath, crashDumpsPath, strlen(crashDumpsPath) + 1);
    } else {
      parameters->crashDumpsPath[0] = 0;
      parameters->crashDumpsType    = CrashDumpsType::None;
    }

    // we can't use the whole buffer as we need a few bytes to store a running
    // counter
    strncpy_s(parameters->currentSHMName, 60, instanceName, _TRUNCATE);
    memset(parameters->currentInverseSHMName, '\0',
           _countof(parameters->currentInverseSHMName));
    _snprintf(parameters->currentInverseSHMName, 60, "inv_%s", instanceName);
  }

  DLLEXPORT void WINAPI USVFSUpdateParams(LogLevel level, CrashDumpsType type)
  {
    auto* p = usvfsCreateParameters();

    usvfsSetLogLevel(p, level);
    usvfsSetCrashDumpType(p, type);

    usvfsUpdateParameters(p);
    usvfsFreeParameters(p);
  }

  DLLEXPORT int WINAPI CreateMiniDump(PEXCEPTION_POINTERS exceptionPtrs,
                                      CrashDumpsType type, const wchar_t* dumpPath)
  {
    return usvfsCreateMiniDump(exceptionPtrs, type, dumpPath);
  }

  DLLEXPORT const char* WINAPI USVFSVersionString()
  {
    return usvfsVersionString();
  }
}
