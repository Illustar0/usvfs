#pragma once

#include <cstring>
#include <shared_mutex>
#include <unordered_map>

#include <ntdll_declarations.h>
#include <unicodestring.h>

class HandleTracker
{
public:
  using handle_type = HANDLE;
  using info_type   = usvfs::UnicodeString;

  HandleTracker() { insert_current_directory(); }

  info_type lookup(handle_type handle) const
  {
    if (valid_handle(handle)) {
      std::shared_lock<std::shared_mutex> lock(m_mutex);
      auto find = m_map.find(handle);
      if (find != m_map.end())
        return find->second;
    }
    return info_type();
  }

  void insert(handle_type handle, const info_type& info)
  {
    if (!valid_handle(handle))
      return;
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_map[handle] = info;
  }

  void erase(handle_type handle)
  {
    if (!valid_handle(handle))
      return;
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_map.erase(handle);
  }

private:
  static bool valid_handle(handle_type handle)
  {
    return handle && handle != INVALID_HANDLE_VALUE;
  }

  void insert_current_directory()
  {
    ntdll_declarations_init();

    UNICODE_STRING p{0};
    RTL_RELATIVE_NAME r{0};
    NTSTATUS status =
        RtlDosPathNameToRelativeNtPathName_U_WithStatus(L"x", &p, nullptr, &r);
    if (status >= 0) {
      if (r.ContainingDirectory && p.Buffer) {
        size_t len  = p.Length / sizeof(WCHAR);
        size_t trim = strlen("\\x") + (p.Buffer[len - 1] ? 0 : 1);
        if (len > trim)
          insert(r.ContainingDirectory, info_type(p.Buffer, len - trim));
      }
      RtlReleaseRelativeName(&r);
      if (p.Buffer)
        HeapFree(GetProcessHeap(), 0, p.Buffer);
    }
  }

  mutable std::shared_mutex m_mutex;
  std::unordered_map<handle_type, info_type> m_map;
};

extern HandleTracker ntdllHandleTracker;
