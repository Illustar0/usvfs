#include "recursive_shared_lock.h"

#include <stdexcept>
#include <system_error>

// Only the outermost acquisition of a thread takes the SRW lock, as an SRW lock can be
// acquired recursively in neither mode: a nested exclusive acquisition deadlocks, and
// so does a nested shared one once a writer waits, since new readers queue behind it.

RecursiveSharedLock::RecursiveSharedLock() : m_holdSlot(::TlsAlloc())
{
  if (m_holdSlot == TLS_OUT_OF_INDEXES) {
    throw std::system_error(static_cast<int>(::GetLastError()), std::system_category(),
                            "no TLS slot is left for the hook context lock");
  }
}

RecursiveSharedLock::~RecursiveSharedLock()
{
  ::TlsFree(m_holdSlot);
}

void RecursiveSharedLock::lockShared()
{
  Hold hold = holdOfCurrentThread();
  if (hold.depth == 0) {
    ::AcquireSRWLockShared(&m_lock);
    hold.isExclusive = false;
  }
  ++hold.depth;
  setHoldOfCurrentThread(hold);
}

void RecursiveSharedLock::lockExclusive()
{
  Hold hold = holdOfCurrentThread();
  if (hold.depth == 0) {
    ::AcquireSRWLockExclusive(&m_lock);
    hold.isExclusive = true;
  } else if (!hold.isExclusive) {
    throw std::logic_error("exclusive access requested by a thread holding the hook "
                           "context lock shared");
  }
  ++hold.depth;
  setHoldOfCurrentThread(hold);
}

void RecursiveSharedLock::unlock()
{
  Hold hold = holdOfCurrentThread();
  --hold.depth;
  if (hold.depth == 0) {
    if (hold.isExclusive) {
      ::ReleaseSRWLockExclusive(&m_lock);
    } else {
      ::ReleaseSRWLockShared(&m_lock);
    }
  }
  setHoldOfCurrentThread(hold);
}

bool RecursiveSharedLock::isHeldByCurrentThread() const
{
  return holdOfCurrentThread().depth > 0;
}

// the slot holds the depth shifted left by one, with the mode in the lowest bit, so
// that a thread that never took the lock reads 0
RecursiveSharedLock::Hold RecursiveSharedLock::holdOfCurrentThread() const
{
  // TlsGetValue resets the last error, which the hooks leave as their caller set it
  const DWORD lastError = ::GetLastError();
  const auto value      = reinterpret_cast<std::uintptr_t>(::TlsGetValue(m_holdSlot));
  ::SetLastError(lastError);
  return Hold{.depth = value >> 1, .isExclusive = (value & 1) != 0};
}

void RecursiveSharedLock::setHoldOfCurrentThread(Hold hold)
{
  const std::uintptr_t value = (hold.depth << 1) | (hold.isExclusive ? 1 : 0);
  ::TlsSetValue(m_holdSlot, reinterpret_cast<LPVOID>(value));
}
