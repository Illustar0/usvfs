#pragma once

#include <cstdint>

#include <windows.h>

// A reader/writer lock that a thread may take again while it holds it, as the hooks
// call functions that are hooked themselves.
//
// A thread holding the lock exclusively may take it again in either mode, and the
// nested acquisition counts as exclusive. A thread holding it shared may take it
// shared again, but not exclusively: the lock cannot be upgraded, as another thread
// may be reading under the same shared hold.
//
// Waiting is unbounded: a thread waits for as long as another one holds the lock.
// Every acquisition is released by unlock(), on the thread that made it.
class RecursiveSharedLock
{
public:
  // throws std::system_error when no TLS slot is left
  RecursiveSharedLock();
  ~RecursiveSharedLock();

  RecursiveSharedLock(const RecursiveSharedLock&)            = delete;
  RecursiveSharedLock& operator=(const RecursiveSharedLock&) = delete;

  void lockShared();

  // throws std::logic_error, rather than deadlock, when the calling thread holds the
  // lock shared
  void lockExclusive();

  // releases the latest acquisition of the calling thread, which must hold the lock
  void unlock();

  // returns whether the calling thread holds the lock, in either mode
  bool isHeldByCurrentThread() const;

private:
  // how the calling thread holds the lock; a depth of 0 means it does not
  struct Hold
  {
    std::uintptr_t depth;
    bool isExclusive;
  };

  Hold holdOfCurrentThread() const;
  void setHoldOfCurrentThread(Hold hold);

  SRWLOCK m_lock = SRWLOCK_INIT;
  // the hold of each thread lives in a Win32 TLS slot rather than in a thread_local:
  // the hooks run on every thread of the process, and a slot lives in the TEB, which
  // every thread has, whereas the implicit TLS block of the DLL exists only on threads
  // the loader initialized
  DWORD m_holdSlot;
};
