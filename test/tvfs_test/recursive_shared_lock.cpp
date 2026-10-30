#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <thread>

#include <recursive_shared_lock.h>

#include <gtest/gtest.h>

using namespace std::chrono_literals;

namespace
{

// long enough for a thread to get the lock unless something holds it
constexpr auto LockDeadline = 5s;
// long enough for a thread waiting on the lock to queue up on it
constexpr auto QueueingDelay = 200ms;

// Runs `body` on a thread of its own and returns a future that is ready once the body
// returned. The thread is detached and shares the lock, so that a body that deadlocks
// fails the test instead of hanging it.
template <typename Body>
std::future<void> runOnThread(const std::shared_ptr<RecursiveSharedLock>& lock,
                              Body body)
{
  auto done   = std::make_shared<std::promise<void>>();
  auto result = done->get_future();
  std::thread([lock, done, body] {
    body(*lock);
    done->set_value();
  }).detach();
  return result;
}

bool finishesInTime(std::future<void>& future)
{
  return future.wait_for(LockDeadline) == std::future_status::ready;
}

std::future<void>
lockExclusiveOnThread(const std::shared_ptr<RecursiveSharedLock>& lock)
{
  return runOnThread(lock, [](RecursiveSharedLock& lock) {
    lock.lockExclusive();
    lock.unlock();
  });
}

}  // namespace

TEST(RecursiveSharedLockTest, ReentersExclusiveAccess)
{
  auto lock = std::make_shared<RecursiveSharedLock>();

  auto reentry = runOnThread(lock, [](RecursiveSharedLock& lock) {
    lock.lockExclusive();
    lock.lockExclusive();
    lock.unlock();
    lock.unlock();
  });
  ASSERT_TRUE(finishesInTime(reentry));

  auto writer = lockExclusiveOnThread(lock);
  EXPECT_TRUE(finishesInTime(writer));
}

TEST(RecursiveSharedLockTest, TakesSharedAccessUnderExclusiveAccess)
{
  auto lock = std::make_shared<RecursiveSharedLock>();

  auto nested = runOnThread(lock, [](RecursiveSharedLock& lock) {
    lock.lockExclusive();
    lock.lockShared();
    lock.lockExclusive();
    lock.unlock();
    lock.unlock();
    lock.unlock();
  });
  ASSERT_TRUE(finishesInTime(nested));

  auto writer = lockExclusiveOnThread(lock);
  EXPECT_TRUE(finishesInTime(writer));
}

TEST(RecursiveSharedLockTest, ReentersSharedAccessWhileAWriterWaits)
{
  auto lock = std::make_shared<RecursiveSharedLock>();
  std::promise<void> readerHolds;
  std::promise<void> writerQueued;

  auto reader = runOnThread(lock, [&](RecursiveSharedLock& lock) {
    lock.lockShared();
    readerHolds.set_value();
    writerQueued.get_future().wait();
    // a plain SRW lock queues this reader behind the writer, which waits for it
    lock.lockShared();
    lock.unlock();
    lock.unlock();
  });
  readerHolds.get_future().wait();
  auto writer = lockExclusiveOnThread(lock);
  std::this_thread::sleep_for(QueueingDelay);
  writerQueued.set_value();

  ASSERT_TRUE(finishesInTime(reader));
  EXPECT_TRUE(finishesInTime(writer));
}

TEST(RecursiveSharedLockTest, RefusesToUpgradeSharedAccess)
{
  RecursiveSharedLock lock;

  lock.lockShared();
  EXPECT_THROW(lock.lockExclusive(), std::logic_error);
  EXPECT_TRUE(lock.isHeldByCurrentThread());
  lock.unlock();

  EXPECT_FALSE(lock.isHeldByCurrentThread());
}

TEST(RecursiveSharedLockTest, SharesAccessBetweenReaders)
{
  auto lock = std::make_shared<RecursiveSharedLock>();
  lock->lockShared();

  auto otherReader = runOnThread(lock, [](RecursiveSharedLock& lock) {
    lock.lockShared();
    lock.unlock();
  });
  EXPECT_TRUE(finishesInTime(otherReader));

  lock->unlock();
}

TEST(RecursiveSharedLockTest, ExcludesReadersWhileAWriterHoldsIt)
{
  auto lock = std::make_shared<RecursiveSharedLock>();
  lock->lockExclusive();

  auto reader = runOnThread(lock, [](RecursiveSharedLock& lock) {
    lock.lockShared();
    lock.unlock();
  });
  EXPECT_EQ(std::future_status::timeout, reader.wait_for(QueueingDelay));

  lock->unlock();
  EXPECT_TRUE(finishesInTime(reader));
}

TEST(RecursiveSharedLockTest, TellsWhetherTheCallingThreadHoldsIt)
{
  auto lock = std::make_shared<RecursiveSharedLock>();
  EXPECT_FALSE(lock->isHeldByCurrentThread());

  lock->lockShared();
  lock->lockShared();
  lock->unlock();
  EXPECT_TRUE(lock->isHeldByCurrentThread());

  bool isHeldByOtherThread = true;
  auto otherThread         = runOnThread(lock, [&](RecursiveSharedLock& lock) {
    isHeldByOtherThread = lock.isHeldByCurrentThread();
  });
  ASSERT_TRUE(finishesInTime(otherThread));
  EXPECT_FALSE(isHeldByOtherThread);

  lock->unlock();
  EXPECT_FALSE(lock->isHeldByCurrentThread());
}
