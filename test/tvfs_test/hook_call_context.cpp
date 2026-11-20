#include <hookcallcontext.h>
#include <hookcontext.h>

#include <gtest/gtest.h>

using usvfs::FunctionGroupLock;
using usvfs::HookCallContext;
using usvfs::MutExHookGroup;

TEST(HookCallContextTest, UngroupedHookIsActiveInsideGroupedHook)
{
  const HookCallContext openFile(MutExHookGroup::OPEN_FILE);

  const HookCallContext ungrouped;

  EXPECT_TRUE(ungrouped.active());
}

TEST(HookCallContextTest, AllGroupsKeepsUngroupedHookInactive)
{
  {
    const FunctionGroupLock allGroups(MutExHookGroup::ALL_GROUPS);

    const HookCallContext ungrouped;

    EXPECT_FALSE(ungrouped.active());
  }
  const HookCallContext afterwards;
  EXPECT_TRUE(afterwards.active());
}
