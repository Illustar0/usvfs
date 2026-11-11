#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/predef.h>
#include <dos_path.h>
#include <gtest/gtest.h>
#include <shared_memory.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <wildcard.h>
#include <windows_sane.h>

#define PRIVATE public
#include <directory_tree.h>
#undef PRIVATE

#include <tree_container.h>

using namespace usvfs::shared;

using namespace boost::interprocess;

static const char g_SHMName[] = "treetest_shm";
static const char TreeName[]  = "treetest_tree";

typedef DirectoryTree<int> TreeType;
typedef TreeContainer<TreeType> ContainerType;

typedef boost::container::scoped_allocator_adaptor<
    boost::interprocess::allocator<void, SegmentManagerT>>
    VoidAllocator;
typedef VoidAllocator::rebind<char>::other CharAllocator;
typedef basic_string<char, std::char_traits<char>, CharAllocator> SHMString;
typedef DirectoryTree<SHMString> ComplexTreeType;
typedef TreeContainer<ComplexTreeType> ComplexContainerType;

template <>
struct usvfs::shared::SHMDataCreator<int, int>
{
  static int create(int source, const VoidAllocatorT&) { return source; }
};

template <>
inline int usvfs::shared::createDataEmpty<int>(const typename VoidAllocatorT&)
{
  return 0;
}

template <>
inline void usvfs::shared::dataAssign<int>(int& destination, const int& source)
{
  destination = source;
}

template <>
inline SHMString
usvfs::shared::createDataEmpty<SHMString>(const typename VoidAllocatorT& allocator)
{
  return SHMString("", allocator);
}

template <>
inline void usvfs::shared::dataAssign<SHMString>(SHMString& destination,
                                                 const SHMString& source)
{
  destination.assign(source.c_str());
}

static std::shared_ptr<spdlog::logger> logger()
{
  std::shared_ptr<spdlog::logger> result = spdlog::get("test");
  if (result.get() == nullptr) {
    result = spdlog::stdout_logger_mt("test");
  }
  return result;
}

TEST(WildcardTest, MatchWildcard)
{
  EXPECT_TRUE(wildcard::Match(TEXT("abc"), TEXT("a*")));
  EXPECT_TRUE(wildcard::Match(TEXT("abc"), TEXT("a*c")));
  EXPECT_TRUE(wildcard::Match(TEXT("abc"), TEXT("a?c")));
  EXPECT_TRUE(wildcard::Match(TEXT("abc"), TEXT("abc")));
  EXPECT_TRUE(wildcard::Match(TEXT("abc"), TEXT("abc*")));

  EXPECT_TRUE(wildcard::Match("abc", "*.*"));
  EXPECT_TRUE(wildcard::Match("abc.def", "*"));
  EXPECT_TRUE(wildcard::Match(TEXT("abc"), TEXT("*.*")));
  EXPECT_TRUE(wildcard::Match(TEXT("abc.def"), TEXT("*")));

  EXPECT_NE(nullptr, wildcard::PartialMatch("abc", "*.*"));
  EXPECT_NE(nullptr, wildcard::PartialMatch("abc.def", "*"));
  EXPECT_EQ('\0', *wildcard::PartialMatch("abc", "*.*"));
  EXPECT_EQ('\0', *wildcard::PartialMatch("abc.def", "*"));

  EXPECT_FALSE(wildcard::Match(TEXT("abc"), TEXT("b*")));
}

TEST(DirectoryTreeTest, SimpleTreeInit)
{
  EXPECT_NO_THROW({
    ContainerType tree(g_SHMName, 4096);
    TreeType::NodePtrT p = tree.addFile(R"(C:\temp\test.txt)", 42, false);
    EXPECT_NE(TreeType::NodePtrT(), p);
  });
}

TEST(DirectoryTreeTest, FindNode)
{
  shared_memory_object::remove(g_SHMName);
  ContainerType tree(g_SHMName, 64 * 1024);
  EXPECT_NE(nullptr, tree.addFile(R"(C:\temp\bla)", 0x42, 0, false));

  EXPECT_NE(nullptr, tree->findNode(R"(C:\temp)").get());
  EXPECT_EQ(nullptr, tree->findNode(R"(C:\temp\bla\blubb)").get());
}

struct TestVisitor
{
  TreeType::NodePtrT lastNode;
  bool flag40{false};

  void operator()(const TreeType::NodePtrT& node)
  {
    lastNode = node;
    flag40   = node->hasFlag(0x40);
    logger()->debug("{0} - {1}", lastNode->name(), flag40);
    // BOOST_LOG_SEV(globalLogger::get(), LogLevel::Debug) << lastNode->name() << " - "
    // << flag40;
  }
};

TEST(DirectoryTreeTest, VisitPath)
{
  shared_memory_object::remove(g_SHMName);
  ContainerType tree(g_SHMName, 64 * 1024);
  EXPECT_NE(nullptr, tree.addFile(R"(C:\temp\bla)", 1, 0x40, false));

  TestVisitor visitor;

  tree->visitPath(R"(C:\temp\bla\blubb)",
                  TreeType::VisitorFunction([&](const TreeType::NodePtrT& node) {
                    visitor(node);
                  }));
  EXPECT_TRUE(visitor.flag40);
  EXPECT_EQ("bla", visitor.lastNode->name());
}

TEST(DirectoryTreeTest, WildCardFind)
{
  shared_memory_object::remove(g_SHMName);
  EXPECT_NO_THROW({
    ContainerType tree(g_SHMName, 64 * 1024);

    EXPECT_NE(nullptr, tree.addFile(R"(C:\temp)", 1, FLAG_DIRECTORY, false));
    EXPECT_NE(nullptr, tree.addFile(R"(C:\temp\abc)", 1, 0, false));
    EXPECT_NE(nullptr, tree.addFile(R"(C:\temp\abd)", 2, 0, false));
    EXPECT_NE(nullptr, tree.addFile(R"(C:\temp\ace)", 3, 0, false));

    EXPECT_EQ(3, tree->find(R"(C:\temp\*)").size());
    EXPECT_NE(nullptr, tree->node("C:"));
    EXPECT_EQ(1, tree->node("C:")->find("*").size());
    EXPECT_NE(nullptr, tree->node("C:")->node("temp"));
    EXPECT_EQ(3, tree->node("C:")->node("temp")->find("*").size());  // alternative
    // search on the top-level
    EXPECT_EQ(1, tree->find("*").size());
    // * should work
    EXPECT_EQ(2, tree->find(R"(C:\temp\ab*)").size());
    // * does not match directory separators
    EXPECT_EQ(0, tree->find("*ab*").size());
    // matches only the directory itself
    EXPECT_EQ(1, tree->find(R"(C:\temp*)").size());
  });
}

TEST(DirectoryTreeTest, SHMAllocation)
{
  EXPECT_NO_THROW({
    ContainerType create(g_SHMName, 64 * 1024);

    {  // creation
      create.addFile(R"(C:\temp\abc)", 1, false);
      create.addFile(R"(C:\temp\abd)", 2, false);
      create.addFile(R"(C:\temp\ace)", 3, false);
    }

    {  // access
      ContainerType access(g_SHMName, 64 * 1024);
      EXPECT_NE(nullptr, access.get());
      std::vector<TreeType::NodePtrT> res = access->find(R"(C:\temp\*)");
      EXPECT_EQ(3, res.size());  // matches the three files
      EXPECT_EQ(access->m_Self.lock().get(), access->node("C:")->parent().get());
    }
  });
}

TEST(DirectoryTreeTest, SHMAllocationError)
{
  EXPECT_NO_THROW({
    try {
      ContainerType tree(g_SHMName, 4096);
      int c = 0;
      for (char i = 'a'; i <= 'z'; ++i) {
        for (char j = 'a'; j <= 'z'; ++j) {
          std::string name = std::string(R"(C:\temp\)") + i + j;
          tree.addFile(name, ++c, false);
        }
      }

      EXPECT_EQ(1, tree->node("C:")->node("temp")->node("aa", MissingThrow)->data());
      EXPECT_EQ(26, tree->node("C:")->node("temp")->node("az", MissingThrow)->data());
    } catch (const std::exception& e) {
      logger()->error("{0}", e.what());
      // BOOST_LOG_SEV(globalLogger::get(), LogLevel::Error) << e.what();
      throw;
    }
  });
}

TEST(DirectoryTreeTest, SHMAllocationErrorComplex)
{
  EXPECT_NO_THROW({
    try {
      ComplexContainerType tree(g_SHMName, 4096);
      SHMString str = tree.create("gaga");
      for (char i = 'a'; i <= 'z'; ++i) {
        for (char j = 'a'; j <= 'z'; ++j) {
          std::string name = std::string(R"(C:\temp\)") + i + j;
          tree.addFile(name, str, false);
        }
      }
      EXPECT_STREQ(
          str.c_str(),
          tree->node("C:")->node("temp")->node("aa", MissingThrow)->data().c_str());
      EXPECT_STREQ(
          str.c_str(),
          tree->node("C:")->node("temp")->node("az", MissingThrow)->data().c_str());
    } catch (const std::exception& e) {
      logger()->error("{}", e.what());
      throw;
    }
  });
}

// the DOS form of the path `path` holds, nothing when it holds none
static std::optional<std::wstring> dosForm(const std::optional<DosPath>& path)
{
  return path ? std::optional(path->str()) : std::nullopt;
}

// more than MAX_PATH characters below the root, in components short enough for NTFS
static std::wstring longRelativePath()
{
  std::wstring path;
  for (wchar_t letter = L'a'; letter < L'g'; ++letter) {
    path += std::wstring(48, letter) + L'\\';
  }
  return path + L"file.txt";
}

TEST(DosPathTest, NormalizesDrivePath)
{
  EXPECT_EQ(LR"(C:\a\b\d)", dosForm(DosPath::fromWin32(LR"(C:/a//b\.\c\..\d. )")));
}

TEST(DosPathTest, DropsTrailingSeparator)
{
  EXPECT_EQ(LR"(C:\a)", dosForm(DosPath::fromWin32(LR"(C:\a\)")));
  EXPECT_EQ(LR"(\\server\share)", dosForm(DosPath::fromWin32(LR"(\\server\share\)")));
  EXPECT_EQ(LR"(C:\a)", dosForm(DosPath::fromNt(LR"(\??\C:\a\\)")));
}

TEST(DosPathTest, KeepsDriveRootSeparator)
{
  EXPECT_EQ(LR"(C:\)", dosForm(DosPath::fromWin32(LR"(C:\)")));
  EXPECT_EQ(LR"(\??\C:\)", DosPath::fromNt(LR"(\??\C:\\)")->ntPath());
}

TEST(DosPathTest, NormalizesUncPath)
{
  EXPECT_EQ(LR"(\\server\share\y)",
            dosForm(DosPath::fromWin32(LR"(\\server\share\x\..\y)")));
}

TEST(DosPathTest, ResolvesRelativePathAgainstCurrentDirectory)
{
  EXPECT_EQ(LR"(C:\Game\Data\plugin.esp)",
            dosForm(DosPath::fromWin32(LR"(Data\..\Data\plugin.esp)", LR"(C:\Game)")));
  EXPECT_EQ(LR"(C:\Game\plugin.esp)",
            dosForm(DosPath::fromWin32(L"plugin.esp", LR"(C:\Game\)")));
}

TEST(DosPathTest, ResolvesRootedPathAgainstCurrentDirectoryRoot)
{
  EXPECT_EQ(LR"(D:\Windows)",
            dosForm(DosPath::fromWin32(LR"(\Windows)", LR"(D:\Game)")));
  EXPECT_EQ(LR"(\\server\share\x)",
            dosForm(DosPath::fromWin32(LR"(\x)", LR"(\\server\share\dir)")));
}

TEST(DosPathTest, ResolvesDriveRelativePathAgainstCurrentDirectoryOnItsDrive)
{
  EXPECT_EQ(LR"(D:\Game\Data)", dosForm(DosPath::fromWin32(L"d:Data", LR"(D:\Game)")));
  EXPECT_EQ(LR"(D:\Game)", dosForm(DosPath::fromWin32(L"D:", LR"(D:\Game)")));
}

TEST(DosPathTest, ResolvesDriveRelativePathOnAnotherDriveWithoutCurrentDirectory)
{
  const auto path = dosForm(DosPath::fromWin32(L"E:Data", LR"(D:\Game)"));

  ASSERT_TRUE(path);
  EXPECT_TRUE(path->starts_with(LR"(E:\)")) << *path;
  EXPECT_TRUE(path->ends_with(LR"(\Data)")) << *path;
}

TEST(DosPathTest, ResolvesRelativePathAgainstProcessCurrentDirectory)
{
  wchar_t expected[MAX_PATH];
  ASSERT_NE(0UL, ::GetFullPathNameW(L"plugin.esp", MAX_PATH, expected, nullptr));

  EXPECT_EQ(std::wstring(expected), dosForm(DosPath::fromWin32(L"plugin.esp")));
}

TEST(DosPathTest, TakesVerbatimPathAsItIs)
{
  EXPECT_EQ(LR"(C:\a\..\b)", dosForm(DosPath::fromWin32(LR"(\\?\C:\a\..\b)")));
  EXPECT_EQ(LR"(\\server\share\x)",
            dosForm(DosPath::fromWin32(LR"(\\?\UNC\server\share\x)")));
}

TEST(DosPathTest, TakesNtPathGivenToWin32FunctionAsItIs)
{
  EXPECT_EQ(LR"(C:\a\..\b)",
            dosForm(DosPath::fromWin32(LR"(\??\C:\a\..\b)", LR"(D:\Game)")));
}

TEST(DosPathTest, NormalizesLocalDevicePathToDrive)
{
  EXPECT_EQ(LR"(C:\b)", dosForm(DosPath::fromWin32(LR"(\\.\C:\a\..\b)")));
}

TEST(DosPathTest, RejectsWin32PathToNoDriveOrShare)
{
  wchar_t volume[MAX_PATH];
  ASSERT_TRUE(::GetVolumeNameForVolumeMountPointW(LR"(C:\)", volume, MAX_PATH));

  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromWin32(L"")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromWin32(L"", LR"(C:\Game)")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromWin32(LR"(\\.\pipe\name)")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromWin32(L"CON")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromWin32(LR"(\\?\C:)")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromWin32(LR"(\\server)")));
  EXPECT_EQ(std::nullopt,
            dosForm(DosPath::fromWin32(std::wstring(volume) + L"Windows")));
}

TEST(DosPathTest, TakesLongVerbatimPath)
{
  EXPECT_EQ(LR"(C:\)" + longRelativePath(),
            dosForm(DosPath::fromWin32(LR"(\\?\C:\)" + longRelativePath())));
}

TEST(DosPathTest, TakesLongPathWhereFileFunctionsTakeIt)
{
  // a directory the file functions find without the \\?\ prefix only in a process that
  // is long path aware; a rejected path reports a missing parent, as a missing one does
  const std::wstring root =
      LR"(C:\Users\Public\usvfs_dos_path_)" + std::to_wstring(::GetCurrentProcessId());
  std::wstring directory = root;
  ::CreateDirectoryW(root.c_str(), nullptr);
  for (wchar_t letter = L'a'; letter < L'g'; ++letter) {
    directory += L'\\' + std::wstring(48, letter);
    ::CreateDirectoryW((LR"(\\?\)" + directory).c_str(), nullptr);
  }
  const bool isCreated =
      ::GetFileAttributesW((LR"(\\?\)" + directory).c_str()) != INVALID_FILE_ATTRIBUTES;
  const bool isTaken =
      ::GetFileAttributesW(directory.c_str()) != INVALID_FILE_ATTRIBUTES;
  const bool isConverted = DosPath::fromWin32(directory).has_value();
  for (; directory.size() > root.size(); directory.erase(directory.rfind(L'\\'))) {
    ::RemoveDirectoryW((LR"(\\?\)" + directory).c_str());
  }
  ::RemoveDirectoryW((LR"(\\?\)" + root).c_str());

  ASSERT_TRUE(isCreated);
  EXPECT_EQ(isTaken, isConverted);
}

TEST(DosPathTest, NormalizesLongFullPathInAnyProcess)
{
  const std::wstring path = LR"(C:/)" + longRelativePath() + LR"(\.\sub\..\name. )";

  EXPECT_EQ(LR"(C:\)" + longRelativePath() + LR"(\name)",
            dosForm(DosPath::fromFullPath(path)));
}

TEST(DosPathTest, TakesFullPathOnShare)
{
  EXPECT_EQ(LR"(\\server\share\x)",
            dosForm(DosPath::fromFullPath(LR"(\\server\share\x)")));
}

TEST(DosPathTest, TakesVerbatimFullPath)
{
  EXPECT_EQ(LR"(C:\x)", dosForm(DosPath::fromFullPath(LR"(\\?\C:\x)")));
}

TEST(DosPathTest, RejectsFullPathToNoDriveOrShare)
{
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromFullPath(LR"(\\.\pipe\name)")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromFullPath(LR"(\\server)")));
}

TEST(DosPathTest, TakesNtPathInDosDeviceNamespace)
{
  EXPECT_EQ(LR"(C:\a\..\b)", dosForm(DosPath::fromNt(LR"(\??\C:\a\..\b)")));
  EXPECT_EQ(LR"(\\server\share\dir)",
            dosForm(DosPath::fromNt(LR"(\??\UNC\server\share\dir)")));
  EXPECT_EQ(LR"(\\server\share)", dosForm(DosPath::fromNt(LR"(\??\unc\server\share)")));
}

TEST(DosPathTest, RejectsNtPathToNoDriveOrShare)
{
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromNt(L"")));
  // a name relative to a directory handle the hooks do not track
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromNt(L"x")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromNt(LR"(dir\file)")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromNt(LR"(\Device\HarddiskVolume1\dir)")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromNt(LR"(\??\C:)")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromNt(LR"(\??\pipe\name)")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromNt(LR"(\??\UNC\server)")));
  EXPECT_EQ(std::nullopt, dosForm(DosPath::fromNt(LR"(C:\dir)")));
}

TEST(DosPathTest, ConvertsToNtPath)
{
  EXPECT_EQ(LR"(\??\C:\dir)", DosPath::fromWin32(LR"(C:\dir)")->ntPath());
  EXPECT_EQ(LR"(\??\UNC\server\share\dir)",
            DosPath::fromWin32(LR"(\\server\share\dir)")->ntPath());
}

TEST(DosPathTest, KeepsShortWin32PathAsItIs)
{
  EXPECT_EQ(LR"(C:\dir)", DosPath::fromWin32(LR"(C:\dir)")->win32Path());
  EXPECT_EQ(LR"(\\server\share\dir)",
            DosPath::fromWin32(LR"(\\server\share\dir)")->win32Path());
}

TEST(DosPathTest, PrefixesWin32PathBeyondCreateDirectoryLimit)
{
  // CreateDirectoryW takes the shortest paths: MAX_PATH less room for an 8.3 name
  const std::wstring longest = LR"(C:\)" + std::wstring(MAX_PATH - 12 - 4, L'a');
  const std::wstring tooLong = longest + L"a";

  EXPECT_EQ(longest, DosPath::fromWin32(longest)->win32Path());
  EXPECT_EQ(LR"(\\?\)" + tooLong, DosPath::fromWin32(tooLong)->win32Path());
}

TEST(DosPathTest, PrefixesLongWin32Path)
{
  const std::wstring longPath = longRelativePath();

  EXPECT_EQ(LR"(\\?\C:\)" + longPath,
            DosPath::fromFullPath(LR"(C:\)" + longPath)->win32Path());
  EXPECT_EQ(LR"(\\?\UNC\server\share\)" + longPath,
            DosPath::fromFullPath(LR"(\\server\share\)" + longPath)->win32Path());
}

TEST(DosPathTest, PrefixesWin32PathTheFileFunctionsWouldNormalize)
{
  EXPECT_EQ(LR"(\\?\C:\a\..\b)", DosPath::fromNt(LR"(\??\C:\a\..\b)")->win32Path());
  EXPECT_EQ(LR"(\\?\C:\name.)", DosPath::fromNt(LR"(\??\C:\name.)")->win32Path());
}

TEST(DosPathTest, ConvertsFullPathToWin32Path)
{
  EXPECT_EQ(LR"(\\?\C:\)" + longRelativePath(),
            toWin32Path(LR"(C:\)" + longRelativePath()));
  EXPECT_EQ(LR"(\\.\pipe\name)", toWin32Path(LR"(\\.\pipe\name)"));
}

int main(int argc, char** argv)
{
  auto logger = spdlog::stdout_logger_mt("usvfs");
  logger->set_level(spdlog::level::warn);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
