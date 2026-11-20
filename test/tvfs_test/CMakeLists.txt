cmake_minimum_required(VERSION 3.16)

find_package(GTest CONFIG REQUIRED)

add_executable(tvfs_test main.cpp connection.cpp directory_enumeration.cpp handle_registry.cpp
                         hook_call_context.cpp process_exit.cpp recursive_shared_lock.cpp)
usvfs_set_test_properties(tvfs_test)
target_link_libraries(tvfs_test PRIVATE test_utils usvfs_helper GTest::gtest GTest::gmock GTest::gtest_main)
usvfs_target_link_usvfs(tvfs_test)

add_executable(usvfs_exit_child exit_child.cpp segment_heap.manifest)
usvfs_set_test_properties(usvfs_exit_child)
add_dependencies(tvfs_test usvfs_exit_child)

# tvfs_test uses a private USVFS header so we need to include it manually
get_target_property(USVFS_SOURCE_DIR usvfs_dll SOURCE_DIR)
target_include_directories(tvfs_test PRIVATE ${USVFS_SOURCE_DIR})

# the directory records, the lock of the hook context and the hook call contexts are
# not exported from the usvfs DLL, so the test builds them itself
target_sources(tvfs_test PRIVATE
    ${USVFS_SOURCE_DIR}/hooks/directory_records.cpp
    ${USVFS_SOURCE_DIR}/hookcallcontext.cpp
    ${USVFS_SOURCE_DIR}/recursive_shared_lock.cpp)
