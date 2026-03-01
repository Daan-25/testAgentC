cmake_minimum_required(VERSION 3.14)
project(bindiff VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Main library (shared between CLI and tests) ---
add_library(bindiff_lib STATIC
    src/pe_parser.cpp
    src/pe_diff.cpp
)
target_include_directories(bindiff_lib PUBLIC src)

# --- CLI executable ---
add_executable(bindiff src/main.cpp)
target_link_libraries(bindiff PRIVATE bindiff_lib)

# --- Tests ---
enable_testing()

# Fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(bindiff_tests
    tests/test_pe_parser.cpp
    tests/test_pe_diff.cpp
)
target_link_libraries(bindiff_tests PRIVATE bindiff_lib GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(bindiff_tests)
