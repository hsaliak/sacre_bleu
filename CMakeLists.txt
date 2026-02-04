cmake_minimum_required(VERSION 3.15)
project(SacreProject LANGUAGES CXX)

# Disable Exceptions
if(MSVC)
  add_compile_options(/EHs-c-)
  add_definitions(-D_HAS_EXCEPTIONS=0)
else()
  add_compile_options(-fno-exceptions)
endif()

# Clang-Tidy Integration
find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
if(CLANG_TIDY_EXE)
  set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
else()
  message(WARNING "clang-tidy not found")
endif()

# Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compilation Flags for Google Style/Strictness
if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -Werror -Wpedantic)
endif()

# Include directories - allows #include "src/common/..."
include_directories(${CMAKE_SOURCE_DIR})

# Common Library (Policy Parser/Binary Format)
add_library(sacre-common
  src/common/policy.cpp
)

# Sacre Injector
add_executable(sacre-inject src/inject/main.cpp)
target_link_libraries(sacre-inject sacre-common)

# Sacre Loader
add_executable(sacre-loader src/loader/main.cpp)
target_link_libraries(sacre-loader sacre-common)

# Unit Tests
add_executable(policy_test src/common/policy_test.cpp)
target_link_libraries(policy_test sacre-common)

# Test Target
add_executable(test_target src/test_target.cpp)
target_link_options(test_target PRIVATE -static)
