cmake_minimum_required(VERSION 3.15)
project(SacreProject LANGUAGES CXX C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
  set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY_EXE}")
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
add_executable(sacre-inject src/inject/main.cpp src/inject/injector.cpp)
target_link_libraries(sacre-inject sacre-common)

# Sacre Loader
add_executable(sacre-loader src/loader/main.cpp)
target_link_libraries(sacre-loader sacre-common)

# Testing
enable_testing()

# Unit Tests
add_executable(policy_test src/common/policy_test.cpp)
target_link_libraries(policy_test sacre-common)
add_test(NAME policy_unit_test COMMAND policy_test)

add_executable(injector_test src/inject/injector_test.cpp src/inject/injector.cpp)
target_link_libraries(injector_test sacre-common)
add_test(NAME injector_unit_test COMMAND injector_test)

# Integration Tests
# 1. Basic success (no seccomp, no namespaces)
add_test(NAME integration_test_basic
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_test.sh
         $<TARGET_FILE:sacre-inject>
         $<TARGET_FILE:sacre-loader>
         $<TARGET_FILE:minimal_target>
         ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_policy_no_seccomp.ini)

# 2. Namespace success (enables namespaces, no seccomp)
add_test(NAME integration_test_namespaces
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_test.sh
         $<TARGET_FILE:sacre-inject>
         $<TARGET_FILE:sacre-loader>
         $<TARGET_FILE:minimal_target>
         ${CMAKE_CURRENT_SOURCE_DIR}/tests/namespaces_only.ini)

# 3. Seccomp success (allows needed syscalls)
add_test(NAME integration_test_seccomp_success
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_test.sh
         $<TARGET_FILE:sacre-inject>
         $<TARGET_FILE:sacre-loader>
         $<TARGET_FILE:minimal_target>
         ${CMAKE_CURRENT_SOURCE_DIR}/tests/seccomp_safe.ini)

# 4. Seccomp violation (killed when calling forbidden getppid)
add_test(NAME integration_test_seccomp_violation
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_test.sh
         $<TARGET_FILE:sacre-inject>
         $<TARGET_FILE:sacre-loader>
         $<TARGET_FILE:violation_target>
         ${CMAKE_CURRENT_SOURCE_DIR}/tests/seccomp_violation.ini)
set_tests_properties(integration_test_seccomp_violation PROPERTIES ENVIRONMENT "EXPECT_KILL=1")

# Test Target
add_executable(test_target src/test_target.cpp)
target_link_options(test_target PRIVATE -static)

add_executable(minimal_target src/minimal_target.c)
set_target_properties(minimal_target PROPERTIES LINKER_LANGUAGE C)
target_link_options(minimal_target PRIVATE -static -nostdlib)

add_executable(violation_target src/violation_target.c)
set_target_properties(violation_target PROPERTIES LINKER_LANGUAGE C)
target_link_options(violation_target PRIVATE -static -nostdlib)

# Helper target to run clang-tidy --fix on all files
if(CLANG_TIDY_EXE)
  file(GLOB_RECURSE ALL_SOURCE_FILES 
       "src/*.cpp" 
       "src/*.h"
       "src/*.c")
  
  add_custom_target(fix-style
    COMMAND ${CLANG_TIDY_EXE} -p ${CMAKE_BINARY_DIR} --fix-errors ${ALL_SOURCE_FILES}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Applying automated clang-tidy fixes to all source files..."
  )
endif()
