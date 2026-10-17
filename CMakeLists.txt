cmake_minimum_required(VERSION 3.10)
project(ResolveX VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(RESOLVEX_SOURCES
  src/dns.cpp
  src/resolver.cpp
  src/cache.cpp
  src/transport.cpp
  src/root_hints.cpp
  src/trace.cpp
)

add_executable(resolvex
  src/main.cpp
  ${RESOLVEX_SOURCES}
)
target_include_directories(resolvex PRIVATE include)
target_compile_options(resolvex PRIVATE -Wall -Wextra -Wpedantic)

# Add symlink for resolveX on case-sensitive Linux platforms
if(NOT APPLE)
  add_custom_command(TARGET resolvex POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE_NAME:resolvex> ${CMAKE_CURRENT_BINARY_DIR}/resolveX
  )
endif()

# `ctest` runs the comprehensive offline test suite (no network required).
enable_testing()
add_test(NAME offline_tests COMMAND resolvex test)
