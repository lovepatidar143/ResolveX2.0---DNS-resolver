cmake_minimum_required(VERSION 3.10)
project(ResolveX VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(resolvex
  src/main.cpp
  src/dns.cpp
  src/resolver.cpp
  src/cache.cpp
)
target_include_directories(resolvex PRIVATE include)
target_compile_options(resolvex PRIVATE -Wall -Wextra -Wpedantic)

# `ctest` runs the offline unit tests (no network required).
enable_testing()
add_test(NAME offline_tests COMMAND resolvex test)
