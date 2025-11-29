cmake_minimum_required(VERSION 3.13)

project(urpc_framework_test)

option(ENABLE_ASAN "Enable AddressSanitizer" ON)

add_compile_options(-Werror -fno-inline -O0 -g -Wall -fPIC -fno-omit-frame-pointer)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

set(URPC_ROOT_DIR ${CMAKE_SOURCE_DIR}/../../src/urpc)

add_subdirectory(core)
add_subdirectory(lib)
add_subdirectory(protocol)
add_subdirectory(util)
