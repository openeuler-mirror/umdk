#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(CMAKE_C_COMPILER "/usr/bin/gcc")

if(BUILD_WITH_UT)
    set(CMAKE_FLAG_COVERAGE " -fprofile-arcs -ftest-coverage")
endif()

set(CMAKE_FLAGS_PUBILC " -Wall -Werror -Wfloat-equal -Wtrampolines -g -O2 -rdynamic -Wl,-z,noexecstack,-z,relro,-z,now \
-fno-strict-aliasing -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wno-implicit-fallthrough -ftrapv -s")

set(CMAKE_FLAGS_ARM64 " -march=armv8-a+crc -DUB_ARCH_ARM64")
set(CMAKE_FLAGS_x86_64 " -msse4.2 -DUB_ARCH_X86_64")
if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
    set(CMAKE_C_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ARM64} ${CMAKE_FLAG_COVERAGE}")
    set(CMAKE_CXX_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ARM64} ${CMAKE_FLAG_COVERAGE} -std=c++11")
else()
    set(CMAKE_C_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_x86_64} ${CMAKE_FLAG_COVERAGE}")
    set(CMAKE_CXX_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_x86_64} ${CMAKE_FLAG_COVERAGE} -std=c++11")
endif()

set(CMAKE_SKIP_RPATH TRUE)

message(STATUS "CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")

include_directories(include)

add_subdirectory(kmod)
add_subdirectory(tools)
add_subdirectory(ums_agent)

# uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()