# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(CMAKE_C_COMPILER "/usr/bin/gcc")

set(CMAKE_FLAGS_PUBILC " -Wall -Werror -Wfloat-equal -Wtrampolines -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -g -O2 -rdynamic -Wl,-z,noexecstack,-z,relro,-z,now \
-fno-strict-aliasing -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -fPIC -funsigned-char -Wformat=2 -Wdate-time -Wswitch-default -Wshadow \
-fno-common -s")

if("${UB_AGG_DIS}" STREQUAL "enable")
    set(UB_AGG "disable")
    message(STATUS "UB_AGG disable!")
else()
    message(STATUS "UB_AGG enable!")
    set(UB_AGG "enable")
    set(CMAKE_FLAGS_PUBILC "${CMAKE_FLAGS_PUBILC} -DUB_AGG")
endif()

# ASAN ENABLE
if("${ASAN}" STREQUAL "enable")
    set(CMAKE_FLAGS_ASAN "-fsanitize=address -fsanitize-recover=address -fsanitize=leak \
        -fno-stack-protector -fno-omit-frame-pointer")
    set(CMAKE_FLAGS_PUBILC "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ASAN}")
    string(REPLACE "-fstack-protector-strong" "" CMAKE_FLAGS_PUBILC "${CMAKE_FLAGS_PUBILC}")
else ()
    set(CMAKE_FLAGS_ASAN "")
endif("${ASAN}" STREQUAL "enable")

# TSAN ENABLE
if("${TSAN}" STREQUAL "enable")
    set(CMAKE_FLAGS_TSAN "-fsanitize=thread -fsanitize-recover=address \
        -fno-stack-protector -fno-omit-frame-pointer")
    set(CMAKE_FLAGS_PUBILC "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_TSAN}")
    string(REPLACE "-fstack-protector-strong" "" CMAKE_FLAGS_PUBILC "${CMAKE_FLAGS_PUBILC}")
else ()
    set(CMAKE_FLAGS_TSAN "")
endif("${TSAN}" STREQUAL "enable")

# CODE_COVERAGE ENABLE
if("${CODE_COVERAGE}" STREQUAL "enable")
    set(CMAKE_FLAGS_COVERAGE "-fprofile-arcs -ftest-coverage")
else ()
    set(CMAKE_FLAGS_COVERAGE "")
endif()

set(CMAKE_FLAGS_ARM64 " -march=armv8-a+crc -DUB_ARCH_ARM64")
set(CMAKE_FLAGS_x86_64 " -msse4.2 -DUB_ARCH_X86_64")
if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
    set(CMAKE_C_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ARM64} -std=c11")
    set(CMAKE_CXX_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ARM64} -std=c++11")
else()
    set(CMAKE_C_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_x86_64} -std=c11")
    set(CMAKE_CXX_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_x86_64} -std=c++11")
endif()

set(CMAKE_SKIP_RPATH TRUE)

enable_testing()

include_directories(include)
add_subdirectory(include)
add_subdirectory(lib)
add_subdirectory(examples)

# uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
