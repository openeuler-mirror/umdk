# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.


set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_FLAGS_PUBILC " -Wall -Werror -Wformat -Wfloat-equal -Wtrampolines -g -O2 -rdynamic -Wl,-z,noexecstack,-z,relro,-z,now \
-fno-strict-aliasing -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -fPIC")

if(CROSS_COMPILE)
    set(CMAKE_C_COMPILER "${CROSS_COMPILE}")
    message(STATUS "CMAKE_C_COMPILER: ${CROSS_COMPILE}")
else()
    set(CMAKE_C_COMPILER "/usr/bin/gcc")
endif()

if(CROSS_COMPILE_LINK)
    set(CMAKE_FLAGS_PUBILC "${CMAKE_FLAGS_PUBILC} ${CROSS_COMPILE_LINK}")
    message(STATUS "CROSS_COMPILE_LINK: ${CROSS_COMPILE_LINK}")
endif()

if(NOT "${BUILD_DEBUG}" STREQUAL "off")
    add_definitions(-DUNIT_TEST)
endif()

# GTEST ENABLE
if("${GTEST}" STREQUAL "enable")
# mockcpp can only run on -O0 mode, because it need to change assembly code,
# so we cannot do compiler optimization.
    set(CMAKE_FLAGS_PUBILC " -g -Wall -Werror -O0 -DUT -fPIC")
endif()

# PERF_CYCLE ENABLE
if("${PERF_CYCLE}" STREQUAL "enable")
    set(CMAKE_FLAGS_PUBILC "${CMAKE_FLAGS_PUBILC} -DPERF_CYCLE_FLAG")
endif()

# ASAN ENABLE
if("${ASAN}" STREQUAL "enable")
    set(CMAKE_FLAGS_ASAN "-fsanitize=address -fsanitize-recover=address -fsanitize=leak -fno-omit-frame-pointer")
    set(CMAKE_FLAGS_PUBILC "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ASAN}")
endif()

set(CMAKE_FLAGS_ARM64 " -march=armv8-a+crc -DUB_ARCH_ARM64")
set(CMAKE_FLAGS_x86_64 " -msse4.2 -DUB_ARCH_X86_64")
if("${X86_CROSS_COMPILATION}" STREQUAL "enable")
    set(CMAKE_FLAGS_x86_64 " -DUB_ARCH_X86_64")
    message(STATUS "x86 cross compilation, disabling msse4.2!")
endif()
if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
    set(CMAKE_C_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ARM64}")
    set(CMAKE_CXX_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ARM64} -std=c++11")
else()
    set(CMAKE_C_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_x86_64}")
    set(CMAKE_CXX_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_x86_64} -std=c++11")
endif()

set(CMAKE_SKIP_RPATH TRUE)

message(STATUS "CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")
enable_testing()

add_subdirectory(common)
add_subdirectory(lib)
add_subdirectory(examples)
add_subdirectory(tools)
if(NOT "${BUILD_UDMA}" STREQUAL "disable")
    add_subdirectory(hw)
endif()

# uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
