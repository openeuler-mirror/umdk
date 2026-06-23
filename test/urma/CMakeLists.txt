# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.

cmake_minimum_required(VERSION 3.13)

project(urma_test)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

find_package(GTest QUIET)
if(NOT GTest_FOUND)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://gitee.com/mirrors/googletest.git
        GIT_TAG v1.14.0
        GIT_SHALLOW TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

if(NOT DEFINED URMA_SRC_DIR)
    set(URMA_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../../src/urma)
endif()

if(NOT DEFINED URMA_BUILD_DIR)
    message(FATAL_ERROR "URMA_BUILD_DIR must point to the URMA source build directory")
endif()

set(URMA_COMMON_INCLUDE_DIR ${URMA_SRC_DIR}/common/include)
set(URMA_CORE_DIR ${URMA_SRC_DIR}/lib/urma/core)
set(URMA_CORE_INCLUDE_DIR ${URMA_CORE_DIR}/include)
set(URMA_BOND_DIR ${URMA_SRC_DIR}/lib/urma/bond)
set(URMA_BOND_UTILS_DIR ${URMA_BOND_DIR}/utils)

set(URMA_COMMON_STATIC ${URMA_BUILD_DIR}/urma/common/liburma_common_static.a)
set(URMA_COMMON_SO ${URMA_BUILD_DIR}/urma/common/liburma_common.so)
set(URMA_STATIC ${URMA_BUILD_DIR}/urma/lib/urma/core/liburma_static.a)
set(URMA_SO ${URMA_BUILD_DIR}/urma/lib/urma/core/liburma.so)
set(URMA_UBAGG_SO ${URMA_BUILD_DIR}/urma/lib/urma/bond/liburma_ubagg.so)

add_library(urma_test_common INTERFACE)
target_include_directories(urma_test_common INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${URMA_COMMON_INCLUDE_DIR}
    ${URMA_CORE_DIR}
    ${URMA_CORE_INCLUDE_DIR}
    ${URMA_BOND_DIR}
    ${URMA_BOND_UTILS_DIR}
    ${URMA_BOND_DIR}/include
)
target_compile_options(urma_test_common INTERFACE
    -Wall -Werror -O0 -g -fsanitize=address -fno-omit-frame-pointer --coverage
)
target_link_options(urma_test_common INTERFACE -fsanitize=address --coverage)

add_executable(urma_core_ut core/core_test.cpp)
target_link_options(urma_core_ut PRIVATE -Wl,--wrap=ioctl)
target_link_libraries(urma_core_ut PRIVATE urma_test_common ${URMA_STATIC} ${URMA_COMMON_STATIC}
    GTest::gtest_main dl rt pthread)

add_executable(urma_cmd_tlv_ut cmd_tlv/cmd_tlv_test.cpp)
target_link_options(urma_cmd_tlv_ut PRIVATE -Wl,--wrap=ioctl -Wl,--wrap=urma_query_eid)
target_link_libraries(urma_cmd_tlv_ut PRIVATE urma_test_common ${URMA_STATIC} ${URMA_COMMON_STATIC}
    GTest::gtest_main dl rt pthread)

add_executable(urma_bond_ut bond/bond_test.cpp)
target_link_libraries(urma_bond_ut PRIVATE urma_test_common ${URMA_UBAGG_SO} ${URMA_SO} ${URMA_COMMON_SO}
    GTest::gtest_main nl-genl-3 nl-3 dl rt pthread)

enable_testing()
add_subdirectory(common)
add_test(NAME urma_core_ut COMMAND urma_core_ut)
set_tests_properties(urma_core_ut PROPERTIES LABELS phase_core)
add_test(NAME urma_cmd_tlv_ut COMMAND urma_cmd_tlv_ut)
set_tests_properties(urma_cmd_tlv_ut PROPERTIES LABELS phase_cmd_tlv)
add_test(NAME urma_bond_ut COMMAND urma_bond_ut)
set_tests_properties(urma_bond_ut PROPERTIES LABELS phase_bond)
