# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

# URMA test code makefile
cmake_minimum_required(VERSION 3.12.1)
project(urma_test)
set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}")

include_directories(${PROJECT_SOURCE_DIR}/../../src/urma/lib/urma/core/include)
include_directories(${PROJECT_SOURCE_DIR}/../../src/urma/common/include)
include_directories(${PROJECT_SOURCE_DIR}/../../src/urma/lib/urma/core)
include_directories(${PROJECT_SOURCE_DIR}/../../src/urma/lib/urma/bond)
include_directories(${PROJECT_SOURCE_DIR}/../../src/urma/lib/urma/bond/include)
include_directories(${PROJECT_SOURCE_DIR}/../../src/urma/lib/urma/bond/utils)

# gtest executable file
add_executable(urma_gtest
    bond/bondp_bitmap_gtest.cpp
    bond/bondp_gtest_basic.h
    bond/bondp_topo_info_gtest.cpp
    bond/common.h
    bond/urma_gtest_basic.h
    bond/urma_gtest_main.cpp
)

target_compile_features(urma_gtest PRIVATE cxx_std_17)
target_compile_definitions(urma_gtest PRIVATE PROJECT_DIR=${PROJECT_SOURCE_DIR})

target_include_directories(urma_gtest PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(urma_gtest PRIVATE libgtest.a libmockcpp.a -lurma /lib64/urma/liburma_ubagg.so pthread)