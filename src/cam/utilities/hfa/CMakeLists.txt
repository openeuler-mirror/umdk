# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.

cmake_minimum_required(VERSION 3.18.0)

add_compile_options(-O3 $<$<COMPILE_LANGUAGE:CXX>:-std=c++17>)

option(BUILD_TESTS "Build the tests" OFF)

project(hbm-fast-alloc)
set(CMAKE_BUILD_TYPE Debug)
set(ASCEND_COMMON_LIBS "/usr/local/Ascend/driver/lib64/common")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")
add_subdirectory(src)
if(BUILD_TESTS)
  add_subdirectory(test)
endif()

