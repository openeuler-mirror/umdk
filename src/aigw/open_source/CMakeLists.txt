#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
#

cmake_minimum_required(VERSION 3.28.2)
project(AIGW LANGUAGES C CXX)

option(WITH_DEBUG "Build the debug version" OFF)

message(STATUS "Building opensource software")
if (WITH_DEBUG)
    message(STATUS "Building debug of opensource software")
    set(CMAKE_BUILD_TYPE Debug)
else ()
    message(STATUS "Building release of opensource software")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif ()

set(CMAKE_SKIP_RPATH TRUE)

add_compile_options(
    -Wall -Werror -rdynamic -fno-strict-aliasing
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2 -O2
    -fPIC
    -fno-common
)

add_link_options(
    -Wl,-z,now
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -fPIE -pie
)

add_subdirectory(LightGBM-v4.6.0)