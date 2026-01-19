# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_options(-fPIC)

add_library(hfa SHARED
            ${CMAKE_SOURCE_DIR}/src/flex_alloc.cpp
            ${CMAKE_SOURCE_DIR}/src/hbm_fast_alloc.cpp
            ${CMAKE_SOURCE_DIR}/src/acl_virtual_memory.cpp
            ${CMAKE_SOURCE_DIR}/src/acl_free_chunks.cpp)
set_target_properties(hfa PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(hfa PRIVATE
            $ENV{ASCEND_HOME_PATH}/include
            ${CMAKE_SOURCE_DIR}/include)

target_link_directories(hfa PRIVATE
            ${ASCEND_COMMON_LIBS})

target_compile_options(hfa PRIVATE -fPIC)
target_link_libraries(hfa PUBLIC
            $ENV{ASCEND_TOOLKIT_HOME}/lib64/libascendcl.so
            -lrt
            -pthread
            -lsecurec)