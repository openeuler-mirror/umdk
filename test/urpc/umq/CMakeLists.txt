# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

cmake_minimum_required(VERSION 3.13)

project(test_umq)

add_compile_definitions(URPC_ASAN)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/ TEST_SOURCE_DIR)

add_executable(${PROJECT_NAME} ${TEST_SOURCE_DIR} ${TEST_C_FILE})

target_include_directories(${PROJECT_NAME} PRIVATE
    /usr/include/ub/umdk/urma
    ${URPC_ROOT_DIR}/include/umq
    ${URPC_ROOT_DIR}/include/umq/transport_layer
    ${URPC_ROOT_DIR}/umq
    ${URPC_ROOT_DIR}/umq/dfx
    ${URPC_ROOT_DIR}/umq/qbuf
    ${URPC_ROOT_DIR}/umq/umq_ub
    ${URPC_ROOT_DIR}/umq/umq_ub/core
    ${URPC_ROOT_DIR}/umq/umq_ub/core/private
    ${URPC_ROOT_DIR}/util
)

if(ENABLE_ASAN)
    target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
endif()

target_link_libraries(${PROJECT_NAME}
    umq
    umq_buf
    umq_ub
    GTest::gtest
    GTest::gtest_main
    mockcpp
    urma
    OpenSSL::SSL
    pthread
    rt
    ${CMAKE_THREAD_LIBS_INIT}
)
