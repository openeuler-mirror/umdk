# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

cmake_minimum_required(VERSION 3.13)

project(test_lib)

add_compile_definitions(URPC_ASAN)

#aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/ TEST_SOURCE_DIR)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/control TEST_SOURCE_DIR)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/datapath TEST_SOURCE_DIR)

set(TEST_C_FILE
    ${URPC_ROOT_DIR}/tools/urpc_admin/urpc_admin_param.c
)

add_executable(${PROJECT_NAME} ${TEST_SOURCE_DIR} ${TEST_C_FILE})

target_include_directories(${PROJECT_NAME} PRIVATE
    /usr/include/ub/umdk/urma
    ${URPC_ROOT_DIR}/include/framework
    ${URPC_ROOT_DIR}/util/
    ${URPC_ROOT_DIR}/framework
    ${URPC_ROOT_DIR}/framework/core/channel/
    ${URPC_ROOT_DIR}/framework/core/queue/
    ${URPC_ROOT_DIR}/framework/core/queue/jetty
    ${URPC_ROOT_DIR}/framework/lib/
    ${URPC_ROOT_DIR}/framework/lib/datapath
    ${URPC_ROOT_DIR}/framework/lib/manager
    ${URPC_ROOT_DIR}/framework/lib/control
    ${URPC_ROOT_DIR}/framework/lib/control/crypto
    ${URPC_ROOT_DIR}/framework/lib/control/ip
    ${URPC_ROOT_DIR}/framework/lib/control/unix_server
    ${URPC_ROOT_DIR}/framework/lib/control/dfx
    ${URPC_ROOT_DIR}/framework/protocol
    ${URPC_ROOT_DIR}/framework/lib/control/allocator
    ${URPC_ROOT_DIR}/tools/urpc_admin
    ${URPC_ROOT_DIR}/tools/urpc_admin/cmds
)

target_compile_options(${PROJECT_NAME} PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-write-strings>
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-sign-compare>
)

if(ENABLE_ASAN)
    target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
endif()

target_link_libraries(${PROJECT_NAME}
    urpc_framework
    GTest::gtest
    GTest::gtest_main
    mockcpp
    urma
    OpenSSL::SSL
    pthread
    ${CMAKE_THREAD_LIBS_INIT}
)
