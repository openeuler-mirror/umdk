#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

cmake_minimum_required(VERSION 3.12.1)

set(UMS_AGENT_SRC_DIR "${CMAKE_SOURCE_DIR}/../../../src/usock/ums/ums_agent")

# socket-level / E2E gtest binaries (only need gtest + libnl)
function(add_ut)
    set(UT_NAME ${ARGV0})

    file(GLOB UT_FILE ./${UT_NAME}.cpp)

    add_executable(${UT_NAME}
        ${UT_FILE}
    )

    target_include_directories(
        ${UT_NAME} PUBLIC
        include
        ${CMAKE_CURRENT_LIST_DIR}
        /usr/include/libnl3
        /usr/local/lib64
    )

    target_link_libraries(
        ${UT_NAME}  PUBLIC
        libgtest.a
        libgtest_main.a
        nl-genl-3
        nl-3
    )

    install(TARGETS ${UT_NAME})
endfunction()

# white-box agent unit tests: #include the production .c, so they need the agent
# source dir on the include path plus glib (g_hash_table_*) and openssl
# (OPENSSL_cleanse via ums_agent_secure_zero).
function(add_agent_ut)
    set(UT_NAME ${ARGV0})

    file(GLOB UT_FILE ./${UT_NAME}.cpp)

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0)
    pkg_check_modules(OPENSSL REQUIRED IMPORTED_TARGET openssl)

    add_executable(${UT_NAME}
        ${UT_FILE}
    )

    target_include_directories(
        ${UT_NAME} PUBLIC
        include
        ${CMAKE_CURRENT_LIST_DIR}
        ${UMS_AGENT_SRC_DIR}
        /usr/include/libnl3
        /usr/local/lib64
    )

    target_link_libraries(
        ${UT_NAME}  PUBLIC
        libgtest.a
        libgtest_main.a
        nl-genl-3
        nl-3
        PkgConfig::GLIB
        PkgConfig::OPENSSL
    )

    install(TARGETS ${UT_NAME})
endfunction()

add_definitions(-DLOCAL_IP=\"${LOCAL_IP}\")
add_definitions(-DREMOTE_IP=\"${REMOTE_IP}\")
add_definitions(-DLOCAL_IPV6=\"${LOCAL_IPV6}\")
add_definitions(-DREMOTE_IPV6=\"${REMOTE_IPV6}\")

add_ut(ums_test_ut)
add_ut(ums_test_ut_client)
add_ut(ums_test_ut_server)

add_agent_ut(ums_agent_token_proxy_ut)
add_agent_ut(ums_agent_nl_ut)
add_ut(ums_token_e2e_ut)

add_subdirectory(kmode_ut)
