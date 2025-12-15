# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/../include/framework
    ${CMAKE_CURRENT_LIST_DIR}/../util
    ${CMAKE_CURRENT_LIST_DIR}/core
    ${CMAKE_CURRENT_LIST_DIR}/core/channel
    ${CMAKE_CURRENT_LIST_DIR}/core/queue
    ${CMAKE_CURRENT_LIST_DIR}/core/queue/jetty
    ${CMAKE_CURRENT_LIST_DIR}/lib
    ${CMAKE_CURRENT_LIST_DIR}/lib/control
    ${CMAKE_CURRENT_LIST_DIR}/lib/control/ip
    ${CMAKE_CURRENT_LIST_DIR}/lib/control/dfx
    ${CMAKE_CURRENT_LIST_DIR}/lib/control/unix_server
    ${CMAKE_CURRENT_LIST_DIR}/lib/control/allocator
    ${CMAKE_CURRENT_LIST_DIR}/lib/control/crypto
    ${CMAKE_CURRENT_LIST_DIR}/lib/datapath
    ${CMAKE_CURRENT_LIST_DIR}/lib/manager
    ${CMAKE_CURRENT_LIST_DIR}/protocol
    ${CMAKE_CURRENT_LIST_DIR}/util
    ${CMAKE_CURRENT_LIST_DIR}
)

add_subdirectory(core)
add_subdirectory(lib)
add_subdirectory(protocol)

include(core/CMakeLists.txt)
include(lib/CMakeLists.txt)
include(protocol/CMakeLists.txt)

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} URPC_LIB_DIR_SRCS)

add_library(urpc SHARED
    $<TARGET_OBJECTS:common_util>
    ${URPC_LIB_DIR_SRCS}
)

set_target_properties(urpc PROPERTIES
    OUTPUT_NAME "urpc_framework"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_STANDARD 11
)

set_property(TARGET urpc PROPERTY C_STANDARD 11)
target_link_libraries(urpc urma urma_common common_util pthread OpenSSL::SSL)
install(TARGETS urpc DESTINATION /usr/lib64)

# uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/../cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/../cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()