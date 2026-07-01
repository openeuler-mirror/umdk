# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include_directories(${CMAKE_CURRENT_LIST_DIR}/../include/framework)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../include/umq)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../include/umq/transport_layer)
include_directories(${CMAKE_CURRENT_LIST_DIR}/qbuf)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../util)
include_directories(${CMAKE_CURRENT_LIST_DIR}/dfx)
include_directories(${CMAKE_CURRENT_LIST_DIR})
include(${CMAKE_SOURCE_DIR}/urpc/umq/dfx/CMakeLists.txt)

add_subdirectory(qbuf)
add_subdirectory(umq_ub)

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} UMQ_LIB_DIR_SRCS)

add_library(umq SHARED
    $<TARGET_OBJECTS:common_util>
    ${UMQ_LIB_DIR_SRCS}
    ${UMQ_DFX_LIB_DIR_SRCS}
)

set_target_properties(umq PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_STANDARD 11
)

target_link_libraries(umq PUBLIC common_util PUBLIC pthread rt PRIVATE umq_buf)
install(TARGETS umq DESTINATION /usr/lib64)

if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/../cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/../cmake_uninstall.cmake"
        IMMEDIATE @ONLY
    )

    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/../cmake_uninstall.cmake)
endif()