# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include_directories(${CMAKE_CURRENT_LIST_DIR}/../../include/umq/umq_ub)
include_directories(${CMAKE_CURRENT_LIST_DIR}/core)
include_directories(${CMAKE_CURRENT_LIST_DIR}/core/flow_control)
include_directories(${CMAKE_CURRENT_LIST_DIR}/core/private)
include(${CMAKE_SOURCE_DIR}/urpc/umq/dfx/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/core/CMakeLists.txt)
aux_source_directory(${CMAKE_CURRENT_LIST_DIR} UMQ_UB_LIB_DIR_SRCS)

add_library(umq_ub SHARED
    ${UMQ_UB_LIB_DIR_SRCS}
)
set_target_properties(umq_ub PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_STANDARD 11
)

target_include_directories(umq_ub
    PUBLIC
        ${CMAKE_SOURCE_DIR}/urma/lib/urma/core/include
        ${CMAKE_SOURCE_DIR}/urma/lib/uvs/core/include
)

target_link_libraries(umq_ub PUBLIC pthread OpenSSL::SSL urma tpsa PRIVATE umq_buf)
install(TARGETS umq_ub DESTINATION /usr/lib64)

# uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake"
        IMMEDIATE @ONLY
    )

    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake)
endif()