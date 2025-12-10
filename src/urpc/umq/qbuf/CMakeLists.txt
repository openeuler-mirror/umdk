# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} UMQ_QBUF_SRC)
file(GLOB UMQ_IPC_IMPL_FILE ${CMAKE_SOURCE_DIR}/lib/util/msg_ring.c)

add_library(umq_buf SHARED
    ${UMQ_IPC_IMPL_FILE}
    ${UMQ_QBUF_SRC}
)

set_target_properties(umq_buf PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_STANDARD 11
)

install(TARGETS umq_buf DESTINATION /usr/lib64)

# uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake"
        IMMEDIATE @ONLY
    )

    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake)
endif()