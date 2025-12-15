# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include_directories(${CMAKE_CURRENT_LIST_DIR}/../../include/umq/umq_ipc)

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} UMQ_IPC_LIB_DIR_SRCS)

add_library(umq_ipc SHARED
    $<TARGET_OBJECTS:common_util>
    ${UMQ_IPC_LIB_DIR_SRCS}
)
set_target_properties(umq_ipc PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_STANDARD 11
)

target_link_libraries(umq_ipc PUBLIC pthread OpenSSL::SSL PRIVATE common_util rt)
install(TARGETS umq_ipc DESTINATION /usr/lib64)

# uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake"
        IMMEDIATE @ONLY
    )

    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake)
endif()