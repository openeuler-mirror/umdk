# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include_directories(${CMAKE_CURRENT_LIST_DIR}/../../include/umq/umq_ubmm)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../umq_ub)

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} UMQ_UBMM_LIB_DIR_SRCS)
file(GLOB UMQ_UB_IMPL_FILE ${CMAKE_SOURCE_DIR}/urpc/umq/umq_ub/umq_ub_impl.c)
file(GLOB UTIL_SRCS ${CMAKE_SOURCE_DIR}/urpc/umq/msg_ring.c)

add_library(umq_ubmm SHARED
        ${UMQ_UBMM_LIB_DIR_SRCS}
        ${UMQ_UB_IMPL_FILE}
        ${UTIL_SRCS}
)
set_target_properties(umq_ubmm PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        C_STANDARD 11
)
target_link_libraries(umq_ubmm PUBLIC pthread OpenSSL::SSL urma PRIVATE obmm umq_buf)
install(TARGETS umq_ubmm DESTINATION /usr/lib64)

# uninstall target
if(NOT TARGET uninstall)
    configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_uninstall.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake"
            IMMEDIATE @ONLY
    )

    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake)
endif()
