# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} URMA_DIR_SRCS)

add_library(urma SHARED
    ${URMA_DIR_SRCS}
)

add_library(urma_static STATIC
    ${URMA_DIR_SRCS}
)
set(PROJECT_VERSION "0.0.2")
set(PROJECT_VERSION_MAJOR "0")

set_target_properties(urma
    PROPERTIES
        C_STANDARD 99
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
)
set_target_properties(urma_static
    PROPERTIES
        C_STANDARD 99
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_include_directories(urma
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
)
target_include_directories(urma_static
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(urma urma_common -ldl -lrt)
target_link_libraries(urma_static urma_common -ldl -lrt)

install(TARGETS urma
    DESTINATION /usr/lib64
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/urma_api.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/urma_cmd.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/urma_opcode.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/urma_provider.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/urma_types_str.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/urma_types.h
    DESTINATION /usr/include/ub/umdk/urma
)
