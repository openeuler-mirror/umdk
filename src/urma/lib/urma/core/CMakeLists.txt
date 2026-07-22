# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(URMA_PERF_USE_CNTVCT_DEFAULT ON)
else()
    set(URMA_PERF_USE_CNTVCT_DEFAULT OFF)
endif()
option(URMA_PERF_USE_CNTVCT "Use ARM CNTVCT_EL0 register for perf timestamp instead of clock_gettime (AArch64 only)" ${URMA_PERF_USE_CNTVCT_DEFAULT})

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} URMA_DIR_SRCS)

add_library(urma SHARED
    ${URMA_DIR_SRCS}
)

add_library(urma_static STATIC
    ${URMA_DIR_SRCS}
)
set(PROJECT_VERSION "0.0.3")
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

if(URMA_PERF_USE_CNTVCT)
    target_compile_definitions(urma PRIVATE URMA_PERF_USE_CNTVCT)
    target_compile_definitions(urma_static PRIVATE URMA_PERF_USE_CNTVCT)
endif()

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
    ${CMAKE_CURRENT_SOURCE_DIR}/include/urma_perf.h
    DESTINATION /usr/include/ub/umdk/urma
)
