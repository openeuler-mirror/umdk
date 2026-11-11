# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.

# API/ABI note versions; keep aligned with urma_types.h.
set(URMA_API_VERSION "1.0.0")
set(URMA_ABI_VERSION "0.1.0")
foreach(kind API ABI)
    string(REPLACE "." ";" URMA_${kind}_VERSION_PARTS "${URMA_${kind}_VERSION}")
    list(GET URMA_${kind}_VERSION_PARTS 0 URMA_${kind}_VERSION_MAJOR)
    list(GET URMA_${kind}_VERSION_PARTS 1 URMA_${kind}_VERSION_MINOR)
    list(GET URMA_${kind}_VERSION_PARTS 2 URMA_${kind}_VERSION_PATCH)
    math(EXPR URMA_${kind}_VERSION_CODE
        "(${URMA_${kind}_VERSION_MAJOR} << 32) | (${URMA_${kind}_VERSION_MINOR} << 16) | ${URMA_${kind}_VERSION_PATCH}")
endforeach()
set(URMA_VERSION_NOTE "${CMAKE_CURRENT_BINARY_DIR}/urma_version_note.S")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/urma_version_note.S.in"
    "${URMA_VERSION_NOTE}" @ONLY)

enable_language(ASM)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(URMA_PERF_USE_CNTVCT_DEFAULT ON)
else()
    set(URMA_PERF_USE_CNTVCT_DEFAULT OFF)
endif()
option(URMA_PERF_USE_CNTVCT "Use ARM CNTVCT_EL0 register for perf timestamp instead of clock_gettime (AArch64 only)" ${URMA_PERF_USE_CNTVCT_DEFAULT})

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} URMA_DIR_SRCS)

add_library(urma SHARED
    ${URMA_VERSION_NOTE}
    ${URMA_DIR_SRCS}
)

add_library(urma_static STATIC
    ${URMA_DIR_SRCS}
)

set_target_properties(urma
    PROPERTIES
        C_STANDARD 99
        VERSION ${URMA_ABI_VERSION}
        SOVERSION ${URMA_ABI_VERSION_MAJOR}
        LINK_FLAGS "-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/liburma.map"
        LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/liburma.map"
)
set_target_properties(urma_static
    PROPERTIES
        C_STANDARD 99
        VERSION ${URMA_ABI_VERSION}
        SOVERSION ${URMA_ABI_VERSION_MAJOR}
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
