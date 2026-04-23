# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}       PROVIDER_AGG_DIR_SRCS)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/utils PROVIDER_AGG_UTILS_DIR_SRCS)

add_library(urma_ubagg SHARED
    ${PROVIDER_AGG_DIR_SRCS}
    ${PROVIDER_AGG_UTILS_DIR_SRCS}
)

set(PROJECT_VERSION "0.0.3")
set(PROJECT_VERSION_MAJOR "0")

set_target_properties(urma_ubagg
    PROPERTIES
        C_STANDARD 99
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_include_directories(urma_ubagg 
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/utils
        /usr/include/libnl3
)

target_link_libraries(urma_ubagg urma nl-genl-3 nl-3)

install(TARGETS urma_ubagg
    DESTINATION /usr/lib64/urma
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/urma_ubagg.h
    DESTINATION /usr/include/ub/umdk/urma
)
