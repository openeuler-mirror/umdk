# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TPSA_SO_DIR_SRCS)

add_library(tpsa SHARED
    ${TPSA_SO_DIR_SRCS}
)

set_target_properties(tpsa
    PROPERTIES
        C_STANDARD 99
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_include_directories(tpsa 
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/urma/lib/urma/core/include
        ${CMAKE_SOURCE_DIR}/urma/common/include
)

target_link_libraries(tpsa urma_common_static nl-genl-3 nl-3 ssl crypto)

install(TARGETS tpsa
    DESTINATION /usr/lib64
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/uvs_api.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/uvs_types.h
    DESTINATION /usr/include/ub/umdk/urma)
