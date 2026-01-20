# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include_directories(${CMAKE_CURRENT_LIST_DIR}/../include/framework)

add_compile_definitions(_GNU_SOURCE)

if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
    set(UTIL_LINK_LIB)
    set(UTIL_INCLUDE_LIB)
else()
    set(UTIL_LINK_LIB urma)
    set(UTIL_INCLUDE_LIB ${CMAKE_SOURCE_DIR}/urma/lib/urma/core/include ${CMAKE_SOURCE_DIR}/urma/common/include)
endif()

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} COMMON_UTIL_SRC)
add_library(common_util OBJECT ${COMMON_UTIL_SRC})
target_link_libraries(common_util OpenSSL::SSL OpenSSL::Crypto pthread ${UTIL_LINK_LIB})
set_property(TARGET common_util PROPERTY C_STANDARD 11)
target_include_directories(common_util
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
        ${UTIL_INCLUDE_LIB}
)