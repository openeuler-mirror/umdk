# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include_directories(common)
include_directories(server)
include_directories(include)

include_directories(${CMAKE_SOURCE_DIR}/urma/common/include)
include_directories(${CMAKE_SOURCE_DIR}/urma/lib/urma/bond/include)
include_directories(${CMAKE_SOURCE_DIR}/urma/lib/urma/core/include)
include_directories(${CMAKE_SOURCE_DIR}/urma/lib/urma/core)

if("${ASAN}" STREQUAL "enable")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize-recover=address -fsanitize=leak \
        -fno-stack-protector -fno-omit-frame-pointer")
endif()

if("${TSAN}" STREQUAL "enable")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fsanitize-recover=address \
        -fno-stack-protector -fno-omit-frame-pointer")
endif()

if("${CODE_COVERAGE}" STREQUAL "enable")
    set(CMAKE_CXX_FLAGS "-fprofile-arcs -ftest-coverage")
endif()

add_subdirectory(common)
add_subdirectory(client)
add_subdirectory(server)

file(GLOB DLOCK_API_FILE
    "${CMAKE_SOURCE_DIR}/ulock/dlock/lib/include/dlock_client_api.h"
    "${CMAKE_SOURCE_DIR}/ulock/dlock/lib/include/dlock_types.h"
    "${CMAKE_SOURCE_DIR}/ulock/dlock/lib/include/dlock_server_api.h"
    )
install(FILES ${DLOCK_API_FILE} DESTINATION /usr/include/ub/umdk/ulock/dlock)
set (CMAKE_CXX_STANDARD 17)
