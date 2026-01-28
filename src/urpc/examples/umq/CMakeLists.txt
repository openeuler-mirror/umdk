# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include(${CMAKE_CURRENT_LIST_DIR}/connection_setup_tool/CMakeLists.txt)

include_directories(/usr/include/umdk)
include_directories(/usr/include/ub/umdk/urma)
include_directories(/usr/include/umdk/umq)
include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/connection_setup_tool)
include_directories(${CMAKE_SOURCE_DIR}/../../include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../include/umq)

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} UMQ_EXAMPLE_DIR_SRCS)

add_executable(umq_example
    ${UMQ_EXAMPLE_DIR_SRCS})

set_property(TARGET umq_example PROPERTY C_STANDARD 11)
target_link_libraries(umq_example umq umq_buf)
install(TARGETS umq_example DESTINATION /usr/bin)
install(DIRECTORY DESTINATION /usr/share/doc/umdk-examples/urpc_example/umq_example)
