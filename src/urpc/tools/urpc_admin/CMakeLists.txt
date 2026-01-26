# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../include/framework)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../util)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../framework/core/queue)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../framework/core/channel)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../framework/lib/control/dfx)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../framework/lib/control/crypto)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../framework/lib/control/unix_server)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../framework/lib/control/)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../framework/lib/control/ip)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../framework/lib/manager/)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../framework/protocol)

include(cmds/CMakeLists.txt)

add_subdirectory(cmds)

add_executable(urpc_admin
    $<TARGET_OBJECTS:common_util>
    urpc_admin_cmd.c
    urpc_admin_param.c
    urpc_admin.c
    ${URPC_ADMIN_CMD_SRC}
)

set_property(TARGET urpc_admin PROPERTY C_STANDARD 11)
target_link_libraries(urpc_admin urpc common_util pthread m)
install(TARGETS urpc_admin DESTINATION /usr/bin)

if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake"
        IMMEDIATE @ONLY
    )

    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/../../cmake_uninstall.cmake)
endif()