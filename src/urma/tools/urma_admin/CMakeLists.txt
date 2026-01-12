# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.

add_subdirectory(config)

add_executable(urma_admin
    admin_cmd.c
    admin_file_ops.c
    admin_log.c
    admin_netlink.c
    admin_parameters.c
    admin.c
)

set_target_properties(urma_admin
    PROPERTIES
        C_STANDARD 99
)

target_include_directories(urma_admin
    PRIVATE
        ${CMAKE_SOURCE_DIR}/urma/lib/urma/core/include
        ${CMAKE_SOURCE_DIR}/urma/common/include
        /usr/include/libnl3
)

target_link_libraries(urma_admin
    PRIVATE
        nl-genl-3 nl-3
)

install(TARGETS urma_admin
    DESTINATION /usr/bin
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/config/urma_admin.conf
    DESTINATION /etc/rsyslog.d/
    PERMISSIONS OWNER_WRITE OWNER_READ
)
