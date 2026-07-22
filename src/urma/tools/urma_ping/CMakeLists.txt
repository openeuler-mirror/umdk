# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

add_executable(urma_ping
    ping_log.c
    ping_netlink.c
    ping_parameters.c
    ping_run.c
    ping_stat.c
    ping.c
)

set_target_properties(urma_ping
    PROPERTIES
        C_STANDARD 99
)

target_include_directories(urma_ping
    PRIVATE
        /usr/include/libnl3
)

target_link_libraries(urma_ping
    PRIVATE
        urma
        nl-genl-3 nl-3
        m
)

install(TARGETS urma_ping
    DESTINATION /usr/bin
)
