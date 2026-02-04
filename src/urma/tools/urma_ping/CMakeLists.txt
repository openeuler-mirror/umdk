# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

add_executable(urma_ping
    ping_log.c
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
        ${CMAKE_SOURCE_DIR}/urma/lib/uvs/core/include
)

target_link_libraries(urma_ping
    PRIVATE
        urma
        tpsa
)

install(TARGETS urma_ping
    DESTINATION /usr/bin
)
