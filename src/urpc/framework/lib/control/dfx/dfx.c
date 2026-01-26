/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc dfx management
 * Create: 2024-4-24
 */

#include "channel_info.h"
#include "dbuf.h"
#include "handshaker_info.h"
#include "perf.h"
#include "queue_info.h"
#include "stats.h"
#include "version.h"

#include "dfx.h"

int urpc_dfx_init(void)
{
    if (version_cmd_init() != 0) {
        return -1;
    }

    if (stats_cmd_init() != 0) {
        goto VERSION_UNSET;
    }

    if (queue_info_cmd_init() != 0) {
        goto STATS_UNSET;
    }

    if (urpc_perf_cmd_init() != 0) {
        goto QUEUE_UNSET;
    }

    if (dbuf_cmd_init() != 0) {
        goto PERF_UNSET;
    }

    if (channel_info_cmd_init() != 0) {
        goto DBUF_UNINIT;
    }

    if (handshaker_cmd_init() != 0) {
        goto CHANNEL_UNINIT;
    }
    return 0;

CHANNEL_UNINIT:
    channel_info_cmd_uninit();
DBUF_UNINIT:
    dbuf_cmd_uninit();
PERF_UNSET:
    urpc_perf_cmd_uninit();
QUEUE_UNSET:
    queue_info_cmd_uninit();
STATS_UNSET:
    stats_cmd_uninit();
VERSION_UNSET:
    version_cmd_uninit();
    return -1;
}

void urpc_dfx_uninit(void)
{
    channel_info_cmd_uninit();
    dbuf_cmd_uninit();
    urpc_perf_cmd_uninit();
    queue_info_cmd_uninit();
    stats_cmd_uninit();
    version_cmd_uninit();
}
