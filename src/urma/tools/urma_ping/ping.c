/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping entry file
 * Author: Wang Hang
 * Create: 2026-02-02
 * Note:
 * History: 2026-02-02 Create file
 */

#include <errno.h>
#include <libgen.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ping_log.h"
#include "ping_parameters.h"
#include "ping_run.h"

int main(int argc, char *argv[])
{
    ping_cfg_t cfg = {
        .argc = argc,
        .argv = argv,
        .filename = basename(argv[0]),
        .count = UINT32_MAX,
        .interval = 1,
        .size = 4,
        .verbose_level = VLOG_LEVEL_NORMAL,
        .deadline = 0,
        .timeout = 1,
    };

    int ret = 0;

    if ((ret = parse_args(&cfg)) != 0) {
        return EXIT_FAILURE;
    }

    if ((ret = check_args(&cfg)) != 0) {
        return EXIT_FAILURE;
    }

    if ((ret = start_ping(&cfg)) != 0) {
        return EXIT_FAILURE;
    }

    return 0;
}
