/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: ubus_tools
 * Author: Qian Guoxin
 * Create: 2021-11-30
 * Note:
 * History: 2021-11-30   create file
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "admin_cmd.h"
#include "admin_file_ops.h"
#include "admin_log.h"
#include "admin_parameters.h"

#define MAX_CMDLINE_LEN 896 /* must less than MAX_LOG_LEN */
static int admin_check_cmd_len(int argc, char *argv[])
{
    uint32_t len = 0;
    for (int i = 0; i < argc; i++) {
        uint32_t tmp_len = (uint32_t)strnlen(argv[i], MAX_CMDLINE_LEN + 1);
        if (tmp_len == MAX_CMDLINE_LEN + 1) {
            URMA_ADMIN_LOG("user: %s, single args len out of range.\n", getlogin());
            return -1;
        }

        len += tmp_len;
    }
    if ((len > INT_MAX) || ((int)len + argc > MAX_CMDLINE_LEN)) {
        URMA_ADMIN_LOG("user: %s, cmd len out of range.\n", getlogin());
        return -1;
    }
    return 0;
}

static void admin_log_cmd(int argc, char *argv[], int ret)
{
    int i;
    char cmd[MAX_CMDLINE_LEN] = {0};
    for (i = 0; i < argc; i++) {
        (void)strcat(cmd, argv[i]);
        (void)strcat(cmd, " ");
    }
    URMA_ADMIN_LOG("user: %s, cmd: %s, ret:%d.\n", getlogin(), cmd, ret);
}

int main(int argc, char *argv[])
{
    if (admin_check_cmd_len(argc, argv) != 0) {
        printf("user: %s, cmd len out of range.\n", getlogin());
        return EXIT_FAILURE;
    }

    admin_config_t cfg = {
        .ue_idx = OWN_UE_IDX,
        .argc = argc,
        .argv = argv,
        .filename = argv[0],
    };

    int ret;

    if ((ret = admin_parse_args(&cfg)) != 0) {
        goto fail;
    }

    if ((ret = admin_cmd_main(&cfg)) != 0) {
        (void)printf("Failed to execute command.\n");
        URMA_ADMIN_LOG("Failed to execute command\n.");
        goto fail;
    }

    admin_log_cmd(argc, argv, ret);
    return EXIT_SUCCESS;

fail:
    admin_log_cmd(argc, argv, ret);
    return EXIT_FAILURE;
}
