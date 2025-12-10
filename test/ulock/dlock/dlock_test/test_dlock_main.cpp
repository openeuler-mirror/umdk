/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: dlock unit test main function
 * Author: huying
 * Create: 2025-12-09
 * Note:
 * History:
 */
#include <getopt.h>
#include "gtest/gtest.h"
#include "utils.h"
#include "test_dlock_comm.h"

#define PRIMARY_ADDRESS "127.0.0.1"

struct test_dlock_cfg g_test_dlock_cfg = {0};

static int test_dlock_parse_args_and_init_cfg(int argc, char *argv[])
{
    int opt;
    char *eid_str = nullptr;

    g_test_dlock_cfg.log_level = LOG_WARNING;

    while ((opt = getopt(argc, argv, "i:e:d:g:")) != -1) {
        switch (opt) {
            case 'i':
                g_test_dlock_cfg.server_ip = strdup(optarg);
                break;
            case 'e':
                eid_str = strdup(optarg);
                break;
            case 'd':
                g_test_dlock_cfg.dev_name = strdup(optarg);
                break;
            case 'g':
                g_test_dlock_cfg.log_level = atoi(optarg);
                break;
            default:
                printf("Usage: %s [-i <server_ip>] [-e <eid>] [-d <dev_name>] [-g <log_level>]\n", argv[0]);
                printf("Options: "
                    "-i <ip>          Server IP \n"
                    "-e <eid>         EID string \n"
                    "-d <dev_name>    UBEP device name \n"
                    "-g <log_level>   Log level\n");
                return -1;
        }
    }

    if (g_test_dlock_cfg.server_ip == nullptr) {
        g_test_dlock_cfg.server_ip = strdup(PRIMARY_ADDRESS);
    }

    if (eid_str != nullptr) {
        if (str_to_urma_eid(eid_str, &g_test_dlock_cfg.eid) != 0) {
            printf("Invalid eid: %s\n", eid_str);
            free(eid_str);
            return -1;
        }
        free(eid_str);
        eid_str = nullptr;
    }

    if ((g_test_dlock_cfg.log_level < LOG_EMERG) || (g_test_dlock_cfg.log_level > LOG_DEBUG)) {
        printf("Invalid log level: %d\n", g_test_dlock_cfg.log_level);
        return -1;
    }

    return 0;
}

static void test_dlock_cfg_deinit(void)
{
    if (g_test_dlock_cfg.server_ip != nullptr) {
        free(g_test_dlock_cfg.server_ip);
        g_test_dlock_cfg.server_ip = nullptr;
    }

    if (g_test_dlock_cfg.dev_name != nullptr) {
        free(g_test_dlock_cfg.dev_name);
        g_test_dlock_cfg.dev_name = nullptr;
    }
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);

    int ret = test_dlock_parse_args_and_init_cfg(argc, argv);
    if (ret != 0) {
        printf("Parsing test parameters and initialization failed.\n");
        test_dlock_cfg_deinit();
        return ret;
    }

    ret = RUN_ALL_TESTS();

    test_dlock_cfg_deinit();
    return ret;
}