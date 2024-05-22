/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: parse parameters for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "ub_util.h"
#include "urma_types.h"
#include "urma_types_str.h"
#include "tp_test_comm.h"
#include "tp_test_para.h"

static void usage(const char *argv0)
{
    (void)printf("Usage: %s [command options]\n", argv0);
    (void)printf("  %s   URMA tp test tool\n", argv0);
    (void)printf("Options:\n");
    (void)printf("  --test_type <type>      Specify test type, {lat|bw}.\n");
    (void)printf("  --dev_name <name>       The name of ubep device.\n");
    (void)printf("  --trans_mode <mode>     Transport mode: 0 for RM(default), 1 for RC, 2 for UM.\n");
    (void)printf("  --port <id>             Server port for bind or connect, default 21115.\n");

    (void)printf("\n  [Server Only]\n");
    (void)printf("  --client_num <num>      Number of client, must be set for server.\n");

    (void)printf("\n  [client Only]\n");
    (void)printf("  --server <ip>           Server ip for bind or connect, default: 127.0.0.1 .\n");
    (void)printf("  --thread_num <num>      Number of thread for client, default 1.\n");
    (void)printf("  --eid_num <num>         Number of eid for client, default 1.\n");
    (void)printf("  --ctxs_pre_eid <num>    Number of ctx created for each EID, default 1.\n");
    (void)printf("  --jettys_pre_ctx <num>  Number of jetty created for each ctx, default 1.\n");
    (void)printf("  --iters <iters>         Number of exchanges (at least 5, default 10000).\n");
}

static void init_cfg(tp_test_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    (void)memset(cfg, 0, sizeof(tp_test_config_t));

    cfg->type = TP_TEST_LAT;
    (void)memset(cfg->dev_name, 0, URMA_MAX_NAME);
    cfg->tp_mode = URMA_TM_RM;
    cfg->iters = TP_TEST_DEFAULT_ITERS;
    cfg->thread_num = 1;
    cfg->eid_num = 1;
    cfg->ctxs_pre_eid = 1;
    cfg->jettys_pre_ctx = 1;
    cfg->is_server = true;
    cfg->port = TP_TEST_DEF_PORT;
    ub_list_init(&cfg->server.client_list);
}

void print_cfg(const tp_test_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    (void)printf(TP_TEST_RESULT_LINE);
}

int parse_args(int argc, char *argv[], tp_test_config_t *cfg)
{
    uint32_t offset;

    init_cfg(cfg);
    static const struct option long_options[] = {
        {"test_type",        required_argument, NULL, TP_TEST_OPT_TYPE_NUM},
        {"dev_name",         required_argument, NULL, TP_TEST_OPT_DEV_NAME_NUM},
        {"trans_mode",       required_argument, NULL, TP_TEST_OPT_TP_MODE_NUM},
        {"iters",            required_argument, NULL, TP_TEST_OPT_ITERS_NUM},
        {"thread_num",       required_argument, NULL, TP_TEST_OPT_THREAD_NUM},
        {"server",           required_argument, NULL, TP_TEST_OPT_SERVER_IP_NUM},
        {"port",             required_argument, NULL, TP_TEST_OPT_SERVER_PORT_NUM},
        {"client_num",       required_argument, NULL, TP_TEST_OPT_CLIENT_NUM},
        {"eid_num",          required_argument, NULL, TP_TEST_OPT_EID_NUM},
        {"ctxs_pre_eid",     required_argument, NULL, TP_TEST_OPT_CTXS_PRE_EID},
        {"jettys_pre_ctx",   required_argument, NULL, TP_TEST_OPT_JETTYS_PRE_CTX},
        {NULL,               no_argument,       NULL, '\0'}
    };

    /* Second parse the options */
    while (1) {
        int c = getopt_long(argc, argv, "+", long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case TP_TEST_OPT_TYPE_NUM:
                if (strcmp("bw", optarg) == 0) {
                    cfg->type = TP_TEST_BW;
                }
                break;
            case TP_TEST_OPT_DEV_NAME_NUM:
                (void)strncpy(cfg->dev_name, optarg, URMA_MAX_NAME - 1);
                break;
            case TP_TEST_OPT_TP_MODE_NUM:
                if (ub_str_to_u32(optarg, &offset) != 0) {
                    (void)fprintf(stderr, "Invalid trans_mode, it has been changed to URMA_TM_RM.\n");
                    cfg->tp_mode = URMA_TM_RM;
                } else {
                    cfg->tp_mode = (urma_transport_mode_t)(0x1U << offset);
                }
                break;
            case TP_TEST_OPT_ITERS_NUM:
                (void)ub_str_to_u64(optarg, &cfg->iters);
                break;
            case TP_TEST_OPT_THREAD_NUM:
                (void)ub_str_to_u32(optarg, &cfg->thread_num);
                break;
            case TP_TEST_OPT_SERVER_IP_NUM:
                cfg->server_ip = strdup(optarg);
                if (cfg->server_ip == NULL) {
                    (void)fprintf(stderr, "failed to allocate server ip memory.\n");
                    return -1;
                }
                cfg->is_server = false;
                break;
            case TP_TEST_OPT_SERVER_PORT_NUM:
                (void)ub_str_to_u16(optarg, &cfg->port);
                break;
            case TP_TEST_OPT_CLIENT_NUM:
                (void)ub_str_to_u32(optarg, &cfg->client_num);
                break;
            case TP_TEST_OPT_EID_NUM:
                (void)ub_str_to_u32(optarg, &cfg->eid_num);
                break;
            case TP_TEST_OPT_CTXS_PRE_EID:
                (void)ub_str_to_u32(optarg, &cfg->ctxs_pre_eid);
                break;
            case TP_TEST_OPT_JETTYS_PRE_CTX:
                (void)ub_str_to_u32(optarg, &cfg->jettys_pre_ctx);
                break;
            default:
                usage(argv[0]);
                return -1;
        }
    }
    return 0;
}

void destroy_cfg(tp_test_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    if (cfg->server_ip != NULL) {
        free(cfg->server_ip);
        cfg->server_ip = NULL;
    }
    return;
}

int check_local_cfg(tp_test_config_t *cfg)
{
    if (cfg == NULL) {
        return -1;
    }

    if (strlen(cfg->dev_name) == 0 || strnlen(cfg->dev_name, URMA_MAX_NAME) >= URMA_MAX_NAME) {
        (void)fprintf(stderr, "No device specified, name: %s.\n", cfg->dev_name);
        return -1;
    }
    if ((cfg->eid_num * cfg->ctxs_pre_eid) % cfg->thread_num != 0) {
        (void)fprintf(stderr, "Sum of ctx[%u * %u] must be a multiple of thread_num[%u].\n",
            cfg->eid_num, cfg->ctxs_pre_eid, cfg->thread_num);
        return -1;
    }

    return 0;
}

int check_remote_cfg(tp_test_config_t *cfg)
{
    return 0;
}