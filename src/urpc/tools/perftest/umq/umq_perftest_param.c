/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: umq lib perftest param process
 * Create: 2024-3-6
 */

#include <getopt.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "umq_perftest_param.h"

// clang-format off
static struct option g_long_options[] = {
    {"dev", required_argument, NULL, 'd'},
    {"test-case", required_argument, NULL, 'c'},
    {"port", required_argument, NULL, 'p'},
    {"local-ip", required_argument, NULL, 'l'},
    {"remote-ip", required_argument, NULL, 'r'},
    {"size", required_argument, NULL, 's'},
    {"cpu_core", required_argument, NULL, 'u'},
    {"feature", required_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    /* Long options only */
    {"server", no_argument, NULL, 'S'},
    {"client", no_argument, NULL, 'C'},
    {"trans-mode", required_argument, NULL, 'T'},
    {"rx-depth", required_argument, NULL, 'R'},
    {"tx-depth", required_argument, NULL, 'U'},

    {"buf-mode", required_argument, NULL, 'b'},
    {"interrupt", no_argument, NULL, 'I'},
    {"cna", required_argument, NULL, 'N'},
    {"deid", required_argument, NULL, 'D'},
    {"eid-index", required_argument, NULL, 'E'},
    {"use_atomic_window", no_argument, NULL, 'A'},
    {"buf_multiplex", no_argument, NULL, 'B'},
    {"num", required_argument, NULL, 'n'},
    {"perf-thresh", required_argument, NULL, 't'},
    {NULL, 0, NULL, 0}
};
// clang-format on

static void usage(void)
{
    (void)printf("Usage:\n");
    (void)printf("  -d, --dev-name <dev>                device name <dev>\n");
    (void)printf("  -l, --local-ip <ip-address>         local ip address\n");
    (void)printf("  -r, --remote-ip <ip-address>        remote ip address\n");
    (void)printf("  -p, --port <port>                   listen on/connect to server's port <port>");
    (void)printf("  -c, --test-case <case index>        test case to be performed(default: 0)\n");
    (void)printf("                                      0: test umq latency(default)\n");
    (void)printf("                                      1: test umq qps\n");
    (void)printf("  -u, --cpu-core <cpu_core>           from which cpu core to set affinity for each thread\n");
    (void)printf("      --server                        to launch server.\n");
    (void)printf("      --client                        to launch client.\n");

    (void)printf("      --buf-mode                      set umq_buf_mode_t.\n");
    (void)printf("  -f, --feature <feature>             umq feature, 0 for base api, 1 for pro api\n");
    (void)printf("      --interrupt                     set interrupt mode.\n");
    (void)printf("      --cna                           set cna for ubmm mode.\n");
    (void)printf("      --deid                          set deid for ubmm mode.\n");
    (void)printf("  -s, --size <size>                   size of request, not more than 8192\n");
    (void)printf("      --trans-mode                    set umq_trans_mode_t.\n");
    (void)printf("      --tx-depth                      set queue tx-depth(default 512).\n");
    (void)printf("      --rx-depth                      set queue rx-depth(default 512).\n");
    (void)printf("      --eid-index                     set eid index.\n");
    (void)printf("      --use_atomic_window             use atomic window when enable flow control.\n");
    (void)printf("      --num                           set number of iterations.\n");
    (void)printf("      --perf-thresh                   set perf thresh array, length not exceed 8.\n");
    (void)printf("  -h, --help                          show help info.\n\n");
}

static void init_cfg(umq_perftest_config_t *cfg)
{
    perftest_config_t *config = &cfg->config;

    config->tcp_port = DEFAULT_LISTEN_PORT;
    config->case_type = PERFTEST_CASE_LAT;
    config->cpu_affinity = UINT32_MAX;
    config->size = DEFAULT_REQUEST_SIZE_4K;
    config->tx_depth = DEFAULT_DEPTH;
    config->rx_depth = DEFAULT_DEPTH;
    config->interrupt = false;
    config->buf_multiplex = false;

    cfg->buf_mode = UMQ_BUF_SPLIT;
    cfg->trans_mode = UMQ_TRANS_MODE_IB;
    cfg->eid_idx = 0;
    cfg->use_atomic_window = false;
    cfg->test_round = DEFAULT_LAT_TEST_ROUND;
    cfg->thresh_num = 0;
}

int umq_perftest_parse_arguments(int argc, char **argv, umq_perftest_config_t *cfg)
{
    if (argc == 1) {
        usage();
        return -1;
    }

    init_cfg(cfg);
    int start_idx = 0;
    while (1) {
        int c = getopt_long(argc, argv, "c:d:f:l:r:p:u:s:hN:D:E:n:", g_long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'd':
                memcpy(cfg->config.dev_name, optarg, strlen(optarg));
                break;
            case 'c':
                cfg->config.case_type = (uint32_t)strtoul(optarg, NULL, 0);
                if (cfg->config.case_type >= PERFTEST_CASE_MAX) {
                    LOG_PRINT("get case_type %d failed\n", (int)cfg->config.case_type);
                    return -1;
                }
                break;
            case 'f':
                cfg->feature = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'p':
                cfg->config.tcp_port = (uint16_t)strtoul(optarg, NULL, 0);
                break;
            case 'l':
                memcpy(cfg->config.local_ip, optarg, strlen(optarg));
                break;
            case 'r':
                memcpy(cfg->config.remote_ip, optarg, strlen(optarg));
                break;
            case 's':
                cfg->config.size = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'h':
                usage();
                return -1;
            case 'S':
                cfg->config.instance_mode = cfg->config.instance_mode == PERF_INSTANCE_NONE ?
                    PERF_INSTANCE_SERVER : cfg->config.instance_mode;
                break;
            case 'C':
                cfg->config.instance_mode = cfg->config.instance_mode == PERF_INSTANCE_NONE ?
                    PERF_INSTANCE_CLIENT : cfg->config.instance_mode;
                break;
            case 'u':
                cfg->config.cpu_affinity = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'T':
                cfg->trans_mode = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'U':
                cfg->config.tx_depth = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'R':
                cfg->config.rx_depth = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'b':
                cfg->buf_mode = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'I':
                cfg->config.interrupt = true;
                break;
            case 'A':
                cfg->use_atomic_window = true;
                break;
            case 'B':
                cfg->config.buf_multiplex = true;
                break;
            case 'N':
                cfg->cna = (uint16_t)strtoul(optarg, NULL, 0);
                break;
            case 'D':
                cfg->deid = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'E':
                cfg->eid_idx = (uint16_t)strtoul(optarg, NULL, 0);
                break;
            case 'n':
                cfg->test_round = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 't':
                start_idx = optind - 1;
                while (start_idx < argc && *argv[start_idx] != '-' && cfg->thresh_num < UMQ_PERF_QUANTILE_MAX_NUM) {
                    cfg->thresh_array[cfg->thresh_num++] = (uint64_t)strtoul(argv[start_idx++], NULL, 0);
                }
                optind = start_idx;
                break;
            default:
                usage();
                return -1;
        }
    }

    if (optind < argc) {
        usage();
        return -1;
    }

    return 0;
}
