/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib perftest param process
 * Create: 2024-3-6
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "urpc_lib_perftest_util.h"

#include "urpc_lib_perftest_param.h"

#define DEFAULT_PORT 19875
#define MAX_SGE_LENGTH 65536

// clang-format off
static struct option g_long_options[] = {
    {"dev", required_argument, NULL, 'd'},
    {"test-case", required_argument, NULL, 'c'},
    {"unix-file-path", required_argument, NULL, 'f'},
    {"port", required_argument, NULL, 'p'},
    {"local-ip", required_argument, NULL, 'l'},
    {"remote-ip", required_argument, NULL, 'r'},
    {"thread-num", required_argument, NULL, 'n'},
    {"target-queue", required_argument, NULL, 't'},
    {"size", required_argument, NULL, 's'},
    {"cpu_core", required_argument, NULL, 'u'},
    {"func-period", no_argument, NULL, 'P'},
    {"help", no_argument, NULL, 'h'},
    /* Long options only */
    {"alloc-buf", no_argument, NULL, 'A'},
    {"server", no_argument, NULL, 'S'},
    {"client", no_argument, NULL, 'C'},
    {"hw-offload", no_argument, NULL, 'H'},
    {"show-thread-qps", no_argument, NULL, 'Q'},
    {"trans-mode", required_argument, NULL, 'T'},
    {"rx-depth", required_argument, NULL, 'R'},
    {"tx-depth", required_argument, NULL, 'U'},
    {"use-one-queue", no_argument, NULL, 'V'},
    {"disorder", no_argument, NULL, 'D'},
    {"align", no_argument, NULL, 'L'},
    {"is_ipv6_dev", no_argument, NULL, 'B'},
    {"concurrent-num", required_argument, NULL, 'W'},
    {"data-trans-mode", required_argument, NULL, 'E'},

    {NULL, 0, NULL, 0}
};
// clang-format on

static void usage(void)
{
    (void)printf("Usage:\n");
    (void)printf("  -d, --dev-name <dev>                device name <dev>\n");
    (void)printf("  -c, --test-case <case index>        test case to be performed(default: 0)\n");
    (void)printf("                                      0: test urpc latency(default)\n");
    (void)printf("                                      1: test urpc qps\n");
    (void)printf("      --server                        to launch server.\n");
    (void)printf("      --client                        to launch client.\n");
    (void)printf("      --hw-offload                    set URPC_FEATURE_HWUB_OFFLOAD, default not set\n");
    (void)printf("      --show-thread-qps               show all worker thread qps, effective in qps test\n");
    (void)printf("      --tx-depth                      set queue tx-depth(default 512).\n");
    (void)printf("      --rx-depth                      set queue rx-depth(default 512).\n");
    (void)printf("      --trans-mode                    set urpc_trans_mode.\n");
    (void)printf("      --use-one-queue                 use one queue in latency test(default 2 queues).\n");
    (void)printf("      --alloc-buf                     don't reuse allocator buffer in latency test(allocator only "
                 "                                      has one sge in latency test by default).\n");
    (void)printf("      --align                         memory address align to 4K.\n");
    (void)printf("      --is_ipv6_dev                   use ipv6 dev for data plane.\n");
    (void)printf("      --concurrent-num <num>          concurrent num for wqe in one time, should go with --alloc-buf,"
                 "                                      and size larger than 105.\n");
    (void)printf("      --data-trans-mode <num>         urpc data trans mode, 0 for send(default), "
                 "                                      2 for read(only support one queue, not support concurrent).\n");
    (void)printf("      --disorder                      use disorder queue.\n");
    (void)printf("  -p, --port <port>                   listen on/connect to server's port <port>, server and client "
                 "may use <port+1> to sync and client may use <port-1> in latency test case (default: 19875)\n");
    (void)printf("  -f, --unix-file-path <path>         unix-file-path for dfx\n");
    (void)printf("  -l, --local-ip <ip-address>         local ip address\n");
    (void)printf("  -r, --remote-ip <ip-address>        remote ip address\n");
    (void)printf("  -n, --thread-num <thread-num>       number of process threads\n");
    (void)printf("  -s, --size <size1,size2...>         size of request, support most 32 sizes, each size should not "
                 "                                      more than 8192, and will provide in order of input\n");
    (void)printf("  -t, --target-queue <target-queue>   target-queue index of remote for client to send request to\n");
    (void)printf("  -u, --cpu_core <cpu_core>           from which cpu core to set affinity for each thread\n");
    (void)printf("  -P, --func-period <func-period>     time for simulating the server to execute handler.\n");
    (void)printf("      --soft                          enable soft feature.\n");
    (void)printf("  -h, --help                          show help info.\n\n");
}

static void init_cfg(perftest_framework_config_t *cfg)
{
    memset(cfg, 0, sizeof(perftest_framework_config_t));
    cfg->tcp_port = DEFAULT_PORT;
    cfg->case_type = PERFTEST_CASE_LAT;
    cfg->thread_num = 1;
    cfg->cpu_affinity = UINT32_MAX;
    cfg->size[0] = DEFAULT_REQUEST_SIZE64;
    cfg->size_len = 1;
    cfg->tx_depth = DEFAULT_TX_DEPTH;
    cfg->rx_depth = DEFAULT_RX_DEPTH;
    cfg->align = false;
    cfg->is_ipv6_dev = false;
    cfg->con_num = 1;
    cfg->data_trans_mode = 0;
    cfg->instance_mode = NONE;
}

static int cfg_check(perftest_framework_config_t *cfg)
{
    if (cfg->case_type == PERFTEST_CASE_QPS && cfg->alloc_buf == false) {
        LOG_PRINT("qps test don't support alloc-buf as false\n");
        cfg->alloc_buf = true;
        return 0;
    }

    return 0;
}

static uint32_t cfg_size_get(uint32_t *size, uint32_t *total, char *data)
{
    char *save;
    char *new_data = strtok_r(data, ",", &save);
    uint32_t i = 0;
    uint32_t count = 0;
    while ((i < MAX_SGE_SIZE) && (new_data != NULL)) {
        size[i] = (uint32_t)strtoul(new_data, NULL, 0);
        if (size[i] > MAX_SGE_LENGTH) {
            return 0;
        }
        count += size[i];
        new_data = strtok_r(NULL, ",", &save);
        i++;
    }
    *total = count;
    return i;
}

int urpc_perftest_parse_arguments(int argc, char **argv, perftest_framework_config_t *cfg)
{
    if (argc == 1) {
        usage();
        return -1;
    }

    init_cfg(cfg);

    while (1) {
        int long_option_index = -1;
        int c = getopt_long(argc, argv, "c:d:f:h:l:n:p:r:s:t:u:P:", g_long_options, &long_option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'd':
                strcpy(cfg->dev_name, optarg);
                break;
            case 'c':
                cfg->case_type = (uint32_t)strtoul(optarg, NULL, 0);
                if (cfg->case_type >= PERFTEST_CASE_MAX) {
                    LOG_PRINT("get case_type %d failed\n", (int)cfg->case_type);
                    return -1;
                }
                break;
            case 'f':
                strcpy(cfg->path, optarg);
                break;
            case 'p':
                cfg->tcp_port = (uint16_t)strtoul(optarg, NULL, 0);
                break;
            case 'l':
                strcpy(cfg->local_ip, optarg);
                break;
            case 'r':
                strcpy(cfg->remote_ip, optarg);
                break;
            case 'n':
                cfg->thread_num = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 's':
                cfg->size_len = cfg_size_get(cfg->size, &cfg->size_total, optarg);
                if (cfg->size_len == 0) {
                    LOG_PRINT("get size num:%u invalid\n", cfg->size_len);
                    return -1;
                }
                break;
            case 'h':
                usage();
                return -1;
            case 'S':
                cfg->instance_mode = cfg->instance_mode == NONE ? SERVER : cfg->instance_mode;
                break;
            case 'C':
                cfg->instance_mode = cfg->instance_mode == NONE ? CLIENT : cfg->instance_mode;
                break;
            case 'P':
                cfg->func_period = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'u':
                cfg->cpu_affinity = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 't':
                cfg->target_queue = (uint8_t)strtoul(optarg, NULL, 0);
                break;
            case 'H':
                cfg->hwub_offlad = true;
                break;
            case 'Q':
                cfg->show_thread_qps = true;
                break;
            case 'T':
                cfg->trans_mode = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'A':
                cfg->alloc_buf = true;
                break;
            case 'V':
                cfg->use_one_q = true;
                break;
            case 'U':
                cfg->tx_depth = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'R':
                cfg->rx_depth = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'L':
                cfg->align = true;
                break;
            case 'B':
                cfg->is_ipv6_dev = true;
                break;
            case 'W':
                cfg->con_num = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'E':
                cfg->data_trans_mode = (data_trans_mode_t)strtoul(optarg, NULL, 0);
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

    if (cfg_check(cfg) != 0) {
        return -1;
    }

    return 0;
}
