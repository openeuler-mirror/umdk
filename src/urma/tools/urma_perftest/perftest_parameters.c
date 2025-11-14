/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
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
#include <linux/limits.h>

#include "ub_util.h"
#include "ub_get_clock.h"
#include "urma_types.h"
#include "urma_types_str.h"
#include "perftest_communication.h"
#include "perftest_parameters.h"
#define PERFTEST_CACHE_LINE_FILE_SIZE (10)
#define PERFTEST_JFC_MUL_THRESHOLD (4)
#define PERFTEST_DEFAULT_DURATION (5)

typedef struct perftest_cmd {
    char *cmd;
    perftest_cmd_type_t type;
} perftest_cmd_t;

static const char *g_atomic_types_str[] = {
    [PERFTEST_CAS] =           "cas",
    [PERFTEST_FAA] =           "faa"
};
static const char *g_print_test_str[] = {
    [PERFTEST_READ] =          "URMA_READ",
    [PERFTEST_WRITE] =         "URMA_WRITE",
    [PERFTEST_SEND] =          "URMA_SEND",
    [PERFTEST_ATOMIC] =        "URMA_ATOMIC"
};
static const char *g_trans_mode_str[] = {
    [URMA_TM_RM] =     "URMA_TM_RM",
    [URMA_TM_RC] =     "URMA_TM_RC",
    [URMA_TM_UM] =     "URMA_TM_UM"
};
static const char *g_jetty_mode_str[] = {
    [PERFTEST_JETTY_SIMPLEX] = "SIMPLEX",
    [PERFTEST_JETTY_DUPLEX] =  "DUPLEX"
};

#define PERFTEST_BOOL_TO_STR(val)    ((val) == true ? "true" : "false")

static const perftest_cmd_t g_cmd[] = {
    { "read_lat",          PERFTEST_READ_LAT },
    { "write_lat",         PERFTEST_WRITE_LAT },
    { "send_lat",          PERFTEST_SEND_LAT },
    { "atomic_lat",        PERFTEST_ATOMIC_LAT },
    { "read_bw",           PERFTEST_READ_BW },
    { "write_bw",          PERFTEST_WRITE_BW },
    { "send_bw",           PERFTEST_SEND_BW },
    { "atomic_bw",         PERFTEST_ATOMIC_BW }
};

static void command_usage(const char *argv0)
{
    (void)printf("Usage: %s command [command options]\n", argv0);
    (void)printf("  %s   URMA perftest tool\n", argv0);
    (void)printf("Command syntax:\n");
    (void)printf("  read_lat                    Test for read latency.\n");
    (void)printf("  write_lat                   Test for write latency.\n");
    (void)printf("  send_lat                    Test for send latency.\n");
    (void)printf("  atomic_lat                  Test for atomic latency.\n");
    (void)printf("  read_bw                     Test for read bandwidth.\n");
    (void)printf("  write_bw                    Test for write bandwidth.\n");
    (void)printf("  send_bw                     Test for send bandwidth.\n");
    (void)printf("  atomic_bw                   Test for atomic bandwidth.\n");
}

static void usage(const char *argv0)
{
    command_usage(argv0);
    (void)printf("Options:\n");
    (void)printf("  -a, --all[order]            Run sizes from 2 till 2^23 (default 2^16), order: exponent of 2.\n");
    (void)printf("  -A, --atomic_type <type>    Specify atomic type, {cas|faa}.\n");
    (void)printf("  -b, --simplex_mode          Run with simplex mode(jfs/jfr), duplex jetty mode for reserved.\n");
    (void)printf("  -B, --bidirection           Measure bidirectional bandwidth (default unidirectional).\n");
    (void)printf("  -c, --jfc_inline            Enable jfc_inline to upgrade latency performance.\n");
    (void)printf("  -C, --jfc_depth <dep>       Size of jfc depth (default 4096 for bw, 1024 for ip bw, 1 for lat.\n");
    (void)printf("  -d, --dev <dev_name>        The name of ubep device.\n");
    (void)printf("  -D, --duration <second>     Run test for a customized period of seconds, this cfg covers iters.\n");
    (void)printf("  -e, --use_jfce              use jfc event.\n");
    (void)printf("  --eid_idx                   Specified eid index of device.\n");
    (void)printf("  -E, --err_timeout <time>    the timeout before report error, ranging from [0, 31],\n"
                 "                              the actual timeout in usec is caculated by: 4.096*(2^err_timeout).\n");
    (void)printf("  -f, --use_flat_api          Choose to use flat API, only works in SIMPLEX mode.\n");
    (void)printf("  -F, --cpu_freq_f            To report warnings when CPU frequency drifts, default as NOT.\n");
    (void)printf("  -h, --help                  Show help info.\n");
    (void)printf("  -I, --inline_size <size>    Max size of message to be sent in inline.\n");
    (void)printf("  -j, --share_jfr <true/false> share jfr on create jetty.\n");
    (void)printf("  -J, --jettys <num of jetty> Num of jettys(default 1).\n");
    (void)printf("  -K, --token_policy <policy> default 0: NONE, 1: PLAIN_TEXT, 2: SIGNED, 3: ALL_ENCRYPTED.\n");
    (void)printf("  -n, --iters <iters>         Number of exchanges (at least 5, default 10000).\n");
    (void)printf("  -N, --no_peak               Cancel peak-bw calculation.\n");
    (void)printf("  -l, --jfs_post_list <size>  Post list of send WQEs of <list size> size.\n");
    (void)printf("  -L, --lock_free             Jetty's interior is unlocked.\n");
    (void)printf("  -O, --priority              set the priority of JFS, ranging from [0, 15].\n");
    (void)printf("  -p, --trans_mode <mode>     Transport mode: 0 for RM(default), 1 for RC, 2 for UM.\n");
    (void)printf("  -P, --port <id>             Server port for bind or connect, default 21115.\n");
    (void)printf("  -Q, --cq_mod <num>          Generate Cqe only after <--cq_mod> completion.\n");
    (void)printf("  -r, --jfr_post_list <size>  Post list of receive WQEs of <list size> size.\n");
    (void)printf("  -R, --jfr_depth <dep>       Size of jfr depth (default 512 for BW, 1 for LAT).\n");
    (void)printf("  -s, --size <size>           Size of message to exchange (default 2).\n");
    (void)printf("  -S, --server <ip>           Server ip for bind or connect, default: 127.0.0.1 .\n");
    (void)printf("  -T, --jfs_depth <dep>       Size of jfs depth (default 128 for BW, 1 for LAT).\n");
    (void)printf("  -w, --warm_up               Choose to use warm_up function, only for read/write/atomic bw test.\n");
    (void)printf("  -y, --infinite[second]      Run perftest infinitely, only available for BW test.\n"
                 "                              Print period for infinite mode, default 2 seconds.\n");
    (void)printf("  --single_path,              Bonding device works in single path mode.\n");
    (void)printf("  --inf_period_ms             Print period (ms) for infinite mode. Must be a multiple of 50.\
                                                if set, value of infinite will be overwrite.\n");
    (void)printf("  --rate_limit <rate>         Set the maximum rate of sent packages. default unit is [Gbps].\n");
    (void)printf("  --rate_units <units>        Set the units for rate, MBps (M), Gbps (G)(default) or Kpps (P).\n");
    (void)printf("  --burst_size <size>         Set the amount of pkts to send in a burst when using rate limiter.\n");
    (void)printf("  --sub_trans_mode <sub_mode>     Sub transport mode: 0 for non ordering(default),\
                    1 for TA dest ordering (only valid for trans_mode RC).\n");
    (void)printf("  --enable_ipv6               enable ipv6 for server ip. default disable.\n");
    (void)printf("  --enable_credit             enable send credit, default: disable.\n");
    (void)printf("  --credit_threshold <num>    Exceed the threshold and do not send, default: jfr_depth * 3 / 4.\n");
    (void)printf("  --credit_notify_cnt <num>   Notify the send side after recv packets, default: jfr_depth / 4.\n");
    (void)printf("  --jettys_pre_jfr <num>      How many jettys share a jfr, default: jettys.\n");
    (void)printf("  --seg_pre_jetty             Enable a segment for each Jetty, default: disable.\n");
    (void)printf("  --enable_imm                Enable immediate data for write or send, default: disable.\n");
    (void)printf("  --enable_err_continue       Enable continue running when cr erros, default: disable.\n");
    (void)printf("  --notify_data <value>       enable write_with_notify, value is ensured by hardware.\n");
    (void)printf("  --enable_user_tp            Enable user tp for UB device, if enable,UVS is not required. \
default: disable.\n");
    (void)printf("  --oor_en                    Enable out of order for user_tp, default: disable.\n");
    (void)printf("  --spray_en                  Enable multipathing for user_tp, default: disable.\n");
    (void)printf("  --cc_en                     Enable congestion control for user_tp, default: disable.\n");
    (void)printf("  --cc_alg <num>              Set congestion Control Algorithm for user_tp, [0, 7], default: 0.\n");
    (void)printf("  --retry_num  <num>          Set retry num for user_tp, default: 7.\n");
    (void)printf("  --ack_timeout <num>         Set ack timeout for user_tp, default: 15.\n");
    (void)printf("  --sge_num <num>             Set sge_num for wr, default: 1.\n");
    (void)printf("  --enable_write_dirty <time> Enable write dirty and set the period of write dirty, \
default: disable.\n");
    (void)printf("  --pair_num <num>            Enable multiplayer model and set the number of connection, \
default: disable.\n");
    (void)printf("  --async_import              Enable asynchronous connection establishment\n");
    (void)printf("  --tp_aware                  Enable tp aware connect, default: disable.\n");
    (void)printf("  --tp_reuse                  Reuse tp in RM mode if enable tp aware, default: disable.\n");
    (void)printf("  --ctp                       Use ctp, default: disable.\n");
    (void)printf("  --jetty_id                  Set the jetty_id, default: 0.\n");
    (void)printf("  --wait_jfc_timeout          Set timeout parameter for urma_wait_jfc (in milliseconds),\n\
                                                timeout = 0: return immediately even if no events are ready,\n\
                                                timeout = -1: an infinite timeout,\n\
                                                default: 1000(1s).\n");
}

static perftest_cmd_type_t parse_command(const char *argv1)
{
    for (int i = 0; i < (int)PERFTEST_CMD_NUM; i++) {
        if (strlen(argv1) != strlen(g_cmd[i].cmd)) {
            continue;
        }
        if (strcmp(argv1, g_cmd[i].cmd) == 0) {
            return g_cmd[i].type;
        }
    }

    return PERFTEST_CMD_NUM;
}

static void init_cfg_api_type(perftest_config_t *cfg)
{
    switch (cfg->cmd) {
        case PERFTEST_READ_LAT:
        case PERFTEST_READ_BW:
            cfg->api_type = PERFTEST_READ;
            break;
        case PERFTEST_WRITE_LAT:
        case PERFTEST_WRITE_BW:
            cfg->api_type = PERFTEST_WRITE;
            break;
        case PERFTEST_SEND_LAT:
        case PERFTEST_SEND_BW:
            cfg->api_type = PERFTEST_SEND;
            break;
        case PERFTEST_ATOMIC_LAT:
        case PERFTEST_ATOMIC_BW:
            cfg->api_type = PERFTEST_ATOMIC;
            break;
        default:
            exit(1);
    }
}

static inline void init_cfg_size(perftest_config_t *cfg)
{
    if (cfg->api_type == PERFTEST_ATOMIC) {
        cfg->size = PERFTEST_DEF_ATOMIC_SIZE;
        return;
    }
    cfg->size = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_SIZE_BW : PERFTEST_DEF_SIZE_LAT;
}

static int get_cache_line_size(void)
{
    int size = 0;

    size = (int)sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    if (size == 0) {
        const char *file = "/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size";
        FILE *f;
        char file_line[PERFTEST_CACHE_LINE_FILE_SIZE] = {0};
        f = fopen(file, "r");
        if (f == NULL) {
            return PERFTEST_DEF_CACHE_LINE_SIZE;
        }

        if (fgets(file_line, PERFTEST_CACHE_LINE_FILE_SIZE, f) != NULL) {
            size = atoi(file_line);
        }
        (void)fclose(f);
    }

    if (size <= 0) {
        size = PERFTEST_DEF_CACHE_LINE_SIZE;
    }

    return size;
}

static void init_cfg(perftest_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    cfg->type = cfg->cmd > PERFTEST_ATOMIC_LAT ? PERFTEST_BW : PERFTEST_LAT;
    init_cfg_api_type(cfg);
    cfg->eid_idx = 0;
    cfg->all = false;
    cfg->atomic_type = PERFTEST_CAS;
    cfg->jfc_depth = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_JFC_DEPTH_BW : PERFTEST_DEF_JFC_DEPTH_LAT;
    (void)memset(cfg->dev_name, 0, URMA_MAX_NAME);
    cfg->duration = PERFTEST_DEFAULT_DURATION;
    cfg->use_jfce = false;
    cfg->time_type.value = 0;
    // Update to max value of the device attr after creation context
    cfg->inline_size = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_INLINE_BW : PERFTEST_DEF_INLINE_LAT;
    cfg->jettys = PERFTEST_DEF_NUM_JETTYS;
    cfg->token_policy = URMA_TOKEN_NONE;
    cfg->iters = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_ITERS_BW : PERFTEST_DEF_ITERS_LAT;
    cfg->no_peak = false;
    cfg->jfs_post_list = 1;
    cfg->jetty_mode = PERFTEST_JETTY_DUPLEX;
    cfg->cq_mod = PERFTEST_DEF_CQ_NUM;
    cfg->jfr_post_list = 1;
    cfg->jfr_depth = (cfg->api_type == PERFTEST_SEND || cfg->api_type == PERFTEST_WRITE) ?
        PERFTEST_DEF_JFR_DEPTH_SEND : PERFTEST_DEF_JFR_DEPTH_OTHER;

    init_cfg_size(cfg);

    cfg->comm.enable_ipv6 = false;
    cfg->comm.server_ip = NULL;
    cfg->comm.port = PERFTEST_DEF_PORT;
    cfg->comm.listen_fd = -1;
    cfg->comm.sock_fd = NULL;
    cfg->jfs_depth = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_JFS_DEPTH_BW : PERFTEST_DEF_JFS_DEPTH_LAT;
    cfg->trans_mode = URMA_TM_RM;

    cfg->cache_line_size = (uint32_t)get_cache_line_size();
    cfg->page_size = (uint64_t)(uint32_t)getpagesize();
    cfg->use_flat_api = false;
    cfg->cpu_freq_f = false;
    cfg->warm_up = false;
    cfg->bidirection = false;
    cfg->jfc_inline = false;
    cfg->inf_period = PERFTEST_DEF_INF_PERIOD;
    cfg->inf_period_ms = 0;
    cfg->order = PERFTEST_SIZE_ORDER;
    cfg->err_timeout = URMA_TYPICAL_ERR_TIMEOUT;
    cfg->lock_free = false;
    cfg->priority = URMA_MAX_PRIORITY;
    cfg->share_jfr = false;
    cfg->jettys_pre_jfr = 0;
    cfg->is_rate_limit = false;
    cfg->rate_limit = 0;
    cfg->burst_size = 0;
    cfg->rate_units = PERFTEST_RATE_LIMIT_GIGA_BIT;
    cfg->enable_credit = false;
    cfg->credit_notify_cnt = cfg->jfr_depth / PERFTEST_DEF_CREDIT_RATE;
    cfg->credit_threshold = cfg->jfr_depth - (cfg->jfr_depth / PERFTEST_DEF_CREDIT_RATE);

    cfg->seg_pre_jetty = false;
    cfg->enable_imm = false;
    cfg->enable_err_continue = false;
    cfg->enable_notify = false;
    cfg->notify_data = 0;
    cfg->enable_user_tp = false;
    cfg->oor_en = false;
    cfg->spray_en = false;
    cfg->cc_en = false;
    cfg->cc_alg = URMA_TP_CC_NONE;
    cfg->retry_num = PERFTEST_DEF_RETRY_NUM;
    cfg->ack_timeout = PERFTEST_DEF_ACK_TIMEOUT;
    cfg->sge_num = 1;
    cfg->pair_num = 1;

    cfg->enable_write_dirty = false;
    cfg->write_dirty_period = PERFTEST_WRITE_DIRTY_PERIOD;
    cfg->pair_flag = false;
    cfg->enable_async_import = false;
    cfg->tp_aware = false;
    cfg->tp_reuse = false;
    cfg->use_ctp = false;

    cfg->wait_jfc_timeout = PERFTEST_DEF_WAIT_JFC_TIME;
}

void print_cfg(const perftest_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    (void)printf(PERFTEST_RESULT_LINE);
    (void)printf("                    ");
    (void)printf("%s ", g_print_test_str[cfg->api_type]);
    if (cfg->api_type == PERFTEST_ATOMIC) {
        (void)printf("%s ", g_atomic_types_str[cfg->atomic_type]);
    }

    if (cfg->type == PERFTEST_BW) {
        if (cfg->bidirection) {
            (void)printf("Bidirectional ");
        }
        if (cfg->jfs_post_list > 1) {
            (void)printf("JFS Post List ");
        }
        (void)printf("BandWidth ");
    } else if (cfg->type == PERFTEST_LAT) {
        (void)printf("Latency ");
    }
    (void)printf("Test\n");

    if (cfg->use_jfce) {
        (void)printf(" Test with jfc events.\n");
    }

    (void)printf(" Number of jettys    : %-10u\t\t Transport mode   : %s\n", cfg->jettys,
        urma_tp_type_to_string(cfg->tp_type));
    (void)printf(" JFC depth           : %-10u\t\t Device name      : %s\n", cfg->jfc_depth, cfg->dev_name);
    (void)printf(" Trans mode          : %-10s\t\t JETTY mode       : %s\n", g_trans_mode_str[cfg->trans_mode],
        g_jetty_mode_str[cfg->jetty_mode]);
    if (cfg->comm.server_ip != NULL || cfg->bidirection) {
        (void)printf(" JFS depth           : %u\n", cfg->jfs_depth);
    }
    if (cfg->jfs_post_list > 1) {
        (void)printf(" JFS post list       : %u\n", cfg->jfs_post_list);
    }
    if (cfg->jfr_post_list > 1) {
        (void)printf(" JFR post list       : %u\n", cfg->jfr_post_list);
    }
    if (cfg->api_type == PERFTEST_SEND && (cfg->comm.server_ip == NULL || cfg->bidirection)) {
        (void)printf(" JFR depth           : %u\n", cfg->jfr_depth);
    }

    if (cfg->type == PERFTEST_BW) {
        (void)printf(" CQ Moderation       : %u\n", cfg->cq_mod);
    }

    if (cfg->api_type != PERFTEST_READ && cfg->api_type != PERFTEST_ATOMIC) {
        (void)printf(" Max inline size     : %u[B]\n", cfg->inline_size);
    }
    (void)printf(PERFTEST_RESULT_LINE);
}

static void parse_arge_atomic_type(perftest_config_t *cfg, char *opt)
{
    if (cfg->api_type != PERFTEST_ATOMIC) {
        (void)fprintf(stderr, "You are not running the atomic_lat/bw test!\n");
        exit(1);
    }

    if (strcmp(g_atomic_types_str[0], opt) == 0) {
        cfg->atomic_type = PERFTEST_CAS;
    } else if (strcmp(g_atomic_types_str[1], opt) == 0) {
        cfg->atomic_type = PERFTEST_FAA;
    } else {
        (void)fprintf(stderr, "Invalid Atomic type! please choose from {cas, faa}\n");
        exit(1);
    }
}

static inline int check_value_range(const perftest_value_range_t *value_range)
{
    if (value_range->value < (uint64_t)value_range->min ||
        value_range->value > (uint64_t)value_range->max) {
        (void)fprintf(stderr, "%s should be between %u and %u.\n", value_range->name,
            value_range->min, value_range->max);
        return -1;
    }
    return 0;
}

static int check_cfg_range(perftest_config_t *cfg)
{
    perftest_value_range_t value_range[] = {
        { cfg->iters,        PERFTEST_ITERS_MIN,         PERFTEST_ITERS_MAX,        "Iteration num" },
        { cfg->jfs_depth,    PERFTEST_JFS_DEPTH_MIN,     PERFTEST_JFS_DEPTH_MAX,    "Jfs depth" },
        { cfg->jettys,       PERFTEST_JETTYS_MIN,        PERFTEST_JETTYS_MAX,       "Jettys" },
        { cfg->inline_size,  PERFTEST_INLINE_MIN,        PERFTEST_INLINE_MAX,       "Inline size" },
        { cfg->jfr_depth,    PERFTEST_JFR_DEPTH_MIN,     PERFTEST_JFR_DEPTH_MAX,    "Jfr depth" },
        { cfg->cq_mod,       PERFTEST_CQ_MOD_MIN,        PERFTEST_CQ_MOD_MAX,       "Cq mod" },
        { cfg->order,        PERFTEST_MIN_ORDER,         PERFTEST_MAX_ORDER,        "Order" },
        { cfg->err_timeout,  PERFTEST_ERR_TIMEOUT_MIN,   PERFTEST_ERR_TIMEOUT_MAX,  "err_timeout" },
        { cfg->priority,     PERFTEST_PRIORITY_MIN,      PERFTEST_PRIORITY_MAX,     "priority" },
        { cfg->token_policy, URMA_TOKEN_NONE,            URMA_TOKEN_ALL_ENCRYPTED,  "token_policy" }
    };
    for (uint32_t i = 0; i < sizeof(value_range) / sizeof(perftest_value_range_t); i++) {
        if (check_value_range(&value_range[i]) != 0) {
            (void)fprintf(stderr, "Failed to check value, value: %lu, min: %u, max: %u, name: %s.\n",
                value_range[i].value, value_range[i].min, value_range[i].max, value_range[i].name);
            return -1;
        }
    }

    return 0;
}

int perftest_parse_args(int argc, char *argv[], perftest_config_t *cfg)
{
    uint32_t offset;
    if (argc == 1) {
        (void)printf("Input invalid with argc: %d.\n", argc);
        usage(argv[0]);
        return -1;
    }

    (void)memset(cfg, 0, sizeof(perftest_config_t));

    /* First parse the command */
    cfg->cmd = parse_command(argv[1]);
    if (cfg->cmd == PERFTEST_CMD_NUM) {
        (void)printf("Input command invalid with argv[1]: %s.\n", argv[1]);
        command_usage(argv[0]);
        return -1;
    }

    init_cfg(cfg);

    static const struct option long_options[] = {
        {"all",           optional_argument, NULL, 'a'},
        {"atomic_type",   required_argument, NULL, 'A'},
        {"simplex_mode",  no_argument,       NULL, 'b'},
        {"bidirection",   no_argument,       NULL, 'B'},
        {"jfc_inline",    no_argument,       NULL, 'c'},
        {"jfc_depth",     required_argument, NULL, 'C'},
        {"dev",           required_argument, NULL, 'd'},
        {"duration",      required_argument, NULL, 'D'},
        {"use_jfce",      no_argument,       NULL, 'e'},
        {"err_timeout",   required_argument, NULL, 'E'},
        {"use_flat_api",  no_argument,       NULL, 'f'},
        {"cpu_freq_f",    no_argument,       NULL, 'F'},
        {"help",          no_argument,       NULL, 'h'},
        {"inline_size",   required_argument, NULL, 'I'},
        {"share_jfr",     required_argument, NULL, 'j'},
        {"jettys",        required_argument, NULL, 'J'},
        {"token_policy",  required_argument, NULL, 'K'},
        {"iters",         required_argument, NULL, 'n'},
        {"no_peak",       no_argument,       NULL, 'N'},
        {"jfs_post_list", required_argument, NULL, 'l'},
        {"lock_free",     no_argument,       NULL, 'L'},
        {"priority",      required_argument, NULL, 'O'},
        {"trans_mode",    required_argument, NULL, 'p'},
        {"port",          required_argument, NULL, 'P'},
        {"cq_mod",        required_argument, NULL, 'Q'},
        {"jfr_post_list", required_argument, NULL, 'r'},
        {"jfr_depth",     required_argument, NULL, 'R'},
        {"size",          required_argument, NULL, 's'},
        {"server",        required_argument, NULL, 'S'},
        {"jfs_depth",     required_argument, NULL, 'T'},
        {"warm_up",       no_argument,       NULL, 'w'},
        {"infinite",      optional_argument, NULL, 'y'},
        {"use_bonding",   no_argument,       NULL, 'z'},
        {"single_path",   no_argument,       NULL, PERFTEST_OPT_SINGLE_PATH},
        {"eid_idx",       required_argument, NULL, PERFTEST_OPT_EID_IDX},
        {"rate_limit",    required_argument, NULL, PERFTEST_OPT_RATE_LIMIT},
        {"rate_units",    required_argument, NULL, PERFTEST_OPT_RATE_UNITS},
        {"burst_size",    required_argument, NULL, PERFTEST_OPT_BURST_SIZE},
        {"order_type",    required_argument, NULL, PERFTEST_OPT_ORDER_TYPE},
        {"enable_ipv6",    no_argument, NULL, PERFTEST_OPT_ENABLE_IPV6},
        {"enable_credit",    no_argument, NULL, PERFTEST_OPT_ENABLE_CREDIT},
        {"credit_threshold",    required_argument, NULL, PERFTEST_OPT_CREDIT_THRESHOLD},
        {"credit_notify_cnt",    required_argument, NULL, PERFTEST_OPT_CREDIT_NOTIFY_CNT},
        {"jettys_pre_jfr",    required_argument, NULL, PERFTEST_OPT_JETTYS_PRE_JFR},
        {"seg_pre_jetty", no_argument,       NULL, PERFTEST_OPT_SEG_PRE_JETTY},
        {"enable_imm",    no_argument,       NULL, PERFTEST_OPT_ENABLE_IMM},
        {"inf_period_ms", required_argument, NULL, PERFTEST_OPT_INF_PERIOD_MS},
        {"enable_err_continue", no_argument, NULL, PERFTEST_OPT_ENABLE_ERR_CONTINUE},
        {"notify_data",   required_argument, NULL, PERFTEST_OPT_NOTIFY_DATA},
        {"enable_user_tp", no_argument,      NULL, PERFTEST_OPT_ENABLE_USER_TP},
        {"oor_en",        no_argument,       NULL, PERFTEST_OPT_OOR_EN},
        {"spray_en",      no_argument,       NULL, PERFTEST_OPT_SPRAY_EN},
        {"cc_en",         no_argument,       NULL, PERFTEST_OPT_CC_EN},
        {"cc_alg",        required_argument, NULL, PERFTEST_OPT_CC_ALG},
        {"retry_num",     required_argument, NULL, PERFTEST_OPT_RETRY_NUM},
        {"ack_timeout",   required_argument, NULL, PERFTEST_OPT_ACK_TIMEOUT},
        {"sge_num",       required_argument, NULL, PERFTEST_OPT_SGE_NUM},
        {"enable_write_dirty", required_argument, NULL, PERFTEST_OPT_WRITE_DIRTY},
        {"pair_num",      required_argument, NULL, PERFTEST_OPT_PAIR_NUM},
        {"async_import",  no_argument,       NULL, PERFTEST_OPT_ASYNC_CONNECT},
        {"tp_aware",      no_argument,       NULL, PERFTEST_OPT_TP_AWARE},
        {"tp_reuse",      no_argument,       NULL, PERFTEST_OPT_TP_REUSE},
        {"ctp",           no_argument,       NULL, PERFTEST_OPT_CTP},
        {"jetty_id",      required_argument, NULL, PERFTEST_OPT_JETTY_ID },
        {"wait_jfc_timeout", required_argument, NULL, PERFTEST_OPT_WAIT_JFC_TIMEOUT },
        {NULL,            no_argument,       NULL, '\0'}
    };

    /* Second parse the options */
    while (1) {
        int c = getopt_long(argc, argv, "a::A:bBcC:d:t:D:eE:fFhI:j:J:K:n:Nl:Lo:O:p:P:Q:r:R:s:S:T:wy::z",
            long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'a':
                cfg->all = true;
                if (optarg != NULL) {
                    (void)ub_str_to_u32(optarg, &cfg->order);
                }
                break;
            case 'A':
                parse_arge_atomic_type(cfg, optarg);
                break;
            case 'b':
                cfg->jetty_mode = PERFTEST_JETTY_SIMPLEX;
                break;
            case 'B':
                cfg->bidirection = true;
                if (cfg->type == PERFTEST_LAT) {
                    (void)fprintf(stderr, "Bidirectional is only available in BW test.\n");
                    return -1;
                }
                break;
            case 'c':
                cfg->jfc_inline = true;
                break;
            case 'C':
                (void)ub_str_to_u32(optarg, &cfg->jfc_depth);
                break;
            case 'd':
                (void)memcpy(cfg->dev_name, optarg, strlen(optarg));
                break;
            case 'D':
                (void)ub_str_to_u32(optarg, &cfg->duration);
                if (cfg->duration < PERFTEST_DEF_WARMUP_TIME) {
                    (void)fprintf(stderr, "Duration should be no less than %d, please check.\n",
                        PERFTEST_DEF_WARMUP_TIME);
                    return -1;
                }
                cfg->time_type.bs.duration = 1;
                break;
            case 'e':
                cfg->use_jfce = true;
                if (cfg->api_type == PERFTEST_WRITE) {
                    (void)fprintf(stderr, "Events feature not available on WRITE test\n");
                    return -1;
                }
                break;
            case 'E':
                (void)ub_str_to_u8(optarg, &cfg->err_timeout);
                break;
            case PERFTEST_OPT_EID_IDX:
                (void)ub_str_to_u32(optarg, &cfg->eid_idx);
                break;
            case 'f':
                if (cfg->api_type == PERFTEST_ATOMIC) {
                    (void)fprintf(stderr, "Use_flat_api feature NOT available on ATOMIC test.\n");
                    return -1;
                }
                cfg->use_flat_api = true;
                break;
            case 'F':
                cfg->cpu_freq_f = true;
                break;
            case 'h':
                usage(argv[0]);
                return -1;
            case 'I':
                if (cfg->api_type == PERFTEST_READ || cfg->api_type == PERFTEST_ATOMIC) {
                    (void)fprintf(stderr, "Warning: Inline feature not available for READ/ATOMIC.\n");
                }
                (void)ub_str_to_u32(optarg, &cfg->inline_size);
                break;
            case 'j':
                if (ub_str_to_bool(optarg, &cfg->share_jfr) != 0) {
                    (void)fprintf(stderr, "Invalid parameter(share_jfr).\n");
                    return -1;
                }
                break;
            case 'J':
                (void)ub_str_to_u32(optarg, &cfg->jettys);
                if (cfg->jettys == 0) {
                    (void)fprintf(stderr, "Invalid parameter(jettys).\n");
                    return -1;
                }
                if (cfg->type != PERFTEST_BW && cfg->jettys > 1) {
                    (void)fprintf(stderr, "Multiple jettys only available on band width tests.\n");
                    return -1;
                }
                break;
            case 'K':
                (void)ub_str_to_u32(optarg, &cfg->token_policy);
                break;
            case 'n':
                (void)ub_str_to_u64(optarg, &cfg->iters);
                cfg->time_type.bs.iterations = 1;
                break;
            case 'N':
                cfg->no_peak = true;
                if (cfg->type == PERFTEST_LAT) {
                    (void)fprintf(stderr, "NoPeak only valid for BW tests\n");
                    return -1;
                }
                break;
            case 'l':
                (void)ub_str_to_u32(optarg, &cfg->jfs_post_list);
                break;
            case 'L':
                cfg->lock_free = true;
                break;
            case 'O':
                (void)ub_str_to_u8(optarg, &cfg->priority);
                break;
            case 'p':
                if (ub_str_to_u32(optarg, &offset) != 0) {
                    (void)fprintf(stderr, "Invalid trans_mode, it has been changed to URMA_TM_RM.\n");
                    cfg->trans_mode = URMA_TM_RM;
                } else {
                    cfg->trans_mode = (urma_transport_mode_t)(0x1U << offset);
                }
                break;
            case 'P':
                (void)ub_str_to_u16(optarg, &cfg->comm.port);
                break;
            case 'Q':
                (void)ub_str_to_u32(optarg, &cfg->cq_mod);
                break;
            case 'r':
                (void)ub_str_to_u32(optarg, &cfg->jfr_post_list);
                break;
            case 'R':
                (void)ub_str_to_u32(optarg, &cfg->jfr_depth);
                if ((cfg->credit_notify_cnt == 0) || (cfg->credit_notify_cnt ==
                    PERFTEST_DEF_JFR_DEPTH_SEND / PERFTEST_DEF_CREDIT_RATE)) {
                    /* credit parameters should be updated according to jfr_depth */
                    cfg->credit_notify_cnt = cfg->jfr_depth / PERFTEST_DEF_CREDIT_RATE;
                    cfg->credit_threshold = cfg->jfr_depth - (cfg->jfr_depth / PERFTEST_DEF_CREDIT_RATE);
                }
                break;
            case 's':
                (void)ub_str_to_u32(optarg, &cfg->size);
                break;
            case 'S':
                cfg->comm.server_ip = strdup(optarg);
                if (cfg->comm.server_ip == NULL) {
                    (void)fprintf(stderr, "failed to allocate server ip memory.\n");
                    return -1;
                }
                break;
            case 'T':
                (void)ub_str_to_u32(optarg, &cfg->jfs_depth);
                break;
            case 'w':
                cfg->warm_up = true;
                break;
            case 'y':
                cfg->time_type.bs.infinite = 1;
                if (optarg != NULL) {
                    (void)ub_str_to_u32(optarg, &cfg->inf_period);
                }
                break;
            case 'z':
                cfg->use_bonding = true;
                break;
            case PERFTEST_OPT_SINGLE_PATH:
                cfg->single_path = true;
                break;
            case PERFTEST_OPT_RATE_LIMIT:
                cfg->rate_limit = atof(optarg);
                if (cfg->rate_limit <= 0) {
                    (void)fprintf(stderr, " Rate limit must be non-negative\n");
                    return -1;
                }
                cfg->is_rate_limit = true;
                break;
            case PERFTEST_OPT_RATE_UNITS:
                if (strcmp("M", optarg) == 0) {
                    cfg->rate_units = PERFTEST_RATE_LIMIT_MEGA_BYTE;
                } else if (strcmp("G", optarg) == 0) {
                    cfg->rate_units = PERFTEST_RATE_LIMIT_GIGA_BIT;
                } else if (strcmp("P", optarg) == 0) {
                    cfg->rate_units = PERFTEST_RATE_LIMIT_PS;
                } else {
                    (void)fprintf(stderr, " Invalid rate limit units. Please use M, G or P\n");
                    return -1;
                }
                break;
            case PERFTEST_OPT_BURST_SIZE:
                (void)ub_str_to_u32(optarg, &cfg->burst_size);
                break;
            case PERFTEST_OPT_ORDER_TYPE:
                (void)ub_str_to_u32(optarg, &cfg->order_type);
                break;
            case PERFTEST_OPT_ENABLE_IPV6:
                cfg->comm.enable_ipv6 = true;
                break;
            case PERFTEST_OPT_ENABLE_CREDIT:
                cfg->enable_credit = true;
                break;
            case PERFTEST_OPT_CREDIT_THRESHOLD:
                (void)ub_str_to_u32(optarg, &cfg->credit_threshold);
                break;
            case PERFTEST_OPT_CREDIT_NOTIFY_CNT:
                (void)ub_str_to_u32(optarg, &cfg->credit_notify_cnt);
                break;
            case PERFTEST_OPT_JETTYS_PRE_JFR:
                (void)ub_str_to_u32(optarg, &cfg->jettys_pre_jfr);
                break;
            case PERFTEST_OPT_SEG_PRE_JETTY:
                cfg->seg_pre_jetty = true;
                break;
            case PERFTEST_OPT_ENABLE_IMM:
                cfg->enable_imm = true;
                break;
            case PERFTEST_OPT_INF_PERIOD_MS:
                (void)ub_str_to_u32(optarg, &cfg->inf_period_ms);
                break;
            case PERFTEST_OPT_ENABLE_ERR_CONTINUE:
                cfg->enable_err_continue = true;
                break;
            case PERFTEST_OPT_NOTIFY_DATA:
                cfg->enable_notify = true;
                (void)ub_str_to_u64(optarg, &cfg->notify_data);
                break;
            case PERFTEST_OPT_ENABLE_USER_TP:
                cfg->enable_user_tp = true;
                break;
            case PERFTEST_OPT_OOR_EN:
                cfg->oor_en = true;
                break;
            case PERFTEST_OPT_SPRAY_EN:
                cfg->spray_en = true;
                break;
            case PERFTEST_OPT_CC_EN:
                cfg->cc_en = true;
                break;
            case PERFTEST_OPT_CC_ALG:
                (void)ub_str_to_u32(optarg, &cfg->cc_alg);
                break;
            case PERFTEST_OPT_RETRY_NUM:
                (void)ub_str_to_u32(optarg, &cfg->retry_num);
                break;
            case PERFTEST_OPT_ACK_TIMEOUT:
                (void)ub_str_to_u32(optarg, &cfg->ack_timeout);
                break;
            case PERFTEST_OPT_SGE_NUM:
                (void)ub_str_to_u32(optarg, &cfg->sge_num);
                break;
            case PERFTEST_OPT_WRITE_DIRTY:
                cfg->enable_write_dirty = true;
                (void)ub_str_to_u32(optarg, &cfg->write_dirty_period);
                break;
            case PERFTEST_OPT_PAIR_NUM:
                (void)ub_str_to_u32(optarg, &cfg->pair_num);
                cfg->pair_flag = true;
                break;
            case PERFTEST_OPT_ASYNC_CONNECT:
                cfg->enable_async_import = true;
                break;
            case PERFTEST_OPT_TP_AWARE:
                cfg->tp_aware = true;
                break;
            case PERFTEST_OPT_TP_REUSE:
                cfg->tp_reuse = true;
                break;
            case PERFTEST_OPT_CTP:
                cfg->use_ctp = true;
                break;
            case PERFTEST_OPT_JETTY_ID:
                (void)ub_str_to_u32(optarg, &cfg->jetty_id);
                break;
            case PERFTEST_OPT_WAIT_JFC_TIMEOUT:
                (void)ub_str_to_int(optarg, &cfg->wait_jfc_timeout);
                break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    if (cfg->pair_flag == true) {
        cfg->jettys = cfg->pair_num;
        (void)fprintf(stderr, "Warning: Multi-play multi-mode jettys must be pair_num\n");
    }

    if (check_cfg_range(cfg) != 0) {
        (void)fprintf(stderr, "Failed to check config range.\n");
        return -1;
    }
    if (optind < argc - 1) {
        usage(argv[0]);
        return -1;
    }
    return 0;
}

void destroy_cfg(perftest_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    if (cfg->comm.server_ip != NULL) {
        free(cfg->comm.server_ip);
        cfg->comm.server_ip = NULL;
    }
    return;
}

static int check_time_type(perftest_config_t *cfg)
{
    if (cfg->time_type.value == 0) {
        cfg->time_type.bs.iterations = 1;
        return 0;
    }
    if (cfg->time_type.bs.iterations == 1 && (cfg->time_type.bs.duration == 1 || cfg->time_type.bs.infinite == 1)) {
        (void)fprintf(stderr, "Time type conflict: %x.\n", cfg->time_type.value);
        return -1;
    }
    if (cfg->time_type.bs.duration == 1 && cfg->time_type.bs.infinite == 1) {
        (void)fprintf(stderr, "Configure both duration and infinite, and the first and last results may be invalid.\n");
    }
    return 0;
}

static int calc_rate_limit_gap(perftest_config_t *cfg)
{
    uint32_t rate_limit_pps = 0;
    double gap_time = 0; /* usec */
    uint32_t num_of_burst = 0;
    double cpu_mhz = 0;
    
    switch (cfg->rate_units) {
        case PERFTEST_RATE_LIMIT_MEGA_BYTE:
            rate_limit_pps = (uint32_t)(((double)(cfg->rate_limit) / cfg->size) * PERFTEST_MBS);
            break;
        case PERFTEST_RATE_LIMIT_GIGA_BIT:
            rate_limit_pps =
                (uint32_t)(((double)(cfg->rate_limit) / (cfg->size * PERFTEST_BYTE_SIZE)) * PERFTEST_G);
            break;
        case PERFTEST_RATE_LIMIT_PS:
            rate_limit_pps = (uint32_t)((double)(cfg->rate_limit) * PERFTEST_KPPS);
            break;
        default:
            return -1;
    }

    cpu_mhz = get_cpu_mhz(cfg->cpu_freq_f);
    if (cpu_mhz <= 0.0) {
        (void)fprintf(stderr, "Failed: couldn't acquire cpu frequency for rate limiter.\n");
        return -1;
    }
    if (rate_limit_pps < cfg->burst_size) {
        (void)fprintf(stderr, "Failed: burst_size is too large.\n");
        return -1;
    }
    num_of_burst = rate_limit_pps / cfg->burst_size;
    gap_time = PERFTEST_M * (1.0 / num_of_burst);
    cfg->gap_cycles = (uint64_t)(cpu_mhz * gap_time);
    return 0;
}

bool is_jfr_depth_valid(perftest_config_t *cfg)
{
    /* jfr depth should be checked only for send/recv operations */
    if (cfg->api_type != PERFTEST_SEND) {
        return true;
    }
    return (cfg->jfr_depth * (cfg->jettys / cfg->jettys_pre_jfr)) >= (cfg->jettys * cfg->jfr_post_list);
}

int check_local_cfg(perftest_config_t *cfg)
{
    if (cfg == NULL) {
        return -1;
    }

    if (strlen(cfg->dev_name) == 0 || strnlen(cfg->dev_name, URMA_MAX_NAME) >= URMA_MAX_NAME) {
        (void)fprintf(stderr, "No device specified, name: %s.\n", cfg->dev_name);
        return -1;
    }

    if (check_time_type(cfg) != 0) {
        return -1;
    }
    if (cfg->time_type.bs.iterations == 1) {
        if (cfg->jfs_depth > cfg->iters) {
            cfg->jfs_depth = (uint32_t)cfg->iters;
        }

        if ((cfg->api_type == PERFTEST_SEND || cfg->enable_imm == true) && cfg->jfr_depth > cfg->iters) {
            cfg->jfr_depth = (uint32_t)cfg->iters;
        }
    }

    if (cfg->jettys_pre_jfr == 0) {
        cfg->jettys_pre_jfr = cfg->jettys;
    }
    if (cfg->share_jfr == true) {
        if (cfg->jettys < cfg->jettys_pre_jfr || cfg->jettys % cfg->jettys_pre_jfr != 0) {
            (void)fprintf(stderr, "Number of jettys must be a multiple of jettys_pre_jfr.\n");
            exit(1);
        }
        if (!is_jfr_depth_valid(cfg)) {
            (void)fprintf(stderr, "Using share jfr jfr_depth and iters should be greater than " \
                "cfg->jettys_pre_jfr * jfr_post_list.\n");
            exit(1);
        }
    }

    /* we disable cq_mod for large message size to prevent from incorrect BW calculation
     *    (and also because it is not needed)
     * we don't disable cq_mod for use_event, because having a lot of processes with use_event leads
     *     to bugs (probably due to issues with events processing, thus we have less events)
     */
    if (cfg->size > PERFTEST_SIZE_CQ_MOD_LIMIT && cfg->all != true && cfg->use_jfce == false) {
        if (cfg->cq_mod == 0) {
            cfg->cq_mod = 1;
        } else if (cfg->cq_mod > 1) {
            (void)printf("Warning: Large message requested and CQ moderation enabled\n");
            (void)printf("Warning: It can lead to inaccurate results\n");
        }
    }

    if (cfg->cq_mod > cfg->jfs_depth) {
        cfg->cq_mod = cfg->jfs_depth;
    }

    if (cfg->tp_type != URMA_TRANSPORT_UB && cfg->token_policy != URMA_TOKEN_NONE) {
        (void)printf("Warning: only UB can be configured token_policy.\n");
    }

    if (cfg->order_type > URMA_NO) {
        (void)fprintf(stderr, "Only support 0 - 4 for order_type.\n");
        exit(1);
    }

    if (cfg->api_type == PERFTEST_READ || cfg->api_type == PERFTEST_ATOMIC) {
        cfg->inline_size = 0;
    }

    if (cfg->all == true) {
        cfg->size = PERFTEST_DEF_MAX_SIZE;
    }

    if (cfg->api_type == PERFTEST_ATOMIC && cfg->size != PERFTEST_DEF_ATOMIC_SIZE) {
        (void)fprintf(stderr, "Message size should not be changed for Atomic tests.\n");
        exit(1);
    }
    if (cfg->jfs_post_list == 0 || cfg->jfr_post_list == 0) {
        (void)fprintf(stderr, "Invalid parameter with jfs_post_list: %u, jfr_post_list: %u.\n",
            cfg->jfs_post_list, cfg->jfr_post_list);
        exit(1);
    }

    if (cfg->jfs_post_list > 1) {
        if (cfg->time_type.bs.iterations == 1 &&
            (cfg->iters < cfg->jfs_post_list || (cfg->iters % cfg->jfs_post_list) != 0)) {
            (void)fprintf(stderr, "Number of iterations must be a multiple of jfs post list size\n");
            exit(1);
        }

        if (cfg->time_type.bs.iterations == 1 &&
            (cfg->type == PERFTEST_LAT && cfg->iters < cfg->jfs_post_list * PERFTEST_ITERS_MIN)) {
            (void)fprintf(stderr, "Number of iterations must be at least 5 times of jfs post list size in LAT tests\n");
            exit(1);
        }

        if (cfg->jfs_post_list > cfg->jfs_depth) {
            (void)fprintf(stderr, "jfs depth must be greater than jfs_post_list.\n");
            exit(1);
        }

        if (cfg->cq_mod == 0) {
            cfg->cq_mod = cfg->jfs_post_list;
            (void)printf("JFS post List requested - CQ moderation will be the size of the post list\n");
        } else if (cfg->jfs_post_list < cfg->cq_mod || (cfg->jfs_post_list % cfg->cq_mod) != 0) {
            (void)fprintf(stderr, "JFS post list size must be a multiple of CQ moderation\n");
            exit(1);
        }

        if (cfg->type == PERFTEST_LAT && cfg->use_flat_api) {
            (void)fprintf(stderr, "JFS post List must be 1 when use flat api.\n");
            exit(1);
        }
    } else {
        if (cfg->type == PERFTEST_LAT && cfg->cmd != PERFTEST_SEND_LAT) {
            (void)printf("Warning: cq_mod should set to 1 in READ/WRITE/ATOMIC_LAT test\n");
            cfg->cq_mod = 1;
        }
    }

    if (cfg->jfr_post_list > 1) {
        if (cfg->type == PERFTEST_BW || cfg->cmd == PERFTEST_SEND_LAT) {
            if (cfg->time_type.bs.iterations == 1 &&
                (cfg->iters < cfg->jfr_post_list || (cfg->iters % cfg->jfr_post_list) != 0)) {
                (void)fprintf(stderr, "Number of iterations must be a multiple of jfr post list size\n");
                exit(1);
            }
        } else {
            (void)fprintf(stderr, "jfr post list is supported in BW tests and SEND_LAT tests only\n");
            exit(1);
        }
    }

    if (cfg->time_type.bs.duration == 1) {
        /* When working with Duration, iters=0 helps us to satisfy loop cond. in run_iter_bw.
         * We also use it for "global" counter of packets.
         */
        cfg->iters = 0;
        cfg->no_peak = true;

        if (cfg->use_jfce == true) {
            (void)fprintf(stderr, "Duration mode doesn't work with events.\n");
            exit(1);
        }

        if (cfg->all) {
            (void)fprintf(stderr, "Duration mode doesn't support running on all sizes.\n");
            exit(1);
        }
    }

    if ((cfg->api_type == PERFTEST_SEND || cfg->enable_imm == true) &&
        cfg->type == PERFTEST_BW && cfg->comm.server_ip == NULL) {
        cfg->no_peak = true;
    }

    if ((cfg->api_type == PERFTEST_SEND || cfg->enable_imm == true) &&
        ((cfg->jfr_depth & 0x1) == 1) && cfg->all == false) {
        cfg->jfr_depth += 1;
    }

    if (cfg->time_type.bs.iterations == 1 && cfg->iters > PERFTEST_BW_NO_PEAK_INTERS &&
        cfg->no_peak == false && cfg->type == PERFTEST_BW) {
        cfg->no_peak = true;
    }

    if (cfg->jetty_mode != PERFTEST_JETTY_SIMPLEX && cfg->use_flat_api) {
        (void)fprintf(stderr, "use_flat_api is noly available in SIMPLEX mode, do not open it in other modes.\n");
        exit(1);
    }

    // there can be a stuck error if jfr_depth/jfs_depth is NOT multiple of jfr_post_list
    if (cfg->type == PERFTEST_BW && cfg->api_type == PERFTEST_SEND) {
        if (cfg->jfr_depth % cfg->jfr_post_list != 0) {
            uint32_t corr_jfr_depth = (cfg->jfr_depth / cfg->jfr_post_list + 1) * cfg->jfr_post_list;
            cfg->jfr_depth = corr_jfr_depth;
            cfg->jfs_depth = corr_jfr_depth;
            (void)printf("Warning: jfr_depth/jfs_depth should be multiple of jfr_post_list.\n");
            (void)printf("jfr_depth/jfs_depth has been changed to %u.\n", corr_jfr_depth);
        }
    }

    if (cfg->type == PERFTEST_BW && (cfg->jfc_depth != PERFTEST_DEF_JFC_DEPTH_BW ||
        cfg->jfr_depth != PERFTEST_DEF_JFR_DEPTH_SEND || cfg->jfs_depth != PERFTEST_DEF_JFS_DEPTH_BW)) {
        uint32_t jfr_mul = cfg->jfc_depth / cfg->jfr_depth;
        uint32_t jfs_mul = cfg->jfc_depth / cfg->jfs_depth;
        if (jfr_mul < PERFTEST_JFC_MUL_THRESHOLD || jfs_mul < PERFTEST_JFC_MUL_THRESHOLD) {
            (void)printf("Warning: jfc_depth too SMALL, which may lead to urma_poll_jfc ERROR.\n");
        }
    }

    if (cfg->time_type.bs.infinite == 1) {
        cfg->no_peak = true;
        if (cfg->type == PERFTEST_LAT) {
            (void)fprintf(stderr, "Infinite only supports BW test currently.\n");
            exit(1);
        }
        if (cfg->all) {
            (void)fprintf(stderr, "Infinite and All function conflict, please check and retry.\n");
            exit(1);
        }
        if (cfg->time_type.bs.duration == 1) {
            if (cfg->duration <= cfg->inf_period) {
                (void)fprintf(stderr, "Duration period should be larger than inf_period.\n");
                exit(1);
            }
            (void)printf("Info: Infinite with duration, period: %u, inf_period: %u.\n",
                cfg->duration, cfg->inf_period);
        }
        if (cfg->bidirection == true && (cfg->api_type == PERFTEST_SEND ||
                (cfg->api_type == PERFTEST_WRITE && cfg->enable_imm == true))) {
            (void)fprintf(stderr, "run_infinitely does not support SEND or WRITE_IMM "
                "Bidirectional BW test\n");
            exit(1);
        }
    }

    if (cfg->jfs_depth > (cfg->jfc_depth * cfg->cq_mod)) {
        (void)fprintf(stderr, "Invalid config, try to decrease jfs depth or increase jfc depth.\n");
        exit(1);
    }
    if (cfg->trans_mode == URMA_TM_UM && cfg->api_type != PERFTEST_SEND) {
        (void)fprintf(stderr, "UM transport mode only supports SEND operation.\n");
        exit(1);
    }
    if (cfg->trans_mode == URMA_TM_RC && cfg->jetty_mode == PERFTEST_JETTY_SIMPLEX) {
        (void)fprintf(stderr, "RC transport mode does NOT support SIMPLEX jetty mode.\n");
        exit(1);
    }
    if (cfg->burst_size > 0 && cfg->is_rate_limit == false) {
        (void)fprintf(stderr, "Can't enable burst mode when rate limiter is off\n");
        exit(1);
    }
    if (cfg->burst_size == 0 && cfg->is_rate_limit == true) {
        cfg->burst_size = cfg->jfs_depth;
        (void)fprintf(stderr, "Setting burst size to jfs depth = %u\n", cfg->jfs_depth);
    }
    if (cfg->is_rate_limit == true) {
        if (calc_rate_limit_gap(cfg) != 0) {
            (void)fprintf(stderr, "Calculate rate limit gap failed.\n");
            exit(1);
        }
        if (cfg->type != PERFTEST_BW || cfg->api_type == PERFTEST_ATOMIC ||
            (cfg->cmd == PERFTEST_SEND_BW && cfg->bidirection == true)) {
            (void)fprintf(stderr, "Rate limiter cann't be executed on non-BW, ATOMIC or bidirectional SEND tests\n");
            exit(1);
        }
    }

    if (cfg->enable_credit == true && (cfg->cmd != PERFTEST_SEND_BW)) {
        (void)fprintf(stderr, "Credit takes effect only in SEND_BW test.\n");
        exit(1);
    }
    if (cfg->enable_credit == true) {
        if (cfg->credit_notify_cnt == 0 || cfg->credit_notify_cnt > cfg->jfr_depth) {
            cfg->credit_notify_cnt = cfg->jfr_depth / PERFTEST_DEF_CREDIT_RATE;
            (void)fprintf(stderr, "credit_notify_cnt out of range (1 ~ %u), change to %u.\n",
                cfg->jfr_depth, cfg->credit_notify_cnt);
        }
        if (cfg->credit_threshold == 0 || cfg->credit_threshold + cfg->jfs_post_list > cfg->jfr_depth) {
            cfg->credit_threshold = cfg->jfr_depth - (cfg->jfr_depth / PERFTEST_DEF_CREDIT_RATE);
            (void)fprintf(stderr, "credit_threshold out of range (1 ~ %u), change to %u.\n",
                cfg->jfr_depth - cfg->jfs_post_list, cfg->credit_notify_cnt);
        }
        if (cfg->trans_mode == URMA_TM_UM) {
            (void)fprintf(stderr, "Credit DOES NOT take effect in UM trans_mode.\n");
            exit(1);
        }
    }

    if (cfg->enable_imm == true) {
        if (cfg->jfr_depth == PERFTEST_DEF_JFR_DEPTH_OTHER) {
            cfg->jfr_depth = PERFTEST_DEF_JFR_DEPTH_SEND;
        }
        if (cfg->api_type != PERFTEST_WRITE && cfg->api_type != PERFTEST_SEND) {
            (void)fprintf(stderr, "immediate takes effect only in write or send test.\n");
            exit(1);
        }
    }
    if (cfg->enable_notify == true &&
        (cfg->api_type != PERFTEST_WRITE || cfg->enable_imm == true)) {
        (void)fprintf(stderr, "notify takes effect only in write test, and conflicts with immediate.\n");
        exit(1);
    }
    if (cfg->inf_period_ms != 0) {
        if (cfg->time_type.bs.infinite != 1) {
            (void)fprintf(stderr, "inf_period_ms takes effect only in infinite mode.\n");
            exit(1);
        }
        if (cfg->inf_period_ms < PERFTEST_DEF_INF_PERIOD_MS || cfg->inf_period_ms % PERFTEST_DEF_INF_PERIOD_MS != 0) {
            (void)fprintf(stderr, "inf_period_ms must be a multiple of 50.\n");
            exit(1);
        }
    } else {
        cfg->inf_period_ms = cfg->inf_period * PERFTEST_SEC_TO_MS;
    }
    if (cfg->enable_err_continue == true && cfg->type != PERFTEST_BW) {
        (void)fprintf(stderr, "enable err continue takes effect only in bw test.\n");
        exit(1);
    }
    if (cfg->enable_user_tp == true) {
        cfg->trans_mode = URMA_TM_RC;
        if (cfg->jetty_mode != PERFTEST_JETTY_DUPLEX) {
            (void)fprintf(stderr, "enable_user_tp: wrong jetty_mode.\n");
            exit(1);
        }
    }
    if (cfg->size % cfg->sge_num != 0) {
        (void)fprintf(stderr, "pkt size must be a multiple of sge_num.\n");
        exit(1);
    }
    if (cfg->pair_flag == true && cfg->seg_pre_jetty == false) {
        (void)fprintf(stderr, "multiplayer mode, seg_pre_jetty must be true\n");
        exit(1);
    }
    if (cfg->pair_flag == true && cfg->type == PERFTEST_LAT) {
        cfg->jettys_pre_jfr = 1;
        (void)fprintf(stderr, "multiplayer mode, jettys_pre_jfr must be 1.\n");
    }

    if (cfg->tp_aware == false) {
        if (cfg->tp_reuse == true) {
            (void)fprintf(stderr, "Warning: tp_reuse feature only work when set tp_aware.\n");
        }
    }
    if (cfg->trans_mode == URMA_TM_UM && cfg->use_ctp) {
        (void)fprintf(stderr, "UM transport mode is not recommended for ctp.\n");
    }

    return 0;
}

static int check_both_side_cfg(const perftest_config_t *local_cfg, const perftest_config_t *remote_cfg)
{
    if (local_cfg == NULL || remote_cfg == NULL) {
        return -1;
    }

    if (local_cfg->cmd != remote_cfg->cmd) {
        (void)fprintf(stderr, "Config inconsistent[cmd],local: %s, remote: %s.\n",
            g_cmd[local_cfg->cmd].cmd, g_cmd[remote_cfg->cmd].cmd);
        return -1;
    }

    if (local_cfg->all != remote_cfg->all) {
        (void)fprintf(stderr, "Config inconsistent[all],local: %s, remote: %s.\n",
            PERFTEST_BOOL_TO_STR(local_cfg->all), PERFTEST_BOOL_TO_STR(remote_cfg->all));
        return -1;
    }

    if (local_cfg->atomic_type != remote_cfg->atomic_type) {
        (void)fprintf(stderr, "Config inconsistent[atomic_type],local: %s, remote: %s.\n",
            g_atomic_types_str[local_cfg->atomic_type], g_atomic_types_str[remote_cfg->atomic_type]);
        return -1;
    }

    if (local_cfg->duration != remote_cfg->duration) {
        (void)fprintf(stderr, "Config inconsistent[duration],local: %u, remote: %u.\n",
            local_cfg->duration, remote_cfg->duration);
        return -1;
    }

    if (local_cfg->time_type.value != remote_cfg->time_type.value) {
        (void)fprintf(stderr, "Config inconsistent[time_type],local: %u, remote: %u.\n",
            local_cfg->time_type.value, remote_cfg->time_type.value);
        return -1;
    }

    if (local_cfg->jettys != remote_cfg->jettys && local_cfg->pair_flag == false) {
        (void)fprintf(stderr, "Config inconsistent[jettys],local: %u, remote: %u.\n",
            local_cfg->jettys, remote_cfg->jettys);
        return -1;
    }

    if (local_cfg->token_policy != remote_cfg->token_policy) {
        (void)fprintf(stderr, "Config inconsistent[token_policy],local: %u, remote: %u.\n",
            local_cfg->token_policy, remote_cfg->token_policy);
        return -1;
    }

    if (local_cfg->iters != remote_cfg->iters) {
        (void)fprintf(stderr, "Config inconsistent[iters],local: %lu, remote: %lu.\n",
            local_cfg->iters, remote_cfg->iters);
        return -1;
    }

    if (local_cfg->jetty_mode != remote_cfg->jetty_mode) {
        (void)fprintf(stderr, "Config inconsistent[jetty_mode],local: %s, remote: %s.\n",
            g_jetty_mode_str[local_cfg->jetty_mode], g_jetty_mode_str[remote_cfg->jetty_mode]);
        return -1;
    }

    if (local_cfg->size != remote_cfg->size) {
        (void)fprintf(stderr, "Config inconsistent[size],local: %u, remote: %u.\n",
            local_cfg->size, remote_cfg->size);
        return -1;
    }

    if (local_cfg->trans_mode != remote_cfg->trans_mode) {
        (void)fprintf(stderr, "Config inconsistent[trans_mode],local: %s, remote: %s.\n",
            g_trans_mode_str[local_cfg->trans_mode], g_trans_mode_str[remote_cfg->trans_mode]);
        return -1;
    }

    if (local_cfg->use_flat_api != remote_cfg->use_flat_api) {
        (void)fprintf(stderr, "Config inconsistent[use_flat_api],local: %s, remote: %s.\n",
            PERFTEST_BOOL_TO_STR(local_cfg->use_flat_api), PERFTEST_BOOL_TO_STR(remote_cfg->use_flat_api));
        return -1;
    }

    if (local_cfg->order != remote_cfg->order) {
        (void)fprintf(stderr, "Config inconsistent[order],local: %u, remote: %u.\n",
            local_cfg->order, remote_cfg->order);
        return -1;
    }
    if (local_cfg->comm.enable_ipv6 != remote_cfg->comm.enable_ipv6) {
        (void)fprintf(stderr, "Config inconsistent[enable_ipv6].\n");
        return -1;
    }
    if (local_cfg->enable_credit != remote_cfg->enable_credit) {
        (void)fprintf(stderr, "Config inconsistent[enable_credit].\n");
        return -1;
    }
    if (local_cfg->seg_pre_jetty != remote_cfg->seg_pre_jetty) {
        (void)fprintf(stderr, "Config inconsistent[seg_pre_jetty], local: %d, remote: %d.\n",
            (int)local_cfg->seg_pre_jetty, (int)remote_cfg->seg_pre_jetty);
        return -1;
    }
    if (local_cfg->enable_imm != remote_cfg->enable_imm) {
        (void)fprintf(stderr, "Config inconsistent[enable_imm].\n");
        return -1;
    }
    if (local_cfg->inf_period_ms != remote_cfg->inf_period_ms) {
        (void)fprintf(stderr, "Config inconsistent[inf_period_ms].\n");
        return -1;
    }
    if (local_cfg->enable_err_continue != remote_cfg->enable_err_continue) {
        (void)fprintf(stderr, "Config inconsistent[enable_err_continue].\n");
        return -1;
    }
    if (local_cfg->enable_user_tp != remote_cfg->enable_user_tp) {
        (void)fprintf(stderr, "Config inconsistent[enable_user_tp].\n");
        return -1;
    }
    if (local_cfg->sge_num != remote_cfg->sge_num) {
        (void)fprintf(stderr, "Config inconsistent[sge_num].\n");
        return -1;
    }

    if (local_cfg->write_dirty_period != remote_cfg->write_dirty_period) {
        (void)fprintf(stderr, "Config inconsistent[write_dirty_period].\n");
        return -1;
    }
    return 0;
}

int check_remote_cfg(perftest_config_t *cfg)
{
    perftest_config_t remote_cfg;
    for (uint32_t i = 0; i < cfg->pair_num; i++) {
        int sock_fd = cfg->comm.sock_fd[i];
        int ret = sock_sync_data(sock_fd, sizeof(perftest_config_t), (char *)cfg, (char *)&remote_cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "Failed to sync remote configuration, pair_num:%u, errno:%s.\n", i, strerror(errno));
            return ret;
        }

        ret = check_both_side_cfg(cfg, &remote_cfg);
        if (ret != 0) {
            (void)fprintf(stderr, "i: %u, Failed to check remote configuration.\n", i);
            return ret;
        }
    }
    return 0;
}