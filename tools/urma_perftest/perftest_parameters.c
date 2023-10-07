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
#include "perftest_communication.h"
#include "perftest_parameters.h"
#define PERFTEST_CACHE_LINE_FILE_SIZE (10)
#define PERFTEST_JFC_MUL_THRESHOLD (4)
#define PERFTEST_DEFAULT_DURATION (5)

typedef enum perftest_trans_mode_offset {
    PERFTEST_RM_OFFSET,
    PERFTEST_RC_OFFSET,
    PERFTEST_UM_OFFSET,
} perftest_trans_mode_offset_t;

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
    [PERFTEST_RM_OFFSET] =     "URMA_TM_RM",
    [PERFTEST_RC_OFFSET] =     "URMA_TM_RC",
    [PERFTEST_UM_OFFSET] =     "URMA_TM_UM"
};
static const char *g_ib_tm_mode_str[] = {
    [URMA_IB_RC] =             "RC",
    [URMA_IB_XRC] =            "XRC",
    [URMA_IB_UD] =             "UD"
};
static const char *g_jetty_mode_str[] = {
    [PERFTEST_JETTY_SIMPLEX] = "SIMPLEX",
    [PERFTEST_JETTY_DUPLEX] =  "DUPLEX"
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
    (void)printf("  -a, --all[order]            Run sizes from 2 till 2^15, order: exponent of 2.\n");
    (void)printf("  -A, --atomic_type <type>    Specify atomic type, {cas|faa}.\n");
    (void)printf("  -b, --simplex_mode          Run with simplex mode(jfs/jfr), duplex jetty mode for reserved.\n");
    (void)printf("  -B, --bidirection           Measure bidirectional bandwidth (default unidirectional).\n");
    (void)printf("  -c, --jfc_inline <size>     Enable jfc_inline to upgrade latency performance.\n");
    (void)printf("  -C, --jfc-depth <dep>       Size of jfc depth (default 4096 for bw, 1024 for ip bw, 1 for lat).\n");
    (void)printf("  -d, --dev <dev_name>        The name of ubep device.\n");
    (void)printf("  -D, --duration <second>     Run test for a customized period of seconds, this cfg covers iters.\n");
    (void)printf("  -e, --use_jfce              use jfc event.\n");
    (void)printf("  -E, --err_timeout <time>    the timeout before report error, ranging from [0, 31],\n"
                 "                              the actual timeout in usec is caculated by: 4.096*(2^err_timeout).\n");
    (void)printf("  -f, --use_flat_api          Choose to use flat API, only works in SIMPLEX mode.\n");
    (void)printf("  -F, --cpu_freq_f            To report warnings when CPU frequency drifts, default as NOT.\n");
    (void)printf("  -h, --help                  Show help info.\n");
    (void)printf("  -i, --ignore_jetty_in_cr    NOT to fill jetty_id in parse cr.\n");
    (void)printf("  -I, --inline_size <size>    Max size of message to be sent in inline.\n");
    (void)printf("  -J, --jettys <num of jetty> Num of jettys(default 1).\n");
    (void)printf("  -m, --mtu <mtu>             MTU size : 256 - 4096 (default port mtu).\n");
    (void)printf("  -n, --iters <iters>         Number of exchanges (at least 5, default 10000).\n");
    (void)printf("  -N, --no_peak               Cancel peak-bw calculation.\n");
    (void)printf("  -l, --jfs_post_list <size>  Post list of send WQEs of <list size> size.\n");
    (void)printf("  -L, --lock_free             Jetty's interior is unlocked.\n");
    (void)printf("  -O, --priority              set the priority of JFS, ranging from [0, 15].\n");
    (void)printf("  -p, --trans_mode <mode>     Transport mode: 0 for RM(default), 1 for RC, 2 for UM.\n");
    (void)printf("  -P, --port <id>             Server port for bind or connect, default 21115.\n");
    (void)printf("  -Q, --cq-num <num>          Generate Cqe only after <--cq-mod> completion.\n");
    (void)printf("  -r, --jfr_post_list <size>  Post list of receive WQEs of <list size> size.\n");
    (void)printf("  -R, --jfr-depth <dep>       Size of jfr depth (default 512 for BW, 1 for LAT).\n");
    (void)printf("  -s, --size <size>           Size of message to exchange (default 2).\n");
    (void)printf("  -S, --server <ip>           Server ip for bind or connect, default: 127.0.0.1 .\n");
    (void)printf("  -t, --ib_tm_mode <mode>     IB transport mode: 0 for RC(default), 1 for XRC, 2 for UD.\n");
    (void)printf("  -T, --jfs-depth <dep>       Size of jfs depth (default 128 for BW, 1 for LAT).\n");
    (void)printf("  -U, --retry_cnt <cnt>       number of times that jfs will resend packets before report error,\n"
                 "                              when the remote side does not response, ranging from [0, 7], \n"
                 "                              the value 0 means never retry.\n");
    (void)printf("  -w, --warm_up               Choose to use warm_up function, only for read/write/atomic bw test.\n");
    (void)printf("  -y, --infinite[second]      Run perftest infinitely, only available for BW test.\n"
                 "                              Print period for infinite mode, default 2 seconds.\n");
}

static perftest_cmd_type_t parse_command(const char *argv1)
{
    perftest_cmd_t cmd[] = {
        { "read_lat",          PERFTEST_READ_LAT },
        { "write_lat",         PERFTEST_WRITE_LAT },
        { "send_lat",          PERFTEST_SEND_LAT },
        { "atomic_lat",        PERFTEST_ATOMIC_LAT },
        { "read_bw",           PERFTEST_READ_BW },
        { "write_bw",          PERFTEST_WRITE_BW },
        { "send_bw",           PERFTEST_SEND_BW },
        { "atomic_bw",         PERFTEST_ATOMIC_BW }
    };

    for (int i = 0; i < (int)PERFTEST_CMD_NUM; i++) {
        if (strlen(argv1) != strlen(cmd[i].cmd)) {
            continue;
        }
        if (strcmp(argv1, cmd[i].cmd) == 0) {
            return cmd[i].type;
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
        cfg->size = PERFTEST_DEF_IBP_ATOMIC_SIZE;
        return;
    }
    cfg->size = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_SIZE_BW : PERFTEST_DEF_SIZE_LAT;
}

static int get_cache_line_size(void)
{
    int size = 0;

    size = (int)sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    if (size == 0) {
        char *file = "/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size";
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
    cfg->all = false;
    cfg->atomic_type = PERFTEST_CAS;
    cfg->jfc_depth = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_JFC_DEPTH_BW : PERFTEST_DEF_JFC_DEPTH_LAT;
    memset(cfg->dev_name, 0, URMA_MAX_NAME);
    cfg->duration = PERFTEST_DEFAULT_DURATION;
    cfg->use_jfce = false;
    cfg->time_type.value = 0;
    // Update to max value of the device attr after creation context
    cfg->inline_size = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_INLINE_BW : PERFTEST_DEF_INLINE_LAT;
    cfg->jettys = PERFTEST_DEF_NUM_JETTYS;
    cfg->mtu = 0;
    cfg->iters = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_ITERS_BW : PERFTEST_DEF_ITERS_LAT;
    cfg->no_peak = false;
    cfg->jfs_post_list = 1;
    cfg->jetty_mode = PERFTEST_JETTY_DUPLEX;
    cfg->cq_mod = PERFTEST_DEF_CQ_NUM;
    cfg->jfr_post_list = 1;
    cfg->jfr_depth = (cfg->cmd == PERFTEST_SEND_LAT || cfg->cmd == PERFTEST_SEND_BW) ?
        PERFTEST_DEF_JFR_DEPTH_SEND : PERFTEST_DEF_JFR_DEPTH_OTHER;

    init_cfg_size(cfg);

    cfg->comm.server_ip = NULL;
    cfg->comm.port = PERFTEST_DEF_PORT;
    cfg->comm.listen_fd = -1;
    cfg->comm.sock_fd = -1;
    cfg->jfs_depth = (cfg->type == PERFTEST_BW) ? PERFTEST_DEF_JFS_DEPTH_BW : PERFTEST_DEF_JFS_DEPTH_LAT;
    cfg->ib_tm_mode = URMA_IB_RC;
    cfg->trans_mode = URMA_TM_RM;

    cfg->cache_line_size = (uint32_t)get_cache_line_size();
    cfg->page_size = (uint64_t)(uint32_t)getpagesize();
    cfg->use_flat_api = false;
    cfg->cpu_freq_f = false;
    cfg->ignore_jetty_in_cr = false;
    cfg->warm_up = false;
    cfg->bidirection = false;
    cfg->jfc_inline = false;
    cfg->inf_period = PERFTEST_DEF_INF_PERIOD;
    cfg->order = PERFTEST_SIZE_ORDER;
    cfg->err_timeout = URMA_TYPICAL_ERR_TIMEOUT;
    cfg->retry_cnt = URMA_TYPICAL_RETRY_CNT;
    cfg->lock_free = false;
    cfg->priority = URMA_MAX_PRIORITY;
}

static perftest_trans_mode_offset_t get_offset_by_trans_mode(urma_transport_mode_t trans_mode)
{
    perftest_trans_mode_offset_t offset = PERFTEST_RC_OFFSET;
    switch (trans_mode) {
        case URMA_TM_RM:
            offset =  PERFTEST_RM_OFFSET;
            break;
        case URMA_TM_RC:
            offset = PERFTEST_RC_OFFSET;
            break;
        case URMA_TM_UM:
            offset = PERFTEST_UM_OFFSET;
            break;
        default:
            break;
    }
    return offset;
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
    (void)printf(" Mtu                 : %-10u\t\t JETTY mode       : %s\n", cfg->mtu,
        g_jetty_mode_str[cfg->jetty_mode]);
    (void)printf(" trans mode          : %s\n", g_trans_mode_str[get_offset_by_trans_mode(cfg->trans_mode)]);

    if (cfg->tp_type == URMA_TRANSPORT_IB) {
        (void)printf(" IB tm mode          : %s\n", g_ib_tm_mode_str[cfg->ib_tm_mode]);
    }
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
        { cfg->retry_cnt,    PERFTEST_RETRY_CNT_MIN,     PERFTEST_RETRY_CNT_MAX,    "retry_cnt" },
        { cfg->priority,     PERFTEST_PRIORITY_MIN,      PERFTEST_PRIORITY_MAX,     "priority" }
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
    perftest_trans_mode_offset_t offset;
    if (argc == 1) {
        (void)printf("Input invalid with argc: %d.\n", argc);
        usage(argv[0]);
        return -1;
    }

    memset(cfg, 0, sizeof(perftest_config_t));

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
        {"jfc_inline",    required_argument, NULL, 'c'},
        {"jfc_depth",     required_argument, NULL, 'C'},
        {"dev",           required_argument, NULL, 'd'},
        {"duration",      required_argument, NULL, 'D'},
        {"use_jfce",      no_argument,       NULL, 'e'},
        {"err_timeout",   required_argument, NULL, 'E'},
        {"use_flat_api",  no_argument,       NULL, 'f'},
        {"cpu_freq_f",    no_argument,       NULL, 'F'},
        {"help",          no_argument,       NULL, 'h'},
        {"ignore_jetty_in_cr", no_argument,  NULL, 'i'},
        {"inline_size",   required_argument, NULL, 'I'},
        {"jettys",        required_argument, NULL, 'J'},
        {"mtu",           required_argument, NULL, 'm'},
        {"iters",         required_argument, NULL, 'n'},
        {"no_peak",       no_argument,       NULL, 'N'},
        {"jfs_post_list", required_argument, NULL, 'l'},
        {"lock_free",     no_argument,       NULL, 'L'},
        {"priority",      required_argument, NULL, 'O'},
        {"trans_mode",    required_argument, NULL, 'p'},
        {"port",          required_argument, NULL, 'P'},
        {"cq_num",        required_argument, NULL, 'Q'},
        {"jfr_post_list", required_argument, NULL, 'r'},
        {"jfr_depth",     required_argument, NULL, 'R'},
        {"size",          required_argument, NULL, 's'},
        {"server",        required_argument, NULL, 'S'},
        {"jfs_depth",     required_argument, NULL, 'T'},
        {"ib_tm_mode",    required_argument, NULL, 't'},
        {"retry_cnt",     required_argument, NULL, 'U'},
        {"warm_up",       no_argument,       NULL, 'w'},
        {"infinite",      optional_argument, NULL, 'y'},
        {NULL,            no_argument,       NULL, '\0'}
    };

    /* Second parse the options */
    while (1) {
        int c = getopt_long(argc, argv, "a::A:bBcC:d:t:D:eE:fFhiI:J:m:n:Nl:LO:p:P:Q:r:R:s:S:t:T:U:wy::",
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
            case 'i':
                cfg->ignore_jetty_in_cr = true;
                break;
            case 'I':
                if (cfg->api_type == PERFTEST_READ || cfg->api_type == PERFTEST_ATOMIC) {
                    (void)fprintf(stderr, "Warning: Inline feature not available for READ/ATOMIC.\n");
                }
                (void)ub_str_to_u32(optarg, &cfg->inline_size);
                break;
            case 'J':
                if (cfg->type != PERFTEST_BW) {
                    (void)fprintf(stderr, "Multiple jettys only available on band width tests.\n");
                    return -1;
                }
                (void)ub_str_to_u32(optarg, &cfg->jettys);
                break;
            case 'm':
                (void)ub_str_to_u32(optarg, &cfg->mtu);
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
                if (ub_str_to_u32(optarg, (uint32_t *)&offset) != 0) {
                    (void)fprintf(stderr, "Invalid trans_mode, it has been changed to URMA_TM_RM.\n");
                    cfg->trans_mode = URMA_TM_RM;
                } else {
                    cfg->trans_mode = (urma_transport_mode_t)(0x1U << (uint32_t)offset);
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
            case 't':
                (void)ub_str_to_u32(optarg, (uint32_t *)&cfg->ib_tm_mode);
                break;
            case 'T':
                (void)ub_str_to_u32(optarg, &cfg->jfs_depth);
                break;
            case 'U':
                (void)ub_str_to_u8(optarg, &cfg->retry_cnt);
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
            default:
                usage(argv[0]);
                return -1;
        }
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
int check_local_cfg(perftest_config_t *cfg)
{
    if (cfg == NULL) {
        return -1;
    }

    if (strlen(cfg->dev_name) == 0) {
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

        if (cfg->api_type == PERFTEST_SEND && cfg->jfr_depth > cfg->iters) {
            cfg->jfr_depth = (uint32_t)cfg->iters;
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

    if (cfg->api_type == PERFTEST_READ || cfg->api_type == PERFTEST_ATOMIC) {
        cfg->inline_size = 0;
    }

    if (cfg->all == true) {
        cfg->size = PERFTEST_DEF_MAX_SIZE;
    }

    if (cfg->api_type == PERFTEST_ATOMIC && cfg->size != PERFTEST_DEF_IBP_ATOMIC_SIZE) {
        (void)fprintf(stderr, "Message size should not be changed for Atomic tests.\n");
        exit(1);
    }
    if (cfg->jfs_post_list == 0 || cfg->jfr_post_list == 0) {
        (void)fprintf(stderr, "Invalid parameter with jfs_post_list: %u, jfr_post_list: %u.\n",
            cfg->jfs_post_list, cfg->jfr_post_list);
        exit(1);
    }

    if (cfg->jfs_post_list > 1) {
        if (cfg->type == PERFTEST_BW) {
            if (cfg->time_type.bs.iterations == 1 && (cfg->iters % cfg->jfs_post_list) != 0) {
                (void)fprintf(stderr, "Number of iterations must be a multiple of jfs post list size\n");
                exit(1);
            }

            if (cfg->cq_mod == 0) {
                cfg->cq_mod = cfg->jfs_post_list;
                (void)printf("JFS post List requested - CQ moderation will be the size of the post list\n");
            } else if ((cfg->jfs_post_list % cfg->cq_mod) != 0) {
                (void)fprintf(stderr, "JFS post list size must be a multiple of CQ moderation\n");
                exit(1);
            }
        } else {
            (void)fprintf(stderr, "jfs post list is supported in BW tests only\n");
            exit(1);
        }
    }

    if (cfg->jfr_post_list > 1) {
        if (cfg->type == PERFTEST_BW) {
            if (cfg->time_type.bs.iterations == 1 && (cfg->iters % cfg->jfr_post_list) != 0) {
                (void)fprintf(stderr, "Number of iterations must be a multiple of jfr post list size\n");
                exit(1);
            }
        } else {
            (void)fprintf(stderr, "jfr post list is supported in BW tests only\n");
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

    if (cfg->api_type == PERFTEST_SEND && cfg->type == PERFTEST_BW && cfg->comm.server_ip == NULL) {
        cfg->no_peak = true;
    }

    if (cfg->api_type == PERFTEST_SEND && ((cfg->jfr_depth & 0x1) == 1) && cfg->all == false) {
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
        if (cfg->use_jfce) {
            (void)fprintf(stderr, "Infinite does not support use_jfce currently.\n");
            exit(1);
        }
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
    return 0;
}

static int check_both_side_cfg(const perftest_config_t *local_cfg, const perftest_config_t *remote_cfg)
{
    if (local_cfg == NULL || remote_cfg == NULL) {
        return -1;
    }

    // todo check
    return 0;
}

int check_remote_cfg(perftest_config_t *cfg)
{
    int ret;
    perftest_config_t remote_cfg;
    perftest_comm_t *comm = &cfg->comm;
    ret = sock_sync_data(comm->sock_fd, sizeof(perftest_config_t), (char *)cfg, (char *)&remote_cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to sync remote configuration.\n");
        return ret;
    }

    ret = check_both_side_cfg(cfg, &remote_cfg);
    if (ret != 0) {
        (void)fprintf(stderr, "Failed to check remote configuration.\n");
        return ret;
    }
    return 0;
}