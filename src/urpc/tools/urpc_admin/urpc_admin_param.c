/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc admin param process
 * Create: 2024-4-23
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "channel_info.h"
#include "dbuf.h"
#include "handshaker_info.h"
#include "perf.h"
#include "queue_info.h"
#include "stats.h"
#include "unix_server.h"
#include "urpc_bitmap.h"
#include "urpc_framework_errno.h"
#include "version.h"

#include "urpc_admin_param.h"

// use 256 to save URPC_PERF_QUANTILE_MAX_NUM of u64 is enough
#define PARSE_THRESHOLD_STRING_SIZE (256)
#define CASE_BITMAP_SIZE 64

typedef struct urpc_cmd_map urpc_cmd_map_t;
typedef struct urpc_cmd_map {
    int *cmd_bits;
    int cmd_num;
    urpc_cmd_map_t *cmd_set;
    int cmd_set_num;
    uint16_t module_id;
    uint16_t cmd_id;
} urpc_cmd_map_t;

static int g_urpc_version_cmd_bits[] = {
    URPC_CMD_BITS_VERSION,
};

static int g_urpc_dbuf_cmd_bits[] = {
    URPC_CMD_BITS_DBUF,
};

static int g_urpc_channel_cmd_bits[] = {
    URPC_CMD_BITS_CHANNEL,
};

static int g_urpc_perf_cmd_bits[] = {
    URPC_CMD_BITS_PERF,
    URPC_CMD_BITS_THRESH
};

static int g_urpc_stats_cmd_bits[] = {
    URPC_CMD_BITS_STATS,
    URPC_CMD_BITS_QUEUE_ID
};

static int g_urpc_queue_info_cmd_bits[] = {
    URPC_CMD_BITS_QUEUE_INFO,
    URPC_CMD_BITS_CLIENT_CHANNEL,
    URPC_CMD_BITS_SERVER_CHANNEL,
    URPC_CMD_BITS_QUEUE_ID
};

static int g_urpc_handshaker_cmd_bits[] = {
    URPC_CMD_BITS_HANDSHAKER,
    URPC_CMD_BITS_CLIENT_CHANNEL,
    URPC_CMD_BITS_HANDSHAKER_ID
};

static int g_urpc_perf[] = {URPC_CMD_BITS_PERF};
static int g_urpc_perf_with_thresh[] = {URPC_CMD_BITS_PERF, URPC_CMD_BITS_THRESH};
static urpc_cmd_map_t g_urpc_perf_cmd_map[] = {
    {
        .cmd_bits = g_urpc_perf,
        .cmd_num = sizeof(g_urpc_perf) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_PERF,
        .cmd_id = URPC_U16_FAIL,
    },
    {
        .cmd_bits = g_urpc_perf_with_thresh,
        .cmd_num = sizeof(g_urpc_perf_with_thresh) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_PERF,
        .cmd_id = URPC_U16_FAIL,
    },
};

static int g_urpc_stats[] = {URPC_CMD_BITS_STATS};
static int g_urpc_stats_by_queue_id[] = {URPC_CMD_BITS_STATS, URPC_CMD_BITS_QUEUE_ID};
static urpc_cmd_map_t g_urpc_stats_cmd_map[] = {
    {
        .cmd_bits = g_urpc_stats,
        .cmd_num = sizeof(g_urpc_stats) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_STAT,
        .cmd_id = (uint16_t)URPC_STATS_CMD_ID_GET,
    },
    {
        .cmd_bits = g_urpc_stats_by_queue_id,
        .cmd_num = sizeof(g_urpc_stats_by_queue_id) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_STAT,
        .cmd_id = (uint16_t)URPC_STATS_CMD_ID_GET_BY_QID,
    }
};

static int g_urpc_queue_info[] = {URPC_CMD_BITS_QUEUE_INFO};
static int g_urpc_queue_info_by_client_chid[] = {URPC_CMD_BITS_QUEUE_INFO, URPC_CMD_BITS_CLIENT_CHANNEL};
static int g_urpc_queue_info_by_server_chid[] = {URPC_CMD_BITS_QUEUE_INFO, URPC_CMD_BITS_SERVER_CHANNEL};
static int g_urpc_queue_info_by_queue_id[] = {URPC_CMD_BITS_QUEUE_INFO, URPC_CMD_BITS_QUEUE_ID};
static urpc_cmd_map_t g_urpc_queue_info_cmd_map[] = {
    {
        .cmd_bits = g_urpc_queue_info,
        .cmd_num = sizeof(g_urpc_queue_info) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_LOCAL_ALL,
    },
    {
        .cmd_bits = g_urpc_queue_info_by_client_chid,
        .cmd_num = sizeof(g_urpc_queue_info_by_client_chid) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_BY_CLIENT_CHID,
    },
    {
        .cmd_bits = g_urpc_queue_info_by_server_chid,
        .cmd_num = sizeof(g_urpc_queue_info_by_server_chid) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_BY_SERVER_CHID,
    },
    {
        .cmd_bits = g_urpc_queue_info_by_queue_id,
        .cmd_num = sizeof(g_urpc_queue_info_by_queue_id) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_QUEUE,
        .cmd_id = (uint16_t)URPC_QUEUE_CMD_ID_BY_QID,
    },
};

static int g_urpc_handshaker[] = {URPC_CMD_BITS_HANDSHAKER};
static int g_urpc_handshaker_by_task_id[] = {
    URPC_CMD_BITS_HANDSHAKER, URPC_CMD_BITS_CLIENT_CHANNEL, URPC_CMD_BITS_HANDSHAKER_ID
};
static urpc_cmd_map_t g_urpc_handshaker_cmd_map[] = {
    {
        .cmd_bits = g_urpc_handshaker,
        .cmd_num = sizeof(g_urpc_handshaker) / sizeof(int),
        .module_id = (uint16_t)URPC_IPC_MODULE_HANDSHAKER,
        .cmd_id = (uint16_t)URPC_HANDSHAKER_CMD_ID_ALL_HANDSHAKER,
    }, {
        .cmd_bits = g_urpc_handshaker_by_task_id,
        .cmd_num = sizeof(g_urpc_handshaker_by_task_id) / sizeof(int),
        .module_id = (uint16_t)URPC_IPC_MODULE_HANDSHAKER,
        .cmd_id = (uint16_t)URPC_HANDSHAKER_CMD_ID_BY_TASK_ID,
    }
};

static urpc_cmd_map_t g_urpc_cmd_map[] = {
    {
        .cmd_bits = g_urpc_version_cmd_bits,
        .cmd_num = sizeof(g_urpc_version_cmd_bits) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_VERSION,
        .cmd_id = (uint16_t)URPC_VERSION_CMD_ID_GET,
    },
    {
        .cmd_bits = g_urpc_dbuf_cmd_bits,
        .cmd_num = sizeof(g_urpc_dbuf_cmd_bits) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_DBUF,
        .cmd_id = (uint16_t)URPC_DBUF_CMD_ID_GET,
    },
    {
        .cmd_bits = g_urpc_channel_cmd_bits,
        .cmd_num = sizeof(g_urpc_channel_cmd_bits) / sizeof(int),
        .cmd_set = NULL,
        .cmd_set_num = 0,
        .module_id = (uint16_t)URPC_IPC_MODULE_CHANNEL,
        .cmd_id = URPC_U16_FAIL,
    },
    {
        .cmd_bits = g_urpc_perf_cmd_bits,
        .cmd_num = sizeof(g_urpc_perf_cmd_bits) / sizeof(int),
        .cmd_set = g_urpc_perf_cmd_map,
        .cmd_set_num = sizeof(g_urpc_perf_cmd_map) / sizeof(urpc_cmd_map_t),
        .module_id = (uint16_t)URPC_IPC_MODULE_PERF,
        .cmd_id = URPC_U16_FAIL,
    },
    {
        .cmd_bits = g_urpc_stats_cmd_bits,
        .cmd_num = sizeof(g_urpc_perf_cmd_bits) / sizeof(int),
        .cmd_set = g_urpc_stats_cmd_map,
        .cmd_set_num = sizeof(g_urpc_stats_cmd_map) / sizeof(urpc_cmd_map_t),
    },
    {
        .cmd_bits = g_urpc_queue_info_cmd_bits,
        .cmd_num = sizeof(g_urpc_queue_info_cmd_bits) / sizeof(int),
        .cmd_set = g_urpc_queue_info_cmd_map,
        .cmd_set_num = sizeof(g_urpc_queue_info_cmd_map) / sizeof(urpc_cmd_map_t),
    },
    {
        .cmd_bits = g_urpc_handshaker_cmd_bits,
        .cmd_num = sizeof(g_urpc_handshaker_cmd_bits) / sizeof(int),
        .cmd_set = g_urpc_handshaker_cmd_map,
        .cmd_set_num = sizeof(g_urpc_handshaker_cmd_map) / sizeof(urpc_cmd_map_t),
    }
};

#define URPC_CMD_MAP_NUM (sizeof(g_urpc_cmd_map) / sizeof(urpc_cmd_map_t))

// clang-format off
static struct option g_long_options[] = {
    {"file-path", required_argument, NULL, 'f'},
    {"pid", required_argument, NULL, 'p'},

    {"stats", no_argument, NULL, 's'},
    {"version", no_argument, NULL, 'V'},
    {"queue-info", no_argument, NULL, 'a'},
    {"client-channel", required_argument, NULL, 'C'},
    {"server-channel", required_argument, NULL, 'S'},
    {"queue-id", required_argument, NULL, 'q'},
    {"dbuf-usage", no_argument, NULL, 'D'},
    {"perf", required_argument, NULL, 'P'},
    {"thresh", required_argument, NULL, 't'},
    {"channel", optional_argument, NULL, 'c'},
    {"handshaker-info", no_argument, NULL, 'T'},
    {"task-id", required_argument, NULL, 'i'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};
// clang-format on

static void usage(void)
{
    (void)printf("Usage:\n");
    (void)printf("  -f, --file-path                             file path of unix domain socket, must be specified\n");
    (void)printf("  -p, --pid                                   pid of urpc process\n");
    (void)printf("  -V, --version                               show urpc version\n");
    (void)printf("  -h, --help                                  show help info\n\n");
    (void)printf("IO latency statistic:\n");
    (void)printf("This corresponds to command group, and you can specify two options at the same time.\n");
    (void)printf("  --perf=<cmd>                                urpc performance stats, 0: PERF_START, 1: PERF_STOP, "
                 "2: PERF_CLEAR\n");
    (void)printf("  --thresh=<t1,t2,...>                        perf record thresh value in nanosecond for quantile "
                 "calculation, support maximum 8 configurations\n\n");
    (void)printf("Show urpc statistics:\n");
    (void)printf("This corresponds to command group, and you can specify two options at the same time.\n");
    (void)printf("  -s, --stats                                 show urpc statistics\n");
    (void)printf("  --queue-id=<qid>                            show urpc queue statistics by qid\n\n");
    (void)printf("Query queue transmit information usage:\n");
    (void)printf("This corresponds to command group, and you can specify two options at the same time.\n");
    (void)printf("  --queue-info                                list all local queue transmit information\n");
    (void)printf("  --client-channel=<chid>                     list all local and remote queue transmit information"
        " in this client channel\n");
    (void)printf("  --server-channel=<chid>                     list all local and remote queue transmit information"
        " in this server channel\n");
    (void)printf("  --queue-id=<qid>                            show queue info by qid\n\n");
    (void)printf("Dynamic buffer usage:\n");
    (void)printf("  --dbuf-usage                                show dynamic buffer usage in different"
        " categories\n\n");
    (void)printf("Query channel information usage:\n");
    (void)printf("  --channel=<chid>                            show channel info by chid, support optional argument"
        "\n\n");
    (void)printf("Query task information usage:\n");
    (void)printf("This corresponds to command group, and you can specify multiple options at the same time.\n");
    (void)printf("  --handshaker-info                           show all handshaker information,"
        "print handshaker in global table\n\n");
    (void)printf("  --client-channel=<chid>                     handshaker cmd group,"
        "should be set with --task-id\n");
    (void)printf("  --task-id=<tid>                             handshaker cmd group,"
        "should be set with --client-channel\n\n");
}

/* normal case and group case list:
--------------------------------------------------------------------------------
-V   --dbuf-usage(D)   --channel(c)   -P   -s              --queue-info(a)
--------------------------------------------------------------------------------
                                      -t   --queue-id(q)   --client-channel(C)
--------------------------------------------------------------------------------
                                                           --server-channel(S)
--------------------------------------------------------------------------------
                                                           --queue-id(q)
--------------------------------------------------------------------------------
*/

static bool match_set(int *source, int source_len, int *target, int target_len)
{
    if (target_len != source_len) {
        return false;
    }

    for (int i = 0; i < target_len; i++) {
        if (target[i] != source[i]) {
            return false;
        }
    }
    return true;
}

static bool match_cmd_set(urpc_admin_config_t *cfg, urpc_cmd_map_t *cmd_map, int cmd_map_num, int *target,
    int target_len)
{
    if (cmd_map == NULL) {
        return true;
    }

    for (int i = 0; i < cmd_map_num; i++) {
        if (match_set(cmd_map[i].cmd_bits, cmd_map[i].cmd_num, target, target_len)) {
            cfg->module_id = cmd_map[i].module_id;
            cmd_map[i].cmd_id != URPC_U16_FAIL ? cfg->cmd_id = cmd_map[i].cmd_id : 0;
            return true;
        }
    }

    return false;
}

int admin_cfg_check(urpc_admin_config_t *cfg)
{
    urpc_bitmap_t bitmap = (urpc_bitmap_t)(uintptr_t)&cfg->bitmap;
    for (int i = 0; i < (int)URPC_CMD_MAP_NUM; i++) {
        if (!urpc_bitmap_is_set(bitmap, g_urpc_cmd_map[i].cmd_bits[0])) {
            continue;
        }
        cfg->module_id = g_urpc_cmd_map[i].module_id;
        g_urpc_cmd_map[i].cmd_id != URPC_U16_FAIL ? cfg->cmd_id = g_urpc_cmd_map[i].cmd_id : 0;

        int cmd_set[CASE_BITMAP_SIZE] = {0};
        int cmd_set_num = 0;
        for (int j = 0; j < g_urpc_cmd_map[i].cmd_num; j++) {
            if (urpc_bitmap_is_set(bitmap, g_urpc_cmd_map[i].cmd_bits[j])) {
                urpc_bitmap_set0(bitmap, g_urpc_cmd_map[i].cmd_bits[j]);
                cmd_set[cmd_set_num] = g_urpc_cmd_map[i].cmd_bits[j];
                cmd_set_num++;
            }
        }

        if (!match_cmd_set(cfg, g_urpc_cmd_map[i].cmd_set, g_urpc_cmd_map[i].cmd_set_num, cmd_set, cmd_set_num)) {
            (void)printf("Invalid command group\n");
            return -1;
        }

        if (urpc_bitmap_find_next_bit(bitmap, CASE_BITMAP_SIZE, 0) != CASE_BITMAP_SIZE) {
            (void)printf("Invalid command combination\n");
            return -1;
        }

        if (cfg->module_id == URPC_U16_FAIL || cfg->cmd_id == URPC_U16_FAIL) {
            (void)printf("Invalid command combination.\n");
            return -1;
        }

        return 0;
    }

    return -1;
}

static int parse_numeric_param(char *str, uint64_t *numeric_param)
{
    char *end;
    errno = 0;
    uint64_t val = strtoul(str, &end, 0);
    if (errno != 0 || *end != '\0') {
        printf("invalid input param, need u64 numeric input\n");
        return -1;
    }

    *numeric_param = val;
    return 0;
}

static int parse_threshold(const char *thresh, urpc_admin_config_t *cfg)
{
    char param[PARSE_THRESHOLD_STRING_SIZE] = {0};
    char *num = NULL;
    uint64_t thresh_val = 0;

    (void)snprintf(param, PARSE_THRESHOLD_STRING_SIZE, "%s", thresh);
    cfg->perf.count_thresh_num = 0;
    num = strtok(param, ",");
    if (num == NULL) {
        (void)printf("invalid input param, empty threshold\n");
        return -1;
    }

    while (num != NULL) {
        if (parse_numeric_param(num, &thresh_val) != 0) {
            return -1;
        }

        if (cfg->perf.count_thresh_num >= URPC_PERF_QUANTILE_MAX_NUM) {
            (void)printf("The IO thresh number has reached the maximum %u, "
                         "the input setting will be discard.\n",
                URPC_PERF_QUANTILE_MAX_NUM);
            return 0;
        }

        cfg->perf.count_thresh[cfg->perf.count_thresh_num++] = thresh_val;
        num = strtok(NULL, ",");
    }

    return 0;
}

int urpc_admin_args_parse(int argc, char **argv, urpc_admin_config_t *cfg)
{
    if (argc == 1) {
        usage();
        return -1;
    }

    cfg->channel_id = URPC_U32_FAIL;
    cfg->module_id = URPC_U16_FAIL;
    cfg->cmd_id = URPC_U16_FAIL;
    uint64_t numeric_param = 0;
    urpc_bitmap_t bitmap = (urpc_bitmap_t)(uintptr_t)&cfg->bitmap;

    while (1) {
        int c = getopt_long(argc, argv, "Vhf:p:s", g_long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'f':
                (void)snprintf(cfg->path, PATH_MAX + 1, "%s", optarg);
                break;
            case 'p':
                if (parse_numeric_param(optarg, &numeric_param) != 0) {
                    return -1;
                }
                cfg->pid = (uint32_t)numeric_param;
                break;
            case 'V':
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_VERSION);
                break;
            case 'P':
                // 0: start, 1: stop, 2: clear
                if (parse_numeric_param(optarg, &numeric_param) != 0) {
                    return -1;
                }
                if (numeric_param < URPC_PERF_CMD_MAX) {
                    cfg->cmd_id = (uint16_t)numeric_param;
                } else {
                    cfg->cmd_id = -1;
                }
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_PERF);
                break;
            case 's':
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_STATS);
                break;
            case 'a':
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_QUEUE_INFO);
                break;
            case 'C':
                if (parse_numeric_param(optarg, &numeric_param) != 0) {
                    return -1;
                }
                cfg->channel_id = numeric_param;
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_CLIENT_CHANNEL);
                break;
            case 'S':
                if (parse_numeric_param(optarg, &numeric_param) != 0) {
                    return -1;
                }
                cfg->channel_id = numeric_param;
                cfg->server_flag = 1;
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_SERVER_CHANNEL);
                break;
            case 'q':
                if (parse_numeric_param(optarg, &numeric_param) != 0) {
                    return -1;
                }
                cfg->queue_id = numeric_param;
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_QUEUE_ID);
                break;
            case 't':
                if (parse_threshold(optarg, cfg) != 0) {
                    return -1;
                }
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_THRESH);
                break;
            case 'D':
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_DBUF);
                break;
            case 'c':
                if (optarg != NULL) {
                    if (parse_numeric_param(optarg, &numeric_param) != 0) {
                        return -1;
                    }
                    cfg->channel_id = numeric_param;
                    cfg->cmd_id = (uint16_t)URPC_CHANNEL_CMD_ID_BY_CHID;
                } else {
                    cfg->cmd_id = (uint16_t)URPC_CHANNEL_CMD_ID_ALL_CHANNEL;
                }
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_CHANNEL);
                break;
            case 'i':
                if (parse_numeric_param(optarg, &numeric_param) != 0) {
                    return -1;
                }
                cfg->task_id = (int)numeric_param;
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_HANDSHAKER_ID);
                break;
            case 'T':
                urpc_bitmap_set1(bitmap, URPC_CMD_BITS_HANDSHAKER);
                break;
            case 'h':
                cfg->no_request = true;
                usage();
                return 0;
            default:
                usage();
                return -1;
        }
    }

    if (optind < argc || admin_cfg_check(cfg) != 0) {
        usage();
        return -1;
    }

    return 0;
}
