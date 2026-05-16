/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: perf sub-command source file for urma_admin
 * Author: Ma Chuan
 * Create: 2025-07-15
 * Note:
 * History: 2025-07-15   create file
 */

#include <errno.h>
#include <netlink/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "urma_cmd.h"
#include "urma_private.h"
#include "urma_types.h"

#include "admin_log.h"
#include "admin_netlink.h"
#include "admin_parameters.h"
#include "admin_cmd.h"

enum ub_perf_record_type {
	UB_PERF_URMA_CMD_CREATE_JETTY,
	UB_PERF_CORE_CREATE_JETTY,
	UB_PERF_AGG_CREATE_JETTY,
	UB_PERF_UDMA_CREATE_JETTY,
	UB_PERF_URMA_CMD_CREATE_CTX,
	UB_PERF_CORE_ALLOC_UCONTEXT,
	UB_PERF_AGG_ALLOC_UCONTEXT,
	UB_PERF_UDMA_ALLOC_UCONTEXT,
	UB_PERF_URMA_CMD_CREATE_JFCE,
	UB_PERF_URMA_CMD_CREATE_JFC,
	UB_PERF_CORE_CREATE_JFC,
	UB_PERF_AGG_CREATE_JFC,
	UB_PERF_UDMA_CREATE_JFC,
	UB_PERF_URMA_CMD_CREATE_JFR,
	UB_PERF_CORE_CREATE_JFR,
	UB_PERF_AGG_CREATE_JFR,
	UB_PERF_UDMA_CREATE_JFR,
	UB_PERF_URMA_CMD_CREATE_JFS,
	UB_PERF_CORE_CREATE_JFS,
	UB_PERF_AGG_CREATE_JFS,
	UB_PERF_UDMA_CREATE_JFS,
	UB_PERF_URMA_CMD_REGISTER_SEG,
	UB_PERF_CORE_REGISTER_SEG,
	UB_PERF_AGG_REGISTER_SEG,
	UB_PERF_UDMA_REGISTER_SEG,
	UB_PERF_URMA_CMD_ALLOC_TOKEN_ID,
	UB_PERF_CORE_ALLOC_TOKEN_ID,
	UB_PERF_UDMA_ALLOC_TOKEN_ID,
	UB_PERF_URMA_CMD_IMPORT_JETTY_EX,
	UB_PERF_CORE_IMPORT_JETTY,
	UB_PERF_AGG_IMPORT_JETTY,
	UB_PERF_UDMA_IMPORT_JETTY,
	UB_PERF_URMA_CMD_IMPORT_JFR_EX,
	UB_PERF_CORE_IMPORT_JFR,
	UB_PERF_AGG_IMPORT_JFR,
	UB_PERF_UDMA_IMPORT_JFR,
	UB_PERF_URMA_CMD_BIND_JETTY_EX,
	UB_PERF_CORE_BIND_JETTY,
	UB_PERF_UDMA_BIND_JETTY,
	UB_PERF_URMA_CMD_IMPORT_SEG,
	UB_PERF_CORE_IMPORT_SEG,
	UB_PERF_AGG_IMPORT_SEG,
	UB_PERF_UDMA_IMPORT_SEG,
	UB_PERF_RECORD_TYPE_MAX,
};

static const char *ub_perf_type_names[UB_PERF_RECORD_TYPE_MAX] = {
	"URMA_CMD_CREATE_JETTY",
	"CORE_CREATE_JETTY",
	"AGG_CREATE_JETTY",
	"UDMA_CREATE_JETTY",
	"URMA_CMD_CREATE_CTX",
	"CORE_ALLOC_UCONTEXT",
	"AGG_ALLOC_UCONTEXT",
	"UDMA_ALLOC_UCONTEXT",
	"URMA_CMD_CREATE_JFCE",
	"URMA_CMD_CREATE_JFC",
	"CORE_CREATE_JFC",
	"AGG_CREATE_JFC",
	"UDMA_CREATE_JFC",
	"URMA_CMD_CREATE_JFR",
	"CORE_CREATE_JFR",
	"AGG_CREATE_JFR",
	"UDMA_CREATE_JFR",
	"URMA_CMD_CREATE_JFS",
	"CORE_CREATE_JFS",
	"AGG_CREATE_JFS",
	"UDMA_CREATE_JFS",
	"URMA_CMD_REGISTER_SEG",
	"CORE_REGISTER_SEG",
	"AGG_REGISTER_SEG",
	"UDMA_REGISTER_SEG",
	"URMA_CMD_ALLOC_TOKEN_ID",
	"CORE_ALLOC_TOKEN_ID",
	"UDMA_ALLOC_TOKEN_ID",
	"URMA_CMD_IMPORT_JETTY_EX",
	"CORE_IMPORT_JETTY",
	"AGG_IMPORT_JETTY",
	"UDMA_IMPORT_JETTY",
	"URMA_CMD_IMPORT_JFR_EX",
	"CORE_IMPORT_JFR",
	"AGG_IMPORT_JFR",
	"UDMA_IMPORT_JFR",
	"URMA_CMD_BIND_JETTY_EX",
	"CORE_BIND_JETTY",
	"UDMA_BIND_JETTY",
	"URMA_CMD_IMPORT_SEG",
	"CORE_IMPORT_SEG",
	"AGG_IMPORT_SEG",
	"UDMA_IMPORT_SEG",
};

typedef struct admin_perf_record_stat {
    uint32_t record_type;
    uint64_t count;
    uint64_t min_ns;
    uint64_t max_ns;
    uint64_t avg_ns;
    uint64_t p90_ns;
    uint64_t p99_ns;
    uint64_t p9999_ns;
} admin_perf_record_stat_t;

typedef struct admin_core_latency_stat {
    uint32_t version;
    admin_perf_record_stat_t perf_stat_table[UB_PERF_RECORD_TYPE_MAX];
} admin_core_latency_stat_t;

typedef struct admin_core_cmd_perf_show {
    struct {
        admin_core_latency_stat_t stat;
    } out;
} admin_core_cmd_perf_show_t;

static int cmd_perf_usage(admin_config_t *cfg)
{
    (void)cfg;
    printf("Usage:\n"
           "  urma_admin perf start   Start DFX collection (clear history and restart)\n"
           "  urma_admin perf stop    Stop DFX collection\n"
           "  urma_admin perf show    Show DFX statistics results\n"
           "\n"
           "Description:\n"
           "  Control plane DFX (Diagnostic Function) latency tracer.\n"
           "  'start' enables collection and clears previous results.\n"
           "  'stop' disables collection, keeping current results.\n"
           "  'show' retrieves and displays current DFX statistics.\n");
    return 0;
}

static int cmd_perf_start(admin_config_t *cfg)
{
    (void)cfg;
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_PERF_START, 0);
    if (msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    int ret = admin_nl_send_recv_msg_default(msg);
    if (ret != 0) {
        printf("Failed to start perf, ret: %d\n", ret);
        return ret;
    }

    printf("Perf collection started.\n");
    return 0;
}

static int cmd_perf_stop(admin_config_t *cfg)
{
    (void)cfg;
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_PERF_STOP, 0);
    if (msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    int ret = admin_nl_send_recv_msg_default(msg);
    if (ret != 0) {
        printf("Failed to stop perf, ret: %d\n", ret);
        return ret;
    }

    printf("Perf collection stopped.\n");
    return 0;
}

static void cmd_perf_print_stat(const admin_core_latency_stat_t *stat)
{
    printf("+----------------------+----------+----------+----------+----------+"
           "----------+----------+----------+\n");
    printf("  Type                 | samples  | avg[ns]  | min[ns]  | max[ns]  |"
           " p90[ns]  | p99[ns]  | p9999[ns]\n");
    printf("+----------------------+----------+----------+----------+----------+"
           "----------+----------+----------+\n");

    for (uint32_t i = 0; i < UB_PERF_RECORD_TYPE_MAX; i++) {
        const admin_perf_record_stat_t *rec = &stat->perf_stat_table[i];
        if (rec->count == 0) {
            continue;
        }
        const char *name = (i < UB_PERF_RECORD_TYPE_MAX) ? ub_perf_type_names[i] : "unknown";
        printf("  %-20s | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu\n",
               name, rec->count, rec->avg_ns, rec->min_ns, rec->max_ns,
               rec->p90_ns, rec->p99_ns, rec->p9999_ns);
    }

    printf("+----------------------+----------+----------+----------+----------+"
           "----------+----------+----------+\n");
}

static int cmd_perf_show(admin_config_t *cfg)
{
    (void)cfg;
    admin_core_cmd_perf_show_t arg = {0};

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_PERF_SHOW, 0);
    if (msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    admin_nl_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(arg));
    admin_nl_put_u64(msg, UBCORE_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)&arg);

    int ret = admin_nl_send_recv_msg_default(msg);
    if (ret != 0) {
        printf("Failed to show perf, ret: %d\n", ret);
        return ret;
    }

    printf("\n[Kernel DFX Statistics] version: %u\n", arg.out.stat.version);
    cmd_perf_print_stat(&arg.out.stat);

    return 0;
}

static const admin_cmd_t perf_cmds[] = {
    {NULL, cmd_perf_usage},
    {"start", cmd_perf_start},
    {"stop", cmd_perf_stop},
    {"show", cmd_perf_show},
    {0},
};

int admin_cmd_perf(admin_config_t *cfg)
{
    return exec_cmd(cfg, perf_cmds);
}
