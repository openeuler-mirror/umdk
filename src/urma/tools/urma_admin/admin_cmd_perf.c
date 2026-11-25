/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: perf sub-command source file for urma_admin
 * Author: Chen Yongcheng
 * Create: 2026-05-25
 * Note:
 * History: 2026-05-25   create file
 */

#include <errno.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "urma_cmd.h"
#include "urma_private.h"
#include "urma_types.h"

#include "admin_cmd_perf_layout.h"
#include "admin_netlink.h"
#include "admin_parameters.h"
#include "admin_cmd.h"

static const char *const ub_perf_type_names[ADMIN_PERF_RECORD_TYPE_MAX] = {
    [PERF_URMA_CMD_CREATE_JETTY] = "URMA_CMD_CREATE_JETTY",
    [PERF_CORE_CREATE_JETTY] = "CORE_CREATE_JETTY",
    [PERF_AGG_CREATE_JETTY] = "AGG_CREATE_JETTY",
    [PERF_UB_CREATE_JETTY] = "UB_CREATE_JETTY",
    [PERF_URMA_CMD_CREATE_CTX] = "URMA_CMD_CREATE_CTX",
    [PERF_CORE_ALLOC_UCONTEXT] = "CORE_ALLOC_UCONTEXT",
    [PERF_AGG_ALLOC_UCONTEXT] = "AGG_ALLOC_UCONTEXT",
    [PERF_UB_ALLOC_UCONTEXT] = "UB_ALLOC_UCONTEXT",
    [PERF_URMA_CMD_CREATE_JFCE] = "URMA_CMD_CREATE_JFCE",
    [PERF_URMA_CMD_CREATE_JFC] = "URMA_CMD_CREATE_JFC",
    [PERF_CORE_CREATE_JFC] = "CORE_CREATE_JFC",
    [PERF_AGG_CREATE_JFC] = "AGG_CREATE_JFC",
    [PERF_UB_CREATE_JFC] = "UB_CREATE_JFC",
    [PERF_URMA_CMD_CREATE_JFR] = "URMA_CMD_CREATE_JFR",
    [PERF_CORE_CREATE_JFR] = "CORE_CREATE_JFR",
    [PERF_AGG_CREATE_JFR] = "AGG_CREATE_JFR",
    [PERF_UB_CREATE_JFR] = "UB_CREATE_JFR",
    [PERF_URMA_CMD_CREATE_JFS] = "URMA_CMD_CREATE_JFS",
    [PERF_CORE_CREATE_JFS] = "CORE_CREATE_JFS",
    [PERF_AGG_CREATE_JFS] = "AGG_CREATE_JFS",
    [PERF_UB_CREATE_JFS] = "UB_CREATE_JFS",
    [PERF_URMA_CMD_REGISTER_SEG] = "URMA_CMD_REGISTER_SEG",
    [PERF_CORE_REGISTER_SEG] = "CORE_REGISTER_SEG",
    [PERF_AGG_REGISTER_SEG] = "AGG_REGISTER_SEG",
    [PERF_UB_REGISTER_SEG] = "UB_REGISTER_SEG",
    [PERF_URMA_CMD_ALLOC_TOKEN_ID] = "URMA_CMD_ALLOC_TOKEN_ID",
    [PERF_CORE_ALLOC_TOKEN_ID] = "CORE_ALLOC_TOKEN_ID",
    [PERF_UB_ALLOC_TOKEN_ID] = "UB_ALLOC_TOKEN_ID",
    [PERF_URMA_CMD_IMPORT_JETTY_EX] = "URMA_CMD_IMPORT_JETTY_EX",
    [PERF_CORE_IMPORT_JETTY] = "CORE_IMPORT_JETTY",
    [PERF_AGG_IMPORT_JETTY] = "AGG_IMPORT_JETTY",
    [PERF_UB_GET_TP_LIST] = "UB_GET_TP_LIST",
    [PERF_UB_ACTIVE_TP] = "UB_ACTIVE_TP",
    [PERF_UB_IMPORT_JETTY_EX] = "UB_IMPORT_JETTY_EX",
    [PERF_URMA_CMD_IMPORT_JFR_EX] = "URMA_CMD_IMPORT_JFR_EX",
    [PERF_CORE_IMPORT_JFR] = "CORE_IMPORT_JFR",
    [PERF_AGG_IMPORT_JFR] = "AGG_IMPORT_JFR",
    [PERF_UB_IMPORT_JFR] = "UB_IMPORT_JFR",
    [PERF_URMA_CMD_BIND_JETTY_EX] = "URMA_CMD_BIND_JETTY_EX",
    [PERF_CORE_BIND_JETTY] = "CORE_BIND_JETTY",
    [PERF_UB_BIND_JETTY] = "UB_BIND_JETTY",
    [PERF_URMA_CMD_IMPORT_SEG] = "URMA_CMD_IMPORT_SEG",
    [PERF_CORE_IMPORT_SEG] = "CORE_IMPORT_SEG",
    [PERF_AGG_IMPORT_SEG] = "AGG_IMPORT_SEG",
    [PERF_UB_IMPORT_SEG] = "UB_IMPORT_SEG",
    [PERF_URMA_CMD_UNIMPORT_SEG] = "URMA_CMD_UNIMPORT_SEG",
    [PERF_CORE_UNIMPORT_SEG] = "CORE_UNIMPORT_SEG",
    [PERF_AGG_UNIMPORT_SEG] = "AGG_UNIMPORT_SEG",
    [PERF_UB_UNIMPORT_SEG] = "UB_UNIMPORT_SEG",
    [PERF_URMA_CMD_UNBIND_JETTY] = "URMA_CMD_UNBIND_JETTY",
    [PERF_CORE_UNBIND_JETTY] = "CORE_UNBIND_JETTY",
    [PERF_UB_DEACTIVE_TP] = "UB_DEACTIVE_TP",
    [PERF_UB_UNBIND_JETTY] = "UB_UNBIND_JETTY",
    [PERF_URMA_CMD_UNIMPORT_JETTY] = "URMA_CMD_UNIMPORT_JETTY",
    [PERF_CORE_UNIMPORT_JETTY] = "CORE_UNIMPORT_JETTY",
    [PERF_UB_UNIMPORT_JETTY] = "UB_UNIMPORT_JETTY",
    [PERF_URMA_CMD_UNIMPORT_JFR] = "URMA_CMD_UNIMPORT_JFR",
    [PERF_CORE_UNIMPORT_JFR] = "CORE_UNIMPORT_JFR",
    [PERF_UB_UNIMPORT_JFR] = "UB_UNIMPORT_JFR",
    [PERF_URMA_CMD_FREE_TOKEN_ID] = "URMA_CMD_FREE_TOKEN_ID",
    [PERF_CORE_FREE_TOKEN_ID] = "CORE_FREE_TOKEN_ID",
    [PERF_UB_FREE_TOKEN_ID] = "UB_FREE_TOKEN_ID",
    [PERF_URMA_CMD_UNREGISTER_SEG] = "URMA_CMD_UNREGISTER_SEG",
    [PERF_CORE_UNREGISTER_SEG] = "CORE_UNREGISTER_SEG",
    [PERF_AGG_UNREGISTER_SEG] = "AGG_UNREGISTER_SEG",
    [PERF_UB_UNREGISTER_SEG] = "UB_UNREGISTER_SEG",
    [PERF_URMA_CMD_DELETE_JETTY] = "URMA_CMD_DELETE_JETTY",
    [PERF_CORE_DELETE_JETTY] = "CORE_DELETE_JETTY",
    [PERF_AGG_DESTROY_JETTY] = "AGG_DESTROY_JETTY",
    [PERF_UB_DESTROY_JETTY] = "UB_DESTROY_JETTY",
    [PERF_URMA_CMD_DELETE_JFS] = "URMA_CMD_DELETE_JFS",
    [PERF_CORE_DELETE_JFS] = "CORE_DELETE_JFS",
    [PERF_AGG_DESTROY_JFS] = "AGG_DESTROY_JFS",
    [PERF_UB_DESTROY_JFS] = "UB_DESTROY_JFS",
    [PERF_URMA_CMD_DELETE_JFR] = "URMA_CMD_DELETE_JFR",
    [PERF_CORE_DELETE_JFR] = "CORE_DELETE_JFR",
    [PERF_AGG_DESTROY_JFR] = "AGG_DESTROY_JFR",
    [PERF_UB_DESTROY_JFR] = "UB_DESTROY_JFR",
    [PERF_URMA_CMD_DELETE_JFC] = "URMA_CMD_DELETE_JFC",
    [PERF_CORE_DELETE_JFC] = "CORE_DELETE_JFC",
    [PERF_AGG_DESTROY_JFC] = "AGG_DESTROY_JFC",
    [PERF_UB_DESTROY_JFC] = "UB_DESTROY_JFC",
};

typedef struct admin_perf_show_ctx {
    admin_core_latency_stat_t stat;
    int ret;
    bool received;
} admin_perf_show_ctx_t;

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
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_PERF_START, 0, UBCORE_GENL);
    if (msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    int ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    admin_nl_free_msg(msg);
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
    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_PERF_STOP, 0, UBCORE_GENL);
    if (msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    int ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    admin_nl_free_msg(msg);
    if (ret != 0) {
        printf("Failed to stop perf, ret: %d\n", ret);
        return ret;
    }

    printf("Perf collection stopped.\n");
    return 0;
}

static size_t cmd_perf_get_record_stride(size_t payload_len)
{
    const size_t compact_size = sizeof(admin_core_latency_stat_t);
    const size_t kabi_size = offsetof(admin_core_latency_stat_t, perf_stat_table) +
                             ADMIN_PERF_RECORD_TYPE_MAX * sizeof(admin_perf_record_stat_kabi_t);

    if (payload_len == compact_size) {
        return sizeof(admin_perf_record_stat_t);
    }
    if (payload_len == kabi_size) {
        return sizeof(admin_perf_record_stat_kabi_t);
    }

    printf("Unsupported perf stat payload length: %zu, expected %zu or %zu\n",
           payload_len, compact_size, kabi_size);
    return 0;
}

static int cmd_perf_decode_stat(const struct nlattr *attr, admin_core_latency_stat_t *stat)
{
    const uint8_t *payload;
    size_t payload_len;
    size_t record_stride;
    size_t table_offset;

    if (attr == NULL || stat == NULL) {
        return -EINVAL;
    }

    payload_len = (size_t)nla_len(attr);
    record_stride = cmd_perf_get_record_stride(payload_len);
    if (record_stride == 0) {
        return -EPROTONOSUPPORT;
    }

    payload = nla_data(attr);
    if (payload == NULL) {
        return -EINVAL;
    }

    table_offset = offsetof(admin_core_latency_stat_t, perf_stat_table);
    (void)memset(stat, 0, sizeof(*stat));
    (void)memcpy(&stat->version, payload, sizeof(stat->version));
    for (uint32_t i = 0; i < ADMIN_PERF_RECORD_TYPE_MAX; i++) {
        const uint8_t *record = payload + table_offset + i * record_stride;

        (void)memcpy(&stat->perf_stat_table[i], record,
                     sizeof(stat->perf_stat_table[i]));
    }

    return 0;
}

static void cmd_perf_print_stat(const admin_core_latency_stat_t *stat)
{
    printf("+--------------------------+----------+----------+----------+----------+"
           "----------+----------+----------+\n");
    printf("  Type                     | samples  | avg[ns]  | min[ns]  | max[ns]  |"
           " p90[ns]  | p99[ns]  | p9999[ns]\n");
    printf("+--------------------------+----------+----------+----------+----------+"
           "----------+----------+----------+\n");

    for (uint32_t i = 0; i < ADMIN_PERF_RECORD_TYPE_MAX; i++) {
        const admin_perf_record_stat_t *rec = &stat->perf_stat_table[i];

        if (rec->count == 0) {
            continue;
        }
        if (rec->record_type >= ADMIN_PERF_RECORD_TYPE_MAX) {
            printf("  unknown record type: %u\n", rec->record_type);
            continue;
        }

        const char *name = ub_perf_type_names[rec->record_type];
        if (name == NULL) {
            name = "unknown";
        }
        printf("  %-24s | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu | %-8lu\n",
               name, rec->count, rec->avg_ns, rec->min_ns, rec->max_ns,
               rec->p90_ns, rec->p99_ns, rec->p9999_ns);
    }

    printf("+--------------------------+----------+----------+----------+----------+"
           "----------+----------+----------+\n");
}

static int cmd_perf_show_cb(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attrs[UBCORE_ATTR_AFTER_LAST] = {0};
    admin_perf_show_ctx_t *ctx = (admin_perf_show_ctx_t *)arg;
    struct nlattr *attr;
    int ret;

    ret = nla_parse(attrs, UBCORE_ATTR_AFTER_LAST - 1,
                    genlmsg_attrdata(genlhdr, 0),
                    genlmsg_attrlen(genlhdr, 0), NULL);
    if (ret != 0) {
        ctx->ret = ret;
        return NL_STOP;
    }

    attr = attrs[UBCORE_ATTR_PERF_STAT];
    ret = cmd_perf_decode_stat(attr, &ctx->stat);
    if (ret != 0) {
        ctx->ret = ret;
        return NL_STOP;
    }
    ctx->received = true;

    return NL_STOP;
}

static void cmd_perf_print_jfce_cnt(void)
{
    urma_jfce_cnt_info_t jfce_info[URMA_JFCE_CNT_MAX_DEV_NUM] = {0};
    uint32_t jfce_cnt = 0;
    urma_status_t ret = urma_get_jfce_cnt_info(jfce_info, &jfce_cnt);
    if (ret != URMA_SUCCESS || jfce_cnt == 0) {
        return;
    }

    printf("\n[JFCE Count Statistics]\n");
    printf("+----------------------+----------------------+----------------------+\n");
    printf("  Device               | total_cnt            | thresh_cnt\n");
    printf("+----------------------+----------------------+----------------------+\n");
    for (uint32_t i = 0; i < jfce_cnt; i++) {
        printf("  %-20s | %-20lu | %-20lu\n",
            jfce_info[i].dev_name,
            jfce_info[i].jfce_total_cnt,
            jfce_info[i].jfce_thresh_cnt);
    }
    printf("+----------------------+----------------------+----------------------+\n");
}

static int cmd_perf_show(admin_config_t *cfg)
{
    (void)cfg;
    admin_perf_show_ctx_t ctx = {0};

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_PERF_SHOW, 0, UBCORE_GENL);
    if (msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    int ret = admin_nl_send_recv_msg(msg, cmd_perf_show_cb, &ctx, UBCORE_GENL);
    admin_nl_free_msg(msg);
    if (ret != 0 || ctx.ret != 0 || !ctx.received) {
        ret = (ret != 0) ? ret : (ctx.ret != 0 ? ctx.ret : -ENODATA);
        printf("Failed to show perf, ret: %d\n", ret);
        return ret;
    }

    printf("\n[Kernel DFX Statistics] version: %u\n", ctx.stat.version);
    cmd_perf_print_stat(&ctx.stat);

    cmd_perf_print_jfce_cnt();

    return 0;
}

int admin_cmd_perf(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_perf_usage(cfg);
    }
    static const admin_cmd_t perf_cmds[] = {
        {NULL, cmd_perf_usage},
        {"start", cmd_perf_start},
        {"stop", cmd_perf_stop},
        {"show", cmd_perf_show},
        {0},
    };
    return exec_cmd(cfg, perf_cmds);
}
