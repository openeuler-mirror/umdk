/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: npu sub-command source file for urma_admin
 * Author: Xu Chao
 * Create: 2026-11-12
 * Note:
 * History: 2026-11-12   create file
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ub_util.h"

#include "admin_netlink.h"

#include "admin_cmd.h"

static int cmd_npu_usage(admin_config_t *cfg)
{
    (void)cfg;
    (void)printf("Usage:\n"
                 "  urma_admin npu <NPU_ID> show dev <DEV> jfc   [JFC_ID]\n"
                 "  urma_admin npu <NPU_ID> show dev <DEV> jfs   [JFS_ID]\n"
                 "  urma_admin npu <NPU_ID> show dev <DEV> jfr   [JFR_ID]\n"
                 "  urma_admin npu <NPU_ID> show dev <DEV> jetty [JETTY_ID]\n"
                 "  urma_admin npu <NPU_ID> show dev <DEV> rc    [RC_ID]\n"
                 "  urma_admin npu <NPU_ID> show dev <DEV> tp    [TP_ID]\n"
                 "  urma_admin npu <NPU_ID> show dev <DEV> tpreuse\n"
                 "  urma_admin npu <NPU_ID> set log_level <0-%u>\n"
                 "\n"
                 "Options:\n"
                 "  <NPU_ID>   NPU id of the remote device\n"
                 "  <DEV>      Device name on the NPU side\n"
                 "  <JFC_ID>   JFC id, optional; omit to list all JFCs\n"
                 "  <JFS_ID>   JFS id, optional; omit to list all JFSs\n"
                 "  <JFR_ID>   JFR id, optional; omit to list all JFRs\n"
                 "  <JETTY_ID> Jetty id, optional; omit to list all Jettys\n"
                 "  <RC_ID>    RC id, optional; omit to list all RCs\n"
                 "  <TP_ID>    TP id, optional; omit to list the tpid table\n"
                 "  <0-%u>      NPU log level\n",
                 (uint32_t)URMA_VLOG_LEVEL_DEBUG,
                 (uint32_t)URMA_VLOG_LEVEL_DEBUG);
    return 0;
}

static bool npu_is_supported_res(const char *res)
{
    return strcmp(res, "jfc") == 0 || strcmp(res, "jfs") == 0 ||
           strcmp(res, "jfr") == 0 || strcmp(res, "jetty") == 0 ||
           strcmp(res, "rc") == 0 || strcmp(res, "tp") == 0 ||
           strcmp(res, "tpreuse") == 0;
}

static int cmd_npu_show(admin_config_t *cfg)
{
    char *arg = pop_arg(cfg);
    if (arg == NULL || strcmp(arg, "dev") != 0) {
        (void)printf("Usage: urma_admin npu <NPU_ID> show dev <DEV> <resource> [ID]\n");
        return -EINVAL;
    }

    arg = pop_arg(cfg);
    if (arg == NULL) {
        (void)printf("Missing device name.\n");
        return -EINVAL;
    }

    arg = pop_arg(cfg);
    if (arg == NULL) {
        (void)printf("Missing resource type.\n");
        return -EINVAL;
    }
    if (!npu_is_supported_res(arg)) {
        (void)printf("Invalid resource type: %s.\n", arg);
        return -EINVAL;
    }

    /*
     * TODO: Send URMA_CORE_H2D_QUERY_RES or URMA_CORE_H2D_SHOW_TPID_* with
     * NPU_ID/DEV_NAME/query-key attributes, then print the dump result. The
     * kernel H2D dump handlers currently return -EOPNOTSUPP.
     */
    (void)printf("NPU resource query is not implemented yet, npu: %u, resource: %s.\n",
                 cfg->npu_id, arg);
    return -EOPNOTSUPP;
}

static int cmd_npu_set(admin_config_t *cfg)
{
    char *arg = pop_arg(cfg);
    if (arg == NULL || strcmp(arg, "log_level") != 0) {
        (void)printf("Usage: urma_admin npu <NPU_ID> set log_level <0-%u>\n",
                     (uint32_t)URMA_VLOG_LEVEL_DEBUG);
        return -EINVAL;
    }

    arg = pop_arg(cfg);
    if (arg == NULL) {
        (void)printf("Missing log level.\n");
        return -EINVAL;
    }

    uint32_t level;
    if (ub_str_to_u32(arg, &level) != 0 || level >= URMA_VLOG_LEVEL_MAX) {
        (void)printf("Invalid log level: %s, expected 0-%u.\n", arg,
                     (uint32_t)URMA_VLOG_LEVEL_DEBUG);
        return -EINVAL;
    }

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_H2D_SET_LOG_LEVEL, 0, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    int ret = admin_nl_put_u32(msg, UBCORE_ATTR_NPU_ID, cfg->npu_id);
    if (ret == 0) {
        ret = admin_nl_put_u32(msg, UBCORE_ATTR_LOG_LEVEL, level);
    }
    if (ret == 0) {
        ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    }
    admin_nl_free_msg(msg);
    if (ret < 0) {
        (void)printf("Failed to set NPU log level, npu: %u, level: %u, ret: %d.\n",
                     cfg->npu_id, level, ret);
        return ret;
    }

    return 0;
}

int admin_cmd_npu(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_npu_usage(cfg);
    }

    char *arg = pop_arg(cfg);
    if (arg == NULL) {
        (void)printf("Missing NPU_ID.\n");
        return cmd_npu_usage(cfg);
    }

    uint32_t npu_id;
    if (ub_str_to_u32(arg, &npu_id) != 0) {
        (void)printf("Invalid NPU_ID: %s.\n", arg);
        return -EINVAL;
    }
    cfg->npu_id = npu_id;

    if (cfg->argc == 0) {
        return cmd_npu_usage(cfg);
    }

    static const admin_cmd_t cmds[] = {
        {NULL, cmd_npu_usage},
        {"show", cmd_npu_show},
        {"set", cmd_npu_set},
        {0},
    };
    return exec_cmd(cfg, cmds);
}
