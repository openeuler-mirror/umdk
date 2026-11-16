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
                 "  urma_admin npu <NPU_ID> show dev <DEV> tp    [TP_ID]   (not implemented yet)\n"
                 "  urma_admin npu <NPU_ID> show dev <DEV> tpreuse         (not implemented yet)\n"
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

static int npu_parse_res_type(const char *res, tool_res_key_type_t *type)
{
    if (strcmp(res, "jfc") == 0) {
        *type = TOOL_RES_KEY_JFC;
    } else if (strcmp(res, "jfs") == 0) {
        *type = TOOL_RES_KEY_JFS;
    } else if (strcmp(res, "jfr") == 0) {
        *type = TOOL_RES_KEY_JFR;
    } else if (strcmp(res, "jetty") == 0) {
        *type = TOOL_RES_KEY_JETTY;
    } else if (strcmp(res, "rc") == 0) {
        *type = TOOL_RES_KEY_RC;
    } else {
        (void)printf("Invalid resource type: %s, supported: jfc|jfs|jfr|jetty|rc\n", res);
        return -EINVAL;
    }
    return 0;
}

static void npu_print_query_error(int ret)
{
    switch (ret) {
        case -ENODEV:
            (void)printf("NPU or device not found, check NPU_ID and DEV.\n");
            break;
        case -EOPNOTSUPP:
            (void)printf("NPU resource query is not supported.\n");
            break;
        case -EMSGSIZE:
            (void)printf("NPU resource query result is too large.\n");
            break;
        case -EPERM:
        case -EACCES:
            (void)printf("Permission denied, run as root or grant CAP_NET_ADMIN.\n");
            break;
        case -EIO:
            (void)printf("H2D query failed, check that the H2D link is established.\n");
            break;
        case -EPROTO:
            (void)printf("H2D query returned malformed data.\n");
            break;
        case -EINVAL:
            (void)printf("Invalid NPU resource query parameters.\n");
            break;
        case -ENODATA:
            (void)printf("No NPU resource data returned.\n");
            break;
        default:
            (void)printf("NPU resource query failed, ret: %d.\n", ret);
            break;
    }
}

static int cmd_npu_show(admin_config_t *cfg)
{
    char *arg = pop_arg(cfg);
    if (arg == NULL || strcmp(arg, "dev") != 0) {
        (void)printf("Usage: urma_admin npu <NPU_ID> show dev <DEV> <resource> [ID]\n");
        return -EINVAL;
    }

    char *dev_name = pop_arg(cfg);
    if (dev_name == NULL) {
        (void)printf("Missing device name.\n");
        return -EINVAL;
    }

    char *res = pop_arg(cfg);
    if (res == NULL) {
        (void)printf("Missing resource type.\n");
        return -EINVAL;
    }
    /*
     * TODO: TPID list/state/reuse are C-phase work.
     */
    if (strcmp(res, "tp") == 0 || strcmp(res, "tpreuse") == 0) {
        (void)printf("NPU TPID query is not implemented yet.\n");
        return -EOPNOTSUPP;
    }

    tool_res_key_type_t type;
    int ret = npu_parse_res_type(res, &type);
    if (ret != 0) {
        return ret;
    }

    char *id_arg = pop_arg(cfg);
    uint32_t key = 0;
    uint32_t key_cnt = 0;
    if (id_arg != NULL) {
        ret = ub_str_to_u32(id_arg, &key);
        if (ret != 0) {
            (void)printf("Invalid resource ID: %s.\n", id_arg);
            return -EINVAL;
        }
        key_cnt = 1;
    }
    if (cfg->argc != 0) {
        (void)printf("Too many arguments.\n");
        return -EINVAL;
    }

    ret = admin_cmd_npu_query_res(cfg->npu_id, dev_name, type, key, key_cnt);
    if (ret != 0) {
        npu_print_query_error(ret);
        return ret;
    }

    return 0;
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
