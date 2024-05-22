/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of root command of uvs_admin
 * Author: Ji Lei
 * Create: 2023-06-14
 * Note:
 * History: 2023-06-14 Ji Lei Initial version
 */
#include <errno.h>
#include <getopt.h>

#include "uvs_admin_cmd.h"
#include "tpservice/tpservice_cmd.h"
#include "vport_table/vport_table_cmd.h"
#include "sip_table/sip_table_cmd.h"
#include "dip_table/dip_table_cmd.h"
#include "live_migrate_table/live_migrate_table_cmd.h"
#include "global_cfg/global_cfg_cmd.h"

enum ROOT_OPT {
    #define ROOT_OPT_HELP_LONG "help"
        ROOT_OPT_HELP_NUM = 0,
};

static const struct option g_rootcmd_long_options[] = {
    {ROOT_OPT_HELP_LONG, no_argument, NULL, ROOT_OPT_HELP_NUM},
    {0, 0, 0, 0},
};

static const uvs_admin_opt_usage_t g_rootcmd_opt_usage[] = {
    {ROOT_OPT_HELP_LONG, "display this help and exit", false},
};

static const uvs_admin_cmd_usage_t g_rootcmd_usage = {
    .opt_usage = g_rootcmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_rootcmd_opt_usage),
};

static int32_t uvs_admin_rootcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int32_t status = 0;
    int             ret;

    optind = 1;
    for (;;) {
        ret = getopt_long(ctx->argc, ctx->argv, "+",
                          g_rootcmd_long_options, NULL);
        if (ret == -1) {
            /*
             * getopt didn't recognize this argument. It might be a sub-command,
             * or, bad option. Just return and let sub-command handlers to
             * process it.
             */
            ctx->argc -= optind;
            ctx->argv += optind;
            break;
        }

        switch (ret) {
            case ROOT_OPT_HELP_NUM:
                uvs_admin_cmd_usages(ctx);
                status = -EBADMSG;
                break;
            case '?':
                /* Fall through */
            default:
                status = -EINVAL;
                break;
        }
        if (status != 0) {
            break;
        }
    }
    return status;
}

uvs_admin_cmd_t g_uvs_admin_root_cmd = {
    .command = "root",
    .summary = "uvs_admin root command namespace",
    .usage   = &g_rootcmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_root_cmd.subcmds)),
    .run     = uvs_admin_rootcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

static uvs_admin_cmd_t *g_uvs_admin_root_subcmds[] = {
    &g_uvs_admin_tpservice_cmd,   /* uvs_admin tpservice */
    &g_uvs_admin_vport_table_cmd, /* uvs_admin vport table */
    &g_uvs_admin_sip_table_cmd,   /* uvs_admin sip table */
    &g_uvs_admin_dip_table_cmd,   /* uvs_admin dip table */
    &g_uvs_admin_live_migrate_table_cmd,   /* uvs_admin live_migrate table */
    &g_uvs_admin_global_cfg_cmd,   /* uvs_admin global cfg */
};

REGISTER_UVS_ADMIN_COMMANDS(g_uvs_admin_root_cmd, g_uvs_admin_root_subcmds)
