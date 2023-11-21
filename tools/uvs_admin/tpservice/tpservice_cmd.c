/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: 'uvs_admin tpservice/show' command implementation
 * Author: Jilei
 * Create: 2023-06-14
 * Note: We declared a series of macro functions to check parameters,
 *          for reducing repetition rate, and being easier to amend
 * History: 2023-06-14 Jilei Initial version
 */

#include <getopt.h>
#include <arpa/inet.h>
#include <errno.h>

#include "uvs_admin_cmd_client.h"
#include "tpservice_cmd.h"

UVS_ADMIN_BRANCH_SUBCMD_USAGE(tpservice)

uvs_admin_cmd_t g_uvs_admin_tpservice_cmd = {
    .command = "tpservice",
    .summary = "tpservice config cmd",
    .usage   = UVS_ADMIN_BRANCH_SUBCMD_USAGE_VAR(tpservice),
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_tpservice_cmd.subcmds)),
    .run     = uvs_admin_branch_subcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

enum tpservice_opts {
#define TPSERVICE_OPT_HELP_LONG "help"
    TPSERVICE_OPT_HELP_NUM = 0,
};

/* long options */
static const struct option g_tpservice_show_long_options[] = {
    {TPSERVICE_OPT_HELP_LONG,      no_argument,       NULL, TPSERVICE_OPT_HELP_NUM },
    {0,                            0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_tpservice_show_cmd_opt_usage[] = {
    {TPSERVICE_OPT_HELP_LONG,         "this command need none opt.\n" },
};

static const uvs_admin_cmd_usage_t g_tpservice_show_cmd_usage = {
    .opt_usage = g_tpservice_show_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_tpservice_show_cmd_opt_usage),
};

static int32_t tpservice_cmd_prep_args(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;

    optind = 1;
    for (;;) {
        ret = getopt_long(ctx->argc, ctx->argv, "+", g_tpservice_show_long_options, NULL);
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

        if (ret >= TPSERVICE_OPT_HELP_NUM) {
            uvs_admin_cmd_usages(ctx);
            return -EINVAL;
        }
    }

    return ret;
}

static void uvs_admin_print_tpservice(uvs_admin_service_show_rsp_t *show_rsp)
{
    char listen_ip[INET_ADDRSTRLEN] = {0};
    (void)inet_ntop(AF_INET, &show_rsp->service_ip, listen_ip, INET_ADDRSTRLEN);
    (void)printf(UVS_ADMIN_SHOW_PREFIX);
    (void)printf("server_ip                  : %s\n", listen_ip);
    (void)printf("port_id                    : %d\n", ntohs(show_rsp->port_id));
}

static int32_t uvs_admin_tpservice_showcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;

    uvs_admin_request_t req = {0};
    uvs_admin_response_t *rsp = NULL;
    char buf[MAX_MSG_LEN] = {0};

    /*
     * show can not take args, prep_agrs will return -1,
     * and ctx->argc must be 0
     */
    ret = tpservice_cmd_prep_args(ctx);
    if (ret != 0 && (ctx->argc != 0)) {
        return ret;
    }

    req.cmd_type = UVS_ADMIN_SERVICE_SHOW;
    req.req_len = 0;

    rsp = client_get_rsp(ctx, &req, buf);
    if (rsp == NULL) {
        return -EIO;
    }

    uvs_admin_service_show_rsp_t *show_rsp = (uvs_admin_service_show_rsp_t *)rsp->rsp;
    uvs_admin_print_tpservice(show_rsp);

    return 0;
}

uvs_admin_cmd_t g_uvs_admin_tpservice_show_cmd = {
    .command = "show",
    .summary = "show tpservice config",
    .usage = &g_tpservice_show_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_tpservice_show_cmd.subcmds)),
    .run = uvs_admin_tpservice_showcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_ONE,
};

static uvs_admin_cmd_t *g_uvs_admin_tpservice_subcmds[] = {
    &g_uvs_admin_tpservice_show_cmd,
};

REGISTER_UVS_ADMIN_COMMANDS(g_uvs_admin_tpservice_cmd, g_uvs_admin_tpservice_subcmds)
