/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: 'uvs_admin live_migrate add/show/del' command implementation
 * Author: sunfang
 * Create: 2023-08-02
 * Note: We declared a series of macro functions to check parameters,
 *          for reducing repetition rate, and being easier to amend
 * History: 2023-08-02 SunFang Initial version
 */

#include <getopt.h>
#include <arpa/inet.h>

#include "uvs_admin_cmd_util.h"
#include "uvs_admin_cmd_client.h"
#include "live_migrate_table_cmd.h"

UVS_ADMIN_BRANCH_SUBCMD_USAGE(live_migrate_table)

uvs_admin_cmd_t g_uvs_admin_live_migrate_table_cmd = {
    .command = "live_migrate_table",
    .summary = "live_migrate_table config cmd",
    .usage   = UVS_ADMIN_BRANCH_SUBCMD_USAGE_VAR(live_migrate_table),
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_live_migrate_table_cmd.subcmds)),
    .run     = uvs_admin_branch_subcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

enum live_migrate_table_opts {
#define LIVE_MIGRATE_TABLE_OPT_HELP_LONG "help"
    LIVE_MIGRATE_TABLE_OPT_HELP_NUM = 0,

#define LIVE_MIGRATE_TABLE_OPT_DEV_NAME_LONG "dev_name"
    LIVE_MIGRATE_TABLE_OPT_DEV_NAME_NUM,

#define LIVE_MIGRATE_TABLE_OPT_FE_IDX_LONG "fe_idx"
    LIVE_MIGRATE_TABLE_OPT_FE_IDX_NUM,

#define LIVE_MIGRATE_TABLE_OPT_UVS_IP_LONG   "uvs_ip"
    LIVE_MIGRATE_TABLE_OPT_UVS_IP_NUM,

    LIVE_MIGRATE_TABLE_OPT_MAX_NUM,
};

typedef int (*live_migrate_table_parse)(uvs_admin_live_migrate_table_args_t *args, const char *_optarg);

static const struct opt_arg g_live_migrate_table_opt_args[LIVE_MIGRATE_TABLE_OPT_MAX_NUM] = {
    [LIVE_MIGRATE_TABLE_OPT_HELP_NUM] = {LIVE_MIGRATE_TABLE_OPT_HELP_LONG, ARG_TYPE_OTHERS},
    [LIVE_MIGRATE_TABLE_OPT_DEV_NAME_NUM] = {LIVE_MIGRATE_TABLE_OPT_DEV_NAME_LONG, ARG_TYPE_STR},
    [LIVE_MIGRATE_TABLE_OPT_FE_IDX_NUM] = {LIVE_MIGRATE_TABLE_OPT_FE_IDX_LONG, ARG_TYPE_NUM},
    [LIVE_MIGRATE_TABLE_OPT_UVS_IP_NUM] = {LIVE_MIGRATE_TABLE_OPT_UVS_IP_LONG, ARG_TYPE_STR},
};

/* live migrate table show long options */
static const struct option g_live_migrate_table_show_long_options[] = {
    {LIVE_MIGRATE_TABLE_OPT_HELP_LONG,           no_argument,         NULL, LIVE_MIGRATE_TABLE_OPT_HELP_NUM },
    {LIVE_MIGRATE_TABLE_OPT_DEV_NAME_LONG,       required_argument,   NULL, LIVE_MIGRATE_TABLE_OPT_DEV_NAME_NUM },
    {LIVE_MIGRATE_TABLE_OPT_FE_IDX_LONG,         required_argument,   NULL, LIVE_MIGRATE_TABLE_OPT_FE_IDX_NUM },
    {0,                                          0,                   0,    0 },
};

static const uvs_admin_opt_usage_t g_live_migrate_table_show_cmd_opt_usage[] = {
    {LIVE_MIGRATE_TABLE_OPT_HELP_LONG,           "display this help and exit", false},
    {LIVE_MIGRATE_TABLE_OPT_DEV_NAME_LONG,       "specifies the name of tpf device", true},
    {LIVE_MIGRATE_TABLE_OPT_FE_IDX_LONG,         "fe_idx is determined by tpf device", true},
};

static const uvs_admin_cmd_usage_t g_live_migrate_table_show_cmd_usage = {
    .opt_usage = g_live_migrate_table_show_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_live_migrate_table_show_cmd_opt_usage),
};

/* live_migrate table add long options */
static const struct option g_live_migrate_table_add_long_options[] = {
    {LIVE_MIGRATE_TABLE_OPT_HELP_LONG,           no_argument,         NULL, LIVE_MIGRATE_TABLE_OPT_HELP_NUM },
    {LIVE_MIGRATE_TABLE_OPT_DEV_NAME_LONG,       required_argument,   NULL, LIVE_MIGRATE_TABLE_OPT_DEV_NAME_NUM },
    {LIVE_MIGRATE_TABLE_OPT_FE_IDX_LONG,         required_argument,   NULL, LIVE_MIGRATE_TABLE_OPT_FE_IDX_NUM },
    {LIVE_MIGRATE_TABLE_OPT_UVS_IP_LONG,         required_argument,   NULL, LIVE_MIGRATE_TABLE_OPT_UVS_IP_NUM},
    {0,                                          0,                   0,    0 },
};

static const uvs_admin_opt_usage_t g_live_migrate_table_add_cmd_opt_usage[] = {
    {LIVE_MIGRATE_TABLE_OPT_HELP_LONG,           "display this help and exit", false},
    {LIVE_MIGRATE_TABLE_OPT_DEV_NAME_LONG,       "specifies the name of tpf device", true},
    {LIVE_MIGRATE_TABLE_OPT_FE_IDX_LONG,         "fe_idx is determined by tpf device", true},
    {LIVE_MIGRATE_TABLE_OPT_UVS_IP_LONG,         "ip addr of remote uvs", true},
};

static const uvs_admin_cmd_usage_t g_live_migrate_table_add_cmd_usage = {
    .opt_usage = g_live_migrate_table_add_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_live_migrate_table_add_cmd_opt_usage),
};

/* live_migrate table del long options */
static const struct option g_live_migrate_table_del_long_options[] = {
    {LIVE_MIGRATE_TABLE_OPT_HELP_LONG,      no_argument,       NULL, LIVE_MIGRATE_TABLE_OPT_HELP_NUM },
    {LIVE_MIGRATE_TABLE_OPT_DEV_NAME_LONG,  required_argument,   NULL, LIVE_MIGRATE_TABLE_OPT_DEV_NAME_NUM },
    {LIVE_MIGRATE_TABLE_OPT_FE_IDX_LONG,    required_argument, NULL, LIVE_MIGRATE_TABLE_OPT_FE_IDX_NUM },
    {0,                                     0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_live_migrate_table_del_cmd_opt_usage[] = {
    {LIVE_MIGRATE_TABLE_OPT_HELP_LONG,      "display this help and exit", false},
    {LIVE_MIGRATE_TABLE_OPT_DEV_NAME_LONG,  "specifies the name of tpf device", true},
    {LIVE_MIGRATE_TABLE_OPT_FE_IDX_LONG,    "fe_idx is determined by tpf device", true},
};

static const uvs_admin_cmd_usage_t g_live_migrate_table_del_cmd_usage = {
    .opt_usage = g_live_migrate_table_del_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_live_migrate_table_del_cmd_opt_usage),
};

static inline int parse_dev_name(uvs_admin_live_migrate_table_args_t *args, const char *_optarg)
{
    if (strnlen(_optarg, UVS_ADMIN_MAX_DEV_NAME) >= UVS_ADMIN_MAX_DEV_NAME) {
        return -EINVAL;
    }
    strcpy(args->dev_name, _optarg);
    args->mask.bs.dev_name = 1;
    return 0;
}

static inline int parse_fe_idx(uvs_admin_live_migrate_table_args_t *args, const char *_optarg)
{
    int ret;
    uint16_t num;

    ret = ub_str_to_u16(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    args->fe_idx = num;
    args->mask.bs.fe_idx = 1;
    return 0;
}

static inline int parse_dip(uvs_admin_live_migrate_table_args_t *args, const char *_optarg)
{
    int ret;

    ret = str_to_eid(_optarg, (urma_eid_t *)&args->uvs_ip);
    if (ret != 0) {
        return -EINVAL;
    }
    args->mask.bs.uvs_ip = 1;
    return 0;
}

static const live_migrate_table_parse g_live_migrate_table_parse[LIVE_MIGRATE_TABLE_OPT_MAX_NUM] = {
    [LIVE_MIGRATE_TABLE_OPT_DEV_NAME_NUM] = parse_dev_name,
    [LIVE_MIGRATE_TABLE_OPT_FE_IDX_NUM] = parse_fe_idx,
    [LIVE_MIGRATE_TABLE_OPT_UVS_IP_NUM] = parse_dip,
};

static int32_t live_migrate_table_cmd_prep_args(uvs_admin_cmd_ctx_t *ctx, const struct option *longopts,
                                                const struct opt_arg *optargs,
                                                uvs_admin_live_migrate_table_args_t *args)
{
    int32_t ret;
    int32_t status = 0;

    optind = 1;
    for (;;) {
        ret = getopt_long(ctx->argc, ctx->argv, "+", longopts, NULL);
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

        if ((ret >= LIVE_MIGRATE_TABLE_OPT_HELP_NUM) && (ret < LIVE_MIGRATE_TABLE_OPT_MAX_NUM)) {
            if (ret == LIVE_MIGRATE_TABLE_OPT_HELP_NUM) {
                uvs_admin_cmd_usages(ctx);
                status = -EINVAL;
                break;
            }
            status = g_live_migrate_table_parse[ret](args, optarg);
            if (status != 0) {
                (void)printf("ERR: invalid parameter --%s %s\n", optargs[ret].arg_name, optarg);
            }
        } else {
            status = -EINVAL;
        }

        if (status != 0) {
            break;
        }
    }

    return status;
}

static void uvs_admin_print_live_migrate(uint16_t fe_idx, uvs_admin_live_migrate_table_show_rsp_t *show_rsp)
{
    (void)printf(UVS_ADMIN_SHOW_PREFIX);
    (void)printf("fe_idx                     : %hu\n", fe_idx);
    (void)printf("dev_name                   : %s\n", show_rsp->dev_name);
    (void)printf("uvs_ip                     : "EID_FMT"\n", EID_ARGS(show_rsp->uvs_ip));
}

static int32_t uvs_admin_live_migrate_table_showcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_live_migrate_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = live_migrate_table_cmd_prep_args(ctx, g_live_migrate_table_show_long_options,
                                           g_live_migrate_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    if (args.mask.bs.dev_name == 0 || args.mask.bs.fe_idx == 0) {
        (void)printf("ERR: invalid parameter, must set dev_name/fe_idx, mask:%x\n", args.mask.value);
        return -EINVAL;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_live_migrate_table_show_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_LIVE_MIGRATE_TABLE_SHOW;
    req->req_len = (ssize_t)sizeof(uvs_admin_live_migrate_table_show_req_t);

    uvs_admin_live_migrate_table_show_req_t *live_migrate_table_req =
                                                       (uvs_admin_live_migrate_table_show_req_t *)req->req;
    live_migrate_table_req->fe_idx = args.fe_idx;
    (void)memcpy(live_migrate_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_live_migrate_table_show_rsp_t *show_rsp = (uvs_admin_live_migrate_table_show_rsp_t *)rsp->rsp;
    if (show_rsp->res != 0) {
        (void)printf("ERR: failed to show live_migrate_table info, ret: %d, fe_idx: %hu\n",
            show_rsp->res, live_migrate_table_req->fe_idx);
    } else {
        uvs_admin_print_live_migrate(live_migrate_table_req->fe_idx, show_rsp);
    }

    free(req);
    return 0;
}

static int32_t uvs_admin_live_migrate_table_addcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_live_migrate_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = live_migrate_table_cmd_prep_args(ctx, g_live_migrate_table_add_long_options,
                                           g_live_migrate_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    if (args.mask.bs.dev_name == 0 || args.mask.bs.fe_idx == 0 || args.mask.bs.uvs_ip == 0) {
        (void)printf("ERR: invalid parameter, must set dev_name/fe_idx/dip, mask:%x\n", args.mask.value);
        return -EINVAL;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_live_migrate_table_add_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_LIVE_MIGRATE_TABLE_ADD;
    req->req_len = (ssize_t)sizeof(uvs_admin_live_migrate_table_add_req_t);

    uvs_admin_live_migrate_table_add_req_t *live_migrate_table_req = (uvs_admin_live_migrate_table_add_req_t *)req->req;
    live_migrate_table_req->fe_idx = args.fe_idx;
    (void)memcpy(live_migrate_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);
    (void)memcpy(&live_migrate_table_req->uvs_ip, &args.uvs_ip, sizeof(uvs_admin_net_addr_t));

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_live_migrate_table_add_rsp_t *add_rsp = (uvs_admin_live_migrate_table_add_rsp_t *)rsp->rsp;
    if (add_rsp->res != 0) {
        (void)printf("ERR: failed to add live migrate, ret: %d.\n", add_rsp->res);
    }

    free(req);
    return 0;
}

static int32_t uvs_admin_live_migrate_table_delcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_live_migrate_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = live_migrate_table_cmd_prep_args(ctx, g_live_migrate_table_del_long_options,
                                           g_live_migrate_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    if (args.mask.bs.dev_name == 0 || args.mask.bs.fe_idx == 0) {
        (void)printf("ERR: invalid parameter, must set dev_name/fe_idx, mask:%x\n", args.mask.value);
        return -EINVAL;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_live_migrate_table_del_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_LIVE_MIGRATE_TABLE_DEL;
    req->req_len = (ssize_t)sizeof(uvs_admin_live_migrate_table_del_req_t);

    uvs_admin_live_migrate_table_del_req_t *live_migrate_table_req = (uvs_admin_live_migrate_table_del_req_t *)req->req;
    (void)memcpy(live_migrate_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);
    live_migrate_table_req->fe_idx = args.fe_idx;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_live_migrate_table_del_rsp_t *del_rsp = (uvs_admin_live_migrate_table_del_rsp_t *)rsp->rsp;
    if (del_rsp->res != 0) {
        (void)printf("ERR: failed to del live migrate, ret: %d.\n", del_rsp->res);
    }

    free(req);
    return 0;
}

uvs_admin_cmd_t g_uvs_admin_live_migrate_table_show_cmd = {
    .command = "show",
    .summary = "show live_migrate_table entry",
    .usage = &g_live_migrate_table_show_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_live_migrate_table_show_cmd.subcmds)),
    .run = uvs_admin_live_migrate_table_showcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

uvs_admin_cmd_t g_uvs_admin_live_migrate_table_add_cmd = {
    .command = "add",
    .summary = "add live_migrate_table entry",
    .usage = &g_live_migrate_table_add_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_live_migrate_table_add_cmd.subcmds)),
    .run = uvs_admin_live_migrate_table_addcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_FIVE,
};

uvs_admin_cmd_t g_uvs_admin_live_migrate_table_del_cmd = {
    .command = "del",
    .summary = "del live_migrate_table entry",
    .usage = &g_live_migrate_table_del_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_live_migrate_table_del_cmd.subcmds)),
    .run = uvs_admin_live_migrate_table_delcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

static uvs_admin_cmd_t *g_uvs_admin_live_migrate_table_subcmds[] = {
    &g_uvs_admin_live_migrate_table_show_cmd,
    &g_uvs_admin_live_migrate_table_add_cmd,
    &g_uvs_admin_live_migrate_table_del_cmd
};

REGISTER_UVS_ADMIN_COMMANDS(g_uvs_admin_live_migrate_table_cmd, g_uvs_admin_live_migrate_table_subcmds)
