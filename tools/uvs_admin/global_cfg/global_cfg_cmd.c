/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: 'uvs_admin global_cfg' command implementation
 * Author: Jilei
 * Create: 2023-07-23
 * Note: Declared a series of functions global_cfg
 *
 * History: 2023-07-23 Jilei Initial version
 */

#include <getopt.h>
#include <arpa/inet.h>

#include "uvs_admin_cmd_client.h"
#include "uvs_admin_cmd_util.h"
#include "global_cfg_cmd.h"

UVS_ADMIN_BRANCH_SUBCMD_USAGE(global_cfg)

uvs_admin_cmd_t g_uvs_admin_global_cfg_cmd = {
    .command = "global_cfg",
    .summary = "global_cfg config cmd",
    .usage   = UVS_ADMIN_BRANCH_SUBCMD_USAGE_VAR(global_cfg),
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_global_cfg_cmd.subcmds)),
    .run     = uvs_admin_branch_subcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

static char *g_mtu_str[UVS_ADMIN_MTU_CNT] = {
    [UVS_ADMIN_MTU_256] = "256",
    [UVS_ADMIN_MTU_512] = "512",
    [UVS_ADMIN_MTU_1024] = "1024",
    [UVS_ADMIN_MTU_2048] = "2048",
    [UVS_ADMIN_MTU_4096] = "4096",
    [UVS_ADMIN_MTU_8192] = "8192"
};

static char *g_slice_str[UVS_ADMIN_SLICE_CNT] = {
    [UVS_ADMIN_SLICE_32] = "32",
    [UVS_ADMIN_SLICE_64] = "64",
    [UVS_ADMIN_SLICE_128] = "128",
    [UVS_ADMIN_SLICE_256] = "256",
};

enum global_cfg_opts {
#define GLOBAL_CFG_OPT_HELP_LONG "help"
    GLOBAL_CFG_OPT_HELP_NUM = 0,

#define GLOBAL_CFG_OPT_MTU_LONG "mtu"
    GLOBAL_CFG_OPT_MTU_NUM,

#define GLOBAL_CFG_OPT_SLICE_LONG "slice"
    GLOBAL_CFG_OPT_SLICE_NUM,

#define GLOBAL_CFG_OPT_SUSPEND_PERIOD_LONG "suspend_period"
    GLOBAL_CFG_OPT_SUSPEND_PERIOD_NUM,

#define GLOBAL_CFG_OPT_SUSPEND_CNT_LONG "suspend_cnt"
    GLOBAL_CFG_OPT_SUSPEND_CNT_NUM,

#define GLOBAL_CFG_OPT_SUS2ERR_PERIOD_LONG "sus2err_period"
    GLOBAL_CFG_OPT_SUS2ERR_PERIOD_NUM,

#define GLOBAL_CFG_OPT_TP_FAST_DESTROY "tp_fast_destroy"
    GLOBAL_CFG_OPT_TP_FAST_DESTROY_NUM,

    GLOBAL_CFG_OPT_MAX_NUM,
};

static const struct opt_arg g_global_cfg_opt_args[GLOBAL_CFG_OPT_MAX_NUM] = {
    [GLOBAL_CFG_OPT_HELP_NUM]                   = {GLOBAL_CFG_OPT_HELP_LONG, ARG_TYPE_OTHERS},
    [GLOBAL_CFG_OPT_MTU_NUM]                    = {GLOBAL_CFG_OPT_MTU_LONG, ARG_TYPE_STR},
    [GLOBAL_CFG_OPT_SLICE_NUM]                  = {GLOBAL_CFG_OPT_SLICE_LONG, ARG_TYPE_STR},
    [GLOBAL_CFG_OPT_SUSPEND_PERIOD_NUM]         = {GLOBAL_CFG_OPT_SUSPEND_PERIOD_LONG, ARG_TYPE_NUM},
    [GLOBAL_CFG_OPT_SUSPEND_CNT_NUM]            = {GLOBAL_CFG_OPT_SUSPEND_CNT_LONG, ARG_TYPE_NUM},
    [GLOBAL_CFG_OPT_SUS2ERR_PERIOD_NUM]         = {GLOBAL_CFG_OPT_SUS2ERR_PERIOD_LONG, ARG_TYPE_NUM},
    [GLOBAL_CFG_OPT_TP_FAST_DESTROY_NUM]        = {GLOBAL_CFG_OPT_TP_FAST_DESTROY, ARG_TYPE_NUM},
};

/* global_cfg show long options */
static const struct option g_global_cfg_show_long_options[] = {
    {GLOBAL_CFG_OPT_HELP_LONG,      no_argument,       NULL, GLOBAL_CFG_OPT_HELP_NUM },
    {0,                             0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_global_cfg_show_cmd_opt_usage[] = {
    {GLOBAL_CFG_OPT_HELP_LONG,    "display this help and exit", false},
};

static const uvs_admin_cmd_usage_t g_global_cfg_show_cmd_usage = {
    .opt_usage = g_global_cfg_show_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_global_cfg_show_cmd_opt_usage),
};

/* global_cfg set options */
static const struct option g_global_cfg_set_long_options[] = {
    {GLOBAL_CFG_OPT_HELP_LONG,               no_argument,       NULL, GLOBAL_CFG_OPT_HELP_NUM },
    {GLOBAL_CFG_OPT_MTU_LONG,                required_argument, NULL, GLOBAL_CFG_OPT_MTU_NUM },
    {GLOBAL_CFG_OPT_SLICE_LONG,              required_argument, NULL, GLOBAL_CFG_OPT_SLICE_NUM },
    {GLOBAL_CFG_OPT_SUSPEND_PERIOD_LONG,     required_argument, NULL, GLOBAL_CFG_OPT_SUSPEND_PERIOD_NUM },
    {GLOBAL_CFG_OPT_SUSPEND_CNT_LONG,        required_argument, NULL, GLOBAL_CFG_OPT_SUSPEND_CNT_NUM },
    {GLOBAL_CFG_OPT_SUS2ERR_PERIOD_LONG,     required_argument, NULL, GLOBAL_CFG_OPT_SUS2ERR_PERIOD_NUM },
    {GLOBAL_CFG_OPT_TP_FAST_DESTROY,         required_argument, NULL, GLOBAL_CFG_OPT_TP_FAST_DESTROY_NUM },
    {0,                             0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_global_cfg_set_cmd_opt_usage[] = {
    {GLOBAL_CFG_OPT_HELP_LONG,              "display this help and exit", false},
    {GLOBAL_CFG_OPT_MTU_LONG,               "mtu [1024, 4096, 8192]", true},
    {GLOBAL_CFG_OPT_SLICE_LONG,             "packet fragment size[32, 64, 128, 256]", true},
    {GLOBAL_CFG_OPT_SUSPEND_PERIOD_LONG,    "suspend_period, default: 1000 us", false},
    {GLOBAL_CFG_OPT_SUSPEND_CNT_LONG,       "suspend_cnt, defalut: 3", false},
    {GLOBAL_CFG_OPT_SUS2ERR_PERIOD_LONG,    "sus2eer_period, defalut: 30000000us", false},
    {GLOBAL_CFG_OPT_TP_FAST_DESTROY,        "tp_fast_destroy[0, 1], defalut: 0", false},
};

static const uvs_admin_cmd_usage_t g_global_cfg_set_cmd_usage = {
    .opt_usage = g_global_cfg_set_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_global_cfg_set_cmd_opt_usage),
};

static int global_cfg_input_valid_mtu(uvs_admin_global_cfg_args_t *args, const char *_optarg)
{
    int i;
    for (i = 1; i < UVS_ADMIN_MTU_CNT; i++) {
        if (!strcmp(_optarg, g_mtu_str[i])) {
            if (i != UVS_ADMIN_MTU_1024 && i != UVS_ADMIN_MTU_4096 && i != UVS_ADMIN_MTU_8192) {
                (void)printf("ERR: invalid parameter mtu %s; valid range = [1024, 4096, 8192]\n",
                    g_mtu_str[i]);
                return -1;
            }

            args->mtu = (uvs_admin_mtu_t)i;
            args->mask.bs.mtu = 1;
            return 0;
        }
    }
    return -1;
}

static int global_cfg_input_valid_slice(uvs_admin_global_cfg_args_t *args, const char *_optarg)
{
    int i;
    for (i = 0; i < UVS_ADMIN_SLICE_CNT; i++) {
        if (!strcmp(_optarg, g_slice_str[i])) {
            args->slice = (uvs_admin_slice_t)(1 << UVS_ADMIN_SLICE_SHIFT(i));
            args->mask.bs.slice = 1;
            return 0;
        }
    }
    return -1;
}

static int global_cfg_input_valid_str(uvs_admin_global_cfg_args_t *args, const char *_optarg,
    const char *arg_name)
{
    int ret = 0;
    if (!strcmp(arg_name, GLOBAL_CFG_OPT_MTU_LONG)) {
        ret = global_cfg_input_valid_mtu(args, _optarg);
    }
    if (!strcmp(arg_name, GLOBAL_CFG_OPT_SLICE_LONG)) {
        ret = global_cfg_input_valid_slice(args, _optarg);
    }

    if (ret != 0) {
        (void)printf("ERR: invalid parameter --%s %s\n", arg_name, _optarg);
        return -EINVAL;
    }

    return 0;
}

static inline int global_cfg_input_range_check(uint32_t num, uint32_t range_min, uint32_t range_max)
{
    if (range_min <= num && num <= range_max) {
        return 0;
    }
    return -1;
}

static int global_cfg_get_valid_tp_fast_destroy(uint32_t num, bool *tp_fast_destroy)
{
    if (global_cfg_input_range_check(num, 0, 1) != 0) {
        (void)printf("ERR: invalid parameter range  tp_fast_destroy:%u; valid range = [0, 1]\n", num);
        return -1;
    }
    *tp_fast_destroy = (num != 0);
    return 0;
}

static int global_cfg_input_valid_num(uvs_admin_global_cfg_args_t *args, const char *_optarg,
    const char *arg_name)
{
    uint32_t num;
    int ret;
    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        (void)printf("ERR: invalid parameter --%s %s\n", arg_name, _optarg);
        return -EINVAL;
    }

    if (global_cfg_input_range_check(num, 0, UINT32_MAX) != 0) {
        (void)printf("ERR: invalid parameter range --%s %u; valid range = [%u, %u]\n",
            arg_name, num, 0, UINT32_MAX);
        return -EINVAL;
    }

    if (!strcmp(arg_name, GLOBAL_CFG_OPT_SUSPEND_PERIOD_LONG)) {
        args->suspend_period = num;
        args->mask.bs.suspend_period = 1;
    } else if (!strcmp(arg_name, GLOBAL_CFG_OPT_SUSPEND_CNT_LONG)) {
        args->suspend_cnt = num;
        args->mask.bs.suspend_cnt = 1;
    } else if (!strcmp(arg_name, GLOBAL_CFG_OPT_SUS2ERR_PERIOD_LONG)) {
        args->sus2err_period = num;
        args->mask.bs.sus2err_period = 1;
    } else if (!strcmp(arg_name, GLOBAL_CFG_OPT_TP_FAST_DESTROY)) {
        return global_cfg_get_valid_tp_fast_destroy(num, &args->tp_fast_destroy);
    } else {
        (void)printf("ERR: invalid parameter --%s %u\n", arg_name, num);
        return -EINVAL;
    }

    return 0;
}

static int32_t global_cfg_cmd_check_push_opt(uvs_admin_global_cfg_args_t *args, const char *_optarg,
    const char *arg_name, int arg_type)
{
    if (arg_type == ARG_TYPE_STR) {
        return global_cfg_input_valid_str(args, _optarg, arg_name);
    } else if (arg_type == ARG_TYPE_NUM) {
        return global_cfg_input_valid_num(args, _optarg, arg_name);
    }

    return 0;
}

static int32_t global_cfg_cmd_prep_args(uvs_admin_cmd_ctx_t *ctx, const struct option *longopts,
    const struct opt_arg *optargs, uvs_admin_global_cfg_args_t *args)
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

        if ((ret >= GLOBAL_CFG_OPT_HELP_NUM) && (ret < GLOBAL_CFG_OPT_MAX_NUM)) {
            if (ret == GLOBAL_CFG_OPT_HELP_NUM) {
                uvs_admin_cmd_usages(ctx);
                status = -EINVAL;
            } else {
                status = global_cfg_cmd_check_push_opt(args, optarg,
                    optargs[ret].arg_name, optargs[ret].arg_type);
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

static void uvs_admin_print_global_cfg_show(uvs_admin_response_t *rsp)
{
    uvs_admin_global_cfg_show_rsp_t *show_rsp = (uvs_admin_global_cfg_show_rsp_t *)rsp->rsp;
    (void)printf(UVS_ADMIN_SHOW_PREFIX);
    (void)printf("mtu                        : %u[%s]\n",
        (uint32_t)show_rsp->mtu_show, g_mtu_str[show_rsp->mtu_show]);
    (void)printf("slice                      : %u\n", show_rsp->slice >> UVS_ADMIN_SLICE_K_SHIFT);
    (void)printf("suspend_period             : %u\n", show_rsp->suspend_period);
    (void)printf("suspend_cnt                : %u\n", show_rsp->suspend_cnt);
    (void)printf("sus2err_period             : %u\n", show_rsp->sus2err_period);
    (void)printf("tp_fast_destroy            : %u\n", show_rsp->tp_fast_destroy);
}

static int32_t uvs_admin_global_cfg_show_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_global_cfg_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = global_cfg_cmd_prep_args(ctx, g_global_cfg_show_long_options, g_global_cfg_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_GLOBAL_CFG_SHOW;
    req->req_len = 0;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        (void)printf("ERR: failed to show global config.\n");
        free(req);
        return -EIO;
    }

    uvs_admin_print_global_cfg_show(rsp);

    free(req);
    return 0;
}

static int32_t uvs_admin_global_cfg_set_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_global_cfg_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = global_cfg_cmd_prep_args(ctx, g_global_cfg_set_long_options, g_global_cfg_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_global_cfg_set_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_GLOBAL_CFG_SET;
    req->req_len = (ssize_t)sizeof(uvs_admin_global_cfg_set_req_t);

    uvs_admin_global_cfg_set_req_t *mtu_set_req = (uvs_admin_global_cfg_set_req_t *)req->req;
    mtu_set_req->mask = args.mask;
    mtu_set_req->mtu = args.mtu;
    mtu_set_req->slice = args.slice;
    mtu_set_req->suspend_period = args.suspend_period;
    mtu_set_req->suspend_cnt = args.suspend_cnt;
    mtu_set_req->sus2err_period = args.sus2err_period;
    mtu_set_req->tp_fast_destroy = args.tp_fast_destroy;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        (void)printf("ERR: failed to implement global cfg\n");
        return -EIO;
    }

    uvs_admin_global_cfg_set_rsp_t *set_rsp = (uvs_admin_global_cfg_set_rsp_t *)rsp->rsp;

    if (set_rsp->ret != 0) {
        (void)printf("ERR: failed to set global config, ret: %d.\n", set_rsp->ret);
    }

    free(req);
    return 0;
}


uvs_admin_cmd_t g_uvs_admin_global_cfg_show_cmd = {
    .command = "show",
    .summary = "show global configuration",
    .usage = &g_global_cfg_show_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_global_cfg_show_cmd.subcmds)),
    .run = uvs_admin_global_cfg_show_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_ONE,
};

uvs_admin_cmd_t g_uvs_admin_global_cfg_set_cmd = {
    .command = "set",
    .summary = "set global configuration",
    .usage = &g_global_cfg_set_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_global_cfg_set_cmd.subcmds)),
    .run = uvs_admin_global_cfg_set_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

static uvs_admin_cmd_t *g_uvs_admin_global_cfg_subcmds[] = {
    &g_uvs_admin_global_cfg_show_cmd,
    &g_uvs_admin_global_cfg_set_cmd
};

REGISTER_UVS_ADMIN_COMMANDS(g_uvs_admin_global_cfg_cmd, g_uvs_admin_global_cfg_subcmds)