/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: 'uvs_admin dip_table show/add/del' command implementation
 * Author: ChenWen
 * Create: 2023-08-23
 * Note: Declared a series of  functions show/add/del dip_table
 *
 * History: 2023-08-23 ChenWen Initial version
 */

#include <getopt.h>
#include <arpa/inet.h>

#include "uvs_admin_cmd_client.h"
#include "dip_table_cmd.h"

UVS_ADMIN_BRANCH_SUBCMD_USAGE(dip_table)

uvs_admin_cmd_t g_uvs_admin_dip_table_cmd = {
    .command = "dip_table",
    .summary = "dip_table config cmd",
    .usage   = UVS_ADMIN_BRANCH_SUBCMD_USAGE_VAR(dip_table),
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_dip_table_cmd.subcmds)),
    .run     = uvs_admin_branch_subcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

enum dip_table_opts {
#define DIP_TABLE_OPT_HELP_LONG "help"
    DIP_TABLE_OPT_HELP_NUM = 0,

#define DIP_TABLE_OPT_DIP_LONG "dip"
    DIP_TABLE_OPT_DIP_NUM,

#define DIP_TABLE_OPT_PEER_TPSA_IP_LONG "peer_tpsa_ip"
    DIP_TABLE_OPT_PEER_TPSA_IP_NUM,

#define DIP_TABLE_OPT_UNDERLAY_EID_LONG "underlay_eid"
    DIP_TABLE_OPT_UNDERLAY_EID_NUM,

#define DIP_TABLE_OPT_NETADDR_BASE_EID_LONG "netaddr_base_eid"
    DIP_TABLE_OPT_NETADDR_BASE_EID_NUM,

#define DIP_TABLE_OPT_NETADDR_MAC_LONG "netaddr_mac"
    DIP_TABLE_OPT_NETADDR_MAC_NUM,

#define DIP_TABLE_OPT_NETADDR_IP_TYPE_LONG "netaddr_is_ipv6"
    DIP_TABLE_OPT_NETADDR_IP_TYPE_NUM,

#define DIP_TABLE_OPT_NEW_DIP_LONG "new_dip"
    DIP_TABLE_OPT_NEW_DIP_NUM,

    DIP_TABLE_OPT_MAX_NUM,
};

#define VALID_IS_IPV6_FLAG 1

static const struct opt_arg g_dip_table_opt_args[DIP_TABLE_OPT_MAX_NUM] = {
    [DIP_TABLE_OPT_HELP_NUM] = {DIP_TABLE_OPT_HELP_LONG, ARG_TYPE_OTHERS},
    [DIP_TABLE_OPT_DIP_NUM] = {DIP_TABLE_OPT_DIP_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_PEER_TPSA_IP_NUM] = {DIP_TABLE_OPT_PEER_TPSA_IP_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_UNDERLAY_EID_NUM] = {DIP_TABLE_OPT_UNDERLAY_EID_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_NETADDR_BASE_EID_NUM] = {DIP_TABLE_OPT_NETADDR_BASE_EID_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_NETADDR_MAC_NUM] = {DIP_TABLE_OPT_NETADDR_MAC_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_NETADDR_IP_TYPE_NUM] = {DIP_TABLE_OPT_NETADDR_IP_TYPE_LONG, ARG_TYPE_NUM},
    [DIP_TABLE_OPT_NEW_DIP_NUM] = {DIP_TABLE_OPT_NEW_DIP_LONG, ARG_TYPE_STR},
};

/* dip_table_show long options */
static const struct option g_dip_table_show_long_options[] = {
    {DIP_TABLE_OPT_HELP_LONG,  no_argument,       NULL, DIP_TABLE_OPT_HELP_NUM },
    {DIP_TABLE_OPT_DIP_LONG,   required_argument, NULL, DIP_TABLE_OPT_DIP_NUM },
    {0,                            0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_dip_table_show_cmd_opt_usage[] = {
    {DIP_TABLE_OPT_HELP_LONG,    "display this help and exit" },
    {DIP_TABLE_OPT_DIP_LONG,     "dip" },
};

static const uvs_admin_cmd_usage_t g_dip_table_show_cmd_usage = {
    .opt_usage = g_dip_table_show_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_dip_table_show_cmd_opt_usage),
};

/* dip_table_add long options */
static const struct option g_dip_table_add_long_options[] = {
    {DIP_TABLE_OPT_HELP_LONG,              no_argument,       NULL, DIP_TABLE_OPT_HELP_NUM },
    {DIP_TABLE_OPT_DIP_LONG,               required_argument, NULL, DIP_TABLE_OPT_DIP_NUM },
    {DIP_TABLE_OPT_PEER_TPSA_IP_LONG,      required_argument, NULL, DIP_TABLE_OPT_PEER_TPSA_IP_NUM },
    {DIP_TABLE_OPT_UNDERLAY_EID_LONG,      required_argument, NULL, DIP_TABLE_OPT_UNDERLAY_EID_NUM },
    {DIP_TABLE_OPT_NETADDR_BASE_EID_LONG,  required_argument, NULL, DIP_TABLE_OPT_NETADDR_BASE_EID_NUM },
    {DIP_TABLE_OPT_NETADDR_MAC_LONG,       required_argument, NULL, DIP_TABLE_OPT_NETADDR_MAC_NUM },
    {DIP_TABLE_OPT_NETADDR_IP_TYPE_LONG,   required_argument, NULL, DIP_TABLE_OPT_NETADDR_IP_TYPE_NUM },
    {0,                                    0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_dip_table_add_cmd_opt_usage[] = {
    {DIP_TABLE_OPT_HELP_LONG,             "display this help and exit" },
    {DIP_TABLE_OPT_DIP_LONG,              "dip need add" },
    {DIP_TABLE_OPT_PEER_TPSA_IP_LONG,     "peer tpsa ip need add" },
    {DIP_TABLE_OPT_UNDERLAY_EID_LONG,     "underylay eid need add" },
    {DIP_TABLE_OPT_NETADDR_BASE_EID_LONG, "netaddr base eid add" },
    {DIP_TABLE_OPT_NETADDR_MAC_LONG,      "netaddr mac need add" },
    {DIP_TABLE_OPT_NETADDR_IP_TYPE_LONG,  "netaddr ip type need add" },
};

static const uvs_admin_cmd_usage_t g_dip_table_add_cmd_usage = {
    .opt_usage = g_dip_table_add_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_dip_table_add_cmd_opt_usage),
};

/* dip_table_del long options */
static const struct option g_dip_table_del_long_options[] = {
    {DIP_TABLE_OPT_HELP_LONG,  no_argument,       NULL, DIP_TABLE_OPT_HELP_NUM },
    {DIP_TABLE_OPT_DIP_LONG,   required_argument, NULL, DIP_TABLE_OPT_DIP_NUM },
    {0,                            0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_dip_table_del_cmd_opt_usage[] = {
    {DIP_TABLE_OPT_HELP_LONG,    "display this help and exit" },
    {DIP_TABLE_OPT_DIP_LONG,     "dip need del" },
};

static const uvs_admin_cmd_usage_t g_dip_table_del_cmd_usage = {
    .opt_usage = g_dip_table_del_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_dip_table_del_cmd_opt_usage),
};

/* dip_table_modify long options */
static const struct option g_dip_table_modify_long_options[] = {
    {DIP_TABLE_OPT_HELP_LONG,              no_argument,       NULL, DIP_TABLE_OPT_HELP_NUM },
    {DIP_TABLE_OPT_DIP_LONG,               required_argument, NULL, DIP_TABLE_OPT_DIP_NUM },
    {DIP_TABLE_OPT_PEER_TPSA_IP_LONG,      required_argument, NULL, DIP_TABLE_OPT_PEER_TPSA_IP_NUM },
    {DIP_TABLE_OPT_UNDERLAY_EID_LONG,      required_argument, NULL, DIP_TABLE_OPT_UNDERLAY_EID_NUM },
    {DIP_TABLE_OPT_NETADDR_BASE_EID_LONG,  required_argument, NULL, DIP_TABLE_OPT_NETADDR_BASE_EID_NUM },
    {DIP_TABLE_OPT_NETADDR_MAC_LONG,       required_argument, NULL, DIP_TABLE_OPT_NETADDR_MAC_NUM },
    {DIP_TABLE_OPT_NETADDR_IP_TYPE_LONG,   required_argument, NULL, DIP_TABLE_OPT_NETADDR_IP_TYPE_NUM },
    {DIP_TABLE_OPT_NEW_DIP_LONG,           required_argument, NULL, DIP_TABLE_OPT_NEW_DIP_NUM },
    {0,                                    0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_dip_table_modify_cmd_opt_usage[] = {
    {DIP_TABLE_OPT_HELP_LONG,             "display this help and exit" },
    {DIP_TABLE_OPT_DIP_LONG,              "dip need modify" },
    {DIP_TABLE_OPT_PEER_TPSA_IP_LONG,     "peer tpsa ip need modify" },
    {DIP_TABLE_OPT_UNDERLAY_EID_LONG,     "underylay eid need modify" },
    {DIP_TABLE_OPT_NETADDR_BASE_EID_LONG, "netaddr base eid modify" },
    {DIP_TABLE_OPT_NETADDR_MAC_LONG,      "netaddr mac need modify" },
    {DIP_TABLE_OPT_NETADDR_IP_TYPE_LONG,  "netaddr ip type need modify" },
    {DIP_TABLE_OPT_NEW_DIP_LONG,          "new dip need modify" },
};

static const uvs_admin_cmd_usage_t g_dip_table_modify_cmd_usage = {
    .opt_usage = g_dip_table_modify_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_dip_table_modify_cmd_opt_usage),
};

static inline int dip_table_input_range_check(uint32_t num, uint32_t range_min, uint32_t range_max)
{
    if (range_min <= num && num <= range_max) {
        return 0;
    }
    return -1;
}

static int dip_table_input_valid_num(uvs_admin_dip_table_args_t *args, const char *_optarg,
    const char *arg_name)
{
    uint32_t num;
    int ret;
    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        (void)printf("invalid parameter --%s %s\n", arg_name, _optarg);
        return -EINVAL;
    }
    if (!strcmp(arg_name, DIP_TABLE_OPT_NETADDR_IP_TYPE_LONG)) {
        if (dip_table_input_range_check(num, 0, VALID_IS_IPV6_FLAG) != 0) {
            (void)printf("invalid parameter range --%s %u; valid range = [%u, %u]\n",
                arg_name, num, 0, VALID_IS_IPV6_FLAG);
            return -EINVAL;
        }
        args->net_addr.type = (bool)num;
        args->mask.bs.netaddr = 1;
    } else {
        (void)printf("invalid parameter --%s %s\n", arg_name, _optarg);
        return -EINVAL;
    }

    return 0;
}

static int dip_table_input_valid_str(uvs_admin_dip_table_args_t *args, const char *_optarg,
    const char *arg_name)
{
    int ret = 0;
    if (!strcmp(arg_name, DIP_TABLE_OPT_DIP_LONG)) {
        ret = str_to_eid(_optarg, &args->dip);
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_PEER_TPSA_IP_LONG)) {
        ret = str_to_eid(_optarg, &args->peer_tpsa_ip);
        args->mask.bs.peer_tpsa = 1;
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_UNDERLAY_EID_LONG)) {
        ret = str_to_eid(_optarg, &args->underlay_eid);
        args->mask.bs.underlay_eid = 1;
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_NETADDR_BASE_EID_LONG)) {
        ret = str_to_eid(_optarg, &args->net_addr.base);
        args->mask.bs.netaddr = 1;
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_NETADDR_MAC_LONG)) {
        ret = parse_mac(_optarg, args->net_addr.mac);
        args->mask.bs.netaddr = 1;
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_NEW_DIP_LONG)) {
        ret = str_to_eid(_optarg, &args->new_dip);
        args->mask.bs.dip = 1;
    } else {
        ret = -EINVAL;
    }

    if (ret != 0) {
        (void)printf("invalid parameter --%s %s\n", arg_name, _optarg);
        return -ret;
    }

    return 0;
}

static int32_t dip_table_cmd_check_push_opt(uvs_admin_dip_table_args_t *args, const char *_optarg,
    const char *arg_name, int arg_type)
{
    if (arg_type == ARG_TYPE_NUM) {
        return dip_table_input_valid_num(args, _optarg, arg_name);
    } else if (arg_type == ARG_TYPE_STR) {
        return dip_table_input_valid_str(args, _optarg, arg_name);
    }

    return 0;
}

static int32_t dip_table_cmd_prep_args(uvs_admin_cmd_ctx_t *ctx, const struct option *longopts,
    const struct opt_arg *optargs, uvs_admin_dip_table_args_t *args)
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

        if ((ret >= DIP_TABLE_OPT_HELP_NUM) && (ret < DIP_TABLE_OPT_MAX_NUM)) {
            if (ret == DIP_TABLE_OPT_HELP_NUM) {
                uvs_admin_cmd_usages(ctx);
                status = -EINVAL;
            } else {
                status = dip_table_cmd_check_push_opt(args, optarg,
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

static void uvs_admin_print_dip(uvs_admin_dip_table_show_rsp_t *show_rsp)
{
    int ret;
    char mac_str[MAC_STR_LEN] = {0};

    ret = mac_n2p(mac_str, MAC_STR_LEN, show_rsp->net_addr.mac);
    if (ret < 0) {
        (void)printf("mac address error\n");
    }

    (void)printf(UVS_ADMIN_SHOW_PREFIX);
    (void)printf("dip                        : "EID_FMT"\n", EID_ARGS(show_rsp->dip));
    (void)printf("peer_tps_ip                : "EID_FMT"\n", EID_ARGS(show_rsp->peer_tpsa_ip));
    (void)printf("underlay_eid               : "EID_FMT"\n", EID_ARGS(show_rsp->underlay_eid));
    (void)printf("net_addr_base_eid          : "EID_FMT"\n", EID_ARGS(show_rsp->net_addr.base));
    (void)printf("net_addr_mac               : %s\n", mac_str);
    (void)printf("net_addr_is_ipv6           : %s\n", show_rsp->net_addr.type ? "true" : "false");
}

static int32_t uvs_admin_dip_table_showcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_dip_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = dip_table_cmd_prep_args(ctx, g_dip_table_show_long_options, g_dip_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_dip_table_show_req_t));
    if (req == NULL) {
        (void)printf("Can not alloc mem\n");
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_DIP_TABLE_SHOW;
    req->req_len = (ssize_t)sizeof(uvs_admin_dip_table_show_req_t);

    uvs_admin_dip_table_show_req_t *dip_table_req = (uvs_admin_dip_table_show_req_t *)req->req;
    dip_table_req->dip = args.dip;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_dip_table_show_rsp_t *show_rsp = (uvs_admin_dip_table_show_rsp_t *)rsp->rsp;
    if (show_rsp->res != 0) {
        (void)printf("can not find dip_table info by dip: "EID_FMT"\n", EID_ARGS(dip_table_req->dip));
    } else {
        uvs_admin_print_dip(show_rsp);
    }

    free(req);
    return 0;
}

static int32_t uvs_admin_dip_table_addcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_dip_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = dip_table_cmd_prep_args(ctx, g_dip_table_add_long_options, g_dip_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_dip_table_add_req_t));
    if (req == NULL) {
        (void)printf("Can not alloc mem\n");
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_DIP_TABLE_ADD;
    req->req_len = (ssize_t)sizeof(uvs_admin_dip_table_add_req_t);

    uvs_admin_dip_table_add_req_t *dip_table_req = (uvs_admin_dip_table_add_req_t *)req->req;
    dip_table_req->dip = args.dip;
    dip_table_req->peer_tpsa_ip = args.peer_tpsa_ip;
    dip_table_req->underlay_eid = args.underlay_eid;
    dip_table_req->net_addr = args.net_addr;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_dip_table_add_rsp_t *add_rsp = (uvs_admin_dip_table_add_rsp_t *)rsp->rsp;
    if (add_rsp->res != 0) {
        (void)printf("add dip_table table failed, ret %d\n", add_rsp->res);
    }

    free(req);
    return 0;
}

static int32_t uvs_admin_dip_table_delcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_dip_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = dip_table_cmd_prep_args(ctx, g_dip_table_del_long_options, g_dip_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_dip_table_del_req_t));
    if (req == NULL) {
        (void)printf("Can not alloc mem\n");
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_DIP_TABLE_DEL;
    req->req_len = (ssize_t)sizeof(uvs_admin_dip_table_del_req_t);

    uvs_admin_dip_table_del_req_t *dip_table_req = (uvs_admin_dip_table_del_req_t *)req->req;
    dip_table_req->dip = args.dip;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_dip_table_del_rsp_t *del_rsp = (uvs_admin_dip_table_del_rsp_t *)rsp->rsp;
    if (del_rsp->res != 0) {
        (void)printf("del dip_table table failed, ret %d\n", del_rsp->res);
    }

    free(req);
    return 0;
}

static int32_t uvs_admin_dip_table_modifycmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_dip_table_args_t args = {0};
    char *buf = NULL;

    ret = dip_table_cmd_prep_args(ctx, g_dip_table_modify_long_options, g_dip_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_dip_table_modify_req_t));
    if (req == NULL) {
        (void)printf("Can not alloc req mem\n");
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_DIP_TABLE_MODIFY;
    req->req_len = (ssize_t)sizeof(uvs_admin_dip_table_modify_req_t);

    uvs_admin_dip_table_modify_req_t *dip_table_req = (uvs_admin_dip_table_modify_req_t *)req->req;
    dip_table_req->old_dip = args.dip;
    dip_table_req->new_peer_tpsa = args.peer_tpsa_ip;
    dip_table_req->new_underlay_eid = args.underlay_eid;
    dip_table_req->new_netaddr = args.net_addr;
    dip_table_req->new_dip = args.new_dip;
    dip_table_req->mask = args.mask;

    buf = malloc(MAX_MSG_LEN);
    if (buf == NULL) {
        (void)printf("Can not alloc buf mem\n");
        free(req);
        return -ENOMEM;
    }

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        ret = -EIO;
        goto free_and_exit;
    }

    uvs_admin_dip_table_modify_rsp_t *modify_rsp = (uvs_admin_dip_table_modify_rsp_t *)rsp->rsp;
    if (modify_rsp->res != 0) {
        (void)printf("modify dip_table table failed, ret %d\n", modify_rsp->res);
    }

free_and_exit:
    free(req);
    free(buf);
    return ret;
}

uvs_admin_cmd_t g_uvs_admin_dip_table_show_cmd = {
    .command = "show",
    .summary = "show dip_table table",
    .usage = &g_dip_table_show_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_dip_table_show_cmd.subcmds)),
    .run = uvs_admin_dip_table_showcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

uvs_admin_cmd_t g_uvs_admin_dip_table_add_cmd = {
    .command = "add",
    .summary = "add dip_table table",
    .usage = &g_dip_table_add_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_dip_table_add_cmd.subcmds)),
    .run = uvs_admin_dip_table_addcmd_exec,
    .min_argc = (int)UVS_ADMIN_CMD_PARM_SIX + (int)UVS_ADMIN_CMD_PARM_SIX,
};

uvs_admin_cmd_t g_uvs_admin_dip_table_del_cmd = {
    .command = "del",
    .summary = "del dip_table table",
    .usage = &g_dip_table_del_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_dip_table_del_cmd.subcmds)),
    .run = uvs_admin_dip_table_delcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

uvs_admin_cmd_t g_uvs_admin_dip_table_modify_cmd = {
    .command = "modify",
    .summary = "modify dip_table entry",
    .usage = &g_dip_table_modify_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_dip_table_modify_cmd.subcmds)),
    .run = uvs_admin_dip_table_modifycmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_THREE,
};

static uvs_admin_cmd_t *g_uvs_admin_dip_table_subcmds[] = {
    &g_uvs_admin_dip_table_show_cmd,
    &g_uvs_admin_dip_table_add_cmd,
    &g_uvs_admin_dip_table_del_cmd,
    &g_uvs_admin_dip_table_modify_cmd,
};

REGISTER_UVS_ADMIN_COMMANDS(g_uvs_admin_dip_table_cmd, g_uvs_admin_dip_table_subcmds)
