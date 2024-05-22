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
    .summary = "config the information for the remote node",
    .usage   = UVS_ADMIN_BRANCH_SUBCMD_USAGE_VAR(dip_table),
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_dip_table_cmd.subcmds)),
    .run     = uvs_admin_branch_subcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

enum dip_table_opts {
#define DIP_TABLE_OPT_HELP_LONG "help"
    DIP_TABLE_OPT_HELP_NUM = 0,

#define DIP_TABLE_OPT_EID_LONG "eid"
    DIP_TABLE_OPT_EID_NUM,

#define DIP_TABLE_OPT_UPI_LONG "upi"
    DIP_TABLE_OPT_UPI_NUM,

#define DIP_TABLE_OPT_UVS_IP_LONG "uvs_ip"
    DIP_TABLE_OPT_UVS_IP_NUM,

#define DIP_TABLE_OPT_NET_ADDR_LONG "net_addr"
    DIP_TABLE_OPT_NET_ADDR_NUM,

#define DIP_TABLE_OPT_MAC_LONG "mac"
    DIP_TABLE_OPT_MAC_NUM,

#define DIP_TABLE_OPT_NET_ADDR_TYPE_LONG "net_addr_type"
    DIP_TABLE_OPT_NET_ADDR_TYPE_NUM,

#define DIP_TABLE_OPT_NEW_EID_LONG "new_eid"
    DIP_TABLE_OPT_NEW_EID_NUM,

#define DIP_TABLE_OPT_NEW_UPI_LONG "new_upi"
    DIP_TABLE_OPT_NEW_UPI_NUM,

    DIP_TABLE_OPT_MAX_NUM,
};

#define VALID_IS_IPV6_FLAG 1

static const struct opt_arg g_dip_table_opt_args[DIP_TABLE_OPT_MAX_NUM] = {
    [DIP_TABLE_OPT_HELP_NUM] = {DIP_TABLE_OPT_HELP_LONG, ARG_TYPE_OTHERS},
    [DIP_TABLE_OPT_EID_NUM] = {DIP_TABLE_OPT_EID_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_UPI_NUM] = {DIP_TABLE_OPT_UPI_LONG, ARG_TYPE_NUM},
    [DIP_TABLE_OPT_UVS_IP_NUM] = {DIP_TABLE_OPT_UVS_IP_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_NET_ADDR_NUM] = {DIP_TABLE_OPT_NET_ADDR_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_MAC_NUM] = {DIP_TABLE_OPT_MAC_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_NET_ADDR_TYPE_NUM] = {DIP_TABLE_OPT_NET_ADDR_TYPE_LONG, ARG_TYPE_NUM},
    [DIP_TABLE_OPT_NEW_EID_NUM] = {DIP_TABLE_OPT_NEW_EID_LONG, ARG_TYPE_STR},
    [DIP_TABLE_OPT_NEW_UPI_NUM] = {DIP_TABLE_OPT_NEW_UPI_LONG, ARG_TYPE_NUM},
};

/* dip_table_show long options */
static const struct option g_dip_table_show_long_options[] = {
    {DIP_TABLE_OPT_HELP_LONG,  no_argument,       NULL, DIP_TABLE_OPT_HELP_NUM },
    {DIP_TABLE_OPT_EID_LONG,   required_argument, NULL, DIP_TABLE_OPT_EID_NUM },
    {DIP_TABLE_OPT_UPI_LONG,   required_argument, NULL, DIP_TABLE_OPT_UPI_NUM },
    {0,                            0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_dip_table_show_cmd_opt_usage[] = {
    {DIP_TABLE_OPT_HELP_LONG,    "display this help and exit", false},
    {DIP_TABLE_OPT_EID_LONG,     "eid of remote node", true},
    {DIP_TABLE_OPT_UPI_LONG,     "upi of remote node", true},
};

static const uvs_admin_cmd_usage_t g_dip_table_show_cmd_usage = {
    .opt_usage = g_dip_table_show_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_dip_table_show_cmd_opt_usage),
};

/* dip_table_add long options */
static const struct option g_dip_table_add_long_options[] = {
    {DIP_TABLE_OPT_HELP_LONG,              no_argument,       NULL, DIP_TABLE_OPT_HELP_NUM },
    {DIP_TABLE_OPT_EID_LONG,               required_argument, NULL, DIP_TABLE_OPT_EID_NUM },
    {DIP_TABLE_OPT_UPI_LONG,               required_argument, NULL, DIP_TABLE_OPT_UPI_NUM },
    {DIP_TABLE_OPT_UVS_IP_LONG,            required_argument, NULL, DIP_TABLE_OPT_UVS_IP_NUM },
    {DIP_TABLE_OPT_NET_ADDR_LONG,          required_argument, NULL, DIP_TABLE_OPT_NET_ADDR_NUM },
    {DIP_TABLE_OPT_MAC_LONG,               required_argument, NULL, DIP_TABLE_OPT_MAC_NUM },
    {DIP_TABLE_OPT_NET_ADDR_TYPE_LONG,     required_argument, NULL, DIP_TABLE_OPT_NET_ADDR_TYPE_NUM },
    {0,                                    0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_dip_table_add_cmd_opt_usage[] = {
    {DIP_TABLE_OPT_HELP_LONG,             "display this help and exit", false},
    {DIP_TABLE_OPT_EID_LONG,              "eid of remote node", true},
    {DIP_TABLE_OPT_UPI_LONG,              "upi of remote node", true},
    {DIP_TABLE_OPT_UVS_IP_LONG,           "ip addr of remote uvs", true},
    {DIP_TABLE_OPT_NET_ADDR_LONG,         "used at the network layer, for the remote UB device", true},
    {DIP_TABLE_OPT_MAC_LONG,              "used at the network layer, for the remote UB device", true},
    {DIP_TABLE_OPT_NET_ADDR_TYPE_LONG,    "net addr type ((ipv4: 0) | (ipv6:1))", true},
};

static const uvs_admin_cmd_usage_t g_dip_table_add_cmd_usage = {
    .opt_usage = g_dip_table_add_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_dip_table_add_cmd_opt_usage),
};

/* dip_table_del long options */
static const struct option g_dip_table_del_long_options[] = {
    {DIP_TABLE_OPT_HELP_LONG,  no_argument,       NULL, DIP_TABLE_OPT_HELP_NUM },
    {DIP_TABLE_OPT_EID_LONG,   required_argument, NULL, DIP_TABLE_OPT_EID_NUM },
    {DIP_TABLE_OPT_UPI_LONG,   required_argument, NULL, DIP_TABLE_OPT_UPI_NUM },
    {0,                            0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_dip_table_del_cmd_opt_usage[] = {
    {DIP_TABLE_OPT_HELP_LONG,    "display this help and exit", false},
    {DIP_TABLE_OPT_EID_LONG,     "eid of remote node", true},
    {DIP_TABLE_OPT_UPI_LONG,     "upi of remote node", true},
};

static const uvs_admin_cmd_usage_t g_dip_table_del_cmd_usage = {
    .opt_usage = g_dip_table_del_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_dip_table_del_cmd_opt_usage),
};

/* dip_table_modify long options */
static const struct option g_dip_table_modify_long_options[] = {
    {DIP_TABLE_OPT_HELP_LONG,              no_argument,       NULL, DIP_TABLE_OPT_HELP_NUM },
    {DIP_TABLE_OPT_EID_LONG,               required_argument, NULL, DIP_TABLE_OPT_EID_NUM },
    {DIP_TABLE_OPT_UPI_LONG,               required_argument, NULL, DIP_TABLE_OPT_UPI_NUM },
    {DIP_TABLE_OPT_UVS_IP_LONG,            required_argument, NULL, DIP_TABLE_OPT_UVS_IP_NUM },
    {DIP_TABLE_OPT_NET_ADDR_LONG,          required_argument, NULL, DIP_TABLE_OPT_NET_ADDR_NUM },
    {DIP_TABLE_OPT_MAC_LONG,               required_argument, NULL, DIP_TABLE_OPT_MAC_NUM },
    {DIP_TABLE_OPT_NET_ADDR_TYPE_LONG,     required_argument, NULL, DIP_TABLE_OPT_NET_ADDR_TYPE_NUM },
    {DIP_TABLE_OPT_NEW_EID_LONG,           required_argument, NULL, DIP_TABLE_OPT_NEW_EID_NUM },
    {DIP_TABLE_OPT_NEW_UPI_LONG,           required_argument, NULL, DIP_TABLE_OPT_NEW_UPI_NUM },
    {0,                                    0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_dip_table_modify_cmd_opt_usage[] = {
    {DIP_TABLE_OPT_HELP_LONG,             "display this help and exit", false},
    {DIP_TABLE_OPT_EID_LONG,              "eid of remote node", true},
    {DIP_TABLE_OPT_UPI_LONG,              "upi of remote node", true},
    {DIP_TABLE_OPT_UVS_IP_LONG,           "ip addr of remote uvs", true},
    {DIP_TABLE_OPT_NET_ADDR_LONG,         "used at the network layer, for the remote UB device", true},
    {DIP_TABLE_OPT_MAC_LONG,              "used at the network layer, for the remote UB device", true},
    {DIP_TABLE_OPT_NET_ADDR_TYPE_LONG,    "net addr type ((ipv4: 0) | (ipv6:1))", true},
    {DIP_TABLE_OPT_NEW_EID_LONG,          "new eid need modify", true},
    {DIP_TABLE_OPT_NEW_UPI_LONG,          "new upi need modify", true},
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
        (void)printf("ERR: invalid parameter --%s %s\n", arg_name, _optarg);
        return -EINVAL;
    }
    if (!strcmp(arg_name, DIP_TABLE_OPT_NET_ADDR_TYPE_LONG)) {
        if (dip_table_input_range_check(num, 0, VALID_IS_IPV6_FLAG) != 0) {
            (void)printf("ERR: invalid parameter range --%s %u; valid range = [%u, %u]\n",
                arg_name, num, 0, VALID_IS_IPV6_FLAG);
            return -EINVAL;
        }
        args->net_addr.type = (bool)num;
        args->mask.bs.net_addr = 1;
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_UPI_LONG)) {
        if (dip_table_input_range_check(num, 0, UINT32_MAX) != 0) {
            (void)printf("invalid parameter range --%s %u; valid range = [%u, %u]\n",
                arg_name, num, 0, UINT32_MAX);
            return -EINVAL;
        }
        args->upi = num;
        args->mask.bs.upi = 1;
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_NEW_UPI_LONG)) {
        if (dip_table_input_range_check(num, 0, UINT32_MAX) != 0) {
            (void)printf("invalid parameter range --%s %u; valid range = [%u, %u]\n",
                arg_name, num, 0, UINT32_MAX);
            return -EINVAL;
        }
        args->new_upi = num;
        args->mask.bs.upi = 1;
    } else {
        (void)printf("ERR: invalid parameter --%s %s\n", arg_name, _optarg);
        return -EINVAL;
    }

    return 0;
}

static int dip_table_input_valid_str(uvs_admin_dip_table_args_t *args, const char *_optarg,
    const char *arg_name)
{
    int ret = 0;
    if (!strcmp(arg_name, DIP_TABLE_OPT_EID_LONG)) {
        ret = str_to_eid(_optarg, &args->eid);
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_UVS_IP_LONG)) {
        ret = str_to_eid(_optarg, (urma_eid_t *)&args->uvs_ip);
        args->mask.bs.uvs_ip = 1;
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_NET_ADDR_LONG)) {
        ret = str_to_eid(_optarg, (urma_eid_t *)&args->net_addr.net_addr);
        args->mask.bs.net_addr = 1;
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_MAC_LONG)) {
        ret = parse_mac(_optarg, args->net_addr.mac);
        args->mask.bs.net_addr = 1;
    } else if (!strcmp(arg_name, DIP_TABLE_OPT_NEW_EID_LONG)) {
        ret = str_to_eid(_optarg, &args->new_eid);
        args->mask.bs.eid = 1;
    } else {
        ret = -EINVAL;
    }

    if (ret != 0) {
        (void)printf("ERR: invalid parameter --%s %s\n", arg_name, _optarg);
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
        (void)printf("ERR: mac address error\n");
    }

    (void)printf(UVS_ADMIN_SHOW_PREFIX);
    (void)printf("eid                        : "EID_FMT"\n", EID_ARGS(show_rsp->eid));
    (void)printf("upi                        : %u\n", show_rsp->upi);
    (void)printf("uvs_ip                     : "EID_FMT"\n", EID_ARGS(show_rsp->uvs_ip));
    (void)printf("net_addr                   : "EID_FMT"\n", EID_ARGS(show_rsp->net_addr.net_addr));
    (void)printf("mac                        : %s\n", mac_str);
    (void)printf("net_addr_type              : %s\n", show_rsp->net_addr.type ? "IPv6" : "IPv4");
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
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_DIP_TABLE_SHOW;
    req->req_len = (ssize_t)sizeof(uvs_admin_dip_table_show_req_t);

    uvs_admin_dip_table_show_req_t *dip_table_req = (uvs_admin_dip_table_show_req_t *)req->req;
    dip_table_req->eid = args.eid;
    dip_table_req->upi = args.upi;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_dip_table_show_rsp_t *show_rsp = (uvs_admin_dip_table_show_rsp_t *)rsp->rsp;
    if (show_rsp->res != 0) {
        (void)printf("ERR: failed to show dip info, ret: %d, dip: "EID_FMT".\n",
            show_rsp->res, EID_ARGS(dip_table_req->eid));
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
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_DIP_TABLE_ADD;
    req->req_len = (ssize_t)sizeof(uvs_admin_dip_table_add_req_t);

    uvs_admin_dip_table_add_req_t *dip_table_req = (uvs_admin_dip_table_add_req_t *)req->req;
    dip_table_req->eid = args.eid;
    dip_table_req->upi = args.upi;
    dip_table_req->uvs_ip = args.uvs_ip;
    dip_table_req->net_addr = args.net_addr;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_dip_table_add_rsp_t *add_rsp = (uvs_admin_dip_table_add_rsp_t *)rsp->rsp;
    if (add_rsp->res != 0) {
        (void)printf("ERR: failed to add dip info, ret: %d.\n", add_rsp->res);
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
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_DIP_TABLE_DEL;
    req->req_len = (ssize_t)sizeof(uvs_admin_dip_table_del_req_t);

    uvs_admin_dip_table_del_req_t *dip_table_req = (uvs_admin_dip_table_del_req_t *)req->req;
    dip_table_req->eid = args.eid;
    dip_table_req->upi = args.upi;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_dip_table_del_rsp_t *del_rsp = (uvs_admin_dip_table_del_rsp_t *)rsp->rsp;
    if (del_rsp->res != 0) {
        (void)printf("ERR: failed to del dip info, ret: %d.\n", del_rsp->res);
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
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_DIP_TABLE_MODIFY;
    req->req_len = (ssize_t)sizeof(uvs_admin_dip_table_modify_req_t);

    uvs_admin_dip_table_modify_req_t *dip_table_req = (uvs_admin_dip_table_modify_req_t *)req->req;
    dip_table_req->old_eid = args.eid;
    dip_table_req->old_upi = args.upi;
    dip_table_req->new_uvs_ip = args.uvs_ip;
    dip_table_req->new_net_addr = args.net_addr;
    dip_table_req->new_eid = args.new_eid;
    dip_table_req->new_upi = args.new_upi;
    dip_table_req->mask = args.mask;

    buf = malloc(MAX_MSG_LEN);
    if (buf == NULL) {
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
        (void)printf("ERR: failed to modify dip info, ret: %d.\n", modify_rsp->res);
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
    .min_argc = UVS_ADMIN_CMD_PARM_TWO + UVS_ADMIN_CMD_PARM_TWO,
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
    .min_argc = UVS_ADMIN_CMD_PARM_TWO + UVS_ADMIN_CMD_PARM_TWO,
};

uvs_admin_cmd_t g_uvs_admin_dip_table_modify_cmd = {
    .command = "modify",
    .summary = "modify dip_table entry",
    .usage = &g_dip_table_modify_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_dip_table_modify_cmd.subcmds)),
    .run = uvs_admin_dip_table_modifycmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_EIGHT + UVS_ADMIN_CMD_PARM_EIGHT,
};

static uvs_admin_cmd_t *g_uvs_admin_dip_table_subcmds[] = {
    &g_uvs_admin_dip_table_show_cmd,
    &g_uvs_admin_dip_table_add_cmd,
    &g_uvs_admin_dip_table_del_cmd,
    &g_uvs_admin_dip_table_modify_cmd,
};

REGISTER_UVS_ADMIN_COMMANDS(g_uvs_admin_dip_table_cmd, g_uvs_admin_dip_table_subcmds)
