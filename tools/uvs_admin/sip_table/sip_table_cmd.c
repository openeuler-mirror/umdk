/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: 'uvs_admin sip_table show/add/del' command implementation
 * Author: Jilei
 * Create: 2023-07-14
 * Note: Declared a series of  functions show/add/del sip_table
 *
 * History: 2023-07-14 Jilei Initial version
 */

#include <getopt.h>
#include <arpa/inet.h>

#include "uvs_admin_cmd_client.h"
#include "sip_table_cmd.h"

UVS_ADMIN_BRANCH_SUBCMD_USAGE(sip_table)

uvs_admin_cmd_t g_uvs_admin_sip_table_cmd = {
    .command = "sip_table",
    .summary = "sip_table config cmd",
    .usage   = UVS_ADMIN_BRANCH_SUBCMD_USAGE_VAR(sip_table),
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_sip_table_cmd.subcmds)),
    .run     = uvs_admin_branch_subcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

enum sip_table_opts {
#define SIP_TABLE_OPT_HELP_LONG "help"
    SIP_TABLE_OPT_HELP_NUM = 0,

#define SIP_TABLE_OPT_SIP_IDX_LONG "sip_idx"
    SIP_TABLE_OPT_SIP_IDX_NUM,

#define SIP_TABLE_OPT_DEV_NAME_LONG "dev_name"
    SIP_TABLE_OPT_DEV_NAME_NUM,

#define SIP_TABLE_OPT_NET_ADDR_LONG "net_addr"
    SIP_TABLE_OPT_NET_ADDR_NUM,

#define SIP_TABLE_OPT_VLAN_LONG "vlan"
    SIP_TABLE_OPT_VLAN_NUM,

#define SIP_TABLE_OPT_MAC_LONG "mac"
    SIP_TABLE_OPT_MAC_NUM,

#define SIP_TABLE_OPT_PORT_LONG "port"
    SIP_TABLE_OPT_PORT_NUM,

#define SIP_TABLE_OPT_NET_ADDR_TYPE_LONG "net_addr_type"
    SIP_TABLE_OPT_NET_ADDR_TYPE_NUM,

#define SIP_TABLE_OPT_PREFIX_LEN_LONG "prefix_len"
        SIP_TABLE_OPT_PREFIX_LEN_NUM,

#define SIP_TABLE_OPT_MTU_LONG "mtu"
    SIP_TABLE_OPT_MTU_NUM,

    SIP_TABLE_OPT_MAX_NUM,
};

#define VALID_IS_IPV6_FLAG       1
#define MAX_VLAN_ID              4095
#define SIP_IDX_MAX              10239
#define IS_IPV6_MAX              1
#define IPV6_MAX_PREFIX_LEN      128
#define IPV4_MAX_PREFIX_LEN      32

static const struct opt_arg g_sip_table_opt_args[SIP_TABLE_OPT_MAX_NUM] = {
    [SIP_TABLE_OPT_HELP_NUM] = {SIP_TABLE_OPT_HELP_LONG, ARG_TYPE_OTHERS},
    [SIP_TABLE_OPT_SIP_IDX_NUM] = {SIP_TABLE_OPT_SIP_IDX_LONG, ARG_TYPE_NUM},
    [SIP_TABLE_OPT_DEV_NAME_NUM] = {SIP_TABLE_OPT_DEV_NAME_LONG, ARG_TYPE_STR},
    [SIP_TABLE_OPT_NET_ADDR_NUM] = {SIP_TABLE_OPT_NET_ADDR_LONG, ARG_TYPE_STR},
    [SIP_TABLE_OPT_VLAN_NUM] = {SIP_TABLE_OPT_VLAN_LONG, ARG_TYPE_NUM},
    [SIP_TABLE_OPT_MAC_NUM] = {SIP_TABLE_OPT_MAC_LONG, ARG_TYPE_STR},
    [SIP_TABLE_OPT_PORT_NUM] = {SIP_TABLE_OPT_PORT_LONG, ARG_TYPE_NUM},
    [SIP_TABLE_OPT_NET_ADDR_TYPE_NUM] = {SIP_TABLE_OPT_NET_ADDR_TYPE_LONG, ARG_TYPE_NUM},
    [SIP_TABLE_OPT_PREFIX_LEN_NUM] = {SIP_TABLE_OPT_PREFIX_LEN_LONG, ARG_TYPE_NUM},
    [SIP_TABLE_OPT_MTU_NUM] = {SIP_TABLE_OPT_MTU_LONG, ARG_TYPE_STR},
};

/* sip_table_show long options */
static const struct option g_sip_table_show_long_options[] = {
    {SIP_TABLE_OPT_HELP_LONG,      no_argument,       NULL, SIP_TABLE_OPT_HELP_NUM },
    {SIP_TABLE_OPT_DEV_NAME_LONG,  required_argument, NULL, SIP_TABLE_OPT_DEV_NAME_NUM },
    {SIP_TABLE_OPT_SIP_IDX_LONG,   required_argument, NULL, SIP_TABLE_OPT_SIP_IDX_NUM },
    {0,                            0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_sip_table_show_cmd_opt_usage[] = {
    {SIP_TABLE_OPT_HELP_LONG,    "display this help and exit", false},
    {SIP_TABLE_OPT_DEV_NAME_LONG, "sip index is allocated based on tpf domain", true},
    {SIP_TABLE_OPT_SIP_IDX_LONG, "index of the entry in sip_table, allocated by ubcore", true},
};

static const uvs_admin_cmd_usage_t g_sip_table_show_cmd_usage = {
    .opt_usage = g_sip_table_show_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_sip_table_show_cmd_opt_usage),
};

/* sip_table_add long options */
static const struct option g_sip_table_add_long_options[] = {
    {SIP_TABLE_OPT_HELP_LONG,       no_argument,       NULL, SIP_TABLE_OPT_HELP_NUM },
    {SIP_TABLE_OPT_DEV_NAME_LONG,   required_argument, NULL, SIP_TABLE_OPT_DEV_NAME_NUM },
    {SIP_TABLE_OPT_NET_ADDR_LONG,         required_argument, NULL, SIP_TABLE_OPT_NET_ADDR_NUM },
    {SIP_TABLE_OPT_VLAN_LONG,       required_argument, NULL, SIP_TABLE_OPT_VLAN_NUM },
    {SIP_TABLE_OPT_MAC_LONG,        required_argument, NULL, SIP_TABLE_OPT_MAC_NUM },
    {SIP_TABLE_OPT_PORT_LONG,       required_argument, NULL, SIP_TABLE_OPT_PORT_NUM },
    {SIP_TABLE_OPT_NET_ADDR_TYPE_LONG,    required_argument, NULL, SIP_TABLE_OPT_NET_ADDR_TYPE_NUM },
    {SIP_TABLE_OPT_PREFIX_LEN_LONG, required_argument, NULL, SIP_TABLE_OPT_PREFIX_LEN_NUM },
    {SIP_TABLE_OPT_MTU_LONG,        required_argument, NULL, SIP_TABLE_OPT_MTU_NUM },
    {0,                            0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_sip_table_add_cmd_opt_usage[] = {
    {SIP_TABLE_OPT_HELP_LONG,           "display this help and exit", false},
    {SIP_TABLE_OPT_DEV_NAME_LONG,       "specifies the name of tpf device", true},
    {SIP_TABLE_OPT_NET_ADDR_LONG,       "used at the network layer, for the local UB device", true},
    {SIP_TABLE_OPT_VLAN_LONG,           "used at the network layer, for the local UB device", true},
    {SIP_TABLE_OPT_MAC_LONG,            "used at the network layer, for the local UB device", true},
    {SIP_TABLE_OPT_PORT_LONG,           "used at the network layer, for the local UB device", true},
    {SIP_TABLE_OPT_NET_ADDR_TYPE_LONG,  "net_addr type ((ipv4: 0) | (ipv6:1))", true},
    {SIP_TABLE_OPT_PREFIX_LEN_LONG,     "prefix_len of net_addr", true},
    {SIP_TABLE_OPT_MTU_LONG,            "mtu [1024, 4096, 8192]", false},
};

static const uvs_admin_cmd_usage_t g_sip_table_add_cmd_usage = {
    .opt_usage = g_sip_table_add_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_sip_table_add_cmd_opt_usage),
};

/* sip_table_del long options */
static const struct option g_sip_table_del_long_options[] = {
    {SIP_TABLE_OPT_HELP_LONG,      no_argument,       NULL, SIP_TABLE_OPT_HELP_NUM },
    {SIP_TABLE_OPT_DEV_NAME_LONG,  required_argument, NULL, SIP_TABLE_OPT_DEV_NAME_NUM },
    {SIP_TABLE_OPT_SIP_IDX_LONG,   required_argument, NULL, SIP_TABLE_OPT_SIP_IDX_NUM },
    {0,                            0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_sip_table_del_cmd_opt_usage[] = {
    {SIP_TABLE_OPT_HELP_LONG,    "display this help and exit", false},
    {SIP_TABLE_OPT_DEV_NAME_LONG, "sip index is destroyed based on tpf domain", true},
    {SIP_TABLE_OPT_SIP_IDX_LONG, "index of the entry in sip_table, allocated by ubcore", true},
};

static const uvs_admin_cmd_usage_t g_sip_table_del_cmd_usage = {
    .opt_usage = g_sip_table_del_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_sip_table_del_cmd_opt_usage),
};

static inline int sip_table_input_range_check(uint32_t num, uint32_t range_min, uint32_t range_max)
{
    if (range_min <= num && num <= range_max) {
        return 0;
    }
    return -1;
}

static int sip_table_input_valid_num(uvs_admin_sip_table_args_t *args, const char *_optarg,
    const char *arg_name)
{
    uint32_t num;
    int ret;
    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        (void)printf("ERR: invalid parameter --%s %s\n", arg_name, _optarg);
        return -EINVAL;
    }

    if (!strcmp(arg_name, SIP_TABLE_OPT_SIP_IDX_LONG)) {
        if (sip_table_input_range_check(num, 0, SIP_IDX_MAX) != 0) {
            (void)printf("ERR: invalid parameter range --%s %u; valid range = [%u, %u]\n",
                arg_name, num, 0, SIP_IDX_MAX);
            return -EINVAL;
        }
        args->sip_idx = num;
        args->mask.bs.sip_idx = 1;
    } else if (!strcmp(arg_name, SIP_TABLE_OPT_VLAN_LONG) && num <= MAX_VLAN_ID) {
        if (sip_table_input_range_check(num, 0, MAX_VLAN_ID) != 0) {
            (void)printf("ERR: invalid parameter range --%s %u; valid range = [%u, %u]\n",
                arg_name, num, 0, MAX_VLAN_ID);
            return -EINVAL;
        }
        args->vlan = (uint16_t)num;
        args->mask.bs.vlan = 1;
    } else if (!strcmp(arg_name, SIP_TABLE_OPT_PORT_LONG)) {
        if (sip_table_input_range_check(num, 0, UINT8_MAX) != 0) {
            (void)printf("ERR: invalid parameter range --%s %u; valid range = [%u, %u]\n",
                arg_name, num, 0, (uint32_t)UINT8_MAX);
            return -EINVAL;
        }
        args->port_id = (uint8_t)num;
        args->mask.bs.port_id = 1;
    } else if (!strcmp(arg_name, SIP_TABLE_OPT_NET_ADDR_TYPE_LONG) && num <= VALID_IS_IPV6_FLAG) {
        if (sip_table_input_range_check(num, 0, IS_IPV6_MAX) != 0) {
            (void)printf("ERR: invalid parameter range --%s %u; valid range = [%u, %u]\n",
                arg_name, num, 0, IS_IPV6_MAX);
            return -EINVAL;
        }
        args->net_addr_type = (bool)num;
        args->mask.bs.net_addr_type = 1;
    } else if (!strcmp(arg_name, SIP_TABLE_OPT_PREFIX_LEN_LONG)) {
        uint32_t prefix_len_max;
        if (args->net_addr_type) {
            prefix_len_max = IPV6_MAX_PREFIX_LEN;
        } else {
            prefix_len_max = IPV4_MAX_PREFIX_LEN;
        }

        if (sip_table_input_range_check(num, 0, prefix_len_max) != 0) {
            (void)printf("ERR: invalid parameter range --%s %u; valid range = [%u, %u]\n",
                arg_name, num, (uint32_t)0, prefix_len_max);
            return -EINVAL;
        }
        args->prefix_len = num;
        args->mask.bs.prefix_len = 1;
    } else {
        (void)printf("ERR: invalid parameter --%s %s\n", arg_name, _optarg);
        return -EINVAL;
    }

    return 0;
}

static inline int sip_table_input_str_range_check(uint32_t str_len_max, uint32_t input_str_len)
{
    if (input_str_len >= str_len_max) {
        return -1;
    }
    return 0;
}

static char *g_mtu_str[UVS_ADMIN_MTU_CNT] = {
    [UVS_ADMIN_MTU_256] = "256",
    [UVS_ADMIN_MTU_512] = "512",
    [UVS_ADMIN_MTU_1024] = "1024",
    [UVS_ADMIN_MTU_2048] = "2048",
    [UVS_ADMIN_MTU_4096] = "4096",
    [UVS_ADMIN_MTU_8192] = "8192"
};

static int parse_mtu(const char *_optarg, uvs_admin_mtu_t *mtu)
{
    int i;
    for (i = 1; i < UVS_ADMIN_MTU_CNT; i++) {
        if (!strcmp(_optarg, g_mtu_str[i])) {
            if (i != UVS_ADMIN_MTU_1024 && i != UVS_ADMIN_MTU_4096 && i != UVS_ADMIN_MTU_8192) {
                (void)printf("ERR: invalid parameter mtu %s; valid range = [1024, 4096, 8192]\n",
                    g_mtu_str[i]);
                return -1;
            }

            *mtu = (uvs_admin_mtu_t)i;
            return 0;
        }
    }
    return -1;
}

static int sip_table_input_valid_str(uvs_admin_sip_table_args_t *args, const char *_optarg,
    const char *arg_name)
{
    int ret = 0;
    if (!strcmp(arg_name, SIP_TABLE_OPT_NET_ADDR_LONG)) {
        ret = str_to_eid(_optarg, (urma_eid_t *)&args->net_addr);
        ret |= get_net_addr_type(_optarg, (urma_eid_t *)&args->net_addr,
            &args->input_net_type);
        args->mask.bs.net_addr = 1;
    } else if (!strcmp(arg_name, SIP_TABLE_OPT_DEV_NAME_LONG)) {
        if (sip_table_input_str_range_check((uint32_t)UVS_ADMIN_MAX_DEV_NAME, (uint32_t)strlen(_optarg)) != 0) {
            (void)printf("ERR: invalid parameter range --%s %s; valid range = [%u, %u]\n",
                arg_name, _optarg, 0, UVS_ADMIN_MAX_DEV_NAME);
            return -EINVAL;
        }
        (void)strncpy(args->dev_name, _optarg, UVS_ADMIN_MAX_DEV_NAME - 1);
        args->mask.bs.dev_name = 1;
    } else if (!strcmp(arg_name, SIP_TABLE_OPT_MAC_LONG)) {
        ret = parse_mac(_optarg, args->mac);
        args->mask.bs.mac = 1;
    } else if (!strcmp(arg_name, SIP_TABLE_OPT_MTU_LONG)) {
        ret = parse_mtu(_optarg, &args->mtu);
        args->mask.bs.mtu = 1;
    } else {
        ret = -EINVAL;
    }

    if (ret != 0) {
        (void)printf("ERR: invalid parameter --%s %s\n", arg_name, _optarg);
        return -ret;
    }

    return 0;
}

static int32_t sip_table_cmd_check_push_opt(uvs_admin_sip_table_args_t *args, const char *_optarg,
    const char *arg_name, int arg_type)
{
    if (arg_type == ARG_TYPE_NUM) {
        return sip_table_input_valid_num(args, _optarg, arg_name);
    } else if (arg_type == ARG_TYPE_STR) {
        return sip_table_input_valid_str(args, _optarg, arg_name);
    }

    return 0;
}

static int32_t sip_table_cmd_prep_args(uvs_admin_cmd_ctx_t *ctx, const struct option *longopts,
    const struct opt_arg *optargs, uvs_admin_sip_table_args_t *args)
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

        if ((ret >= SIP_TABLE_OPT_HELP_NUM) && (ret < SIP_TABLE_OPT_MAX_NUM)) {
            if (ret == SIP_TABLE_OPT_HELP_NUM) {
                uvs_admin_cmd_usages(ctx);
                status = -EINVAL;
            } else {
                status = sip_table_cmd_check_push_opt(args, optarg,
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

static void uvs_admin_print_sip(uint32_t sip_idx, uvs_admin_sip_table_show_rsp_t *show_rsp)
{
    int ret;
    char mac_str[MAC_STR_LEN] = {0};
    ret = mac_n2p(mac_str, MAC_STR_LEN, show_rsp->mac);
    if (ret < 0) {
        (void)printf("ERR: mac address error\n");
    }
    (void)printf(UVS_ADMIN_SHOW_PREFIX);
    (void)printf("sip_idx                    : %u\n", sip_idx);
    (void)printf("dev_name                   : %s\n", show_rsp->dev_name);
    (void)printf("net_addr                   : "EID_FMT"\n", EID_ARGS(show_rsp->net_addr));
    (void)printf("vlan                       : %u\n", show_rsp->vlan);
    (void)printf("mac                        : %s\n", mac_str);
    (void)printf("net_addr_type              : %s\n", show_rsp->net_addr_type ? "IPv6" : "IPv4");
    for (int i = 0; i < show_rsp->port_cnt; i++) {
        (void)printf("port%-4d                   : %u\n", i, show_rsp->port[i]);
    }
    (void)printf("prefix_len                 : %u\n", show_rsp->prefix_len);
    (void)printf("mtu                        : %u[%s]\n",
        (uint32_t)show_rsp->mtu, g_mtu_str[show_rsp->mtu]);
}

static int uvs_admin_sip_table_del_show_cmd_validation(uvs_admin_sip_table_args_t args)
{
    if (args.mask.bs.sip_idx == 0 || args.mask.bs.dev_name == 0) {
        (void)printf("ERR: invalid parameter, must set sip_idx/dev_name, mask:0x%x\n",
            args.mask.value);
        return -EINVAL;
    }

    return 0;
}

static int32_t uvs_admin_sip_table_showcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_sip_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = sip_table_cmd_prep_args(ctx, g_sip_table_show_long_options, g_sip_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    ret = uvs_admin_sip_table_del_show_cmd_validation(args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_sip_table_show_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_SIP_TABLE_SHOW;
    req->req_len = (ssize_t)sizeof(uvs_admin_sip_table_show_req_t);

    uvs_admin_sip_table_show_req_t *sip_table_req = (uvs_admin_sip_table_show_req_t *)req->req;
    sip_table_req->sip_idx = args.sip_idx;
    (void)memcpy(sip_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_sip_table_show_rsp_t *show_rsp = (uvs_admin_sip_table_show_rsp_t *)rsp->rsp;
    if (show_rsp->res != 0) {
        (void)printf("ERR: failed to show sip info, ret: %d, sip_idx: %u.\n",
            show_rsp->res, sip_table_req->sip_idx);
    } else {
        uvs_admin_print_sip(sip_table_req->sip_idx, show_rsp);
    }

    free(req);
    return 0;
}

static int uvs_admin_sip_table_addcmd_validation(uvs_admin_sip_table_args_t args)
{
    if (args.mask.bs.net_addr == 0 || args.mask.bs.vlan == 0 ||
        args.mask.bs.mac == 0 || args.mask.bs.dev_name == 0 || args.mask.bs.port_id == 0 ||
        args.mask.bs.net_addr_type == 0 || args.mask.bs.prefix_len == 0) {
        (void)printf("ERR: invalid parameter, must set net_addr/vlan/mac/dev_name/port_id/"
            "net_addr_type/prefix_len, mask:0x%x\n", args.mask.value);
        return -EINVAL;
    }

    if (args.net_addr_type != args.input_net_type) {
        (void)printf("ERR: invalid parameter, --net_addr_type is %s "
            "but input net_addr ip type is %s\n",
            args.net_addr_type == UVS_ADMIN_NET_ADDR_TYPE_IPV4 ? "IPV4" : "IPV6",
            args.input_net_type == UVS_ADMIN_NET_ADDR_TYPE_IPV4 ? "IPV4" : "IPV6");
        return -EINVAL;
    }

    return 0;
}

static int32_t uvs_admin_sip_table_addcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_sip_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = sip_table_cmd_prep_args(ctx, g_sip_table_add_long_options, g_sip_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    ret = uvs_admin_sip_table_addcmd_validation(args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_sip_table_add_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_SIP_TABLE_ADD;
    req->req_len = (ssize_t)sizeof(uvs_admin_sip_table_add_req_t);

    uvs_admin_sip_table_add_req_t *sip_table_req = (uvs_admin_sip_table_add_req_t *)req->req;
    sip_table_req->vlan = args.vlan;
    sip_table_req->port_id = args.port_id;
    sip_table_req->net_addr_type = args.net_addr_type;
    memcpy(&sip_table_req->net_addr, &args.net_addr, sizeof(uvs_admin_net_addr_t));
    memcpy(sip_table_req->mac, args.mac, UVS_ADMIN_MAC_BYTES);
    memcpy(sip_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);
    sip_table_req->prefix_len = args.prefix_len;
    sip_table_req->mtu = args.mtu;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_sip_table_add_rsp_t *add_rsp = (uvs_admin_sip_table_add_rsp_t *)rsp->rsp;
    if (add_rsp->res == EEXIST) {
        (void)printf("sip already exist, index %u, update entry will not effect.\n", add_rsp->index);
    } else if (add_rsp->res != 0) {
        (void)printf("ERR: failed to add sip info, ret: %d.\n", add_rsp->res);
    } else {
        (void)printf("Success: add index: %u sip info.\n", add_rsp->index);
    }

    free(req);
    return 0;
}

static int32_t uvs_admin_sip_table_delcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_sip_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = sip_table_cmd_prep_args(ctx, g_sip_table_del_long_options, g_sip_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    ret = uvs_admin_sip_table_del_show_cmd_validation(args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_sip_table_del_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_SIP_TABLE_DEL;
    req->req_len = (ssize_t)sizeof(uvs_admin_sip_table_del_req_t);

    uvs_admin_sip_table_del_req_t *sip_table_req = (uvs_admin_sip_table_del_req_t *)req->req;
    sip_table_req->sip_idx = args.sip_idx;
    (void)memcpy(sip_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_sip_table_del_rsp_t *del_rsp = (uvs_admin_sip_table_del_rsp_t *)rsp->rsp;
    if (del_rsp->res != 0) {
        (void)printf("ERR: failed to del sip info, ret: %d.\n", del_rsp->res);
    } else {
        (void)printf("Success: del index: %u sip info.\n", args.sip_idx);
    }

    free(req);
    return 0;
}

uvs_admin_cmd_t g_uvs_admin_sip_table_show_cmd = {
    .command = "show",
    .summary = "show sip_table table",
    .usage = &g_sip_table_show_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_sip_table_show_cmd.subcmds)),
    .run = uvs_admin_sip_table_showcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO + UVS_ADMIN_CMD_PARM_TWO,
};

uvs_admin_cmd_t g_uvs_admin_sip_table_add_cmd = {
    .command = "add",
    .summary = "add sip_table table",
    .usage = &g_sip_table_add_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_sip_table_add_cmd.subcmds)),
    .run = uvs_admin_sip_table_addcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_SEVEN + UVS_ADMIN_CMD_PARM_SEVEN,
};

uvs_admin_cmd_t g_uvs_admin_sip_table_del_cmd = {
    .command = "del",
    .summary = "del sip_table table",
    .usage = &g_sip_table_del_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_sip_table_del_cmd.subcmds)),
    .run = uvs_admin_sip_table_delcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO + UVS_ADMIN_CMD_PARM_TWO,
};

static uvs_admin_cmd_t *g_uvs_admin_sip_table_subcmds[] = {
    &g_uvs_admin_sip_table_show_cmd,
    &g_uvs_admin_sip_table_add_cmd,
    &g_uvs_admin_sip_table_del_cmd,
};

REGISTER_UVS_ADMIN_COMMANDS(g_uvs_admin_sip_table_cmd, g_uvs_admin_sip_table_subcmds)
