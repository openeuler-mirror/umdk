/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: 'uvs_admin query_res and list_res' command implementation
 * Author: Zhou Yuhao
 * Create: 2024-03-09
 * Note: implement query_res and list_res, get res info from kernel.
 * History: 2024-03-09 Zhou Yuhao Initial version
 */


#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <getopt.h>
#include <sched.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "urma_types.h"
#include "urma_cmd.h"
#include "urma_types_str.h"
#include "uvs_admin_cmd_util.h"
#include "uvs_admin_types.h"
#include "query_res_cmd.h"

#define UVS_CMD_NUM 3
#define UVS_ADMIN_MAX_DEV_NAME 64
#define UBCORE_GENL_FAMILY_NAME		"UBCORE_GENL"
#define UBCORE_GENL_FAMILY_VERSION	1
#define OWN_FE_IDX (0xffff)
#define CDEV_PATH  "/dev/uburma"

enum {
    UBCORE_ATTR_UNSPEC,
    UBCORE_HDR_COMMAND,
    UBCORE_HDR_ARGS_LEN,
    UBCORE_HDR_ARGS_ADDR,
    UBCORE_ATTR_NS_MODE,
    UBCORE_ATTR_DEV_NAME,
    UBCORE_ATTR_NS_FD,
    UBCORE_ATTR_AFTER_LAST
};

enum {
    UBCORE_RES_TPG_TP_CNT,
	UBCORE_RES_TPG_DSCP,
	UBCORE_RES_TPG_TP_VAL,
	UBCORE_RES_JTGRP_JETTY_CNT,
	UBCORE_RES_JTGRP_JETTY_VAL,
	UBCORE_RES_SEGVAL_SEG_CNT,
	UBCORE_RES_SEGVAL_SEG_VAL,
	UBCORE_RES_DEV_SEG_CNT,
	UBCORE_RES_DEV_SEG_VAL,
	UBCORE_RES_DEV_JFS_CNT,
	UBCORE_RES_DEV_JFS_VAL,
	UBCORE_RES_DEV_JFR_CNT,
	UBCORE_RES_DEV_JFR_VAL,
	UBCORE_RES_DEV_JFC_CNT,
	UBCORE_RES_DEV_JFC_VAL,
	UBCORE_RES_DEV_JETTY_CNT,
	UBCORE_RES_DEV_JETTY_VAL,
	UBCORE_RES_DEV_JTGRP_CNT,
	UBCORE_RES_DEV_JTGRP_VAL,
	UBCORE_RES_DEV_RC_CNT,
	UBCORE_RES_DEV_RC_VAL,
	UBCORE_RES_DEV_VTP_CNT,
	UBCORE_RES_DEV_VTP_VAL,
	UBCORE_RES_DEV_TP_CNT,
	UBCORE_RES_DEV_TP_VAL,
	UBCORE_RES_DEV_TPG_CNT,
	UBCORE_RES_DEV_TPG_VAL,
	UBCORE_RES_DEV_UTP_CNT,
	UBCORE_RES_DEV_UTP_VAL,
	UBCORE_RES_UPI_VAL,
	UBCORE_RES_VTP_VAL,
	UBCORE_RES_TP_VAL,
	UBCORE_RES_UTP_VAL,
	UBCORE_RES_JFS_VAL,
	UBCORE_RES_JFR_VAL,
	UBCORE_RES_JETTY_VAL,
	UBCORE_RES_JFC_VAL,
	UBCORE_RES_RC_VAL,
	UBCORE_ATTR_RES_LAST
};

typedef enum tool_cmd_type {
    TOOL_CMD_SHOW,
    TOOL_CMD_ADD_EID,
    TOOL_CMD_DEL_EID,
    TOOL_CMD_SET_EID_MODE,
    TOOL_CMD_SET_CC_ALG,
    TOOL_CMD_SHOW_UTP,
    TOOL_CMD_SHOW_STATS,
    TOOL_CMD_SHOW_RES,
    TOOL_CMD_SET_NS_MODE,
    TOOL_CMD_SET_DEV_NS,
    TOOL_CMD_LIST_RES,
    TOOL_CMD_NUM
} tool_cmd_type_t;

typedef enum tool_stats_key_type {
    TOOL_STATS_KEY_VTP = 1,
	TOOL_STATS_KEY_TP = 2,
	TOOL_STATS_KEY_TPG = 3,
	TOOL_STATS_KEY_JFS = 4,
	TOOL_STATS_KEY_JFR = 5,
	TOOL_STATS_KEY_JETTY = 6,
	TOOL_STATS_KEY_JETTY_GROUP = 7,
	TOOL_STATS_KEY_URMA_DEV = 8,
} tool_stats_key_type_t;

typedef enum tool_res_key_type {
    TOOL_RES_KEY_VTP = 1,
    TOOL_RES_KEY_TP,
    TOOL_RES_KEY_TPG,
    TOOL_RES_KEY_UTP,
    TOOL_RES_KEY_JFS,
    TOOL_RES_KEY_JFR,
    TOOL_RES_KEY_JETTY,
    TOOL_RES_KEY_JETTY_GROUP,
    TOOL_RES_KEY_JFC,
    TOOL_RES_KEY_RC,
    TOOL_RES_KEY_SEG,
    TOOL_RES_KEY_DEV_TA,
    TOOL_RES_KEY_DEV_TP
} tool_res_key_type_t;

typedef struct netlink_cb_par {
    uint32_t type;
    uint32_t key;
} netlink_cb_par;

typedef struct tool_cmd {
    char *cmd;
    tool_cmd_type_t type;
} tool_cmd_t;

typedef struct uvs_cmd_query_stats {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint32_t type;
        uint32_t key;
    } in;
    struct {
        uint64_t tx_pkt;
        uint64_t rx_pkt;
        uint64_t tx_bytes;
        uint64_t rx_bytes;
        uint64_t tx_pkt_err;
        uint64_t rx_pkt_err;
    } out;
} uvs_cmd_query_stats_t;

typedef struct uvs_cmd_query_res {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint32_t type;
        uint32_t key;
        uint32_t key_ext;
        uint32_t key_cnt;
        bool query_cnt;
    } in;
    struct {
        uint64_t addr;
        uint32_t len;
        uint64_t save_ptr; /* save ubcore address for second ioctl */
    } out;
} uvs_cmd_query_res_t;

typedef struct utp_port {
    uint32_t utpn;
    uint16_t src_port_start;
    uint8_t range_port;
    bool spray_en;
} utp_port_t;

typedef struct tool_query_key {
    uint32_t type;
    uint32_t key;
    uint32_t key_ext;
    uint32_t key_cnt;
} tool_query_key_t;

typedef struct tool_config {
    tool_cmd_type_t cmd;
    bool specify_device;
    bool whole_info;
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];       /* ubep device name */
    urma_eid_t eid;
    bool dynamic_eid_mode;
    uint16_t fe_idx;
    /* eid start */
    uint16_t idx; /* eid idx */
    char ns[UVS_ADMIN_MAX_DEV_NAME]; /* /proc/$pid/ns/net */
    /* eid end */
    utp_port_t utp_port;
    tool_query_key_t key;
    uint16_t cc_alg;
    uint8_t ns_mode; /* 0: exclusive, 1: shared */
} tool_config_t;

typedef union urma_vtp_cfg_flag {
    struct {
        uint32_t clan_tp :  1;
        uint32_t migrate : 1;
        uint32_t reserve : 30;
    } bs;
    uint32_t value;
} urma_vtp_cfg_flag_t;

/* refer to struct ubcore_res_vtp_val */
typedef struct tool_res_vtp_val {
    uint16_t fe_idx;
    uint32_t vtpn;
    urma_eid_t local_eid;
    uint32_t local_jetty;
    urma_eid_t peer_eid;
    uint32_t peer_jetty;
    urma_vtp_cfg_flag_t flag;
    urma_transport_mode_t trans_mode;
    union {
        uint32_t tpgn;
        uint32_t tpn;
        uint32_t utpn;
        uint32_t ctpn;
    };
} tool_res_vtp_val_t;

/* refer to struct ubcore_res_tp_val */
typedef struct tool_res_tp_val {
    uint32_t tpn;
    uint32_t tx_psn;
    uint32_t rx_psn;
    uint8_t dscp;
    uint8_t oor_en;
    uint8_t selective_retrans_en;
    uint8_t state;
    uint16_t data_udp_start;
    uint16_t ack_udp_start;
    uint8_t udp_range;
    uint32_t spray_en;
} tool_res_tp_val_t;

/* refer to struct ubcore_res_tpg_val */
typedef struct tool_res_tpg_val {
    uint32_t tp_cnt;
    uint8_t dscp;
    uint32_t *tp_list;
} tool_res_tpg_val_t;

/* refer to struct ubcore_utp_cfg_flag */
typedef union tool_utp_cfg_flag {
    struct {
        uint32_t loopback :  1;
        uint32_t spray_en :  1;
        uint32_t reserved : 30;
    } bs;
    uint32_t value;
}tool_utp_cfg_flag_t;

/* refer to struct ubcore_res_utp_val */
typedef struct tool_res_utp_val {
    uint32_t utpn;
    uint16_t data_udp_start;
    uint8_t udp_range;
    tool_utp_cfg_flag_t flag;
} tool_res_utp_val_t;

static void init_tool_cfg(tool_config_t *cfg)
{
    (void)memset(cfg, 0, sizeof(tool_config_t));
    cfg->specify_device = false;
    cfg->whole_info = false;
    cfg->utp_port.spray_en = false;
    cfg->whole_info = false;
    cfg->fe_idx = OWN_FE_IDX;
}

static tool_cmd_type_t parse_command(const char *argv1)
{
    int i;

    tool_cmd_t cmd[] = {
        {"show_stats",      TOOL_CMD_SHOW_STATS},
        {"show_res",        TOOL_CMD_SHOW_RES},
        {"list_res",        TOOL_CMD_LIST_RES}
    };

    for (i = 0; i < (int)UVS_CMD_NUM; i++) {
        if (strlen(argv1) != strlen(cmd[i].cmd)) {
            continue;
        }
        if (strcmp(argv1, cmd[i].cmd) == 0) {
            return cmd[i].type;
        }
    }

    return TOOL_CMD_NUM;
}

static int check_query_type(const tool_config_t *cfg)
{
    if (cfg->cmd == TOOL_CMD_SHOW_STATS) {
        if (cfg->key.type < TOOL_STATS_KEY_VTP || cfg->key.type > TOOL_STATS_KEY_URMA_DEV) {
            (void)printf("Invalid type: %d.\n", (int)cfg->key.type);
            return -1;
        }
        if (cfg->key.type == TOOL_STATS_KEY_TPG || cfg->key.type == TOOL_STATS_KEY_JETTY_GROUP) {
            (void)printf("Type: %d currently not supported.\n", (int)cfg->key.type);
            return -1;
        }
    }
    if (cfg->cmd == TOOL_CMD_SHOW_RES) {
        if (cfg->key.type < TOOL_RES_KEY_VTP || cfg->key.type > TOOL_RES_KEY_DEV_TP) {
            (void)printf("Invalid type: %d.\n", (int)cfg->key.type);
            return -1;
        }
    }
    return 0;
}

static bool check_dev_name(char *dev_name)
{
    bool ret = false;
    DIR *cdev_dir;
    struct dirent *dent;

    cdev_dir = opendir(CDEV_PATH);
    if (cdev_dir == NULL) {
        (void)printf("%s open failed, errno: %d.\n", CDEV_PATH, errno);
        return false;
    }

    while ((dent = readdir(cdev_dir)) != NULL) {
        if (strcmp(dent->d_name, dev_name) == 0) {
            ret = true;
            break;
        }
    }

    if (closedir(cdev_dir) < 0) {
        (void)printf("Failed to close dir: %s, errno: %d.\n", CDEV_PATH, errno);
    }
    return ret;
}

static int uvs_str_to_u32(const char *buf, uint32_t *u32)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }
    if (ret > UINT_MAX) {
        return -ERANGE;
    }
    *u32 = (uint32_t)ret;
    return 0;
}

static int uvs_parse_args(int argc, char *argv[], tool_config_t *cfg)
{
    int ret = 0;

    if (argc == 1 || cfg == NULL) {
        return -1;
    }

    init_tool_cfg(cfg);
    /* First parse the command */
    cfg->cmd = parse_command(argv[1]);

    if (cfg->cmd != TOOL_CMD_SHOW_STATS && cfg->cmd != TOOL_CMD_SHOW_RES &&
    cfg->cmd != TOOL_CMD_LIST_RES) {
        return -1;
    }
    static const struct option long_options[] = {
        {"dev",               required_argument, NULL, 'd'},
        {"resource_type",     required_argument, NULL, 'R'},
        {"key_ext",           required_argument, NULL, 'K'},
        {"key_cnt",           required_argument, NULL, 'C'},
        {NULL,                no_argument,       NULL, '\0'}
    };

    /* Second parse the options */
    while (1) {
        int c;
        c = getopt_long(argc, argv, "C:d:R:k:", long_options, NULL);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'C':
                ret = uvs_str_to_u32(optarg, &cfg->key.key_cnt);
                break;
            case 'd':
                if (strnlen(optarg, UVS_ADMIN_MAX_DEV_NAME) + 1 > UVS_ADMIN_MAX_DEV_NAME ||
                    check_dev_name(optarg) == false) {
                    (void)printf("dev_name:%s out of range(%d) or invalid.\n", optarg, UVS_ADMIN_MAX_DEV_NAME);
                    return -1;
                }
                cfg->specify_device = true;
                (void)memcpy(cfg->dev_name, optarg, strlen(optarg));
                break;
            case 'R':
                ret = uvs_str_to_u32(optarg, &cfg->key.type);
                if (check_query_type(cfg) != 0) {
                    (void)printf("Failed to check query type: %u.\n", cfg->key.type);
                    return -1;
                }
                break;
            case 'k':
                ret = uvs_str_to_u32(optarg, &cfg->key.key);
                break;
            default:
                return -1;
        }
        if (ret != 0) {
            (void)printf("Please check the legality of parameters\n");
            return -1;
        }
    }

    if (optind < argc - 1) {
        return -1;
    }
    /* Increase illegal cmd return error */
    if (cfg->cmd == TOOL_CMD_NUM) {
        return -1;
    }
    return 0;
}

static struct nl_sock *alloc_and_connect_nl(int *genl_id)
{
    int ret;
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) {
        (void)printf("Failed to nl_socket_alloc\n");
        return NULL;
    }
    ret = genl_connect(sock);
    if (ret < 0) {
        (void)printf("Failed to nl_connect, ret:%d, errno:%d\n", ret, errno);
        nl_socket_free(sock);
        return NULL;
    }
    *genl_id = genl_ctrl_resolve(sock, UBCORE_GENL_FAMILY_NAME);
    if (*genl_id < 0) {
        (void)printf("Resolving of \"%s\" failed, ret:%d\n", UBCORE_GENL_FAMILY_NAME, *genl_id);
        nl_close(sock);
        nl_socket_free(sock);
        return NULL;
    }
    return sock;
}

static int cmd_nlsend(struct nl_sock *sock, int genl_id, urma_cmd_hdr_t *hdr)
{
    void *msg_hdr;
    struct nl_msg *msg;
    int ret = 0, nlmsg_flags = 0;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        (void)printf("Unable to allocate netlink message\n");
        return -1;
    }

    if (hdr->command == URMA_CORE_CMD_QUERY_RES) {
        nlmsg_flags = NLM_F_DUMP;
    }

    msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_id, 0, nlmsg_flags, (uint8_t)hdr->command,
        UBCORE_GENL_FAMILY_VERSION);
    if (msg_hdr == NULL) {
        (void)printf("Unable to write genl header\n");
        nlmsg_free(msg);
        return -1;
    }

    ret = nla_put_u32(msg, UBCORE_HDR_ARGS_LEN, hdr->args_len);
    if (ret < 0) {
        (void)printf("Unable to add args_len: %d\n", ret);
        nlmsg_free(msg);
        return ret;
    }

    ret = nla_put_u64(msg, UBCORE_HDR_ARGS_ADDR, hdr->args_addr);
    if (ret < 0) {
        (void)printf("Unable to add args_addr: %d\n", ret);
        nlmsg_free(msg);
        return ret;
    }

    ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        (void)printf("Netlink send failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr->command);
        nlmsg_free(msg);
        return ret;
    }

    nlmsg_free(msg);
    return ret;
}

static const char *g_query_res_type[] = {
    [0]                        = NULL,
    [TOOL_RES_KEY_VTP]         = "RES_VTP",
    [TOOL_RES_KEY_TP]          = "RES_TP",
    [TOOL_RES_KEY_TPG]         = "RES_TPG",
    [TOOL_RES_KEY_UTP]         = "RES_UTP",
    [TOOL_RES_KEY_DEV_TP]      = "RES_DEV_TP"
};

static void uvs_print_res_vtp(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_VTP_VAL) {
        tool_res_vtp_val_t *val = (tool_res_vtp_val_t *)nla_data(head);
        (void)printf("fe_idx              : %hu\n", val->fe_idx);
        (void)printf("vtpn                : %u\n", val->vtpn);
        (void)printf("local_eid           : "EID_FMT"\n", EID_ARGS(val->local_eid));
        (void)printf("local_jetty         : %u\n", val->local_jetty);
        (void)printf("peer_eid            : "EID_FMT"\n", EID_ARGS(val->peer_eid));
        (void)printf("per_jetty           : %u\n", val->peer_jetty);
        (void)printf("clan                : %s\n", val->flag.bs.clan_tp == 1 ? "TRUE" : "FALSE");
        (void)printf("migrate             : %s\n", val->flag.bs.migrate == 1 ? "TRUE" : "FALSE");
        (void)printf("trans_mode          : %u [%s]\n", (uint32_t)val->trans_mode,
            urma_trans_mode_to_string(val->trans_mode));
        if (val->flag.bs.clan_tp == 1) {
            (void)printf("ctpn                : %u\n", val->ctpn);
            return;
        }
        if (val->trans_mode == URMA_TM_RM || val->trans_mode == URMA_TM_RC) {
            (void)printf("tpgn                : %u\n", val->tpgn);
            return;
        }
        if (val->trans_mode == URMA_TM_UM) {
            (void)printf("utpn                : %u\n", val->utpn);
            return;
        }
    }
}

static const char *g_admin_tp_state[] = {
    "RESET",
    "RTR",
    "RTS",
    "SUSPENDED",
    "ERR"
};

static void uvs_print_res_tp(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_TP_VAL) {
        tool_res_tp_val_t *val = (tool_res_tp_val_t *)nla_data(head);
        (void)printf("tpn                 : %u\n", val->tpn);
        (void)printf("tx_psn              : %u\n", val->tx_psn);
        (void)printf("rx_psn              : %u\n", val->rx_psn);
        (void)printf("dscp                : %u\n", (uint32_t)val->dscp);
        (void)printf("oor_en              : %u\n", (uint32_t)val->oor_en);
        (void)printf("selective_retrans_en: %u\n", (uint32_t)val->selective_retrans_en);
        (void)printf("state               : %u [%s]\n", (uint32_t)val->state, g_admin_tp_state[val->state]);
        (void)printf("data_udp_start      : %hu\n", val->data_udp_start);
        (void)printf("ack_udp_start       : %hu\n", val->ack_udp_start);
        (void)printf("udp_range           : %u\n", (uint32_t)val->udp_range);
        (void)printf("spray_en            : %u\n", val->spray_en);
    }
}

static void uvs_print_res_tpg(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;

    nla_for_each_attr(nla, head, len, rem) {
        int type = nla_type(nla);
        if (type == UBCORE_RES_TPG_TP_CNT) {
            (void)printf("tp_cnt              : %u\n", nla_get_u32(nla));
        }

        if (type == UBCORE_RES_TPG_DSCP) {
            (void)printf("dscp                : %u\n", (uint32_t)nla_get_u8(nla));
            (void)printf("tp_list             : ");
        }

        if (type == UBCORE_RES_TPG_TP_VAL) {
            (void)printf("%u ", nla_get_u32(nla));
        }
    }
    (void)printf("\n");
}

static void uvs_print_res_utp(struct nlattr *head)
{
    int type = nla_type(head);
    if (type == UBCORE_RES_UTP_VAL) {
        tool_res_utp_val_t *val = (tool_res_utp_val_t *)nla_data(head);
        (void)printf("utp                 : %u\n", (uint32_t)val->utpn);
        (void)printf("flag                : %u\n", val->flag.value);
        (void)printf("data_udp_start      : %hu\n", val->data_udp_start);
        (void)printf("udp_range           : %u\n", (uint32_t)val->udp_range);
    }
}


static void uvs_print_res_dev(struct nlattr *head, int len)
{
    int rem;
    struct nlattr *nla;

    nla_for_each_attr(nla, head, len, rem)
    {
        int type = nla_type(nla);
        switch (type) {
            case UBCORE_RES_DEV_VTP_CNT: {
                (void)printf("\n----------VTP----------\n");
                (void)printf("vtp_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_TP_CNT: {
                (void)printf("\n----------TP-----------\n");
                (void)printf("tp_cnt              :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_TPG_CNT: {
                (void)printf("\n----------TPG----------\n");
                (void)printf("tpg_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            case UBCORE_RES_DEV_UTP_CNT: {
                (void)printf("\n----------UTP----------\n");
                (void)printf("utp_cnt             :%u \n", nla_get_u32(nla));
                break;
            }
            default:
                break;
        }
    }
    (void)printf("\n");
}

static void print_query_res(struct nlattr *attr_ptr, netlink_cb_par *cb_par, int len)
{
    (void)printf("**********%s**********\n", g_query_res_type[cb_par->type]);
    switch (cb_par->type) {
        case TOOL_RES_KEY_DEV_TP:
            uvs_print_res_dev(attr_ptr, len);
            break;
        case TOOL_RES_KEY_TPG:
            uvs_print_res_tpg(attr_ptr, len);
            break;
        case TOOL_RES_KEY_VTP:
            uvs_print_res_vtp(attr_ptr);
            break;
        case TOOL_RES_KEY_TP:
            uvs_print_res_tp(attr_ptr);
            break;
        case TOOL_RES_KEY_UTP:
            uvs_print_res_utp(attr_ptr);
            break;
        default:
            break;
    }
}

static int uvs_cb_handler(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attr_ptr = genlmsg_data(genlhdr);
    int len = genlmsg_attrlen(genlhdr, 0);

    netlink_cb_par *cb_par = (netlink_cb_par *)arg;
    print_query_res(attr_ptr, cb_par, len);

    return 0;
}

static int uvs_cmd_query_res(struct nl_sock *sock, const tool_config_t *cfg, int genl_id, netlink_cb_par *cb_arg)
{
    uvs_cmd_query_res_t *arg;
    urma_cmd_hdr_t hdr;
    arg = calloc(1, sizeof(uvs_cmd_query_res_t));
    if (arg == NULL) {
        return -1;
    }

    arg->in.key = cfg->key.key;
    arg->in.type = cfg->key.type;
    arg->in.key_ext = cfg->key.key_ext;
    arg->in.key_cnt = cfg->key.key_cnt;
    (void)memcpy(arg->in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    cb_arg->type = arg->in.type;
    cb_arg->key = arg->in.key;

    hdr.command = (uint32_t)URMA_CORE_CMD_QUERY_RES;
    hdr.args_len = (uint32_t)sizeof(uvs_cmd_query_res_t);
    hdr.args_addr = (uint64_t)arg;

    int ret = cmd_nlsend(sock, genl_id, &hdr);
    if (ret < 0) {
        (void)printf("Failed to cmd_nlsend, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
        free(arg);
        return ret;
    }

    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        (void)printf("Failed to nl_recvmsgs_default, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
    }
    free(arg);
    return 0;
}

int uvs_show_res(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;
    netlink_cb_par nl_cb_agr;

    if (cfg->key.key_cnt == 0 && cfg->key.type != TOOL_RES_KEY_DEV_TP) {
        (void)printf("key_cnt in show_res cannot be 0.\n");
        return -1;
    }
    if (cfg->key.type >= TOOL_RES_KEY_JFS && cfg->key.type <= TOOL_RES_KEY_DEV_TA) {
        (void)printf("uvs_admin do not support query ta stats.\n");
        return -1;
    }
    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    (void)nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, uvs_cb_handler, &nl_cb_agr);
    if (uvs_cmd_query_res(sock, cfg, genl_id, &nl_cb_agr) < 0) {
        (void)printf("Failed to query stats by ioctl.\n");
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }

    nl_close(sock);
    nl_socket_free(sock);
    return 0;
}

static void uvs_list_res_tpg(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem) {
        int type = nla_type(nla);
        if (type == UBCORE_RES_DEV_TPG_CNT) {
            (void)printf("\n----------TPG----------\n");
            (void)printf("tpg_cnt             :%u \n", nla_get_u32(nla));
        }

        if (type == UBCORE_RES_DEV_TPG_VAL) {
            (void)printf("tpg_id[%u]          \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void uvs_list_res_vtp(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem) {
        int type = nla_type(nla);
        if (type == UBCORE_RES_DEV_VTP_CNT) {
            (void)printf("\n----------VTP----------\n");
            (void)printf("vtp_cnt             :%u \n", nla_get_u32(nla));
        }

        if (type == UBCORE_RES_DEV_VTP_VAL) {
            (void)printf("vtp_id[%u]          \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void uvs_list_res_tp(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem) {
        int type = nla_type(nla);
        if (type == UBCORE_RES_DEV_TP_CNT) {
            (void)printf("\n----------TP-----------\n");
            (void)printf("tp_cnt              :%u \n", nla_get_u32(nla));
        }

        if (type == UBCORE_RES_DEV_TP_VAL) {
            (void)printf("tp_id[%u]           \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void uvs_list_res_utp(struct nlattr *head, int len)
{
    struct nlattr *nla;
    int rem;
    uint32_t i = 0;

    nla_for_each_attr(nla, head, len, rem) {
        int type = nla_type(nla);
        if (type == UBCORE_RES_DEV_UTP_CNT) {
            (void)printf("\n----------UTP----------\n");
            (void)printf("utp_cnt             :%u \n", nla_get_u32(nla));
        }

        if (type == UBCORE_RES_DEV_UTP_VAL) {
            (void)printf("utp_id[%u]          \t:%u\n", i, nla_get_u32(nla));
            i++;
        }
    }
}

static void print_list_res(struct nlattr *attr_ptr, netlink_cb_par *cb_par, int len)
{
    (void)printf("**********%s**********\n", g_query_res_type[cb_par->type]);
    switch (cb_par->type) {
        case TOOL_RES_KEY_TPG:
            uvs_list_res_tpg(attr_ptr, len);
            break;
        case TOOL_RES_KEY_VTP:
            uvs_list_res_vtp(attr_ptr, len);
            break;
        case TOOL_RES_KEY_TP:
            uvs_list_res_tp(attr_ptr, len);
            break;
        case TOOL_RES_KEY_UTP:
            uvs_list_res_utp(attr_ptr, len);
            break;
        default:
            break;
    }
}

static int uvs_cb_handler_list(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = genlmsg_hdr(hdr);
    struct nlattr *attr_ptr = genlmsg_data(genlhdr);
    int len = genlmsg_attrlen(genlhdr, 0);

    netlink_cb_par *cb_par = (netlink_cb_par *)arg;
    print_list_res(attr_ptr, cb_par, len);

    return 0;
}

static int uvs_cmd_list_res(struct nl_sock *sock, const tool_config_t *cfg, int genl_id, netlink_cb_par *cb_arg)
{
    uvs_cmd_query_res_t *arg;
    urma_cmd_hdr_t hdr;
    arg = calloc(1, sizeof(uvs_cmd_query_res_t));
    if (arg == NULL) {
        return -1;
    }

    arg->in.key = cfg->key.key;
    arg->in.type = cfg->key.type;
    arg->in.key_ext = cfg->key.key_ext;
    arg->in.key_cnt = cfg->key.key_cnt;
    (void)memcpy(arg->in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    cb_arg->type = arg->in.type;
    cb_arg->key = arg->in.key;

    hdr.command = (uint32_t)URMA_CORE_CMD_QUERY_RES;
    hdr.args_len = (uint32_t)sizeof(uvs_cmd_query_res_t);
    hdr.args_addr = (uint64_t)arg;

    int ret = cmd_nlsend(sock, genl_id, &hdr);
    if (ret < 0) {
        (void)printf("Failed to cmd_nlsend, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
        free(arg);
        return ret;
    }

    ret = nl_recvmsgs_default(sock);
    if (ret < 0) {
        (void)printf("Failed to nl_recvmsgs_default, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
    }
    free(arg);
    return 0;
}

int uvs_list_res(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;
    netlink_cb_par nl_cb_agr;

    if (cfg->key.key_cnt != 0) {
        (void)printf("key_cnt in list_res should equal 0.\n");
        return -1;
    }
    if (cfg->key.type >= TOOL_RES_KEY_JFS) {
        (void)printf("uvs_admin do not support query ta and dev stats.\n");
        return -1;
    }
    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    (void)nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, uvs_cb_handler_list, &nl_cb_agr);
    if (uvs_cmd_list_res(sock, cfg, genl_id, &nl_cb_agr) < 0) {
        (void)printf("Failed to query stats by ioctl.\n");
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }

    nl_close(sock);
    nl_socket_free(sock);
    return 0;
}

static inline void uvs_print_stats(const uvs_cmd_query_stats_t *arg)
{
    (void)printf("tx_pkt              : %lu\n", arg->out.tx_pkt);
    (void)printf("rx_pkt              : %lu\n", arg->out.rx_pkt);
    (void)printf("tx_bytes            : %lu\n", arg->out.tx_bytes);
    (void)printf("rx_bytes            : %lu\n", arg->out.rx_bytes);
    (void)printf("tx_pkt_err          : %lu\n", arg->out.tx_pkt_err);
    (void)printf("rx_pkt_err          : %lu\n", arg->out.rx_pkt_err);
}

static int uvs_cmd_query_stats(struct nl_sock *sock, const tool_config_t *cfg, int genl_id)
{
    urma_cmd_hdr_t hdr;
    uvs_cmd_query_stats_t arg = {0};

    hdr.command = (uint32_t)URMA_CORE_CMD_QUERY_STATS;
    hdr.args_len = (uint32_t)sizeof(uvs_cmd_query_stats_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->dev_name, strlen(cfg->dev_name));
    arg.in.key = cfg->key.key;
    arg.in.type = (uint32_t)cfg->key.type;

    int ret = cmd_nlsend(sock, genl_id, &hdr);
    if (ret < 0) {
        (void)printf("Failed to cmd_nlsend, ret: %d, command: %u, errno: %d.\n", ret, hdr.command, errno);
        return ret;
    }
    uvs_print_stats(&arg);
    return 0;
}

static int uvs_show_stats(const tool_config_t *cfg)
{
    struct nl_sock *sock = NULL;
    int genl_id;

    if (cfg->key.type >= TOOL_STATS_KEY_JFS && cfg->key.type <= TOOL_STATS_KEY_JETTY_GROUP) {
        (void)printf("uvs_admin do not support query ta stats.\n");
        return -1;
    }
    sock = alloc_and_connect_nl(&genl_id);
    if (sock == NULL) {
        return -1;
    }
    if (uvs_cmd_query_stats(sock, cfg, genl_id) < 0) {
        (void)printf("Failed to query stats by ioctl.\n");
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }

    nl_close(sock);
    nl_socket_free(sock);
    return 0;
}

static int execute_command(const tool_config_t *cfg)
{
    int ret;

    switch (cfg->cmd) {
        case TOOL_CMD_SHOW_STATS:
            ret = uvs_show_stats(cfg);
            break;
        case TOOL_CMD_SHOW_RES:
            ret = uvs_show_res(cfg);
            break;
        case TOOL_CMD_LIST_RES:
            ret = uvs_list_res(cfg);
            break;
        default:
            ret = -1;
            break;
    }
    return ret;
}

int query_res_cmd_exec(int argc, char *argv[])
{
    int ret;
    tool_config_t tool_cfg;

    ret = uvs_parse_args(argc, argv, &tool_cfg);
    if (ret != 0) {
        return ret;
    }

    ret = execute_command(&tool_cfg);
    if (ret != 0) {
        (void)printf("Failed to execute command.\n");
        return ret;
    }

    return ret;
}
