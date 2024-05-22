/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: 'uvs_admin vport add/show/del' command implementation
 * Author: Jilei
 * Create: 2023-07-14
 * Note: We declared a series of macro functions to check parameters,
 *          for reducing repetition rate, and being easier to amend
 * History: 2023-07-14 Jilei Initial version
 */

#include <getopt.h>
#include <arpa/inet.h>
#include <errno.h>

#include "uvs_admin_cmd_util.h"
#include "uvs_admin_cmd_client.h"
#include "vport_table_cmd.h"

#define UVS_ADMIN_DEFAULT_TP_CNT 2
#define UVS_ADMIN_DEFAULT_OOR_CNT 1024
#define UVS_ADMIN_DEFAULT_ACK_UDP_SRCPORT 0x12b8
#define UVS_AMIND_DEFAULT_UDP_RANGE 1
#define UVS_AMIND_DEFAULT_SHARE_MODE 1
#define UVS_AMIND_DEFAULT_CC_ALG (0x1 << 3) /* LDCP */
#define SIP_IDX_MAX 10239
#define EID_IDX_MAX 10239
#define FLOW_LABEL_MAX 1048575
#define RETRY_NUM_MAX 7
#define RETRY_FACTOR_MAX 7
#define ACK_TIMEOUT_MAX 31
#define DSCP_MAX 63

UVS_ADMIN_BRANCH_SUBCMD_USAGE(vport_table)

uvs_admin_cmd_t g_uvs_admin_vport_table_cmd = {
    .command = "vport_table",
    .summary = "vport_table config cmd",
    .usage   = UVS_ADMIN_BRANCH_SUBCMD_USAGE_VAR(vport_table),
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_vport_table_cmd.subcmds)),
    .run     = uvs_admin_branch_subcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

enum vport_table_table_opts {
#define VPORT_TABLE_OPT_HELP_LONG "help"
    VPORT_TABLE_OPT_HELP_NUM = 0,

#define VPORT_TABLE_OPT_DEV_NAME_LONG "dev_name"
    VPORT_TABLE_OPT_DEV_NAME_NUM,

#define VPORT_TABLE_OPT_FE_IDX_LONG "fe_idx"
    VPORT_TABLE_OPT_FE_IDX_NUM,

#define VPORT_TABLE_OPT_SIP_IDX_LONG "sip_idx"
    VPORT_TABLE_OPT_SIP_IDX_NUM,

#define VPORT_TABLE_OPT_OOR_EN_LONG "oor_en"
    VPORT_TABLE_OPT_OOR_EN_NUM,

#define VPORT_TABLE_OPT_SR_EN_LONG "sr_en"
    VPORT_TABLE_OPT_SR_EN_NUM,

#define VPORT_TABLE_OPT_CC_EN_LONG "cc_en"
    VPORT_TABLE_OPT_CC_EN_NUM,

#define VPORT_TABLE_OPT_CC_ALG_LONG "cc_alg"
    VPORT_TABLE_OPT_CC_ALG_NUM,

#define VPORT_TABLE_OPT_SPRAY_EN_LONG "spray_en"
    VPORT_TABLE_OPT_SPRAY_EN_NUM,

#define VPORT_TABLE_OPT_DCA_ENABLE_LONG "dca_enable"
    VPORT_TABLE_OPT_DCA_ENABLE_NUM,

#define VPORT_TABLE_OPT_FLOW_LABEL_LONG "flow_label"
    VPORT_TABLE_OPT_FLOW_LABEL_NUM,

#define VPORT_TABLE_OPT_OOR_CNT_LONG "oor_cnt"
    VPORT_TABLE_OPT_OOR_CNT_NUM,

#define VPORT_TABLE_OPT_RETRY_NUM_LONG "retry_num"
    VPORT_TABLE_OPT_RETRY_NUM_NUM,

#define VPORT_TABLE_OPT_RETRY_FACTOR_LONG "retry_factor"
    VPORT_TABLE_OPT_RETRY_FACTOR_NUM,

#define VPORT_TABLE_OPT_ACK_TIMEOUT_LONG "ack_timeout"
    VPORT_TABLE_OPT_ACK_TIMEOUT_NUM,

#define VPORT_TABLE_OPT_DSCP_LONG "dscp"
    VPORT_TABLE_OPT_DSCP_NUM,

#define VPORT_TABLE_OPT_DATA_UDP_START_LONG "data_udp_start"
    VPORT_TABLE_OPT_DATA_UDP_START_NUM,

#define VPORT_TABLE_OPT_ACK_UDP_START_LONG "ack_udp_start"
    VPORT_TABLE_OPT_ACK_UDP_START_NUM,

#define VPORT_TABLE_OPT_UDP_RANGE_LONG "udp_range"
    VPORT_TABLE_OPT_UDP_RANGE_NUM,

#define VPORT_TABLE_OPT_HOP_LIMIT_LONG "hop_limit"
    VPORT_TABLE_OPT_HOP_LIMIT_NUM,

#define VPORT_TABLE_OPT_MN_LONG "mn"
    VPORT_TABLE_OPT_MN_NUM,

#define VPORT_TABLE_OPT_LOOP_BACK_LONG "loop_back"
    VPORT_TABLE_OPT_LOOP_BACK_NUM,

#define VPORT_TABLE_OPT_ACK_RESP_LONG "ack_resp"
    VPORT_TABLE_OPT_ACK_RESP_NUM,

#define VPORT_TABLE_OPT_BONDING_LONG "bonding"
    VPORT_TABLE_OPT_BONDING_NUM,

#define VPORT_TABLE_OPT_RC_CNT_LONG "rc_cnt"
    VPORT_TABLE_OPT_RC_CNT_NUM,

#define VPORT_TABLE_OPT_RC_DEPTH_LONG "rc_depth"
    VPORT_TABLE_OPT_RC_DEPTH_NUM,

#define VPORT_TABLE_OPT_SLICE_LONG "slice"
    VPORT_TABLE_OPT_SLICE_NUM,

#define VPORT_TABLE_OPT_TP_CNT_LONG "tp_cnt"
    VPORT_TABLE_OPT_TP_NUM,

#define VPORT_TABLE_OPT_OOS_CNT_LONG "oos_cnt"
    VPORT_TABLE_OPT_OOS_CNT_NUM,

#define VPORT_TABLE_OPT_EID_LONG "eid"
    VPORT_TABLE_OPT_EID_NUM,

#define VPORT_TABLE_OPT_EID_IDX_LONG "eid_idx"
    VPORT_TABLE_OPT_EID_IDX_NUM,

#define VPORT_TABLE_OPT_UPI_LONG "upi"
    VPORT_TABLE_OPT_UPI_NUM,

#define VPORT_TABLE_OPT_PATTERN_LONG "pattern"
    VPORT_TABLE_OPT_PATTERN_NUM,

#define VPORT_TABLE_OPT_SHARE_MODE_LONG "share_mode"
    VPORT_TABLE_OPT_SHARE_MODE_NUM,

/* virtualization */
#define VPORT_TABLE_OPT_VIRTUALIZE_LONG "virtualization"
    VPORT_TABLE_OPT_VIRTUALIZE_NUM,

#define VPORT_TABLE_OPT_MIN_JETTR_CNT_LONG "min_jetty_cnt"
    VPORT_TABLE_OPT_MIN_JETTY_CNT_NUM,

#define VPORT_TABLE_OPT_MAX_JETTY_CNT_LONG "max_jetty_cnt"
    VPORT_TABLE_OPT_MAX_JETTY_CNT_NUM,

#define VPORT_TABLE_OPT_MIN_JFR_CNT_LONG "min_jfr_cnt"
    VPORT_TABLE_OPT_MIN_JFR_CNT_NUM,

#define VPORT_TABLE_OPT_MAX_JFR_CNT_LONG "max_jfr_cnt"
    VPORT_TABLE_OPT_MAX_JFR_CNT_NUM,

#define VPORT_TABLE_OPT_CC_PRIORITY_LONG "cc_priority"
    VPORT_TABLE_OPT_CC_PRIORITY_NUM,

#define VPORT_TABLE_OPT_FORCE_G_DOMAIN_LONG "force_g_domain"
    VPORT_TABLE_OPT_FORCE_G_DOMAIN_NUM,

    VPORT_TABLE_OPT_MAX_NUM,
};

typedef int (*vport_table_parse)(uvs_admin_vport_table_args_t *args, const char *_optarg);

static const struct opt_arg g_vport_table_opt_args[VPORT_TABLE_OPT_MAX_NUM] = {
    [VPORT_TABLE_OPT_HELP_NUM] = {VPORT_TABLE_OPT_HELP_LONG, ARG_TYPE_OTHERS},
    [VPORT_TABLE_OPT_DEV_NAME_NUM] = {VPORT_TABLE_OPT_DEV_NAME_LONG, ARG_TYPE_STR},
    [VPORT_TABLE_OPT_FE_IDX_NUM] = {VPORT_TABLE_OPT_FE_IDX_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_SIP_IDX_NUM] = {VPORT_TABLE_OPT_SIP_IDX_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_OOR_EN_NUM] = {VPORT_TABLE_OPT_OOR_EN_LONG, ARG_TYPE_STR},
    [VPORT_TABLE_OPT_SR_EN_NUM] = {VPORT_TABLE_OPT_SR_EN_LONG, ARG_TYPE_STR},
    [VPORT_TABLE_OPT_CC_EN_NUM] = {VPORT_TABLE_OPT_CC_EN_LONG, ARG_TYPE_STR},
    [VPORT_TABLE_OPT_CC_ALG_NUM] = {VPORT_TABLE_OPT_CC_ALG_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_SPRAY_EN_NUM] = {VPORT_TABLE_OPT_SPRAY_EN_LONG, ARG_TYPE_STR},
    [VPORT_TABLE_OPT_DCA_ENABLE_NUM] = {VPORT_TABLE_OPT_DCA_ENABLE_LONG, ARG_TYPE_STR},
    [VPORT_TABLE_OPT_FLOW_LABEL_NUM] = {VPORT_TABLE_OPT_FLOW_LABEL_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_OOR_CNT_NUM] = {VPORT_TABLE_OPT_OOR_CNT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_RETRY_NUM_NUM] = {VPORT_TABLE_OPT_RETRY_NUM_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_RETRY_FACTOR_NUM] = {VPORT_TABLE_OPT_RETRY_FACTOR_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_ACK_TIMEOUT_NUM] = {VPORT_TABLE_OPT_ACK_TIMEOUT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_DSCP_NUM] = {VPORT_TABLE_OPT_DSCP_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_DATA_UDP_START_NUM] = {VPORT_TABLE_OPT_DATA_UDP_START_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_ACK_UDP_START_NUM] = {VPORT_TABLE_OPT_ACK_UDP_START_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_UDP_RANGE_NUM] = {VPORT_TABLE_OPT_UDP_RANGE_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_HOP_LIMIT_NUM] = {VPORT_TABLE_OPT_HOP_LIMIT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_MN_NUM] = {VPORT_TABLE_OPT_MN_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_LOOP_BACK_NUM] = {VPORT_TABLE_OPT_LOOP_BACK_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_ACK_RESP_NUM] = {VPORT_TABLE_OPT_ACK_RESP_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_BONDING_NUM] = {VPORT_TABLE_OPT_BONDING_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_RC_CNT_NUM] = {VPORT_TABLE_OPT_RC_CNT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_RC_DEPTH_NUM] = {VPORT_TABLE_OPT_RC_DEPTH_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_SLICE_NUM] = {VPORT_TABLE_OPT_SLICE_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_TP_NUM] = {VPORT_TABLE_OPT_TP_CNT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_OOS_CNT_NUM] = {VPORT_TABLE_OPT_OOS_CNT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_EID_NUM] = {VPORT_TABLE_OPT_EID_LONG, ARG_TYPE_STR},
    [VPORT_TABLE_OPT_EID_IDX_NUM] = {VPORT_TABLE_OPT_EID_IDX_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_UPI_NUM] = {VPORT_TABLE_OPT_UPI_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_PATTERN_NUM] = {VPORT_TABLE_OPT_PATTERN_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_SHARE_MODE_NUM] = {VPORT_TABLE_OPT_SHARE_MODE_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_VIRTUALIZE_NUM] = {VPORT_TABLE_OPT_VIRTUALIZE_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_MIN_JETTY_CNT_NUM] = {VPORT_TABLE_OPT_MIN_JETTR_CNT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_MAX_JETTY_CNT_NUM] = {VPORT_TABLE_OPT_MAX_JETTY_CNT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_MIN_JFR_CNT_NUM] = {VPORT_TABLE_OPT_MIN_JFR_CNT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_MAX_JFR_CNT_NUM] = {VPORT_TABLE_OPT_MAX_JFR_CNT_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_CC_PRIORITY_NUM] = {VPORT_TABLE_OPT_CC_PRIORITY_LONG, ARG_TYPE_NUM},
    [VPORT_TABLE_OPT_FORCE_G_DOMAIN_NUM] = {VPORT_TABLE_OPT_FORCE_G_DOMAIN_LONG, ARG_TYPE_STR},
};

/* vport table show long options */
static const struct option g_vport_table_show_long_options[] = {
    {VPORT_TABLE_OPT_HELP_LONG,           no_argument,         NULL, VPORT_TABLE_OPT_HELP_NUM },
    {VPORT_TABLE_OPT_DEV_NAME_LONG,       required_argument,   NULL, VPORT_TABLE_OPT_DEV_NAME_NUM },
    {VPORT_TABLE_OPT_FE_IDX_LONG,         required_argument,   NULL, VPORT_TABLE_OPT_FE_IDX_NUM },
    {0,                                   0,                   0,    0 },
};

static const uvs_admin_opt_usage_t g_vport_table_show_cmd_opt_usage[] = {
    {VPORT_TABLE_OPT_HELP_LONG,           "display this help and exit", false},
    {VPORT_TABLE_OPT_DEV_NAME_LONG,       "specifies the name of tpf device", true},
    {VPORT_TABLE_OPT_FE_IDX_LONG,         "fe_idx is determined by tpf device", true},
};

static const uvs_admin_cmd_usage_t g_vport_table_show_cmd_usage = {
    .opt_usage = g_vport_table_show_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_vport_table_show_cmd_opt_usage),
};

/* vport table add long options */
static const struct option g_vport_table_add_long_options[] = {
    {VPORT_TABLE_OPT_HELP_LONG,           no_argument,         NULL, VPORT_TABLE_OPT_HELP_NUM },
    {VPORT_TABLE_OPT_DEV_NAME_LONG,       required_argument,   NULL, VPORT_TABLE_OPT_DEV_NAME_NUM },
    {VPORT_TABLE_OPT_FE_IDX_LONG,         required_argument,   NULL, VPORT_TABLE_OPT_FE_IDX_NUM },
    {VPORT_TABLE_OPT_SIP_IDX_LONG,        required_argument,   NULL, VPORT_TABLE_OPT_SIP_IDX_NUM },
    {VPORT_TABLE_OPT_OOR_EN_LONG,         required_argument,   NULL, VPORT_TABLE_OPT_OOR_EN_NUM },
    {VPORT_TABLE_OPT_SR_EN_LONG,          required_argument,   NULL, VPORT_TABLE_OPT_SR_EN_NUM },
    {VPORT_TABLE_OPT_CC_EN_LONG,          required_argument,   NULL, VPORT_TABLE_OPT_CC_EN_NUM },
    {VPORT_TABLE_OPT_CC_ALG_LONG,         required_argument,   NULL, VPORT_TABLE_OPT_CC_ALG_NUM },
    {VPORT_TABLE_OPT_SPRAY_EN_LONG,       required_argument,   NULL, VPORT_TABLE_OPT_SPRAY_EN_NUM },
    {VPORT_TABLE_OPT_DCA_ENABLE_LONG,     required_argument,   NULL, VPORT_TABLE_OPT_DCA_ENABLE_NUM },
    {VPORT_TABLE_OPT_FLOW_LABEL_LONG,     required_argument,   NULL, VPORT_TABLE_OPT_FLOW_LABEL_NUM },
    {VPORT_TABLE_OPT_OOR_CNT_LONG,        required_argument,   NULL, VPORT_TABLE_OPT_OOR_CNT_NUM },
    {VPORT_TABLE_OPT_RETRY_NUM_LONG,      required_argument,   NULL, VPORT_TABLE_OPT_RETRY_NUM_NUM },
    {VPORT_TABLE_OPT_RETRY_FACTOR_LONG,   required_argument,   NULL, VPORT_TABLE_OPT_RETRY_FACTOR_NUM },
    {VPORT_TABLE_OPT_ACK_TIMEOUT_LONG,    required_argument,   NULL, VPORT_TABLE_OPT_ACK_TIMEOUT_NUM },
    {VPORT_TABLE_OPT_DSCP_LONG,           required_argument,   NULL, VPORT_TABLE_OPT_DSCP_NUM },
    {VPORT_TABLE_OPT_DATA_UDP_START_LONG, required_argument,   NULL, VPORT_TABLE_OPT_DATA_UDP_START_NUM },
    {VPORT_TABLE_OPT_ACK_UDP_START_LONG,  required_argument,   NULL, VPORT_TABLE_OPT_ACK_UDP_START_NUM },
    {VPORT_TABLE_OPT_UDP_RANGE_LONG,      required_argument,   NULL, VPORT_TABLE_OPT_UDP_RANGE_NUM },
    {VPORT_TABLE_OPT_HOP_LIMIT_LONG,      required_argument,   NULL, VPORT_TABLE_OPT_HOP_LIMIT_NUM },
    {VPORT_TABLE_OPT_MN_LONG,             required_argument,   NULL, VPORT_TABLE_OPT_MN_NUM },
    {VPORT_TABLE_OPT_LOOP_BACK_LONG,      required_argument,   NULL, VPORT_TABLE_OPT_LOOP_BACK_NUM },
    {VPORT_TABLE_OPT_ACK_RESP_LONG,       required_argument,   NULL, VPORT_TABLE_OPT_ACK_RESP_NUM },
    {VPORT_TABLE_OPT_BONDING_LONG,        required_argument,   NULL, VPORT_TABLE_OPT_BONDING_NUM },
    {VPORT_TABLE_OPT_RC_CNT_LONG,         required_argument,   NULL, VPORT_TABLE_OPT_RC_CNT_NUM },
    {VPORT_TABLE_OPT_RC_DEPTH_LONG,       required_argument,   NULL, VPORT_TABLE_OPT_RC_DEPTH_NUM },
    {VPORT_TABLE_OPT_SLICE_LONG,          required_argument,   NULL, VPORT_TABLE_OPT_SLICE_NUM },
    {VPORT_TABLE_OPT_TP_CNT_LONG,         required_argument,   NULL, VPORT_TABLE_OPT_TP_NUM },
    {VPORT_TABLE_OPT_OOS_CNT_LONG,        required_argument,   NULL, VPORT_TABLE_OPT_OOS_CNT_NUM },
    {VPORT_TABLE_OPT_PATTERN_LONG,        required_argument,   NULL, VPORT_TABLE_OPT_PATTERN_NUM },
    {VPORT_TABLE_OPT_SHARE_MODE_LONG,     required_argument,   NULL, VPORT_TABLE_OPT_SHARE_MODE_NUM },
    {VPORT_TABLE_OPT_VIRTUALIZE_LONG,     required_argument,   NULL, VPORT_TABLE_OPT_VIRTUALIZE_NUM },
    {VPORT_TABLE_OPT_MIN_JETTR_CNT_LONG,  required_argument,   NULL, VPORT_TABLE_OPT_MIN_JETTY_CNT_NUM },
    {VPORT_TABLE_OPT_MAX_JETTY_CNT_LONG,  required_argument,   NULL, VPORT_TABLE_OPT_MAX_JETTY_CNT_NUM },
    {VPORT_TABLE_OPT_MIN_JFR_CNT_LONG,    required_argument,   NULL, VPORT_TABLE_OPT_MIN_JFR_CNT_NUM },
    {VPORT_TABLE_OPT_MAX_JFR_CNT_LONG,    required_argument,   NULL, VPORT_TABLE_OPT_MAX_JFR_CNT_NUM },
    {VPORT_TABLE_OPT_CC_PRIORITY_LONG,    required_argument,   NULL, VPORT_TABLE_OPT_CC_PRIORITY_NUM },
    {VPORT_TABLE_OPT_FORCE_G_DOMAIN_LONG, required_argument,   NULL, VPORT_TABLE_OPT_FORCE_G_DOMAIN_NUM },
    {0,                                   0,                   0,    0 },
};

#define CC_ALG_HELP "control algorith value:\n\
    \t\t\t\t((PFC: 1) | (DCQCN: 2) | (CC_DCQCN_AND_NETWORK_CC: 4) |\n\
    \t\t\t\t(CC_LDCP: 8) | (CC_LDCP_AND_CAQM: 16) | (CC_LDCP_AND_OPEN_CC: 32) |\n\
    \t\t\t\t(CC_HC3: 64) | (CC_DIP: 128))(default: CC_LDCP)"

static const uvs_admin_opt_usage_t g_vport_table_add_cmd_opt_usage[] = {
    {VPORT_TABLE_OPT_HELP_LONG,           "display this help and exit", false},
    {VPORT_TABLE_OPT_DEV_NAME_LONG,       "specifies the name of tpf device", true},
    {VPORT_TABLE_OPT_FE_IDX_LONG,         "fe_idx is determined by tpf device", true},
    {VPORT_TABLE_OPT_SIP_IDX_LONG,        "index of the entry in sip_table, allocated by ubcore", true},
    {VPORT_TABLE_OPT_OOR_EN_LONG,         "out of order receive(default disable)", false},
    {VPORT_TABLE_OPT_SR_EN_LONG,          "selective retransmission(default disable)", false},
    {VPORT_TABLE_OPT_CC_EN_LONG,          "congestion control algorithm(default disable)", false},
    {VPORT_TABLE_OPT_CC_ALG_LONG,         CC_ALG_HELP, false},
    {VPORT_TABLE_OPT_CC_PRIORITY_LONG,    "selective retransmission priority", false},
    {VPORT_TABLE_OPT_SPRAY_EN_LONG,       "spray with src udp port(default disable)", false},
    {VPORT_TABLE_OPT_DCA_ENABLE_LONG,     "dynamic connection administrate(default disable)", false},
    {VPORT_TABLE_OPT_FLOW_LABEL_LONG,     "IPv6 Flow Label[0 - 1048575]", false},
    {VPORT_TABLE_OPT_OOR_CNT_LONG,        "oor_cnt(default 4)", false},
    {VPORT_TABLE_OPT_RETRY_NUM_LONG,      "retry num[0 - 7]", false},
    {VPORT_TABLE_OPT_RETRY_FACTOR_LONG,   "retry factor[0 - 7]", false},
    {VPORT_TABLE_OPT_ACK_TIMEOUT_LONG,    "ack timeout[0 - 31]", false},
    {VPORT_TABLE_OPT_DSCP_LONG,           "differentiated Services Code Point[0 - 63]", false},
    {VPORT_TABLE_OPT_DATA_UDP_START_LONG, "data_udp_start(default 0)", true},
    {VPORT_TABLE_OPT_ACK_UDP_START_LONG,  "ack_udp_start(default 0x12b8)", false},
    {VPORT_TABLE_OPT_UDP_RANGE_LONG,      "udp range(default 1)", false},
    {VPORT_TABLE_OPT_HOP_LIMIT_LONG,      "hop_limit(default 0)", false},
    {VPORT_TABLE_OPT_MN_LONG,             "mn(default 0)", false},
    {VPORT_TABLE_OPT_LOOP_BACK_LONG,      "loop_back(default 0)", false},
    {VPORT_TABLE_OPT_ACK_RESP_LONG,       "ack_resp(default 0)", false},
    {VPORT_TABLE_OPT_BONDING_LONG,        "bonding(default 0)", false},
    {VPORT_TABLE_OPT_RC_CNT_LONG,         "rc cnt(default 2)", false},
    {VPORT_TABLE_OPT_RC_DEPTH_LONG,       "rc depth", false},
    {VPORT_TABLE_OPT_SLICE_LONG,          "slice", false},
    {VPORT_TABLE_OPT_TP_CNT_LONG,         "tp_cnt(default 2)", false},
    {VPORT_TABLE_OPT_OOS_CNT_LONG,        "oos_cnt(default 0)", false},
    {VPORT_TABLE_OPT_PATTERN_LONG,        "pattern (0: pattern1; 1: pattern3)", false},
    {VPORT_TABLE_OPT_SHARE_MODE_LONG,     "share_mode(default 1, share_mode)", false},
    {VPORT_TABLE_OPT_VIRTUALIZE_LONG,     "supports virtualization(default disable)", false},
    {VPORT_TABLE_OPT_MIN_JETTR_CNT_LONG,  "min jetty cnt supported by a FE", false},
    {VPORT_TABLE_OPT_MAX_JETTY_CNT_LONG,  "max jetty cnt supported by a FE", false},
    {VPORT_TABLE_OPT_MIN_JFR_CNT_LONG,    "min jfr cnt supported by a FE", false},
    {VPORT_TABLE_OPT_MAX_JFR_CNT_LONG,    "max jfr cnt supported by a FE", false},
    {VPORT_TABLE_OPT_FORCE_G_DOMAIN_LONG, "force link in global domain mode(default disable)", false},
};

static const uvs_admin_cmd_usage_t g_vport_table_add_cmd_usage = {
    .opt_usage = g_vport_table_add_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_vport_table_add_cmd_opt_usage),
};

/* vport table del long options */
static const struct option g_vport_table_del_long_options[] = {
    {VPORT_TABLE_OPT_HELP_LONG,      no_argument,       NULL, VPORT_TABLE_OPT_HELP_NUM },
    {VPORT_TABLE_OPT_DEV_NAME_LONG,  required_argument,   NULL, VPORT_TABLE_OPT_DEV_NAME_NUM },
    {VPORT_TABLE_OPT_FE_IDX_LONG,      required_argument, NULL, VPORT_TABLE_OPT_FE_IDX_NUM },
    {0,                        0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_vport_table_del_cmd_opt_usage[] = {
    {VPORT_TABLE_OPT_HELP_LONG,     "display this help and exit", false},
    {VPORT_TABLE_OPT_DEV_NAME_LONG, "specifies the name of tpf device", true},
    {VPORT_TABLE_OPT_FE_IDX_LONG,   "fe_idx is determined by tpf device", true},
};

static const uvs_admin_cmd_usage_t g_vport_table_del_cmd_usage = {
    .opt_usage = g_vport_table_del_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_vport_table_del_cmd_opt_usage),
};

/* vport table show ueid long options */
static const struct option g_vport_table_show_ueid_long_options[] = {
    {VPORT_TABLE_OPT_HELP_LONG,      no_argument,       NULL, VPORT_TABLE_OPT_HELP_NUM },
    {VPORT_TABLE_OPT_DEV_NAME_LONG,  required_argument,   NULL, VPORT_TABLE_OPT_DEV_NAME_NUM },
    {VPORT_TABLE_OPT_FE_IDX_LONG,      required_argument, NULL, VPORT_TABLE_OPT_FE_IDX_NUM },
    {VPORT_TABLE_OPT_EID_IDX_LONG,   required_argument, NULL, VPORT_TABLE_OPT_EID_IDX_NUM },
    {0,                              0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_vport_table_show_ueid_cmd_opt_usage[] = {
    {VPORT_TABLE_OPT_HELP_LONG,      "display this help and exit", false},
    {VPORT_TABLE_OPT_DEV_NAME_LONG,  "specifies the name of tpf device", true},
    {VPORT_TABLE_OPT_FE_IDX_LONG,    "fe_idx is determined by tpf device", true},
    {VPORT_TABLE_OPT_EID_IDX_LONG,   "index of the entry in ueid_table", true},
};

static const uvs_admin_cmd_usage_t g_vport_table_show_ueid_cmd_usage = {
    .opt_usage = g_vport_table_show_ueid_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_vport_table_show_ueid_cmd_opt_usage),
};

/* vport table add ueid long options */
static const struct option g_vport_table_add_ueid_long_options[] = {
    {VPORT_TABLE_OPT_HELP_LONG,      no_argument,       NULL, VPORT_TABLE_OPT_HELP_NUM },
    {VPORT_TABLE_OPT_DEV_NAME_LONG,  required_argument, NULL, VPORT_TABLE_OPT_DEV_NAME_NUM },
    {VPORT_TABLE_OPT_FE_IDX_LONG,    required_argument, NULL, VPORT_TABLE_OPT_FE_IDX_NUM },
    {VPORT_TABLE_OPT_EID_LONG,       required_argument, NULL, VPORT_TABLE_OPT_EID_NUM },
    {VPORT_TABLE_OPT_UPI_LONG,       required_argument, NULL, VPORT_TABLE_OPT_UPI_NUM },
    {VPORT_TABLE_OPT_EID_IDX_LONG,   required_argument, NULL, VPORT_TABLE_OPT_EID_IDX_NUM},
    {0,                        0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_vport_table_add_ueid_cmd_opt_usage[] = {
    {VPORT_TABLE_OPT_HELP_LONG,     "display this help and exit", false},
    {VPORT_TABLE_OPT_DEV_NAME_LONG, "specifies the name of tpf device", true},
    {VPORT_TABLE_OPT_FE_IDX_LONG,   "fe_idx is determined by tpf device", true},
    {VPORT_TABLE_OPT_EID_LONG,      "config the eid for UB device", true},
    {VPORT_TABLE_OPT_UPI_LONG,      "virtual or pattern3 static mode need set(default 0)", true},
    {VPORT_TABLE_OPT_EID_IDX_LONG,  "index of the entry in ueid_table", true},
};

static const uvs_admin_cmd_usage_t g_vport_table_add_ueid_cmd_usage = {
    .opt_usage = g_vport_table_add_ueid_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_vport_table_add_ueid_cmd_opt_usage),
};

/* vport table del_ueid long options */
static const struct option g_vport_table_del_ueid_long_options[] = {
    {VPORT_TABLE_OPT_HELP_LONG,      no_argument,       NULL, VPORT_TABLE_OPT_HELP_NUM },
    {VPORT_TABLE_OPT_DEV_NAME_LONG,  required_argument,   NULL, VPORT_TABLE_OPT_DEV_NAME_NUM },
    {VPORT_TABLE_OPT_FE_IDX_LONG,      required_argument, NULL, VPORT_TABLE_OPT_FE_IDX_NUM },
    {VPORT_TABLE_OPT_EID_IDX_LONG,   required_argument, NULL, VPORT_TABLE_OPT_EID_IDX_NUM},
    {0,                        0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_vport_table_del_eid_cmd_opt_usage[] = {
    {VPORT_TABLE_OPT_HELP_LONG,     "display this help and exit", false},
    {VPORT_TABLE_OPT_DEV_NAME_LONG, "specifies the name of tpf device", true},
    {VPORT_TABLE_OPT_FE_IDX_LONG,   "fe_idx is determined by tpf device", true},
    {VPORT_TABLE_OPT_EID_IDX_LONG,  "index of the entry in ueid_table", true},
};

static const uvs_admin_cmd_usage_t g_vport_table_del_ueid_cmd_usage = {
    .opt_usage = g_vport_table_del_eid_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_vport_table_del_eid_cmd_opt_usage),
};

/* vport table set upi long options */
static const struct option g_vport_table_set_upi_long_options[] = {
    {VPORT_TABLE_OPT_HELP_LONG,      no_argument,       NULL, VPORT_TABLE_OPT_HELP_NUM },
    {VPORT_TABLE_OPT_DEV_NAME_LONG,  required_argument, NULL, VPORT_TABLE_OPT_DEV_NAME_NUM },
    {VPORT_TABLE_OPT_UPI_LONG,       required_argument, NULL, VPORT_TABLE_OPT_UPI_NUM },
    {0,                        0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_vport_table_set_upi_cmd_opt_usage[] = {
    {VPORT_TABLE_OPT_HELP_LONG,     "display this help and exit", false},
    {VPORT_TABLE_OPT_DEV_NAME_LONG, "specifies the name of tpf device", true},
    {VPORT_TABLE_OPT_UPI_LONG,      "pattern3 dynamic mode upi need set", true},
};

static const uvs_admin_cmd_usage_t g_vport_table_set_upi_cmd_usage = {
    .opt_usage = g_vport_table_set_upi_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_vport_table_set_upi_cmd_opt_usage),
};

static const struct option g_vport_table_show_upi_long_options[] = {
    {VPORT_TABLE_OPT_HELP_LONG,      no_argument,       NULL, VPORT_TABLE_OPT_HELP_NUM },
    {VPORT_TABLE_OPT_DEV_NAME_LONG,  required_argument, NULL, VPORT_TABLE_OPT_DEV_NAME_NUM },
    {0,                        0,                 0,    0 },
};

static const uvs_admin_opt_usage_t g_vport_table_show_upi_cmd_opt_usage[] = {
    {VPORT_TABLE_OPT_HELP_LONG,     "display this help and exit", false},
    {VPORT_TABLE_OPT_DEV_NAME_LONG, "specifies the name of tpf device", true},
};

static const uvs_admin_cmd_usage_t g_vport_table_show_upi_cmd_usage = {
    .opt_usage = g_vport_table_show_upi_cmd_opt_usage,
    .opt_num   = ARRAY_SIZE(g_vport_table_show_upi_cmd_opt_usage),
};

static inline int vport_table_input_range_check(uint32_t num, uint32_t range_min, uint32_t range_max)
{
    if (range_min <= num && num <= range_max) {
        return 0;
    }
    return -EINVAL;
}

static inline int parse_fe_idx(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint16_t num;

    ret = ub_str_to_u16(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT16_MAX) != 0) {
        return -EINVAL;
    }

    args->fe_idx = num;
    args->mask.bs.fe_idx = 1;
    return 0;
}

static inline int parse_sip_idx(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, SIP_IDX_MAX) != 0) {
        return -EINVAL;
    }

    args->sip_idx = num;
    args->mask.bs.sip_idx = 1;
    return 0;
}

static inline int parse_oor_en(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    bool res;

    ret = ub_str_to_bool(_optarg, &res);
    if (ret != 0) {
        return -EINVAL;
    }

    args->tp_cfg.tp_mod_flag.bs.oor_en = res;
    return 0;
}

static inline int parse_sr_en(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    bool res;

    ret = ub_str_to_bool(_optarg, &res);
    if (ret != 0) {
        return -EINVAL;
    }

    args->tp_cfg.tp_mod_flag.bs.sr_en = res;
    return 0;
}

static inline int parse_cc_en(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    bool res;

    ret = ub_str_to_bool(_optarg, &res);
    if (ret != 0) {
        return -EINVAL;
    }

    args->tp_cfg.tp_mod_flag.bs.cc_en = res;
    return 0;
}

static inline int parse_cc_alg(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint16_t res;

    ret = ub_str_to_u16(_optarg, &res);
    if (ret != 0) {
        return -EINVAL;
    }

    if (res >= (uint16_t)UVS_ADMIN_VPORT_TABLE_CC_ALG_MAX) { // include all cc alg
        return -EINVAL;
    }
    args->tp_cfg.cc_alg = res;
    args->tp_cfg.set_cc_alg = true;

    return 0;
}

static inline int parse_spray_en(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    bool res;

    ret = ub_str_to_bool(_optarg, &res);
    if (ret != 0) {
        return -EINVAL;
    }

    args->tp_cfg.tp_mod_flag.bs.spray_en = res;
    return 0;
}

static inline int parse_dca_enable(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    bool res;

    ret = ub_str_to_bool(_optarg, &res);
    if (ret != 0) {
        return -EINVAL;
    }

    args->tp_cfg.tp_mod_flag.bs.dca_enable = res;
    return 0;
}

static inline int parse_flow_label(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, FLOW_LABEL_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.flow_label = num;
    args->mask.bs.flow_label = 1;
    return 0;
}

static inline int parse_oor_cnt(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.oor_cnt = num;
    args->mask.bs.oor_cnt = 1;
    return 0;
}

static inline int parse_retry_num(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint8_t num;

    ret = ub_str_to_u8(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, RETRY_NUM_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.retry_num = num;
    args->mask.bs.retry_num = 1;
    return 0;
}

static inline int parse_retry_factor(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint8_t num;

    ret = ub_str_to_u8(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, RETRY_FACTOR_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.retry_factor = num;
    args->mask.bs.retry_factor = 1;
    return 0;
}

static inline int parse_ack_timeout(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint8_t num;

    ret = ub_str_to_u8(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, ACK_TIMEOUT_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.ack_timeout = num;
    args->mask.bs.ack_timeout = 1;
    return 0;
}

static inline int parse_dscp(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint8_t num;

    ret = ub_str_to_u8(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, DSCP_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.dscp = num;
    args->mask.bs.dscp = 1;
    return 0;
}

static inline int parse_data_udp_start(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint16_t num;

    ret = ub_str_to_u16(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT16_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.data_udp_start = num;
    args->mask.bs.data_udp_start = 1;
    return 0;
}

static inline int parse_ack_udp_start(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint16_t num;

    ret = ub_str_to_u16(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT16_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.ack_udp_start = num;
    args->mask.bs.ack_udp_start = 1;
    return 0;
}

static inline int parse_udp_range(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint8_t num;

    ret = ub_str_to_u8(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT8_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.udp_range = num;
    args->mask.bs.udp_range = 1;
    return 0;
}

static inline int parse_hop_limit(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint8_t num;

    ret = ub_str_to_u8(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT8_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.hop_limit = num;
    args->mask.bs.hop_limit = 1;
    return 0;
}

static inline int parse_mn(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint8_t num;

    ret = ub_str_to_u8(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT8_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.mn = num;
    args->mask.bs.mn = 1;
    return 0;
}

static inline int parse_loop_back(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.loop_back = num;
    args->mask.bs.loop_back = 1;
    return 0;
}

static inline int parse_ack_resp(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.ack_resp = num;
    args->mask.bs.ack_resp = 1;
    return 0;
}

static inline int parse_bonding(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.bonding = num;
    args->mask.bs.bonding = 1;
    return 0;
}

static inline int parse_rc_cnt(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->rc_cfg.rc_cnt = num;
    args->mask.bs.rc_cnt = 1;
    return 0;
}

static inline int parse_rc_depth(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->rc_cfg.rc_depth = num;
    args->mask.bs.rc_depth = 1;
    return 0;
}

static inline int parse_rc_slice(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->rc_cfg.slice = num;
    args->mask.bs.slice = 1;
    return 0;
}

static inline int parse_tp_cnt(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cnt = num;
    args->mask.bs.tp_cnt = 1;
    return 0;
}

static inline int parse_oos_cnt(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.oos_cnt = num;
    args->mask.bs.oos_cnt = 1;
    return 0;
}

static inline int parse_upi(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, UINT32_MAX) != 0) {
        return -EINVAL;
    }

    args->upi = num;
    args->mask.bs.upi = 1;
    return 0;
}

static inline int parse_eid_index(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, EID_IDX_MAX) != 0) {
        return -EINVAL;
    }

    args->eid_idx = num;
    args->mask.bs.eid_idx = 1;
    return 0;
}

static inline int parse_eid(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;

    ret = str_to_eid(_optarg, &args->eid);
    if (ret != 0) {
        return -EINVAL;
    }

    args->mask.bs.eid = 1;
    return 0;
}

static inline int vport_table_input_str_range_check(uint32_t str_len_max, uint32_t input_str_len)
{
    if (input_str_len >= str_len_max) {
        return -1;
    }
    return 0;
}

static inline int parse_dev_name(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    if (vport_table_input_str_range_check((uint32_t)UVS_ADMIN_MAX_DEV_NAME, (uint32_t)strlen(_optarg)) != 0) {
        return -EINVAL;
    }
    (void)strcpy(args->dev_name, _optarg);
    args->mask.bs.dev_name = 1;
    return 0;
}

static inline int parse_pattern(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    args->pattern = num;
    args->mask.bs.pattern = 1;
    return 0;
}

static inline int parse_share_mode(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    if (vport_table_input_range_check(num, 0, 1) != 0) {
        return -EINVAL;
    }

    args->tp_cfg.tp_mod_flag.bs.share_mode = num;
    args->mask.bs.share_mode = 1;
    return 0;
}

static inline int parse_virtualize(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    args->virtualization = num;
    args->mask.bs.virtualization = 1;
    return 0;
}

static inline int parse_min_jetty_cnt(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    args->min_jetty_cnt = num;
    args->mask.bs.min_jetty_cnt = 1;
    return 0;
}

static inline int parse_max_jetty_cnt(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    args->max_jetty_cnt = num;
    args->mask.bs.max_jetty_cnt = 1;
    return 0;
}

static inline int parse_min_jfr_cnt(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    args->min_jfr_cnt = num;
    args->mask.bs.min_jfr_cnt = 1;
    return 0;
}

static inline int parse_max_jfr_cnt(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint32_t num;

    ret = ub_str_to_u32(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    args->max_jfr_cnt = num;
    args->mask.bs.max_jfr_cnt = 1;
    return 0;
}

static inline int parse_cc_priority(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    uint8_t num;

    ret = ub_str_to_u8(_optarg, &num);
    if (ret != 0) {
        return -EINVAL;
    }

    args->tp_cfg.cc_priority = num;
    args->tp_cfg.set_cc_priority = true;
    return 0;
}

static inline int parse_force_global_domain(uvs_admin_vport_table_args_t *args, const char *_optarg)
{
    int ret;
    bool res;

    ret = ub_str_to_bool(_optarg, &res);
    if (ret != 0) {
        return -EINVAL;
    }

    args->tp_cfg.force_g_domain = res;
    return 0;
}

static const vport_table_parse g_vport_table_parse[VPORT_TABLE_OPT_MAX_NUM] = {
    [VPORT_TABLE_OPT_DEV_NAME_NUM ] = parse_dev_name,
    [VPORT_TABLE_OPT_FE_IDX_NUM] = parse_fe_idx,
    [VPORT_TABLE_OPT_SIP_IDX_NUM] = parse_sip_idx,
    [VPORT_TABLE_OPT_OOR_EN_NUM] = parse_oor_en,
    [VPORT_TABLE_OPT_SR_EN_NUM] = parse_sr_en,
    [VPORT_TABLE_OPT_CC_EN_NUM] = parse_cc_en,
    [VPORT_TABLE_OPT_CC_ALG_NUM] = parse_cc_alg,
    [VPORT_TABLE_OPT_SPRAY_EN_NUM] = parse_spray_en,
    [VPORT_TABLE_OPT_DCA_ENABLE_NUM] = parse_dca_enable,
    [VPORT_TABLE_OPT_FLOW_LABEL_NUM] = parse_flow_label,
    [VPORT_TABLE_OPT_OOR_CNT_NUM] = parse_oor_cnt,
    [VPORT_TABLE_OPT_RETRY_NUM_NUM] = parse_retry_num,
    [VPORT_TABLE_OPT_RETRY_FACTOR_NUM] = parse_retry_factor,
    [VPORT_TABLE_OPT_ACK_TIMEOUT_NUM] = parse_ack_timeout,
    [VPORT_TABLE_OPT_DSCP_NUM] = parse_dscp,
    [VPORT_TABLE_OPT_DATA_UDP_START_NUM] = parse_data_udp_start,
    [VPORT_TABLE_OPT_ACK_UDP_START_NUM] = parse_ack_udp_start,
    [VPORT_TABLE_OPT_UDP_RANGE_NUM] = parse_udp_range,
    [VPORT_TABLE_OPT_HOP_LIMIT_NUM] = parse_hop_limit,
    [VPORT_TABLE_OPT_MN_NUM] = parse_mn,
    [VPORT_TABLE_OPT_LOOP_BACK_NUM] = parse_loop_back,
    [VPORT_TABLE_OPT_ACK_RESP_NUM] = parse_ack_resp,
    [VPORT_TABLE_OPT_BONDING_NUM] = parse_bonding,
    [VPORT_TABLE_OPT_RC_CNT_NUM] = parse_rc_cnt,
    [VPORT_TABLE_OPT_RC_DEPTH_NUM] = parse_rc_depth,
    [VPORT_TABLE_OPT_SLICE_NUM] = parse_rc_slice,
    [VPORT_TABLE_OPT_TP_NUM] = parse_tp_cnt,
    [VPORT_TABLE_OPT_OOS_CNT_NUM] = parse_oos_cnt,
    [VPORT_TABLE_OPT_EID_NUM] = parse_eid,
    [VPORT_TABLE_OPT_EID_IDX_NUM] = parse_eid_index,
    [VPORT_TABLE_OPT_UPI_NUM] = parse_upi,
    [VPORT_TABLE_OPT_PATTERN_NUM] = parse_pattern,
    [VPORT_TABLE_OPT_SHARE_MODE_NUM] = parse_share_mode,
    [VPORT_TABLE_OPT_VIRTUALIZE_NUM] = parse_virtualize,
    [VPORT_TABLE_OPT_MIN_JETTY_CNT_NUM] = parse_min_jetty_cnt,
    [VPORT_TABLE_OPT_MAX_JETTY_CNT_NUM] = parse_max_jetty_cnt,
    [VPORT_TABLE_OPT_MIN_JFR_CNT_NUM] = parse_min_jfr_cnt,
    [VPORT_TABLE_OPT_MAX_JFR_CNT_NUM] = parse_max_jfr_cnt,
    [VPORT_TABLE_OPT_CC_PRIORITY_NUM ] = parse_cc_priority,
    [VPORT_TABLE_OPT_FORCE_G_DOMAIN_NUM] = parse_force_global_domain,
};

static int32_t vport_table_cmd_prep_args(uvs_admin_cmd_ctx_t *ctx, const struct option *longopts,
    const struct opt_arg *optargs, uvs_admin_vport_table_args_t *args)
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

        if ((ret >= VPORT_TABLE_OPT_HELP_NUM) && (ret < VPORT_TABLE_OPT_MAX_NUM)) {
            if (ret == VPORT_TABLE_OPT_HELP_NUM) {
                uvs_admin_cmd_usages(ctx);
                status = -EINVAL;
                break;
            }
            status = g_vport_table_parse[ret](args, optarg);
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

static void uvs_admin_print_vport(uvs_admin_vport_table_show_rsp_t *show_rsp)
{
    (void)printf(UVS_ADMIN_SHOW_PREFIX);
    (void)printf("dev_name                   : %s\n", show_rsp->args.dev_name);
    (void)printf("fe_idx                     : %hu\n", show_rsp->args.fe_idx);
    (void)printf("sip_idx                    : %u\n", show_rsp->args.sip_idx);
    (void)printf("tp_cnt                     : %u\n", show_rsp->args.tp_cnt);
    (void)printf("tp_cfg:\n");
    print_tp_mod_flag_str(show_rsp->args.tp_cfg.tp_mod_flag);
    (void)printf("    flow_label             : %u\n", show_rsp->args.tp_cfg.flow_label);
    (void)printf("    oor_cnt                : %u\n", show_rsp->args.tp_cfg.oor_cnt);
    (void)printf("    retry_num              : %u\n", show_rsp->args.tp_cfg.retry_num);
    (void)printf("    retry_factor           : %u\n", show_rsp->args.tp_cfg.retry_factor);
    (void)printf("    ack_timeout            : %u\n", show_rsp->args.tp_cfg.ack_timeout);
    (void)printf("    dscp                   : %u\n", show_rsp->args.tp_cfg.dscp);
    (void)printf("    data_udp_start         : %hu\n", show_rsp->args.tp_cfg.data_udp_start);
    (void)printf("    ack_udp_start          : %hu\n", show_rsp->args.tp_cfg.ack_udp_start);
    (void)printf("    udp_range              : %u\n", show_rsp->args.tp_cfg.udp_range);
    (void)printf("    hop_limit              : %u\n", show_rsp->args.tp_cfg.hop_limit);
    (void)printf("    port                   : %u\n", show_rsp->args.tp_cfg.port);
    (void)printf("    mn                     : %u\n", show_rsp->args.tp_cfg.mn);
    (void)printf("    loop_back              : %u\n", show_rsp->args.tp_cfg.loop_back);
    (void)printf("    ack_resp               : %u\n", show_rsp->args.tp_cfg.ack_resp);
    (void)printf("    bonding                : %u\n", show_rsp->args.tp_cfg.bonding);
    (void)printf("    oos_cnt                : %u\n", show_rsp->args.tp_cfg.oos_cnt);
    (void)printf("    cc_alg                 : %u\n", show_rsp->args.tp_cfg.cc_alg);
    (void)printf("    cc_priority            : %u\n", show_rsp->args.tp_cfg.cc_priority);
    (void)printf("rc_cfg:\n");
    (void)printf("    rc_cnt                 : %u\n", show_rsp->args.rc_cfg.rc_cnt);
    (void)printf("    rc_depth               : %u\n", show_rsp->args.rc_cfg.rc_depth);
    (void)printf("    slice                  : %u\n", show_rsp->args.rc_cfg.slice);
    (void)printf("pattern                    : %u\n", show_rsp->args.pattern);

    (void)printf("virtualization             : %u\n", show_rsp->args.virtualization);
    (void)printf("force_g_domain             : %d\n", show_rsp->args.tp_cfg.force_g_domain);
    (void)printf("min_jetty_cnt              : %u\n", show_rsp->args.min_jetty_cnt);
    (void)printf("max_jetty_cnt              : %u\n", show_rsp->args.max_jetty_cnt);
    (void)printf("min_jfr_cnt                : %u\n", show_rsp->args.min_jfr_cnt);
    (void)printf("max_jfr_cnt                : %u\n", show_rsp->args.max_jfr_cnt);
}

static int32_t uvs_admin_vport_table_showcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_vport_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = vport_table_cmd_prep_args(ctx, g_vport_table_show_long_options, g_vport_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_vport_table_show_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_VPORT_TABLE_SHOW;
    req->req_len = (ssize_t)sizeof(uvs_admin_vport_table_show_req_t);

    uvs_admin_vport_table_show_req_t *vport_table_req = (uvs_admin_vport_table_show_req_t *)req->req;
    (void)memcpy(vport_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);
    vport_table_req->fe_idx = args.fe_idx;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        (void)printf("err: failed to recv resp: vport_table show\n");
        free(req);
        return -EIO;
    }

    uvs_admin_vport_table_show_rsp_t *show_rsp = (uvs_admin_vport_table_show_rsp_t *)rsp->rsp;
    if (show_rsp->res != 0) {
        (void)printf("ERR: failed to show vport info, ret: %d, fe_idx: %hu, dev_name: %s.\n",
            show_rsp->res, vport_table_req->fe_idx, args.dev_name);
    } else {
        uvs_admin_print_vport(show_rsp);
    }

    free(req);
    return 0;
}

static void uvs_admin_set_default_para(uvs_admin_vport_table_add_req_t *vport_table_req)
{
    uvs_admin_vport_table_args_t *args = &vport_table_req->args;

    args->tp_cnt = (args->mask.bs.tp_cnt == 0 || args->tp_cnt == 0) ?
        UVS_ADMIN_DEFAULT_TP_CNT : args->tp_cnt;
    args->tp_cfg.ack_udp_start = args->mask.bs.ack_udp_start == 0 ?
        UVS_ADMIN_DEFAULT_ACK_UDP_SRCPORT : args->tp_cfg.ack_udp_start;
    args->tp_cfg.oor_cnt = args->mask.bs.oor_cnt == 0 ?
        UVS_ADMIN_DEFAULT_OOR_CNT : args->tp_cfg.oor_cnt;
    args->tp_cfg.cc_alg = args->tp_cfg.set_cc_alg == 0 ?
        UVS_AMIND_DEFAULT_CC_ALG : args->tp_cfg.cc_alg;
    args->tp_cfg.udp_range = args->mask.bs.udp_range == 0 ?
        UVS_AMIND_DEFAULT_UDP_RANGE : args->tp_cfg.udp_range;
    args->tp_cfg.tp_mod_flag.bs.share_mode = args->mask.bs.share_mode == 0 ?
        UVS_AMIND_DEFAULT_SHARE_MODE : args->tp_cfg.tp_mod_flag.bs.share_mode;

    args->mask.bs.tp_cnt = 1;
    args->mask.bs.ack_udp_start = 1;
    args->mask.bs.oor_cnt = 1;
    args->mask.bs.udp_range = 1;
    args->tp_cfg.set_cc_alg = 1;
    args->mask.bs.share_mode = 1;
}

static int uvs_admin_vport_check_tp_cnt_valid(uint32_t tp_cnt)
{
    if (tp_cnt <= 1) {
        return -1;
    }
    /* check if tp_cnt is the power of 2 */
    if ((tp_cnt & (tp_cnt - 1)) != 0) {
        return -1;
    }
    return 0;
}

static int uvs_admin_vport_table_addcmd_validation(uvs_admin_vport_table_args_t args)
{
    if (args.mask.bs.dev_name == 0 || args.mask.bs.fe_idx == 0 || args.mask.bs.sip_idx == 0) {
        (void)printf("ERR: invalid parameter, must set dev_name/fe_idx/sip_idx, mask:%lx\n", args.mask.value);
        return -EINVAL;
    }

    if (args.mask.bs.tp_cnt == 1 && (uvs_admin_vport_check_tp_cnt_valid(args.tp_cnt) < 0)) {
        (void)printf("ERR: invalid parameter, tp_cnt: %u, it should be the power of 2\n", args.tp_cnt);
        return -EINVAL;
    }
    return 0;
}

static int32_t uvs_admin_vport_table_addcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_vport_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = vport_table_cmd_prep_args(ctx, g_vport_table_add_long_options, g_vport_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    ret = uvs_admin_vport_table_addcmd_validation(args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_vport_table_add_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_VPORT_TABLE_ADD;
    req->req_len = (ssize_t)sizeof(uvs_admin_vport_table_add_req_t);

    uvs_admin_vport_table_add_req_t *vport_table_req = (uvs_admin_vport_table_add_req_t *)req->req;
    vport_table_req->args = args;
    /* defualt para */
    uvs_admin_set_default_para(vport_table_req);

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        (void)printf("err: failed to recv resp: vport_table add\n");
        free(req);
        return -EIO;
    }

    uvs_admin_vport_table_add_rsp_t *add_rsp = (uvs_admin_vport_table_add_rsp_t *)rsp->rsp;
    if (add_rsp->res != 0) {
        (void)printf("ERR: failed to add vport info, ret: %d, fe_idx: %hu, dev_name: %s.\n",
                     add_rsp->res, args.fe_idx, args.dev_name);
    }

    free(req);
    return 0;
}

static int32_t uvs_admin_vport_table_delcmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_vport_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = vport_table_cmd_prep_args(ctx, g_vport_table_del_long_options, g_vport_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_vport_table_del_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_VPORT_TABLE_DEL;
    req->req_len = (ssize_t)sizeof(uvs_admin_vport_table_del_req_t);

    uvs_admin_vport_table_del_req_t *vport_table_req = (uvs_admin_vport_table_del_req_t *)req->req;
    (void)memcpy(vport_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);
    vport_table_req->fe_idx = args.fe_idx;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        (void)printf("err: failed to recv resp: vport_table del\n");
        free(req);
        return -EIO;
    }

    uvs_admin_vport_table_del_rsp_t *del_rsp = (uvs_admin_vport_table_del_rsp_t *)rsp->rsp;
    if (del_rsp->res != 0) {
        (void)printf("ERR: failed to del vport info, ret: %d, fe_idx: %hu, dev_name: %s.\n",
            del_rsp->res, args.fe_idx, args.dev_name);
    }

    free(req);
    return 0;
}

static void uvs_admin_print_ueid(uvs_admin_vport_table_show_ueid_req_t *req,
    uvs_admin_vport_table_show_ueid_rsp_t *show_rsp)
{
    (void)printf(UVS_ADMIN_SHOW_PREFIX);
    (void)printf("dev_name                   : %s\n", req->dev_name);
    (void)printf("fe_idx                     : %hu\n", req->fe_idx);
    (void)printf("eid_idx                    : %u\n", req->eid_idx);
    (void)printf("eid                        : "EID_FMT"\n", EID_ARGS(show_rsp->eid));
    (void)printf("upi(static mode)           : %u\n", show_rsp->upi);
}

static int32_t uvs_admin_vport_table_showueid_cmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_vport_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = vport_table_cmd_prep_args(ctx, g_vport_table_show_ueid_long_options, g_vport_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    if (args.mask.bs.dev_name == 0 || args.mask.bs.fe_idx == 0 || args.mask.bs.eid_idx == 0) {
        (void)printf("ERR: invalid parameter, must set dev_name/fe_idx/eid_idx, mask:%lx\n", args.mask.value);
        return -EINVAL;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_vport_table_show_ueid_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_UEID_TABLE_SHOW;
    req->req_len = (ssize_t)sizeof(uvs_admin_vport_table_show_ueid_req_t);

    uvs_admin_vport_table_show_ueid_req_t *vport_table_req = (uvs_admin_vport_table_show_ueid_req_t *)req->req;
    (void)memcpy(vport_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);
    vport_table_req->fe_idx = args.fe_idx;
    vport_table_req->eid_idx = args.eid_idx;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        (void)printf("err: failed to recv resp: vport_table show_ueid\n");
        free(req);
        return -EIO;
    }

    uvs_admin_vport_table_show_ueid_rsp_t *show_rsp = (uvs_admin_vport_table_show_ueid_rsp_t *)rsp->rsp;
    if (show_rsp->res != 0) {
        (void)printf("ERR: failed to show ueid, ret: %d, dev_name: %s, fe_idx: %hu, eid_index: %u.\n",
            show_rsp->res, vport_table_req->dev_name, vport_table_req->fe_idx, args.eid_idx);
    } else {
        uvs_admin_print_ueid(vport_table_req, show_rsp);
    }

    free(req);
    return 0;
}

static int32_t uvs_admin_vport_table_addueid_cmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_vport_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = vport_table_cmd_prep_args(ctx, g_vport_table_add_ueid_long_options, g_vport_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_vport_table_add_ueid_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_UEID_TABLE_ADD;
    req->req_len = (ssize_t)sizeof(uvs_admin_vport_table_add_ueid_req_t);

    uvs_admin_vport_table_add_ueid_req_t *vport_table_req = (uvs_admin_vport_table_add_ueid_req_t *)req->req;
    (void)memcpy(vport_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);
    vport_table_req->fe_idx = args.fe_idx;
    vport_table_req->eid = args.eid;
    vport_table_req->upi = args.upi;
    vport_table_req->eid_idx = args.eid_idx;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        (void)printf("err: failed to recv resp: vport_table add_ueid\n");
        free(req);
        return -EIO;
    }

    uvs_admin_vport_table_add_ueid_rsp_t *add_rsp = (uvs_admin_vport_table_add_ueid_rsp_t *)rsp->rsp;
    if (add_rsp->res != 0) {
        (void)printf("ERR: failed to add ueid, ret: %d.\n", add_rsp->res);
    }

    free(req);
    return 0;
}

static int32_t uvs_admin_vport_table_delueid_cmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_vport_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = vport_table_cmd_prep_args(ctx, g_vport_table_del_ueid_long_options, g_vport_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_vport_table_del_ueid_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_UEID_TABLE_DEL;
    req->req_len = (ssize_t)sizeof(uvs_admin_vport_table_del_ueid_req_t);

    uvs_admin_vport_table_del_ueid_req_t *vport_table_req = (uvs_admin_vport_table_del_ueid_req_t *)req->req;
    (void)memcpy(vport_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);
    vport_table_req->fe_idx = args.fe_idx;
    vport_table_req->eid_idx = args.eid_idx;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        (void)printf("err: failed to recv resp: vport_table del_ueid\n");
        return -EIO;
    }

    uvs_admin_vport_table_del_ueid_rsp_t *del_rsp = (uvs_admin_vport_table_del_ueid_rsp_t *)rsp->rsp;
    if (del_rsp->res != 0) {
        (void)printf("ERR: failed to del ueid, ret: %d.\n", del_rsp->res);
    }

    (void)printf("SUCCESS to del ueid, ret: %d.\n", del_rsp->res);

    free(req);
    return 0;
}

static int32_t uvs_admin_vport_table_setupi_cmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_vport_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = vport_table_cmd_prep_args(ctx, g_vport_table_set_upi_long_options, g_vport_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_vport_table_set_upi_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_SET_UPI;
    req->req_len = (ssize_t)sizeof(uvs_admin_vport_table_set_upi_req_t);

    uvs_admin_vport_table_set_upi_req_t *vport_table_req = (uvs_admin_vport_table_set_upi_req_t *)req->req;
    (void)memcpy(vport_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);
    vport_table_req->upi = args.upi;

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_vport_table_set_upi_rsp_t *set_upi_rsp = (uvs_admin_vport_table_set_upi_rsp_t *)rsp->rsp;
    if (set_upi_rsp->res != 0) {
        (void)printf("ERR: failed to set upi, ret: %d.\n", set_upi_rsp->res);
    }

    free(req);
    return 0;
}

static void uvs_admin_print_upi(char *dev_name, uvs_admin_vport_table_show_upi_rsp_t *show_rsp)
{
    (void)printf(UVS_ADMIN_SHOW_PREFIX);
    (void)printf("dev_name                   : %s\n", dev_name);
    (void)printf("upi(dynamic mode) : 0x%x\n", show_rsp->upi);
}

static int32_t uvs_admin_vport_table_showupi_cmd_exec(uvs_admin_cmd_ctx_t *ctx)
{
    int ret;
    uvs_admin_request_t *req = NULL;
    uvs_admin_response_t *rsp = NULL;
    uvs_admin_vport_table_args_t args = {0};
    char buf[MAX_MSG_LEN] = {0};

    ret = vport_table_cmd_prep_args(ctx, g_vport_table_show_upi_long_options, g_vport_table_opt_args, &args);
    if (ret != 0) {
        return ret;
    }

    req = malloc(sizeof(uvs_admin_request_t) + sizeof(uvs_admin_vport_table_show_upi_req_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    req->cmd_type = UVS_ADMIN_SHOW_UPI;
    req->req_len = (ssize_t)sizeof(uvs_admin_vport_table_show_upi_req_t);

    uvs_admin_vport_table_show_upi_req_t *vport_table_req = (uvs_admin_vport_table_show_upi_req_t *)req->req;
    (void)memcpy(vport_table_req->dev_name, args.dev_name, UVS_ADMIN_MAX_DEV_NAME);

    rsp = client_get_rsp(ctx, req, buf);
    if (rsp == NULL) {
        free(req);
        return -EIO;
    }

    uvs_admin_vport_table_show_upi_rsp_t *show_upi_rsp = (uvs_admin_vport_table_show_upi_rsp_t *)rsp->rsp;
    if (show_upi_rsp->res != 0) {
        (void)printf("ERR: failed to show upi, ret: %d.\n", show_upi_rsp->res);
        (void)printf("Use uvs_admin vport_table show_ueid to query upi in pattern3 static mode.\n");
    } else {
        uvs_admin_print_upi(vport_table_req->dev_name, show_upi_rsp);
    }

    free(req);
    return 0;
}

uvs_admin_cmd_t g_uvs_admin_vport_table_show_cmd = {
    .command = "show",
    .summary = "show vport_table entry",
    .usage = &g_vport_table_show_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_vport_table_show_cmd.subcmds)),
    .run = uvs_admin_vport_table_showcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO + UVS_ADMIN_CMD_PARM_TWO,
};

uvs_admin_cmd_t g_uvs_admin_vport_table_add_cmd = {
    .command = "add",
    .summary = "add vport_table entry",
    .usage = &g_vport_table_add_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_vport_table_add_cmd.subcmds)),
    .run = uvs_admin_vport_table_addcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_THREE + UVS_ADMIN_CMD_PARM_THREE,
};

uvs_admin_cmd_t g_uvs_admin_vport_table_del_cmd = {
    .command = "del",
    .summary = "del vport_table entry",
    .usage = &g_vport_table_del_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_vport_table_del_cmd.subcmds)),
    .run = uvs_admin_vport_table_delcmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO + UVS_ADMIN_CMD_PARM_TWO,
};

uvs_admin_cmd_t g_uvs_admin_vport_table_show_ueid_cmd = {
    .command = "show_ueid",
    .summary = "show vport ueid table entry",
    .usage = &g_vport_table_show_ueid_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_vport_table_show_ueid_cmd.subcmds)),
    .run = uvs_admin_vport_table_showueid_cmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_THREE + UVS_ADMIN_CMD_PARM_THREE,
};

uvs_admin_cmd_t g_uvs_admin_vport_table_add_ueid_cmd = {
    .command = "add_ueid",
    .summary = "add ueid entry",
    .usage = &g_vport_table_add_ueid_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_vport_table_add_ueid_cmd.subcmds)),
    .run = uvs_admin_vport_table_addueid_cmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_FIVE + UVS_ADMIN_CMD_PARM_FIVE,
};

uvs_admin_cmd_t g_uvs_admin_vport_table_del_ueid_cmd = {
    .command = "del_ueid",
    .summary = "del ueid entry",
    .usage = &g_vport_table_del_ueid_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_vport_table_del_ueid_cmd.subcmds)),
    .run = uvs_admin_vport_table_delueid_cmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_THREE + UVS_ADMIN_CMD_PARM_THREE,
};

uvs_admin_cmd_t g_uvs_admin_vport_table_set_upi_cmd = {
    .command = "set_upi",
    .summary = "set upi value",
    .usage = &g_vport_table_set_upi_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_vport_table_set_upi_cmd.subcmds)),
    .run = uvs_admin_vport_table_setupi_cmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_FOUR,
};

uvs_admin_cmd_t g_uvs_admin_vport_table_show_upi_cmd = {
    .command = "show_upi",
    .summary = "show upi value",
    .usage = &g_vport_table_show_upi_cmd_usage,
    .node = NULL,
    .subcmds = SHASH_INITIALIZER(&(g_uvs_admin_vport_table_show_upi_cmd.subcmds)),
    .run = uvs_admin_vport_table_showupi_cmd_exec,
    .min_argc = UVS_ADMIN_CMD_PARM_TWO,
};

static uvs_admin_cmd_t *g_uvs_admin_vport_table_subcmds[] = {
    &g_uvs_admin_vport_table_show_cmd,
    &g_uvs_admin_vport_table_add_cmd,
    &g_uvs_admin_vport_table_del_cmd,
    &g_uvs_admin_vport_table_show_ueid_cmd,
    &g_uvs_admin_vport_table_add_ueid_cmd,
    &g_uvs_admin_vport_table_del_ueid_cmd,
    &g_uvs_admin_vport_table_set_upi_cmd,
    &g_uvs_admin_vport_table_show_upi_cmd,
};

REGISTER_UVS_ADMIN_COMMANDS(g_uvs_admin_vport_table_cmd, g_uvs_admin_vport_table_subcmds)
