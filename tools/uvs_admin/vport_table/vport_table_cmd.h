/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of 'uvs_admin vport add/show/del' command
 * Author: Ji Lei
 * Create: 2023-07-15
 * Note:
 * History: 2023-07-15 Ji Lei Initial version
 */

#ifndef VPORT_TABLE_CMD_H
#define VPORT_TABLE_CMD_H

#include <netinet/in.h>
#include "uvs_admin_cmd.h"
#include "uvs_admin_types.h"
#include "urma_types.h"

# define UVS_ADMIN_VPORT_TABLE_CC_ALG_MAX 256

typedef union uvs_admin_vport_table_mask {
    struct {
        uint64_t dev_name            : 1;
        uint64_t fe_idx              : 1;
        uint64_t sip_idx             : 1;
        uint64_t tp_cnt              : 1;
        uint64_t flow_label          : 1;
        uint64_t oor_cnt             : 1;
        uint64_t retry_num           : 1;
        uint64_t retry_factor        : 1;
        uint64_t ack_timeout         : 1;
        uint64_t dscp                : 1;
        uint64_t cc_pattern_idx      : 1;
        uint64_t data_udp_start      : 1;
        uint64_t ack_udp_start       : 1;
        uint64_t udp_range           : 1;
        uint64_t hop_limit           : 1;
        uint64_t port                : 1;
        uint64_t mn                  : 1;
        uint64_t loop_back           : 1;
        uint64_t ack_resp            : 1;
        uint64_t bonding             : 1;
        uint64_t oos_cnt             : 1;
        uint64_t rc_cnt              : 1;
        uint64_t rc_depth            : 1;
        uint64_t slice               : 1;
        uint64_t eid                 : 1;
        uint64_t eid_index           : 1;
        uint64_t upi                 : 1;
        uint64_t pattern             : 1;
        uint64_t virtualization      : 1;
        uint64_t min_jetty_cnt       : 1;
        uint64_t max_jetty_cnt       : 1;
        uint64_t min_jfr_cnt         : 1;
        uint64_t max_jfr_cnt         : 1;
        uint64_t reserved            : 27;
    } bs;
    uint64_t value;
} uvs_admin_vport_table_mask_t;

typedef struct uvs_admin_vport_table_args {
    uvs_admin_vport_table_mask_t mask;
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t sip_idx;
    uint32_t tp_cnt;
    uvs_admin_tp_mod_cfg_t tp_cfg;
    uvs_admin_rc_cfg_t rc_cfg;
    urma_eid_t eid;
    uint32_t eid_index;
    uint32_t upi;
    uint32_t pattern;
    uint32_t virtualization;
    uint32_t min_jetty_cnt;
    uint32_t max_jetty_cnt;
    uint32_t min_jfr_cnt;
    uint32_t max_jfr_cnt;
} uvs_admin_vport_table_args_t;

typedef struct uvs_admin_vport_table_show_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
} uvs_admin_vport_table_show_req_t;

typedef struct uvs_admin_vport_table_show_rsp {
    int res;
    uvs_admin_vport_table_args_t args;
} uvs_admin_vport_table_show_rsp_t;

typedef struct uvs_admin_vport_table_add_req {
    uvs_admin_vport_table_args_t args;
} uvs_admin_vport_table_add_req_t;

typedef struct uvs_admin_vport_table_add_rsp {
    int32_t res;
} uvs_admin_vport_table_add_rsp_t;

typedef struct uvs_admin_vport_table_del_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
} uvs_admin_vport_table_del_req_t;

typedef struct uvs_admin_vport_table_del_rsp {
    int32_t res;
} uvs_admin_vport_table_del_rsp_t;

typedef struct uvs_admin_vport_table_show_ueid_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t eid_index;
} uvs_admin_vport_table_show_ueid_req_t;

typedef struct uvs_admin_vport_table_show_ueid_rsp {
    int res;
    uint32_t upi;
    urma_eid_t eid;
} uvs_admin_vport_table_show_ueid_rsp_t;

typedef struct uvs_admin_vport_table_add_ueid_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t upi;
    urma_eid_t eid;
    uint32_t eid_index;
} uvs_admin_vport_table_add_ueid_req_t;

typedef struct uvs_admin_vport_table_add_ueid_rsp {
    int32_t res;
} uvs_admin_vport_table_add_ueid_rsp_t;

typedef struct uvs_admin_vport_table_del_ueid_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t eid_index;
} uvs_admin_vport_table_del_ueid_req_t;

typedef struct uvs_admin_vport_table_del_ueid_rsp {
    int32_t res;
} uvs_admin_vport_table_del_ueid_rsp_t;

typedef struct uvs_admin_vport_table_set_upi_req {
    uint32_t upi;
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
} uvs_admin_vport_table_set_upi_req_t;

typedef struct uvs_admin_vport_table_set_upi_rsp {
    int32_t res;
} uvs_admin_vport_table_set_upi_rsp_t;

typedef struct uvs_admin_vport_table_show_upi_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
} uvs_admin_vport_table_show_upi_req_t;

typedef struct uvs_admin_vport_table_show_upi_rsp {
    int32_t res;
    uint32_t upi;
} uvs_admin_vport_table_show_upi_rsp_t;

extern uvs_admin_cmd_t g_uvs_admin_vport_table_cmd;

static const char * const g_uvs_admin_tp_mod_flag_str[] = {
#define UVS_ADMIN_TP_MOD_FLAG_OOR_EN 0
    [UVS_ADMIN_TP_MOD_FLAG_OOR_EN] = "OOR_EN",
#define UVS_ADMIN_TP_MOD_FLAG_SR_EN 1
    [UVS_ADMIN_TP_MOD_FLAG_SR_EN] = "SR_EN",
#define UVS_ADMIN_TP_MOD_FLAG_CC_EN 2
    [UVS_ADMIN_TP_MOD_FLAG_CC_EN] = "CC_EN",

#define UVS_ADMIN_TP_MOD_FLAG_SPRAY_EN 7
    [UVS_ADMIN_TP_MOD_FLAG_SPRAY_EN] = "SPRAY_EN",
#define UVS_ADMIN_TP_MOD_FLAG_DCA_EN 8
    [UVS_ADMIN_TP_MOD_FLAG_DCA_EN] = "DCA_EN",
};

static const char * const g_uvs_admin_cc_alg_str[] = {
    [UVS_ADMIN_TP_CC_NONE]                  =      "CC_NONE",
    [UVS_ADMIN_TP_CC_DCQCN]                 =      "DCQCN",
    [UVS_ADMIN_TP_CC_DCQCN_AND_NETWORK_CC]  =      "DCQCN_AND_NETWORK_CC",
    [UVS_ADMIN_TP_CC_LDCP]                  =      "LDCP",
    [UVS_ADMIN_TP_CC_LDCP_AND_CAQM]         =      "LDCP_AND_CAQM",
    [UVS_ADMIN_TP_CC_LDCP_AND_OPEN_CC]      =      "LDCP_AND_OPEN_CC",
    [UVS_ADMIN_TP_CC_HC3]                   =      "HC3",
    [UVS_ADMIN_TP_CC_DIP]                   =      "DIP"
};

static inline const char *uvs_admin_tp_mod_flag_to_string(uint8_t bit)
{
    if (bit > UVS_ADMIN_TP_MOD_FLAG_DCA_EN) {
        return "Invalid Value";
    }
    return g_uvs_admin_tp_mod_flag_str[bit];
}
static inline void print_tp_mod_flag_str(uvs_admin_tp_mod_flag_t flag)
{
    uint8_t i;

    (void)printf("    tp_mod_flag            : 0x%x [", flag.value);
    for (i = 0; i <= UVS_ADMIN_TP_MOD_FLAG_DCA_EN; i++) {
        if (i > UVS_ADMIN_TP_MOD_FLAG_CC_EN && i < UVS_ADMIN_TP_MOD_FLAG_SPRAY_EN) {
            continue;
        }
        if (!!(flag.value & (1 << i))) {
            (void)printf("%s ", uvs_admin_tp_mod_flag_to_string(i));
        }
    }
    (void)printf("%s ", g_uvs_admin_cc_alg_str[flag.bs.cc_alg]);
    (void)printf("]\n");
}

#endif /* VPORT_TABLE_CMD_H */
