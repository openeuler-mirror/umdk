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

#define UVS_ADMIN_VPORT_TABLE_CC_ALG_MAX 256
#define UVS_ADMIN_UUID_LEN 16
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
        uint64_t eid_idx             : 1;
        uint64_t upi                 : 1;
        uint64_t pattern             : 1;
        uint64_t virtualization      : 1;
        uint64_t min_jetty_cnt       : 1;
        uint64_t max_jetty_cnt       : 1;
        uint64_t min_jfr_cnt         : 1;
        uint64_t max_jfr_cnt         : 1;
        uint64_t um_en               : 1;
        uint64_t share_mode          : 1;
        uint64_t uuid                : 1;
        uint64_t reserved            : 28;
    } bs;
    uint64_t value;
} uvs_admin_vport_table_mask_t;

typedef struct uvs_admin_uuid {
    uint8_t b[UVS_ADMIN_UUID_LEN];
} uvs_admin_uuid_t;

typedef struct uvs_admin_vport_table_args {
    uvs_admin_vport_table_mask_t mask;
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t sip_idx;
    uint32_t tp_cnt;
    uvs_admin_tp_mod_cfg_t tp_cfg;
    uvs_admin_rc_cfg_t rc_cfg;
    urma_eid_t eid;
    uint32_t eid_idx;
    uint32_t upi;
    uvs_admin_uuid_t uuid;
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
    uint32_t eid_idx;
} uvs_admin_vport_table_show_ueid_req_t;

typedef struct uvs_admin_vport_table_show_ueid_rsp {
    int res;
    uint32_t upi;
    urma_eid_t eid;
    uvs_admin_uuid_t uuid;
} uvs_admin_vport_table_show_ueid_rsp_t;

typedef struct uvs_admin_vport_table_add_ueid_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t upi;
    urma_eid_t eid;
    uint32_t eid_idx;
    uvs_admin_uuid_t uuid;
} uvs_admin_vport_table_add_ueid_req_t;

typedef struct uvs_admin_vport_table_add_ueid_rsp {
    int32_t res;
} uvs_admin_vport_table_add_ueid_rsp_t;

typedef struct uvs_admin_vport_table_del_ueid_req {
    char dev_name[UVS_ADMIN_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t eid_idx;
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

typedef enum uvs_admin_tp_mod_flag_print {
    UVS_ADMIN_TP_MOD_FLAG_OOR_EN = 0,
    UVS_ADMIN_TP_MOD_FLAG_SR_EN,
    UVS_ADMIN_TP_MOD_FLAG_CC_EN,
    UVS_ADMIN_TP_MOD_FLAG_CC_ALG_BIT1,
    UVS_ADMIN_TP_MOD_FLAG_CC_ALG_BIT2,
    UVS_ADMIN_TP_MOD_FLAG_CC_ALG_BIT3,
    UVS_ADMIN_TP_MOD_FLAG_CC_ALG_BIT4,
    UVS_ADMIN_TP_MOD_FLAG_SPRAY_EN,
    UVS_ADMIN_TP_MOD_FLAG_CLAN_EN,
    UVS_ADMIN_TP_MOD_FLAG_DCA_EN,
    UVS_ADMIN_TP_MOD_FLAG_UM_EN,
    UVS_ADMIN_TP_MOD_FLAG_SHARE_MODE,
    UVS_ADMIN_TP_MOD_FLAG_NUM,
} uvs_admin_tp_mod_flag_print_t;

static const char * const g_uvs_admin_tp_mod_flag_str[] = {
    [UVS_ADMIN_TP_MOD_FLAG_OOR_EN] = "OOR_EN",
    [UVS_ADMIN_TP_MOD_FLAG_SR_EN] = "SR_EN",
    [UVS_ADMIN_TP_MOD_FLAG_CC_EN] = "CC_EN",
    [UVS_ADMIN_TP_MOD_FLAG_SPRAY_EN] = "SPRAY_EN",
    [UVS_ADMIN_TP_MOD_FLAG_CLAN_EN] = "CLAN_EN",
    [UVS_ADMIN_TP_MOD_FLAG_DCA_EN] = "DCA_EN",
    [UVS_ADMIN_TP_MOD_FLAG_UM_EN] = "UM_EN",
    [UVS_ADMIN_TP_MOD_FLAG_SHARE_MODE] = "SHARE_MODE",
};

static inline const char *uvs_admin_tp_mod_flag_to_string(uint8_t bit)
{
    if (bit >= UVS_ADMIN_TP_MOD_FLAG_NUM) {
        return "Invalid Value";
    }
    return g_uvs_admin_tp_mod_flag_str[bit];
}
static inline void print_tp_mod_flag_str(uvs_admin_tp_mod_flag_t flag)
{
    uint8_t i;

    (void)printf("    tp_mod_flag            : 0x%x [", flag.value);
    for (i = 0; i < UVS_ADMIN_TP_MOD_FLAG_NUM; i++) {
        if (i > UVS_ADMIN_TP_MOD_FLAG_CC_EN && i < UVS_ADMIN_TP_MOD_FLAG_SPRAY_EN) {
            continue;
        }
        if (!!(flag.value & (1 << i))) {
            (void)printf("%s ", uvs_admin_tp_mod_flag_to_string(i));
        }
    }
    /* Do not print cc_alg in flag as it may be different from cc_alg in vport_table */
    (void)printf("]\n");
}

#endif /* VPORT_TABLE_CMD_H */
