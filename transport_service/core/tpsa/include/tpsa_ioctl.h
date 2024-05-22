/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa ioctl header file
 * Author: JiLei
 * Create: 2023-7-3
 * Note:
 * History: 2023-7-3 port ioctl functions from tpsa_connect and daemon here
 */

#ifndef TPSA_IOCTL_H
#define TPSA_IOCTL_H

#include <sys/ioctl.h>

#include "ub_util.h"
#include "urma_types.h"
#include "urma_cmd.h"
#include "tpsa_log.h"
#include "uvs_types.h"
#include "tpsa_types.h"
#include "tpsa_sock.h"

#ifdef __cplusplus
extern "C" {
#endif

/* only for uvs ubcore device ioctl */
#define TPSA_CMD_MAGIC 'V'
#define TPSA_CMD _IOWR(TPSA_CMD_MAGIC, 1, urma_cmd_hdr_t)

#define TPSA_CHANNEL_INIT_SIZE 32
#define TPSA_MAX_EID_CONFIG_CNT 32
#define TPSA_MAX_VTP_CFG_CNT 32
#define TPSA_MAX_DSCP_VL_NUM 64
typedef enum tpsa_cmd {
    TPSA_CMD_CHANNEL_INIT = 1,
    TPSA_CMD_CREATE_TPG,
    TPSA_CMD_CREATE_VTP,
    TPSA_CMD_MODIFY_TPG,
    TPSA_CMD_CREATE_TARGET_TPG,
    TPSA_CMD_MODIFY_TARGET_TPG,
    TPSA_CMD_DESTROY_VTP,
    TPSA_CMD_DESTROY_TPG,
    TPSA_CMD_ADD_SIP,
    TPSA_CMD_DEL_SIP,
    TPSA_CMD_MAP_VTP,
    TPSA_CMD_CREATE_UTP,
    TPSA_CMD_ONLY_CREATE_UTP,
    TPSA_CMD_DESTROY_UTP,
    TPSA_CMD_GET_DEV_FEATURE,
    TPSA_CMD_RESTORE_TP_ERROR_RSP,
    TPSA_CMD_RESTORE_TARGET_TP_ERROR_REQ,
    TPSA_CMD_RESTORE_TARGET_TP_ERROR_ACK,
    TPSA_CMD_RESTORE_TP_SUSPEND,
    TPSA_CMD_CHANGE_TP_TO_ERROR,
    TPSA_CMD_SET_UPI,
    TPSA_CMD_SHOW_UPI,
    TPSA_CMD_SET_GLOBAL_CFG,
    TPSA_CMD_CONFIG_FUNCTION_MIGRATE_STATE,
    TPSA_CMD_SET_VPORT_CFG,
    TPSA_CMD_MODIFY_VTP,
    TPSA_CMD_GET_DEV_INFO,
    TPSA_CMD_CREATE_CTP,
    TPSA_CMD_DESTROY_CTP,
    TPSA_CMD_CHANGE_TPG_TO_ERROR,
    TPSA_CMD_ALLOC_EID,
    TPSA_CMD_DEALLOC_EID,
    TPSA_CMD_QUERY_FE_IDX,
    TPSA_CMD_CONFIG_DSCP_VL,
    TPSA_CMD_GET_VTP_TABLE_CNT,
    TPSA_CMD_RESTORE_TABLE,
    TPSA_CMD_MAP_TARGET_VTP,
    TPSA_CMD_LAST
} tpsa_cmd_t;

typedef struct tpsa_cmd_op_eid {
    struct {
        char dev_name[UVS_MAX_DEV_NAME];
        uint32_t upi;
        uint16_t fe_idx;
        urma_eid_t eid;
        uint32_t eid_index;
    } in;
} tpsa_cmd_op_eid_t;

typedef struct tpsa_cmd_channel_init {
    struct {
        char userspace_in[TPSA_CHANNEL_INIT_SIZE];
    } in;
    struct {
        char kernel_out[TPSA_CHANNEL_INIT_SIZE];
    } out;
} tpsa_cmd_channel_init_t;

typedef struct tpsa_ioctl_ctx {
    int ubcore_fd;
} tpsa_ioctl_ctx_t;

typedef struct tpsa_cmd_tpf {
    tpsa_transport_type_t trans_type;
    uvs_net_addr_info_t netaddr;
} tpsa_cmd_tpf_t;

typedef struct tpsa_cmd_tp_cfg {
    tpsa_tp_cfg_flag_t flag; /* flag of initial tp */
    /* transaction layer attributes */
    union {
        urma_eid_t local_eid;
        tpsa_jetty_id_t local_jetty;
    } local;
    uint16_t fe_idx; /* rc mode only */
    union {
        urma_eid_t peer_eid;
        tpsa_jetty_id_t peer_jetty;
    } peer;
    /* tranport layer attributes */
    tpsa_transport_mode_t trans_mode;
    uint8_t retry_num;
    uint8_t retry_factor;      /* for calculate the time slot to retry */
    uint8_t ack_timeout;
    uint8_t dscp;              /* priority */
    uint32_t oor_cnt;          /* OOR window size: by packet */
} tpsa_cmd_tp_cfg_t;

typedef struct tpsa_cmd_destroy_vtp {
    struct {
        tpsa_cmd_tpf_t tpf;
        urma_transport_mode_t mode;
        uint32_t local_jetty;
        uint32_t location;
        /* key start */
        urma_eid_t local_eid;
        urma_eid_t peer_eid;
        uint32_t peer_jetty;
        /* key end */
    } in;
} tpsa_cmd_destroy_vtp_t;

/* modify to error, reset, destroy tps in the tp_list of tpg, then destroy tpg */
typedef struct tpsa_cmd_destroy_tpg {
    struct {
        tpsa_cmd_tpf_t tpf;
        uint32_t tpgn;
    } in;
    struct {
        uint32_t destroyed_tp_cnt;
    } out;
    /* for alpha */
    struct tpsa_ta_data ta_data;
} tpsa_cmd_destroy_tpg_t;

struct tpsa_cmd_udrv_priv {
    uint64_t in_addr;
    uint32_t in_len;
    uint64_t out_addr;
    uint32_t out_len;
};

struct tpsa_udrv_ext {
    uint64_t in_addr;
    uint32_t in_len;
    uint64_t out_addr;
    uint32_t out_len;
};

typedef struct tpsa_cmd_create_tpg {
    struct {
        tpsa_cmd_tpf_t tpf;
        tpsa_tpg_cfg_t tpg_cfg;
        tpsa_cmd_tp_cfg_t tp_cfg[TPSA_MAX_TP_CNT_IN_GRP];
    } in;
    struct {
        uint32_t tpgn;
        uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP];
    } out;
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uvs_mtu_t local_mtu;
} tpsa_cmd_create_tpg_t;

typedef struct tpsa_cmd_create_vtp {
    struct {
        tpsa_cmd_tpf_t tpf;
        /* modify tp to RTR */
        uint32_t tpgn;
        tpsa_tp_attr_t rtr_attr[TPSA_MAX_TP_CNT_IN_GRP];
        tpsa_tp_attr_mask_t rtr_mask[TPSA_MAX_TP_CNT_IN_GRP];

        /* modify tp to RTS */
        /* create vtp */
        tpsa_vtp_cfg_t vtp;
    } in;
    struct {
        uint32_t rtr_tp_cnt;
        uint32_t rts_tp_cnt;
        uint32_t vtpn;
    } out;
} tpsa_cmd_create_vtp_t;

typedef struct tpsa_cmd_modify_tpg {
    struct {
        tpsa_cmd_tpf_t tpf;
        /* modify tp to RTR */
        uint32_t tpgn;
        tpsa_tp_attr_t rtr_attr[TPSA_MAX_TP_CNT_IN_GRP];
        tpsa_tp_attr_mask_t rtr_mask[TPSA_MAX_TP_CNT_IN_GRP];

        /* modify tp to RTS */
    } in;
    struct {
        uint32_t rtr_tp_cnt;
        uint32_t rts_tp_cnt;
    } out;
    /* for alpha */
    struct tpsa_ta_data ta_data;
    struct tpsa_udrv_ext udrv_ext;
} tpsa_cmd_modify_tpg_t;

typedef struct tpsa_cmd_get_dev_info {
    struct {
        char target_pf_name[UVS_MAX_DEV_NAME];
        tpsa_cmd_tpf_t tpf;
    } in;
    struct {
        bool port_is_active;
        char target_tpf_name[UVS_MAX_DEV_NAME];
    } out;
} tpsa_cmd_get_dev_info_t;

/* create tpg, create and modify tps in it to RTR at target */
typedef struct tpsa_cmd_create_target_tpg {
    struct {
        tpsa_cmd_tpf_t tpf;
        /* create tpg and the tps in the tpg */
        tpsa_tpg_cfg_t tpg_cfg;
        tpsa_cmd_tp_cfg_t tp_cfg[TPSA_MAX_TP_CNT_IN_GRP];
        /* modify tp to RTR */
        tpsa_tp_attr_t rtr_attr[TPSA_MAX_TP_CNT_IN_GRP];
        tpsa_tp_attr_mask_t rtr_mask[TPSA_MAX_TP_CNT_IN_GRP];
    } in;
    struct {
        uint32_t tpgn;
        uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP];
    } out;
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uvs_mtu_t local_mtu;
    uvs_mtu_t peer_mtu;
    struct tpsa_cmd_udrv_priv udata;
    struct tpsa_udrv_ext udrv_ext;
} tpsa_cmd_create_target_tpg_t;

typedef struct tpsa_cmd_modify_target_tpg {
    struct {
        tpsa_cmd_tpf_t tpf;
        uint32_t tpgn;
    } in;
    struct {
        uint32_t rts_tp_cnt;
    } out;
    /* for alpha */
    struct tpsa_ta_data ta_data;
} tpsa_cmd_modify_target_tpg_t;

typedef struct tpsa_cmd_map_target_vtp {
    struct {
        tpsa_cmd_tpf_t tpf;
        tpsa_vtp_cfg_t vtp;
        uint32_t location;
    } in;
} tpsa_cmd_map_target_vtp_t;

typedef struct tpsa_cmd_op_sip {
    struct {
        tpsa_op_sip_parm_t parm;
    } in;
} tpsa_cmd_op_sip_t;

typedef struct tpsa_cmd_map_vtp {
    struct {
        tpsa_cmd_tpf_t tpf;
        tpsa_vtp_cfg_t vtp;
        uint32_t location;
    } in;
    struct {
        uint32_t vtpn;
    } out;
} tpsa_cmd_map_vtp_t;

/* create utp */
typedef struct tpsa_cmd_create_utp {
    struct {
        tpsa_cmd_tpf_t tpf;
        tpsa_utp_cfg_t utp_cfg;
        tpsa_vtp_cfg_t vtp;
        /* todonext: add user data and ext */
    } in;
    struct {
        uint32_t idx;
        uint32_t vtpn;
    } out;
} tpsa_cmd_create_utp_t;

/* create ctp */
typedef struct tpsa_cmd_create_ctp {
    struct {
        tpsa_cmd_tpf_t tpf;
        tpsa_ctp_cfg_t ctp_cfg;
        tpsa_vtp_cfg_t vtp;
        /* todonext: add user data */
    } in;
    struct {
        uint32_t idx;
        uint32_t vtpn;
    } out;
} tpsa_cmd_create_ctp_t;

/* destroy ctp */
typedef struct tpsa_cmd_destroy_ctp {
    struct {
        tpsa_cmd_tpf_t tpf;
        uint32_t ctp_idx;
        /* todonext: add user data and ext */
    } in;
} tpsa_cmd_destroy_ctp_t;

typedef struct tpsa_cmd_get_dev_feature {
    struct {
        char dev_name[URMA_MAX_DEV_NAME];
    } in;
    struct {
        tpsa_device_feat_t feature;
        uint32_t max_ueid_cnt;
    } out;
} tpsa_cmd_get_dev_feature_t;

typedef struct tpsa_cmd_query_fe_idx {
    struct {
        char dev_name[URMA_MAX_DEV_NAME];
        uvs_devid_t devid;
    } in;
    struct {
        uint16_t fe_idx;
    } out;
} tpsa_cmd_query_fe_idx_t;

typedef struct tpsa_cmd_config_dscp_vl {
    struct {
        char dev_name[URMA_MAX_DEV_NAME];
        uint8_t dscp[TPSA_MAX_DSCP_VL_NUM];
        uint8_t vl[TPSA_MAX_DSCP_VL_NUM];
        uint8_t num;
    } in;
} tpsa_cmd_config_dscp_vl_t;

/* destroy utp */
typedef struct tpsa_cmd_destroy_utp {
    struct {
        tpsa_cmd_tpf_t tpf;
        uint32_t utp_idx;
    } in;
} tpsa_cmd_destroy_utp_t;

/* modify vtp */
typedef struct tpsa_cmd_modify_vtp {
    struct {
        tpsa_cmd_tpf_t tpf;
        tpsa_vtp_cfg_t vtp[TPSA_MAX_VTP_CFG_CNT];
        uint32_t cfg_cnt;
    } in;
} tpsa_cmd_modify_vtp_t;

typedef struct tpsa_cmd_restore_tp_error {
    struct {
        tpsa_cmd_tpf_t tpf;
        uint32_t tpgn;
        uint32_t tpn;
        uint16_t data_udp_start;
        uint16_t ack_udp_start;
        uint32_t rx_psn;
        uint32_t tx_psn;
    } in;
} tpsa_cmd_restore_tp_error_t;

typedef struct tpsa_cmd_restore_tp_suspend {
    struct {
        tpsa_cmd_tpf_t tpf;
        uint32_t tpgn;
        uint32_t tpn;
        uint16_t data_udp_start;
        uint16_t ack_udp_start;
    } in;
} tpsa_cmd_restore_tp_suspend_t;

typedef struct tpsa_cmd_set_upi {
    struct {
        char dev_name[UVS_MAX_DEV_NAME];
        uint32_t upi;
    } in;
} tpsa_cmd_set_upi_t;

typedef struct tpsa_cmd_show_upi {
    struct {
        char dev_name[UVS_MAX_DEV_NAME];
    } in;
    struct {
        uint32_t upi;
    } out;
} tpsa_cmd_show_upi_t;

typedef struct tpsa_cmd_change_tp_to_error {
    struct {
        tpsa_cmd_tpf_t tpf;
        uint32_t tpgn;
        uint32_t tpn;
    } in;
} tpsa_cmd_change_tp_to_error_t;

typedef struct tpsa_cmd_config_function_migrate_state {
    struct {
        uint16_t fe_idx;
        tpsa_cmd_tpf_t tpf;
        tpsa_ueid_cfg_t config[TPSA_MAX_EID_CONFIG_CNT];
        uint32_t config_cnt;
        tpsa_mig_state_t state;
    } in;
    struct {
        uint32_t cnt;
    } out;
} tpsa_cmd_config_function_migrate_state_t;

typedef union uvs_set_global_cfg_mask {
    struct {
        uint32_t suspend_period : 1;
        uint32_t suspend_cnt    : 1;
        uint32_t reserved       : 30;
    } bs;
    uint32_t value;
} uvs_set_global_cfg_mask_t;

typedef struct uvs_set_global_cfg {
    uvs_set_global_cfg_mask_t mask;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
} uvs_set_global_cfg_t;

typedef struct tpsa_cmd_set_global_cfg {
    struct {
        uvs_set_global_cfg_t set_cfg;
    } in;
} tpsa_cmd_set_global_cfg_t;

typedef union uvs_set_vport_cfg_mask {
    struct {
        uint32_t pattern             : 1;
        uint32_t virtualization      : 1;
        uint32_t min_jetty_cnt       : 1;
        uint32_t max_jetty_cnt       : 1;
        uint32_t min_jfr_cnt         : 1;
        uint32_t max_jfr_cnt         : 1;
        uint32_t tp_cnt              : 1;
        uint32_t slice               : 1;
        uint32_t reserved            : 24;
    } bs;
    uint32_t value;
} uvs_set_vport_cfg_mask_t;

typedef struct uvs_set_vport_cfg {
    uvs_set_vport_cfg_mask_t mask;
    char dev_name[UVS_MAX_DEV_NAME];
    uint16_t fe_idx;
    uint32_t pattern;
    uint32_t virtualization;
    uint32_t min_jetty_cnt;
    uint32_t max_jetty_cnt;
    uint32_t min_jfr_cnt;
    uint32_t max_jfr_cnt;
    uint32_t tp_cnt;
    uint32_t slice;
} uvs_set_vport_cfg_t;

typedef struct tpsa_cmd_set_vport_cfg {
    struct {
        uvs_set_vport_cfg_t set_cfg;
    } in;
} tpsa_cmd_set_vport_cfg_t;

typedef struct tpsa_cmd_change_tpg_to_error {
    struct {
        uint32_t tpgn;
        tpsa_cmd_tpf_t tpf;
    } in;

    struct {
        uint32_t tp_error_cnt;
    } out;
} tpsa_cmd_change_tpg_to_error_t;

typedef struct tpsa_cmd_get_vtp_table_cnt {
    struct {
        uint32_t vtp_cnt;
    } out;
} tpsa_cmd_get_vtp_table_cnt_t;

typedef struct tpsa_cmd_restored_vtp_entry {
    struct {
        uint32_t vtp_cnt;
    } in;
    struct {
        uint32_t vtp_cnt;
        tpsa_restored_vtp_entry_t entry[0];
    } out;
} tpsa_cmd_restored_vtp_entry_t;

typedef struct tpsa_ioctl_cfg {
    tpsa_cmd_t cmd_type;
    union {
        char *channel_init;
        tpsa_cmd_create_tpg_t create_tpg;
        tpsa_cmd_create_vtp_t create_vtp;
        tpsa_cmd_modify_tpg_t modify_tpg;
        tpsa_cmd_get_dev_info_t get_dev_info;
        tpsa_cmd_create_target_tpg_t create_target_tpg;
        tpsa_cmd_modify_target_tpg_t modify_target_tpg;
        tpsa_cmd_destroy_vtp_t destroy_vtp;
        tpsa_cmd_destroy_tpg_t destroy_tpg;
        tpsa_cmd_op_sip_t op_sip;
        tpsa_cmd_op_eid_t op_eid;
        tpsa_cmd_map_vtp_t map_vtp;
        tpsa_cmd_create_utp_t create_utp;
        tpsa_cmd_destroy_utp_t destroy_utp;
        tpsa_cmd_restore_tp_error_t restore_tp_error;
        tpsa_cmd_restore_tp_suspend_t restore_tp_suspend;
        tpsa_cmd_set_upi_t set_upi;
        tpsa_cmd_show_upi_t show_upi;
        tpsa_cmd_get_dev_feature_t get_dev_feature;
        tpsa_cmd_change_tp_to_error_t change_tp_to_error;
        tpsa_cmd_set_global_cfg_t global_cfg;
        tpsa_cmd_set_vport_cfg_t vport_cfg;
        tpsa_cmd_modify_vtp_t modify_vtp;
        tpsa_cmd_config_function_migrate_state_t config_state;
        tpsa_cmd_create_ctp_t create_ctp;
        tpsa_cmd_destroy_ctp_t destroy_ctp;
        tpsa_cmd_change_tpg_to_error_t change_tpg_to_error;
        tpsa_cmd_get_vtp_table_cnt_t get_vtp_table_cnt;
        tpsa_cmd_restored_vtp_entry_t restore_vtp_table;
        tpsa_cmd_map_target_vtp_t map_target_vtp;
    } cmd;
} tpsa_ioctl_cfg_t;

/* Struct used for init create lb vtp cmd message */
typedef struct tpsa_init_vtp_cmd_param {
    uvs_net_addr_info_t sip;
    tpsa_tp_mod_cfg_t local_tp_cfg;
    uvs_mtu_t mtu;
    uint8_t cc_pattern_idx;
    uint8_t udp_range;
    uint32_t local_net_addr_idx;
    uint32_t flow_label;
    uint32_t tp_cnt;
    uint32_t cc_array_cnt;
    tpsa_tp_cc_entry_t cc_result_array[TPSA_CC_IDX_TABLE_SIZE]; // stores the query results
    bool cc_en;
} tpsa_init_vtp_cmd_param_t;

typedef struct tpsa_init_tpg_cmd_param {
    uint16_t fe_idx;
    tpsa_tp_mod_cfg_t tp_cfg;
    uvs_net_addr_info_t sip;
    uvs_net_addr_info_t dip;
    uint32_t sip_idx;
    uvs_mtu_t mtu;
    uint32_t cc_array_cnt;
    tpsa_tp_cc_entry_t cc_result_array[TPSA_CC_IDX_TABLE_SIZE]; // stores the query results
} tpsa_init_tpg_cmd_param_t;

int tpsa_ioctl_init(tpsa_ioctl_ctx_t *ioctl_context);
void tpsa_ioctl_uninit(tpsa_ioctl_ctx_t *ioctl_context);
int tpsa_ioctl(int ubcore_fd, tpsa_ioctl_cfg_t *cfg);

/* ioctl cmd init */
void tpsa_ioctl_cmd_create_tpg(tpsa_ioctl_cfg_t *cfg, tpsa_create_param_t *cparam,
                               uvs_net_addr_info_t *sip, vport_param_t *vport_param, uvs_net_addr_info_t *dip);
void tpsa_ioctl_cmd_create_target_tpg(tpsa_ioctl_cfg_t *cfg, tpsa_sock_msg_t *msg,
                                      tpsa_init_tpg_cmd_param_t *param);
void tpsa_ioctl_cmd_modify_tpg(tpsa_ioctl_cfg_t *cfg, tpsa_sock_msg_t *msg, uvs_net_addr_info_t *sip);
void tpsa_ioctl_cmd_get_dev_info(tpsa_ioctl_cfg_t *cfg, char *target_pf_name,
    uvs_net_addr_info_t *netaddr, tpsa_transport_type_t type);
void tpsa_ioctl_cmd_map_vtp(tpsa_ioctl_cfg_t *cfg, tpsa_create_param_t *cparam, uint32_t number,
                            uvs_net_addr_info_t *sip);
void tpsa_ioctl_cmd_create_lb_vtp(tpsa_ioctl_cfg_t *cfg, tpsa_create_param_t *cparam, tpsa_cmd_create_tpg_t *cmd,
                                  tpsa_init_vtp_cmd_param_t *param);
void tpsa_ioctl_cmd_destroy_tpg(tpsa_ioctl_cfg_t *cfg, uvs_net_addr_info_t *sip, uint32_t tpgn,
    struct tpsa_ta_data *ta_data);
void tpsa_ioctl_cmd_destroy_vtp(tpsa_ioctl_cfg_t *cfg, uvs_net_addr_info_t *sip, urma_transport_mode_t mode,
                                urma_eid_t local_eid, urma_eid_t peer_eid, uint32_t peer_jetty, uint32_t location);

void tpsa_ioctl_cmd_create_utp(tpsa_ioctl_cfg_t *cfg, vport_param_t *vport_param,
                               tpsa_create_param_t *cparam, utp_table_key_t *key);

void tpsa_ioctl_cmd_destroy_utp(tpsa_ioctl_cfg_t *cfg, utp_table_key_t *key,
                                uint32_t utp_idx);
void tpsa_ioctl_cmd_config_state(tpsa_ioctl_cfg_t *cfg, vport_table_entry_t *vport_entry,
                                 tpsa_cmd_tpf_t *tpf, tpsa_mig_state_t state, uint32_t begin_idx);

void tpsa_ioctl_cmd_create_ctp(tpsa_ioctl_cfg_t *cfg, tpsa_create_param_t *cparam,
                               ctp_table_key_t *key, uvs_net_addr_info_t *sip, uint32_t cna_len);
void tpsa_ioctl_cmd_destroy_ctp(tpsa_ioctl_cfg_t *cfg, ctp_table_key_t *key,
                                uvs_net_addr_info_t *sip, uint32_t ctp_idx);
void tpsa_ioctl_cmd_change_tpg_to_error(tpsa_ioctl_cfg_t *cfg, uvs_net_addr_info_t *sip, uint32_t tpgn);

int uvs_ioctl_cmd_set_global_cfg(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_global_cfg_t *global_cfg);
int sip_table_ioctl(tpsa_ioctl_ctx_t *ioctl_ctx, sip_table_entry_t *entry, tpsa_cmd_t cmd_type);
int uvs_ioctl_cmd_set_vport_cfg(tpsa_ioctl_ctx_t *ioctl_ctx,
    vport_table_entry_t *add_entry, tpsa_global_cfg_t *global_cfg);
int uvs_ioctl_cmd_clear_vport_cfg(tpsa_ioctl_ctx_t *ioctl_ctx, vport_key_t *key);
int uvs_ioctl_cmd_modify_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_vtp_cfg_t *vtp_cfg,
                             uvs_net_addr_info_t *sip, uint32_t vice_tpgn);
int tpsa_negotiate_optimal_cc_alg(uint32_t target_cc_cnt, tpsa_tp_cc_entry_t *target_cc_arr, bool target_cc_en,
                                  uint32_t local_cc_cnt, tpsa_tp_cc_entry_t *local_cc_arr, bool local_cc_en,
                                  urma_tp_cc_alg_t *alg, uint8_t *cc_pattern_idx);
void tpsa_lm_ioctl_cmd_create_utp(tpsa_ioctl_cfg_t *cfg, vport_param_t *vport_param,
                                  sip_table_entry_t *sip_entry, utp_table_key_t *key);

int tpsa_ioctl_op_ueid(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_cmd_t cmd_type, vport_key_t *vport_key,
                       tpsa_ueid_t *ueid, uint32_t eid_idx);

int uvs_ioctl_query_fe_idx(int ubcore_fd, tpsa_cmd_query_fe_idx_t *cfg);
int uvs_ioctl_config_dscp_vl(int ubcore_fd, tpsa_cmd_config_dscp_vl_t *cfg);
void tpsa_ioctl_cmd_get_vtp_table_cnt(tpsa_ioctl_cfg_t *cfg);
void tpsa_ioctl_cmd_restore_vtp_table(tpsa_ioctl_cfg_t *cfg, uint32_t vtp_cnt);
void tpsa_ioctl_cmd_map_target_vtp(tpsa_ioctl_cfg_t *cfg, tpsa_create_param_t *cparam,
                                   uint32_t number, uvs_net_addr_info_t *sip);

#ifdef __cplusplus
}
#endif

#endif
