/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa types header file
 * Author: LI Yuxing
 * Create: 2023-7-3
 * Note:
 * History: 2023-7-3 create this file to support type definition in tpsa
 */

#ifndef TPSA_TYPES_H
#define TPSA_TYPES_H

#include <linux/types.h>
#include "urma_types.h"
#include "uvs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TPSA_MAX_TP_CNT_IN_GRP 32
#define TPSA_EID_SIZE (16)
#define TPSA_MIN_TP_NUM 2
#define TPSA_PORT_CNT_MAX 16
#define PAGE_SIZE 4096
#define SEG_SIZE (PAGE_SIZE * 4000)

#define TPSA_TARGET 1
#define TPSA_INITIATOR 0
#define TPSA_DUPLEX 2

#define TPSA_DEFAULT_OOR_EN 0
#define TPSA_DEFAULT_SR_EN 0
#define TPSA_DEFAULT_CC_EN 0
#define TPSA_DEFAULT_CC_ALG 0
#define TPSA_DEFAULT_SPRAY_EN 0
#define TPSA_DEFAULT_LOOPBACK 0
#define TPSA_DEFAULT_ACK_RESP 0
#define TPSA_DEFAULT_DCA_ENABLE 0
#define TPSA_DEFAULT_BONDING 0

// thresholds for net card tp state transition to SUSPENDED
#define TPSA_DEFAULT_SUSPEND_PERIOD_US 1000
#define TPSA_DEFAULT_SUSPEND_CNT 3
// thresholds for tpsa tp state transition from SUSPENDED to ERR
#define TPSA_DEFAULT_SUS2ERR_PERIOD_US 30000000
#define TPSA_DEFAULT_SUS2ERR_CNT 3

#define TPSA_ADD_NOMEM (-1)
#define TPSA_ADD_INVALID (-2)
#define TPSA_LOOKUP_NULL (-1)
#define TPSA_LOOKUP_IN_PROGRESS (-2)
#define TPSA_RC_JETTY_ALREADY_BIND (-3)
#define TPSA_REMOVE_NULL (-1)
#define TPSA_REMOVE_INVALID (-2)
#define TPSA_REMOVE_DUPLICATE (-3)
#define TPSA_REMOVE_SERVER (-4)
#define TPSA_REMOVE_LM (-5)

#define TPSA_CC_IDX_TABLE_SIZE 64 /* support 8 priorities and 8 algorithms */
                                  /* same as UBCORE_CC_IDX_TABLE_SIZE */
                                  /* same as URMA_CC_IDX_TABLE_SIZE */

#define TPSA_UDRV_DATA_LEN 120
#define UVS_UUID_LEN 16

typedef enum tpsa_cap_type {
    TPSA_CAP_OOR = 0,
    TPSA_CAP_SR,
    TPSA_CAP_SPRAY,
    TPSA_CAP_DCA,
    TPSA_CAP_NUM
} tpsa_cap_type_t;

extern const char *g_tpsa_capability[TPSA_CAP_NUM];

typedef enum tpsa_tp_cc_alg {
    TPSA_TP_CC_NONE = 0,
    TPSA_TP_CC_DCQCN,
    TPSA_TP_CC_DCQCN_AND_NETWORK_CC,
    TPSA_TP_CC_LDCP,
    TPSA_TP_CC_LDCP_AND_CAQM,
    TPSA_TP_CC_LDCP_AND_OPEN_CC,
    TPSA_TP_CC_HC3,
    TPSA_TP_CC_DIP,
    TPSA_TP_CC_NUM
} tpsa_tp_cc_alg_t;

typedef enum tpsa_lm_location {
    LM_NOT_SET = 0,
    LM_SOURCE,
    LM_DESTINATION
} tpsa_lm_location_t;

typedef struct tpsa_cc_entry {
    tpsa_tp_cc_alg_t alg;
    uint8_t cc_pattern_idx;
    uint8_t cc_priority;
} __attribute__((packed)) tpsa_cc_entry_t;

typedef struct tpsa_tp_cc_entry {
    urma_tp_cc_alg_t alg;
    uint8_t cc_pattern_idx;
    uint8_t cc_priority;
    bool set_cc_priority;
} tpsa_tp_cc_entry_t;

typedef struct tpsa_cc_param {
    uint32_t target_cc_cnt;
    tpsa_tp_cc_entry_t cc_result_array[TPSA_CC_IDX_TABLE_SIZE]; // stores the query results
    bool target_cc_en;
} tpsa_cc_param_t;

/* refer to union ubcore_device_feat */
typedef union tpsa_device_feat {
    struct {
        uint32_t oor : 1;
        uint32_t jfc_per_wr : 1;
        uint32_t stride_op : 1;
        uint32_t load_store_op : 1;
        uint32_t non_pin : 1;
        uint32_t pmem : 1;
        uint32_t jfc_inline : 1;
        uint32_t spray_en : 1;
        uint32_t selective_retrans : 1;
        uint32_t live_migrate : 1;
        uint32_t dca : 1;
        uint32_t jetty_grp : 1;
        uint32_t err_suspend : 1;
        uint32_t outorder_comp : 1;
        uint32_t mn : 1;
        uint32_t clan : 1;
        uint32_t reserved : 16;
    } bs;
    uint32_t value;
} tpsa_device_feat_t;

typedef struct tpsa_jetty_id {
    urma_eid_t eid;
    uint32_t id;
} tpsa_jetty_id_t;

typedef enum tpsa_ta_type {
    TPSA_TA_NONE = 0,
    TPSA_TA_JFS_TJFR,
    TPSA_TA_JETTY_TJETTY,
    TPSA_TA_VIRT /* virtualization */
} tpsa_ta_type_t;

typedef union tpsa_tp_flag {
    struct {
        uint32_t target : 1;          /* 0: initiator, 1: target */
        uint32_t oor_en : 1;          /* out of order receive, 0: disable 1: enable */
        uint32_t sr_en : 1;           /* selective retransmission, 0: disable 1: enable */
        uint32_t cc_en : 1;           /* congestion control algorithm, 0: disable 1: enable */
        uint32_t cc_alg : 4;          /* ubcore_tp_cc_alg_t */
        uint32_t spray_en : 1; 	      /* spray with src udp port, 0: disable 1: enable */
        uint32_t loopback : 1;
        uint32_t ack_resp : 1;
        uint32_t dca_enable : 1;
        uint32_t bonding : 1;         /* for the bonding case, the hardware selects the port
                                         ignoring the port of tp context and selects the port based on hash value
                                         along with the information in the bonding group table. */
        uint32_t reserved : 19;
    } bs;
    uint32_t value;
} tpsa_tp_flag_t;

typedef union tpsa_tp_cfg_flag {
    struct {
        uint32_t target : 1;          /* 0: initiator, 1: target */
        uint32_t loopback : 1;
        uint32_t ack_resp : 1;
        uint32_t dca_enable : 1;
        uint32_t bonding : 1;         /* for the bonding case, the hardware selects the port
                                         ignoring the port of tp context and selects the port based on hash value
                                         along with the information in the bonding group table. */
        uint32_t reserved : 27;
    } bs;
    uint32_t value;
} tpsa_tp_cfg_flag_t;

typedef struct tpsa_multipath_tp_cfg {
    tpsa_tp_flag_t flag;
    uint16_t data_rctp_start;
    uint16_t ack_rctp_start;
    uint16_t data_rmtp_start;
    uint16_t ack_rmtp_start;
    uint8_t udp_range;
    uint16_t congestion_alg;
} tpsa_multipath_tp_cfg_t;

typedef enum tpsa_transport_mode {
    TPSA_TP_RM = 0x1,     /* Reliable message */
    TPSA_TP_RC = 0x1 << 1, /* Reliable connection */
    TPSA_TP_UM = 0x1 << 2 /* Unreliable message */
} tpsa_transport_mode_t;

typedef enum tpsa_transport_type {
    TPSA_TRANSPORT_INVALID = -1,
    TPSA_TRANSPORT_UB      = 0,
    TPSA_TRANSPORT_IB      = 1,
    TPSA_TRANSPORT_IP      = 2,
    TPSA_TRANSPORT_HNS_UB  = 5,
    TPSA_TRANSPORT_MAX
} tpsa_transport_type_t;

typedef union tpsa_tp_mod_flag {
    struct {
        uint32_t oor_en : 1;
        uint32_t sr_en : 1;
        uint32_t cc_en : 1;
        uint32_t cc_alg : 4;
        uint32_t spray_en : 1;
        uint32_t clan : 1;
        uint32_t dca_enable : 1;
        uint32_t um_en : 1;
        uint32_t share_mode : 1;
                                   /* Inconsistent with ubcore_tp_mod_flag and combined.
                                    * If ubcore_tp_cfg_flag parameter needs to be set,
                                    * the parameter must be set separately.
                                    */
        uint32_t reserved : 20; /* revise this struct need to sync print_tp_mod_flag_str fucntion */
    } bs;
    uint32_t value;
} tpsa_tp_mod_flag_t;

typedef struct uvs_uuid {
    uint8_t b[UVS_UUID_LEN];
} uvs_uuid_t;

typedef struct tpsa_tp_mod_cfg {
    tpsa_tp_mod_flag_t tp_mod_flag;
    uint32_t flow_label;
    uint32_t oor_cnt;
    uint8_t retry_num;
    uint8_t retry_factor;
    uint8_t ack_timeout;
    uint8_t dscp;
    uint8_t cc_pattern_idx;
    uint16_t data_udp_start; /* not used */
    uint16_t ack_udp_start; /* not used */
    uint8_t udp_range; /* not used */
    uint8_t hop_limit;
    uint8_t port;
    uint8_t mn;
    uint32_t loop_back;
    uint32_t ack_resp;
    uint32_t bonding;
    uint32_t oos_cnt;
    uint16_t cc_alg;
    bool set_cc_alg;
    uint8_t cc_priority;
    bool set_cc_priority;
    bool force_g_domain;
} tpsa_tp_mod_cfg_t; // same as uvs_admin_tp_mod_cfg_t

typedef union tpsa_utp_cfg_flag {
    struct {
        uint32_t loopback : 1;
        uint32_t spray_en : 1;
        uint32_t clan     : 1;
        uint32_t reserved : 29;
    } bs;
    uint32_t value;
} tpsa_utp_cfg_flag_t;

typedef struct tpsa_utp_cfg {
    /* transaction layer attributes */
    tpsa_utp_cfg_flag_t flag;
    uint16_t udp_start;     // src udp port start
    uint8_t udp_range;     // src udp port range
    uint32_t local_net_addr_idx;
    uvs_net_addr_info_t peer_net_addr;
    uint32_t flow_label;
    uint8_t dscp;
    uint8_t hop_limit;
    uint32_t port_id;
    enum uvs_mtu mtu;
} tpsa_utp_cfg_t;

typedef struct tpsa_ctp_cfg {
    uvs_net_addr_info_t peer_net_addr;
    uint32_t cna_len;
} tpsa_ctp_cfg_t;

typedef struct tpsa_rc_cfg {
    uint32_t rc_cnt;
    uint32_t rc_depth;
    uint32_t slice;
} tpsa_rc_cfg_t;

typedef struct tpsa_tp_ext {
    uint64_t addr;
    uint32_t len;
} tpsa_tp_ext_t;

/* Struct used for modify tp */
typedef struct tpsa_tp_attr {
    /* Need to negotiate begin */
    tpsa_tp_mod_flag_t flag;
    uint32_t peer_tpn;
    uvs_tp_state_t state;
    uint32_t tx_psn;
    uint32_t rx_psn;
    uvs_mtu_t mtu;
    uint8_t cc_pattern_idx;
    tpsa_tp_ext_t peer_ext;
    uint32_t oos_cnt;
    uint32_t local_net_addr_idx;
    uvs_net_addr_info_t peer_net_addr;
    /* Need to negotiate end */
    uint16_t data_udp_start;
    uint16_t ack_udp_start;
    uint8_t udp_range;
    uint8_t hop_limit;
    uint32_t flow_label;
    uint8_t port;
    uint8_t mn;
    tpsa_transport_type_t peer_trans_type;  /* Only for user tp connection */
} tpsa_tp_attr_t;

typedef union tpsa_tp_attr_mask {
    struct {
        uint32_t flag : 1;
        uint32_t peer_tpn : 1;
        uint32_t state : 1;
        uint32_t tx_psn : 1;
        uint32_t rx_psn : 1; /* modify both rx psn and tx psn when restore tp */
        uint32_t mtu : 1;
        uint32_t cc_pattern_idx : 1;
        uint32_t peer_ext : 1;
        uint32_t oos_cnt : 1;
        uint32_t local_net_addr_idx : 1;
        uint32_t peer_net_addr : 1;
        uint32_t data_udp_start : 1;
        uint32_t ack_udp_start : 1;
        uint32_t udp_range : 1;
        uint32_t hop_limit : 1;
        uint32_t flow_label : 1;
        uint32_t port : 1;
        uint32_t mn : 1;
        uint32_t reserved : 14;
    } bs;
    uint32_t value;
} tpsa_tp_attr_mask_t;

typedef struct tpsa_tpg_cfg {
    /* transaction layer attributes */
    urma_eid_t local_eid;
    urma_eid_t peer_eid;

    /* tranport layer attributes */
    tpsa_transport_mode_t trans_mode;
    uint8_t dscp;
    tpsa_tp_cc_alg_t cc_alg;
    uint8_t cc_pattern_idx;
    uint32_t tp_cnt;
} tpsa_tpg_cfg_t;

typedef struct tpsa_tp_param_common {
    /*
     * The negotiation function is not complete.
     * Add it temporarily(local_tp_cfg)
     */
    tpsa_tp_mod_cfg_t local_tp_cfg;
    tpsa_tp_mod_cfg_t remote_tp_cfg;
    uint32_t local_net_addr_idx;
    uvs_net_addr_info_t peer_net_addr;
    uvs_tp_state_t state;
    uint32_t tx_psn;
    uint32_t rx_psn;
    uvs_mtu_t local_mtu;
    uvs_mtu_t peer_mtu;
    uint64_t local_seg_size;
    uint64_t peer_seg_size;
} tpsa_tp_param_common_t;

typedef struct tpsa_tp_param_unique {
    uint32_t local_tpn;
    uint32_t peer_tpn;
} tpsa_tp_param_unique_t;

/* Struct used for tp parameter negotiation */
typedef struct tpsa_tp_param {
    // common param of tp in tpg
    tpsa_tp_param_common_t com;
    // unique param of tp in tpg
    tpsa_tp_param_unique_t uniq[TPSA_MAX_TP_CNT_IN_GRP]; // UBCORE_MAX_TP_CNT_IN_GRP=32
} tpsa_tp_param_t;

typedef enum tpsa_resp_status {
    TPSA_RESP_FAIL = -1,
    TPSA_RESP_SUCCESS = 0
} tpsa_resp_status_t;

typedef enum tpsa_msg_opcode {
    TPSA_MSG_CREATE_VTP = 0,
    TPSA_MSG_DESTROY_VTP,
    TPSA_MSG_ALLOC_EID,
    TPSA_MSG_DEALLOC_EID,
    TPSA_MSG_CONFIG_DEVICE,
    TPSA_MSG_STOP_PROC_VTP_MSG = 0x10, /* should be all migrate op after this opcode */
    TPSA_MSG_QUERY_VTP_MIG_STATUS,
    TPSA_MSG_FLOW_STOPPED,
    TPSA_MSG_MIG_ROLLBACK,
    TPSA_MSG_MIG_VM_START
} tpsa_msg_opcode_t;

typedef enum tpsa_msg_type {
    TPSA_MSG_TYPE_FE2TPF = 0,     // for create/delete vtp
    TPSA_MSG_TYPE_MPF2TPF,        // for live migration
    TPSA_MSG_TYPE_TPF2FE,         // for create/delete vtp
    TPSA_MSG_TYPE_TPF2MPF         // for live migration
} tpsa_msg_type_t;

typedef enum tpsa_loopback_type {
    TPSA_LOOPBACK_INITIATOR = 0,
    TPSA_LOOPBACK_TARGET,
    TPSA_NON_LOOPBACK,
} tpsa_loopback_type_t;

typedef enum tpsa_table_opcode {
    TPSA_TABLE_ADD = 0,
    TPSA_TABLE_REMOVE,
} tpsa_table_opcode_t;

typedef struct tpsa_nl_req {
    uint32_t msg_id;
    tpsa_msg_opcode_t opcode;
    uint32_t len;
    uint8_t data[0];
} tpsa_nl_req_t;

typedef struct tpsa_nl_req_host {
    uint16_t src_fe_idx;
    tpsa_nl_req_t req;
} tpsa_nl_req_host_t;

typedef struct tpsa_nl_resp {
    uint32_t msg_id;
    tpsa_msg_opcode_t opcode;
    uint32_t len;
    uint8_t data[0];
} tpsa_nl_resp_t;

typedef struct tpsa_nl_resp_host {
    uint16_t src_fe_idx;
    tpsa_nl_resp_t resp;
} tpsa_nl_resp_host_t;

struct tpsa_ta_data {
    enum tpsa_transport_type trans_type;
    enum tpsa_ta_type ta_type;
    struct tpsa_jetty_id jetty_id; /* local jetty id */
    struct tpsa_jetty_id tjetty_id; /* peer jetty id */
    bool is_target;
};

typedef struct tpsa_create_resp {
    uint32_t msg_id;
    uint32_t nlmsg_seq;
    uint16_t src_function_id;
    char dev_name[UVS_MAX_DEV_NAME];

    tpsa_resp_status_t ret;
    tpsa_tpg_cfg_t tpg_cfg;
    tpsa_tp_param_t tp_param;
    bool is_target;
    uint32_t target_cc_cnt;
    tpsa_tp_cc_entry_t target_cc_arr[TPSA_CC_IDX_TABLE_SIZE]; // stores the query results
    bool target_cc_en;
    uint32_t local_cc_cnt;
    tpsa_tp_cc_entry_t local_cc_arr[TPSA_CC_IDX_TABLE_SIZE]; // stores the query results
    bool local_cc_en;
    bool share_mode;
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uint32_t ext_len;
    uint8_t ext[TPSA_UDRV_DATA_LEN];
} tpsa_create_resp_t;

typedef struct tpsa_create_req {
    uint32_t msg_id;
    uint32_t nlmsg_seq;
    uint16_t src_function_id;

    tpsa_tpg_cfg_t tpg_cfg;
    tpsa_tp_param_t tp_param; // UBCORE_MAX_TP_CNT_IN_GRP=32
    bool is_target;
    char dev_name[UVS_MAX_DEV_NAME];
    uint32_t cc_array_cnt;
    tpsa_tp_cc_entry_t cc_result_array[TPSA_CC_IDX_TABLE_SIZE]; // stores the query results
    bool cc_en;
    bool share_mode;
    uint32_t pattern;
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uint32_t udrv_in_len;
    uint32_t ext_len;
    uint8_t udrv_ext[TPSA_UDRV_DATA_LEN];
} tpsa_create_req_t;

typedef tpsa_create_req_t tpsa_create_ack_t;


typedef struct tpsa_create_fail_resp {
    uint32_t msg_id;
    uint32_t nlmsg_seq;
    char dev_name[UVS_MAX_DEV_NAME];
    uint16_t src_function_id;
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uint32_t udrv_in_len;
    uint32_t ext_len;
    uint8_t udrv_ext[TPSA_UDRV_DATA_LEN];
} tpsa_create_fail_resp_t;

typedef struct tpsa_create_finish {
    uint32_t msg_id;
    uint32_t nlmsg_seq;
    char dev_name[UVS_MAX_DEV_NAME];
    uint16_t src_function_id;
    tpsa_tp_param_t tp_param; // UBCORE_MAX_TP_CNT_IN_GRP=32
    tpsa_tpg_cfg_t tpg_cfg;
    bool share_mode;
    /* for alpha */
    struct tpsa_ta_data ta_data;
} tpsa_create_finish_t;

typedef enum uvs_direction {
    TPSA_FROM_CLIENT_TO_SERVER = 0,
    TPSA_FROM_SERVER_TO_CLIENT = 1,
} uvs_direction_t;

typedef struct tpsa_resp_id {
    bool is_need_resp;
    uint32_t nlmsg_seq;
    uint32_t msg_id;
    uint16_t src_fe_idx;
} tpsa_resp_id_t;

typedef struct tpsa_destroy_finish {
    tpsa_resp_id_t resp_id;
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uint16_t src_fe_idx;
    char src_tpf_name[UVS_MAX_DEV_NAME];
} tpsa_destroy_finish_t;

typedef struct tpsa_destroy_req {
    uvs_direction_t direction;
    tpsa_resp_id_t resp_id;
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uint16_t src_fe_idx;
    char src_tpf_name[UVS_MAX_DEV_NAME];
    bool is_rollback;
    tpsa_lm_location_t location;
} tpsa_destroy_req_t;

typedef struct tpsa_table_sync {
    tpsa_table_opcode_t opcode;
    tpsa_resp_id_t nl_resp_id;
    char dev_name[UVS_MAX_DEV_NAME];
    bool share_mode;
} tpsa_table_sync_t;

typedef struct tpsa_table_sync_resp {
    tpsa_resp_status_t ret;
    tpsa_table_opcode_t opcode;
    tpsa_resp_id_t nl_resp_id;
    char dev_name[UVS_MAX_DEV_NAME];
} tpsa_table_sync_resp_t;

typedef struct tpsa_op_sip_parm {
    char dev_name[UVS_MAX_DEV_NAME];
    uvs_net_addr_info_t netaddr;
    uint8_t port_cnt;
    uint8_t port_id[TPSA_PORT_CNT_MAX];
    uint32_t mtu;
    char netdev_name[UVS_MAX_DEV_NAME]; /* for change mtu */
    bool is_active;
} tpsa_op_sip_parm_t;

typedef union tpsa_global_cfg_mask {
    struct {
        uint32_t mtu            : 1;
        uint32_t slice          : 1;
        uint32_t suspend_period : 1;
        uint32_t suspend_cnt    : 1;
        uint32_t sus2err_period : 1;
        uint32_t sus2err_cnt    : 1;
        uint32_t tbl_input_done : 1;

        /* cfg mask for gaea */
        uint32_t hop_limit      : 1;
        uint32_t udp_port_start : 1;
        uint32_t udp_port_end   : 1;
        uint32_t udp_range      : 1;
        uint32_t flag_um_en     : 1;
        uint32_t reserved       : 20;
    } bs;
    uint32_t value;
} tpsa_global_cfg_mask_t;

typedef struct tpsa_global_cfg {
    tpsa_global_cfg_mask_t mask;
    uvs_mtu_t mtu;
    uint32_t slice;
    // thresholds for net card tp state transition to SUSPENDED
    uint32_t suspend_period;        // us
    uint32_t suspend_cnt;
    // thresholds for tpsa tp state transition from SUSPENDED to ERR
    uint32_t sus2err_period;        // us
    uint32_t sus2err_cnt;
    bool vtp_restore_finished;
    bool tbl_input_done;
    bool restored_vtp_tpg_check_finished;

    /* cfg by gaea, for all tp */
    uint8_t hop_limit;
    uint16_t udp_port_start;
    uint16_t udp_port_end;
    uint16_t udp_range;  // src udp port range
    uvs_global_flag_t flag;
} tpsa_global_cfg_t;

typedef struct tpsa_create_param {
    tpsa_transport_mode_t trans_mode;
    uvs_net_addr_info_t dip;
    uvs_net_addr_t dst_uvs_ip; /* In lm scenario, dip and dst_uvs_ip used when deleting and establishing link */
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    uint32_t local_jetty;
    uint32_t peer_jetty;
    char tpf_name[UVS_MAX_DEV_NAME];
    uint32_t eid_index;
    uint16_t fe_idx;
    uint32_t upi;
    uint32_t vtpn;
    bool live_migrate;
    bool migrate_third;
    bool clan_tp;
    uint8_t port_id;
    tpsa_global_cfg_t *global_cfg;
    uvs_mtu_t mtu;
    bool share_mode;
    uint32_t pattern;
    uint32_t location;
    /* used when we need to response nl msg */
    uint32_t msg_id;
    uint32_t nlmsg_seq;
    bool sig_loop;
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uint32_t udrv_in_len;
    uint32_t ext_len;
    uint8_t udrv_ext[0];
} tpsa_create_param_t;

typedef union tpsa_vtp_cfg_flag {
    struct {
        uint32_t clan_tp :  1;
        uint32_t migrate : 1;
        uint32_t reserve : 30;
    } bs;
    uint32_t value;
} tpsa_vtp_cfg_flag_t;

/* map vtpn to tpg, tp, utp or ctp */
typedef struct tpsa_vtp_cfg {
    uint16_t fe_idx;
    uint32_t vtpn;
    uint32_t local_jetty;
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    uint32_t peer_jetty;
    tpsa_vtp_cfg_flag_t flag;
    tpsa_transport_mode_t trans_mode;
    union {
        uint32_t tpgn;
        uint32_t tpn;
        uint32_t utpn;
        uint32_t ctpn;
        uint32_t value;
    } number;
} tpsa_vtp_cfg_t;

/* live migration state */
typedef enum tpsa_mig_state {
    TPSA_MIG_STATE_START,
    TPSA_MIG_STATE_ROLLBACK,
    TPSA_MIG_STATE_FINISH
} tpsa_mig_state_t;

typedef enum tpsa_mig_resp_status {
    TPSA_MIG_MSG_PROC_SUCCESS,
    TPSA_MIG_MSG_PROC_FAILURE,
    TPSA_VTP_MIG_COMPLETE,
    TPSA_VTP_MIG_UNCOMPLETE
} tpsa_mig_resp_status_t;

typedef struct uvs_end_point {
    uvs_net_addr_info_t ip;
    urma_eid_t eid;
    uint32_t jetty_id;
} uvs_end_point_t;

typedef struct tpsa_restored_vtp_entry {
    uint16_t fe_idx;
    uint32_t vtpn;
    uint32_t local_jetty;
    uint32_t peer_jetty;
    uint32_t sip_idx;
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    tpsa_transport_mode_t trans_mode;
    union {
        uint32_t tpgn;
        uint32_t utp_idx;
        uint32_t ctp_idx;
    } index;
    char dev_name[UVS_MAX_DEV_NAME];
    bool target;
    uint32_t tp_cnt;
    uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP];
    uint32_t location;
    uvs_net_addr_info_t sip;
    uvs_net_addr_info_t dip;
    uint32_t eid_idx;
    uint32_t upi;
    bool share_mode;
    bool restore_succeed;
} tpsa_restored_vtp_entry_t;

typedef struct tpsa_restored_table_param {
    uvs_net_addr_info_t sip;
    uvs_net_addr_info_t dip;
} tpsa_restored_table_param_t;

typedef struct uvs_lm_tp_ctx {
    bool is_rollback;
    tpsa_lm_location_t location;
    uvs_direction_t direction;
} uvs_lm_tp_ctx_t;

#define TPSA_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE (0x1)

static inline bool is_uvs_create_rc_shared_tp(tpsa_transport_mode_t trans_mode, uint32_t sub_trans_mode,
    uint32_t rc_share_tp)
{
    if (trans_mode == TPSA_TP_RC &&
		(sub_trans_mode & TPSA_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE) &&
        rc_share_tp == 1) {
        return true;
    }
    return false;
}

#ifdef __cplusplus
}
#endif

#endif // URMA_TYPES_H
