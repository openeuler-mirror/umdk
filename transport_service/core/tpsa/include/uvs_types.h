/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs types header file
 * Author: Zheng Hongqin
 * Create: 2023-10-11
 * Note:
 * History:
 */

#ifndef UVS_TYPES_H
#define UVS_TYPES_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UVS_EID_SIZE 16
#define UVS_NA_SIZE 16
#define ETH_ADDR_LEN 6
#define UVS_MAX_DEV_NAME 64        // Refer to UBCORE_MAX_DEV_NAME
#define UVS_MAX_VPORT_NAME 32
#define UVS_MAX_PORT_CNT 16
#define UVS_MAX_CC_CNT 64
#define UVS_DEVID_SIZE (16)
#define UVS_MAX_TP_CNT_IN_GRP 32
#define MS_PER_SEC          1000ULL
#define NS_PER_MS           1000000ULL
#define NS_PER_SEC          1000000000ULL

typedef enum uvs_tp_state {
    UVS_TP_STATE_RESET = 0,
    UVS_TP_STATE_RTR,
    UVS_TP_STATE_RTS,
    UVS_TP_STATE_SUSPENDED,
    UVS_TP_STATE_ERR,
    UVS_TP_STATE_WAIT_VERIFY,
} uvs_tp_state_t;

typedef union uvs_utp_cfg_flag {
    struct {
        uint32_t loopback : 1;
        uint32_t spray_en : 1;
        uint32_t clan     : 1;
        uint32_t reserved : 29;
    } bs;
    uint32_t value;
} uvs_utp_cfg_flag_t;


// Refer to urma_transport_mode
typedef enum uvs_tp_mode {
    UVS_TM_RM = 0x1,      /* Reliable message */
    UVS_TM_RC = 0x1 << 1, /* Reliable connection */
    UVS_TM_UM = 0x1 << 2, /* Unreliable message */
} uvs_tp_mode_t;

enum uvs_event_type {
    UVS_EVENT_HANG,
    UVS_EVENT_RESUME,
    UVS_EVENT_MAX,
};

struct uvs_event {
    enum uvs_event_type type;
};

typedef enum uvs_mtu {
    UVS_MTU_256 = 1,
    UVS_MTU_512,
    UVS_MTU_1024,
    UVS_MTU_2048,
    UVS_MTU_4096,
    UVS_MTU_8192,
    UVS_MTU_CNT,
} uvs_mtu_t;

typedef enum uvs_net_addr_type {
    UVS_NET_ADDR_TYPE_IPV4 = 0,
    UVS_NET_ADDR_TYPE_IPV6,
} uvs_net_addr_type_t;

typedef union uvs_eid {
    uint8_t raw[UVS_EID_SIZE]; /* Network Order */
    struct {
        uint64_t resv;   /* If IPv4 mapped to IPv6, == 0 */
        uint32_t prefix; /* If IPv4 mapped to IPv6, == 0x0000ffff */
        uint32_t addr;   /* If IPv4 mapped to IPv6, == IPv4 addr */
    } in4;
    struct {
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
} uvs_eid_t;

typedef struct uvs_eid_info {
    uvs_eid_t eid;
    uint32_t eid_idx;
} uvs_eid_info_t;

typedef struct uvs_ueid {
    uvs_eid_t eid;
    uint32_t upi;
} uvs_ueid_t;

typedef struct uvs_tpf {
    char name[UVS_MAX_DEV_NAME];
    char netdev_name[UVS_MAX_DEV_NAME];
} uvs_tpf_t;

typedef union uvs_net_addr {
    uint8_t raw[UVS_NA_SIZE]; /* Network Order */
    struct {
        uint64_t resv;   /* If IPv4 mapped to IPv6, == 0 */
        uint32_t prefix; /* If IPv4 mapped to IPv6, == 0x0000ffff */
        uint32_t addr;   /* If IPv4 mapped to IPv6, == IPv4 addr */
    } in4;
    struct {
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
} uvs_net_addr_t;

typedef enum uvs_cc {
    UVS_TP_CC_NONE = 0,
    UVS_TP_CC_DCQCN,
    UVS_TP_CC_DCQCN_AND_NETWORK_CC,
    UVS_TP_CC_LDCP,
    UVS_TP_CC_LDCP_AND_CAQM,
    UVS_TP_CC_LDCP_AND_OPEN_CC,
    UVS_TP_CC_HC3,
    UVS_TP_CC_DIP
} uvs_cc_t;

typedef enum uvs_port_type {
    UVS_PORT_TYPE_UBPORT,
    UVS_PORT_TYPE_UBSUBPORT,
} uvs_port_type_t;

/* uvs tp data structure */
typedef union uvs_tp_flag {
    struct {
        uint32_t oor_en : 1;      // Out of Order receive enable
        uint32_t sr_en : 1;       // selective retransmit enable
        uint32_t cc_en : 1;       // CC enable
        uint32_t spray_en : 1;    // port spray enable
        uint32_t dca_enable : 1;  // dynamic connection enable
        uint32_t reserved : 27;
    } bs;
    uint32_t value;
} uvs_tp_flag_t;

typedef union uvs_tp_mask {
    struct {
        uint32_t flow_label : 1;
        uint32_t oor_cnt : 1;
        uint32_t tp_cnt_per_tpg : 1;
        uint32_t retry_times : 1;
        uint32_t retry_factor : 1;
        uint32_t ack_timeout : 1;  // config together with retry_xxx
        uint32_t dscp : 1;         // priority dscp
        uint32_t cc_pri : 1;
        uint32_t cc_list : 2; /* 2bit for list:
                              (00): not set.
                              (01): add.
                              (10): delete.
                              (11): replace all entries of cc list. */
        uint32_t cc_cnt : 1;

        uint32_t flag_oor_en : 1;      // Out of Order receive enable
        uint32_t flag_sr_en : 1;       // selective retransmit enable
        uint32_t flag_cc_en : 1;       // CC enable
        uint32_t flag_spray_en : 1;    // port spray enable
        uint32_t flag_dca_enable : 1;  // dynamic connection enable
        uint32_t resereved : 16;
    } bs;
    uint32_t value;
} uvs_tp_mask_t;

typedef struct uvs_tp_info {
    uvs_tp_mask_t mask;
    /* for rc, exclusive rm and shared rm tp */
    uint32_t flow_label;
    uint32_t oor_cnt;
    uint8_t tp_cnt_per_tpg;
    uint8_t retry_times;  // retry times
    uint8_t retry_factor;
    uint8_t ack_timeout;  // config together with retry_xxx
    uint8_t dscp;         // priority dscp
    /* for tpg */
    uint8_t cc_pri;                    // cc priority
    uvs_cc_t cc_list[UVS_MAX_CC_CNT];  // cc algorith list
    uint8_t cc_cnt;
    uvs_tp_flag_t flag;
} uvs_tp_info_t;

/* utp tp data structure */
typedef union uvs_utp_mask {
    struct {
        uint32_t flow_label : 1;
        uint32_t dscp : 1;
        uint32_t flag_spray_en : 1;
        uint32_t reserved : 29;
    } bs;
    uint32_t value;
} uvs_utp_mask_t;

typedef union uvs_utp_flag {
    struct {
        /* for utp */
        uint32_t spray_en : 1;
        /* reserved */
        uint32_t reserved : 31;
    } bs;
    uint32_t value;
} uvs_utp_flag_t;

typedef struct uvs_utp_info {
    uvs_utp_mask_t mask;
    uint32_t flow_label;
    uint8_t dscp;
    uvs_utp_flag_t flag;
} uvs_utp_info_t;

typedef struct uvs_devid {
    uint8_t raw[UVS_DEVID_SIZE];
} uvs_devid_t;

/* global info data structure */
typedef union uvs_global_flag {
    struct {
        uint32_t pattern : 2;      // pattern 1 or pattern 3
        uint32_t um_en : 1;        // UM mode enable
        uint32_t lo_internal : 1;  // internal nic lookback for nic
        uint32_t resereved : 28;
    } bs;
    uint32_t value;
} uvs_global_flag_t;

typedef union uvs_global_info_mask {
    struct {
        uint32_t tpf_name : 1;
        uint32_t mtu : 1;
        uint32_t slice : 1;
        uint32_t suspend_period : 1;
        uint32_t suspend_cnt : 1;
        uint32_t sus2err_period : 1;
        uint32_t sus2err_cnt : 1;
        uint32_t hop_limit : 1;
        uint32_t udp_port_start : 1;
        uint32_t udp_port_end : 1;
        uint32_t udp_range : 1;
        uint32_t sip_idx : 1;
        uint32_t shared_rm_tp_info : 1;
        uint32_t um_tp_info : 1;
        uint32_t flag_pattern : 1;
        uint32_t flag_um_en : 1;
        uint32_t flag_lo_internal : 1;
        uint32_t tbl_input_done : 1;
        uint32_t resereved : 14;
    } bs;
    uint32_t value;
} uvs_global_info_mask_t;

typedef struct uvs_global_info_key {
    char tpf_name[UVS_MAX_DEV_NAME];
} __attribute__((packed)) uvs_global_info_key_t;

typedef struct uvs_global_info {
    uvs_global_info_key_t key;

    uvs_global_info_mask_t mask;
    /* for nic */
    uvs_mtu_t mtu;
    /* for tpf device */
    uint32_t slice;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
    /* for uvs itself process, will not be set to driver */
    uint32_t sus2err_period;
    uint32_t sus2err_cnt;
    bool tbl_input_done;

    /* for all tp */
    uint8_t hop_limit;
    uint16_t udp_port_start;
    uint16_t udp_port_end;
    uint16_t udp_range;  // src udp port range

    /* only for shared rm tp */
    uint32_t sip_idx;
    uvs_tp_info_t shared_rm_tp_info;
    uvs_utp_info_t um_tp_info;

    uvs_global_flag_t flag;
} uvs_global_info_t;

/* vport info data structure */
typedef union uvs_vport_mask {
    struct {
        uint32_t type : 1;
        uint32_t tpf_name : 1;
        uint32_t fe_idx : 1;
        uint32_t sip_idx : 1;
        uint32_t virtualization : 1;
        uint32_t jetty_min_cnt : 1;
        uint32_t jetty_max_cnt : 1;
        uint32_t jfr_min_cnt : 1;
        uint32_t jfr_max_cnt : 1;
        uint32_t rct_cnt : 1;
        uint32_t rct_depth : 1;
        uint32_t rc_max_cnt : 1;
        uint32_t rm_vtp_max_cnt : 1;
        uint32_t um_vtp_max_cnt : 1;
        uint32_t upi : 1;
        uint32_t eid : 1;
        uint32_t parent_name : 1;
        uint32_t tp_info : 1;
        uint32_t flag_share_mode : 1;
        uint32_t flag_pattern : 1;
        uint32_t flag_um_en : 1;
        uint32_t vtp_per_second : 1;
        uint32_t reserved : 10;
    } bs;
    uint32_t value;
} uvs_vport_mask_t;

typedef union uvs_vport_flag {
    struct {
        uint32_t share_mode : 1;  // tpg sharing or exclusive
        uint32_t pattern : 2;     // pattern 1 or pattern 3
        uint32_t um_en : 1;       // UM mode enable
        uint32_t reserved : 28;
    } bs;
    uint32_t value;
} uvs_vport_flag_t;

typedef struct uvs_vport_info_key {
    char name[UVS_MAX_VPORT_NAME];  // vport name or sub_vport name
} __attribute__((packed)) uvs_vport_info_key_t;

typedef struct uvs_vport_info {
    uvs_vport_info_key_t key;              /* key for gaea */
    uvs_vport_mask_t mask;                 // for vport and sub_vport
    uvs_port_type_t type;                  // UBPORT, UBSUBPORT
    char tpf_name[UVS_MAX_DEV_NAME];       // tpf name, for vport and sub_vport
    uint16_t fe_idx;                       // bdf, only for vport
    uint32_t sip_idx;                      // only for vport
    uint32_t virtualization;               // only for vport
    uint32_t jetty_min_cnt;                // Jetty(include JFS) + JFR + RCT, only for vport
    uint32_t jetty_max_cnt;                // Jetty(include JFS) + JFR + RCT, only for vport
    uint32_t jfr_min_cnt;                  // JFR only, only for vport
    uint32_t jfr_max_cnt;                  // JFR only, only for vport
    uint32_t rct_cnt;                      // RC table queue count, only for vport
    uint32_t rct_depth;                    // RC table queue depth, only for vport
    uint32_t rc_max_cnt;                   // the maximum number of RC connections
    uint32_t rm_vtp_max_cnt;               // the maximum number of rm vtp
    uint32_t um_vtp_max_cnt;               // the maximum number of um vtp
    uint32_t vtp_per_second;               // Check every few seconds for vport
    uint32_t upi;                          // for vport and sub_vport
    uvs_eid_info_t eid;                    // for vport and sub_vport
    char parent_name[UVS_MAX_VPORT_NAME];  // parent vport name, only for sub_vport
    uvs_tp_info_t tp_info;                 // for vport and sub_vport
    uvs_vport_flag_t flag;                 // for vport and sub_vport
} uvs_vport_info_t;

/* sip table data structure */
typedef struct uvs_sip_info {
    uvs_net_addr_t sip;  // ipv4 and ipv6
    uint32_t msk;
    uvs_net_addr_type_t type;
    uint8_t mac[ETH_ADDR_LEN];
    uint16_t vlan;
    char tpf_name[UVS_MAX_DEV_NAME];
    uint8_t port_cnt;
    uint8_t port_id[UVS_MAX_PORT_CNT];
} uvs_sip_info_t;

/* cc info data structure */
typedef struct uvs_cc_entry {
    uvs_cc_t cc;
    uint8_t pattern_idx;
    uint8_t priority;
} uvs_cc_entry_t;

typedef struct uvs_net_addr_info {
    uvs_net_addr_type_t type;  // ipv4 or v6
    uvs_net_addr_t net_addr;
    uint64_t vlan; /* available for UBOE */
    uint8_t mac[ETH_ADDR_LEN]; /* available for UBOE */
    uint32_t prefix_len;
} uvs_net_addr_info_t;

typedef struct uvs_net_addr_info uvs_dip_info_t;

typedef struct uvs_user_ops {
    const char *name;
    int (*lookup_netaddr_by_ueid)(uvs_ueid_t *ueid, uvs_dip_info_t *dip);
} uvs_user_ops_t;

typedef enum {
    USER_OPS_GAEA,
    USER_OPS_MAX,
} user_ops_t;

/**
 * UVS private key password generation function prototype.
 * @param[out] pwd:         generated password;
 * @param[out] pwd_len:     password length;
 * Return: void.
 * Note: password should be terminated by '\0'.
 */
typedef void (*uvs_generate_prkey_pwd_t)(char **pwd, int *pwd_len);

/**
 * UVS private key password erasement function prototype.
 * @param[in] pwd:          password to be erased;
 * @param[in] pwd_len:      password length;
 * Return: void.
 */
typedef void (*uvs_erase_prkey_pwd_t)(char *pwd, int pwd_len);

/**
 * UVS certificate verification function prototype.
 * @param[in] ctx:          a X509_STORE_CTX type context;
 * @param[in] crl_path:     certificate revocation list path;
 * Return: 0 on success, other value on error.
 */
typedef int (*uvs_verify_cert_t)(void *ctx, const char *crl_path);

typedef struct uvs_ssl_cfg {
    char *ca_path;      // Required, CA certificate file to verify remote
    char *cert_path;    // Required, local certificate file to be sent to remote
    char *prkey_path;   // Required, encrypted private key file
    char *crl_path;     // Optional, certificate revocation list
    uvs_generate_prkey_pwd_t generate_pwd;  // Required
    uvs_erase_prkey_pwd_t erase_pwd;        // Required
    uvs_verify_cert_t verify_cert;          // Optional
} uvs_ssl_cfg_t;

typedef struct uvs_init_attr {
    bool statistic;
    int cpu_core;
} uvs_init_attr_t;

typedef struct uvs_socket_init_attr {
    uvs_net_addr_type_t type;
    uvs_net_addr_t server_ip;
    uint16_t server_port;
    uvs_ssl_cfg_t *ssl_cfg;     // If NULL, UVS would not establish TLS connection
} uvs_socket_init_attr_t;

/* total number of successful/active/failed/opening link setups in rm/rc/um mode for vport */
typedef struct uvs_vport_statistic {
    uint64_t rm_vtp_est; /* success statistic */
    uint64_t rc_vtp_est;
    uint64_t um_vtp_est;
    uint64_t rm_vtp_active;
    uint64_t rc_vtp_active;
    uint64_t um_vtp_active;
    uint64_t rm_vtp_failed;
    uint64_t rc_vtp_failed;
    uint64_t um_vtp_failed;
    uint64_t rm_vtp_opening;
    uint64_t rc_vtp_opening;
    uint64_t um_vtp_opening;
} uvs_vport_statistic_t;

/* total number of successful/active/err/suspend/opening/closing link setups in rm/rc/utp mode for tp */
typedef struct uvs_tpf_statistic {
    uint64_t rm_tpg_est; /* success statistic only for tpg */
    uint64_t rm_tp_est;
    uint64_t rc_tp_est;
    uint64_t utp_est;
    uint64_t rm_tp_active;
    uint64_t rc_tp_active;
    uint64_t utp_active;
    uint64_t tp_error; /* error statisitc Increases only */
    uint64_t tp_suspend; /* suspend statisitc Increases only */
    uint64_t tp_opening; /* opening statisitc Increases only */
    uint64_t tp_closing; /* closing statisitc Increases only */
} uvs_tpf_statistic_t;

/**
 * Callback function for UVS event.
 * @param[in] event:        event details;
 * @param[in] arg:          argument provided by user;
 * Return: void.
 */
typedef void (*uvs_event_cb_t)(struct uvs_event *event, void *arg);


typedef struct uvs_mig_entry {
    uint32_t upi;
    uvs_eid_info_t eid;
    uint64_t hits;
} uvs_mig_entry_t;

typedef uvs_mig_entry_t* uvs_mig_entry_list_t;

typedef enum uvs_stats_type {
    UVS_STATS_VTP = 1,             // uvs_stats_key id: vtpn, driver not supported yet
    UVS_STATS_TP = 2,              // uvs_stats_key id: tpn, driver not supported yet
    UVS_STATS_TPG = 3,             // uvs_stats_key id: tpgn, driver not supported yet
    UVS_STATS_DEV = 8,             // uvs_stats_key id: fe_idx
} uvs_stats_type_t;

typedef struct uvs_stats_key {
    uvs_stats_type_t type;
    uint32_t id;                   // vtpn/tpn/tpgn/fe_idx, see uvs_stats_type_t
    uint32_t ext;                  // For VTP only, provide fe_idx
} uvs_stats_key_t;

typedef struct uvs_stats_val {
    uvs_stats_key_t key;
    uint64_t tx_pkt;
    uint64_t rx_pkt;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_pkt_err;
    uint64_t rx_pkt_err;
    // UVS_STATS_KEY_DEV only
    uint64_t tx_timeout_cnt;
    uint64_t rx_ce_pkt;
} uvs_stats_val_t;

typedef enum uvs_res_type {
    UVS_RES_VTP = 1,               // driver not supported yet
    UVS_RES_TP = 2,
    UVS_RES_TPG = 3,
    UVS_RES_UTP = 4,               // stats not supported
    UVS_RES_TPF = 13,
    UVS_RES_VPORT = 14,
} uvs_res_type_t;

typedef struct uvs_res_vtp_key {
    uint32_t tp_mode;              // Refer to uvs_tp_mode_t
    uint32_t sub_tp_mode;
    uint32_t share_mode;
    uint32_t upi;
    union {
        struct {
            uvs_eid_t seid;
            uvs_eid_t deid;
        } rm;
        struct {
            uvs_eid_t deid;
            uint32_t djetty_id;
        } rc;
        struct {
            uvs_eid_t seid;
            uvs_eid_t deid;
        } rs_share;
        struct {
            uvs_eid_t deid;
            uint32_t djetty_id;
        } rs_non_share;
        struct {
            uvs_eid_t seid;
            uvs_eid_t deid;
        } um;
    };
} uvs_res_vtp_key_t;

typedef struct uvs_res_vtp_val {
    uvs_res_vtp_key_t key;
    uint32_t vtpn;
    uvs_eid_t seid;
    uint32_t sjetty_id;
    uvs_eid_t deid;
    uint32_t djetty_id;
    uint16_t fe_idx;
    uint32_t eid_index;
    union {
        uint32_t tpgn;             // RM
        uint32_t utpn;             // UM
    };
} uvs_res_vtp_val_t;

typedef struct uvs_res_tp_key_t {
    uint32_t tpn;
} uvs_res_tp_key_t;

typedef struct uvs_res_tp_val {
    uvs_res_tp_key_t key;
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
} uvs_res_tp_val_t;

typedef struct uvs_res_tpg_key {
    uint32_t tp_mode;
    uint32_t sub_tp_mode;
    uint32_t share_mode;
    uint32_t upi;
    union {
        struct {
            uvs_net_addr_t sip;
            uvs_net_addr_t dip;
        } rm;
        struct {
            uvs_eid_t seid;
            uvs_eid_t deid;
        } rm_non_share;
        struct {
            uvs_eid_t seid;
            uvs_eid_t deid;
        } rs_share;
        struct {
            uvs_eid_t deid;
            uint32_t djetty_id;
        } rs_non_share;
        struct {
            uvs_eid_t deid;
            uint32_t djetty_id;
        } rc;
    };
} uvs_res_tpg_key_t;

typedef struct uvs_res_tpg_val {
    uvs_res_tpg_key_t key;
    uint32_t tpgn;
    uint32_t tp_cnt;
    uint8_t dscp;
    uvs_tp_state_t tp_state[UVS_MAX_TP_CNT_IN_GRP];
    uint32_t tpn[UVS_MAX_TP_CNT_IN_GRP];
} uvs_res_tpg_val_t;

typedef struct uvs_res_utp_key {
    uint32_t sip_idx;
    uint32_t upi;
    uvs_eid_t deid;
} uvs_res_utp_key_t;

typedef struct uvs_res_utp_val {
    uvs_res_utp_key_t key;
    uint32_t utpn;
    uint16_t data_udp_start;
    uint8_t udp_range;
    uvs_utp_cfg_flag_t flag;
} uvs_res_utp_val_t;

typedef struct uvs_res_vport_key {
    char vport_name[UVS_MAX_VPORT_NAME];
} uvs_res_vport_key_t;

typedef struct uvs_res_vport_val {
    uvs_res_vport_key_t key;
    uint32_t seg_cnt;
    uint32_t jfs_cnt;
    uint32_t jfr_cnt;
    uint32_t jfc_cnt;
    uint32_t jetty_cnt;
    uint32_t jetty_group_cnt;
    uint32_t rc_cnt;
    uint32_t eid_used_cnt;
} uvs_res_vport_val_t;

typedef struct uvs_res_tpf_key_t {
    char tpf_name[UVS_MAX_DEV_NAME];
} uvs_res_tpf_key_t;

typedef struct uvs_res_tpf_val {
    uvs_res_tpf_key_t key;
    uint32_t vtp_cnt;
    uint32_t tp_cnt;
    uint32_t tpg_cnt;
    uint32_t utp_cnt;
    uint32_t eid_cnt;
} uvs_res_tpf_val_t;

typedef struct uvs_res_key {
    uvs_res_type_t type;
    union {
        uvs_res_vtp_key_t   vtp;
        uvs_res_tpg_key_t   tpg;
        uvs_res_tp_key_t    tp;
        uvs_res_utp_key_t   utp;
        uvs_res_vport_key_t vport;
        uvs_res_tpf_key_t   tpf;
    };
} uvs_res_key_t;

typedef struct uvs_res_val {
    uvs_res_type_t type;
    union {
        uvs_res_vtp_val_t   vtp;
        uvs_res_tpg_val_t   tpg;
        uvs_res_tp_val_t    tp;
        uvs_res_utp_val_t   utp;
        uvs_res_vport_val_t vport;
        uvs_res_tpf_val_t   tpf;
    };
} uvs_res_val_t;
#ifdef __cplusplus
}
#endif

#endif