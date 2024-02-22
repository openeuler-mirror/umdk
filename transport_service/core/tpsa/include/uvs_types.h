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

#include <stdint.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UVS_EID_SIZE 16
#define UVS_NA_SIZE 16
#define ETH_ADDR_LEN 6
#define UVS_MAX_DEV_NAME 64
#define UVS_MAX_VPORT_NAME 32
#define UVS_MAX_PORT_CNT 16
#define UVS_MAX_CC_CNT 64
#define UVS_DEVID_SIZE (16)
typedef struct uvs_init_attr {
    struct in_addr server_ip;
    uint16_t server_port;
} uvs_init_attr_t;

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
    UVS_TP_CC_PFC = 0,
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

typedef union uvs_global_mask {
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
        uint32_t resereved : 15;
    } bs;
    uint32_t value;
} uvs_global_mask_t;

typedef struct uvs_global_info_key {
    char tpf_name[UVS_MAX_DEV_NAME];
} __attribute__((packed)) uvs_global_info_key_t;

typedef struct uvs_global_info {
    uvs_global_info_key_t key;

    uvs_global_mask_t mask;
    /* for nic */
    uvs_mtu_t mtu;
    /* for tpf device */
    uint32_t slice;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
    /* for uvs itself process, will not be set to driver */
    uint32_t sus2err_period;
    uint32_t sus2err_cnt;

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
        uint32_t rc_cnt : 1;
        uint32_t rc_depth : 1;
        uint32_t upi : 1;
        uint32_t eid : 1;
        uint32_t parent_name : 1;
        uint32_t tp_info : 1;
        uint32_t flag_share_mode : 1;
        uint32_t flag_pattern : 1;
        uint32_t flag_um_en : 1;
        uint32_t reserved : 13;
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
    uint32_t rc_cnt;                       // RC queue count, only for vport
    uint32_t rc_depth;                     // RC queue depth, only for vport
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

/* dip position data structure */
typedef struct uvs_loc_dip {
    uvs_net_addr_type_t type;  // ipv4 or v6
    uvs_net_addr_t dip;
    uint8_t dmac[ETH_ADDR_LEN];
    uint64_t vlan;
} uvs_loc_dip_t;

typedef struct uvs_user_ops {
    const char *name;
    int (*lookup_netaddr_by_ueid)(uvs_ueid_t *ueid, uvs_net_addr_t *dip);
} uvs_user_ops_t;

typedef enum {
    USER_OPS_GAEA,
    USER_OPS_MAX,
} user_ops_t;

#ifdef __cplusplus
}
#endif

#endif
