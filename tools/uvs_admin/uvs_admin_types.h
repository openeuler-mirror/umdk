/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs_admin types header file
 * Author: Ji Lei
 * Create: 2023-7-3
 * Note:
 * History: 2023-7-3 create this file to support type definition in uvs_admin
 */

#ifndef UVS_ADMIN_TYPES_H
#define UVS_ADMIN_TYPES_H

#include <linux/types.h>
#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UVS_ADMIN_MAC_BYTES    6
#define UVS_ADMIN_MAX_DEV_NAME 64
#define MAC_STR_LEN            18
#define UVS_ADMIN_SLICE_SHIFT(a) (a + 15)
#define UVS_ADMIN_SLICE_K_SHIFT 10
#define UVS_ADMIN_PORT_CNT_MAX 16
#define UVS_ADMIN_NET_ADDR_SIZE (16)


typedef enum uvs_admin_mtu {
    UVS_ADMIN_MTU_256      = 1,
    UVS_ADMIN_MTU_512,
    UVS_ADMIN_MTU_1024,
    UVS_ADMIN_MTU_2048,
    UVS_ADMIN_MTU_4096,
    UVS_ADMIN_MTU_8192,
    UVS_ADMIN_MTU_CNT
} uvs_admin_mtu_t;

typedef enum uvs_admin_slice {
    UVS_ADMIN_SLICE_32K = 1 << 15,
    UVS_ADMIN_SLICE_64K = 1 << 16,
    UVS_ADMIN_SLICE_128K = 1 << 17,
    UVS_ADMIN_SLICE_256K = 1 << 18
} uvs_admin_slice_t;

typedef enum uvs_admin_slice_idx {
    UVS_ADMIN_SLICE_32 = 0,
    UVS_ADMIN_SLICE_64 = 1,
    UVS_ADMIN_SLICE_128 = 2,
    UVS_ADMIN_SLICE_256 = 3,
    UVS_ADMIN_SLICE_CNT = 4
} uvs_admin_slice_idx_t;

typedef enum uvs_admin_net_addr_type {
    UVS_ADMIN_NET_ADDR_TYPE_IPV4 = 0,
    UVS_ADMIN_NET_ADDR_TYPE_IPV6
} uvs_admin_net_addr_type_t;

typedef enum uvs_admin_tp_cc_alg {
    UVS_ADMIN_TP_CC_NONE = 0,
    UVS_ADMIN_TP_CC_DCQCN,
    UVS_ADMIN_TP_CC_DCQCN_AND_NETWORK_CC,
    UVS_ADMIN_TP_CC_LDCP,
    UVS_ADMIN_TP_CC_LDCP_AND_CAQM,
    UVS_ADMIN_TP_CC_LDCP_AND_OPEN_CC,
    UVS_ADMIN_TP_CC_HC3,
    UVS_ADMIN_TP_CC_DIP,
} uvs_admin_cc_alg_t;

typedef union uvs_admin_net_addr {
    uint8_t raw[UVS_ADMIN_NET_ADDR_SIZE]; /* Network Order */
    struct {
        uint64_t resv;   /* If IPv4 mapped to IPv6, == 0 */
        uint32_t prefix; /* If IPv4 mapped to IPv6, == 0x0000ffff */
        uint32_t addr;   /* If IPv4 mapped to IPv6, == IPv4 addr */
    } in4;
    struct {
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
} uvs_admin_net_addr_t;

typedef struct uvs_admin_net_addr_info {
    uvs_admin_net_addr_type_t type;
    uvs_admin_net_addr_t net_addr;
    uint64_t vlan; /* available for UBOE */
    uint8_t mac[UVS_ADMIN_MAC_BYTES]; /* available for UBOE */
    uint32_t prefix_len;
} uvs_admin_net_addr_info_t;

typedef union uvs_admin_tp_mod_flag {
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
        uint32_t reserved : 20; /* revise this struct need to sync print_tp_mod_flag_str function */
    } bs;
    uint32_t value;
} uvs_admin_tp_mod_flag_t;

typedef struct uvs_admin_tp_cc_entry {
    urma_tp_cc_alg_t alg;
    uint8_t cc_pattern_idx;
    uint8_t cc_priority;
    bool set_cc_priority;
} uvs_admin_tp_cc_entry_t;

typedef struct uvs_admin_tp_mod_cfg {
    uvs_admin_tp_mod_flag_t tp_mod_flag;
    uint32_t flow_label;
    uint32_t oor_cnt;
    uint8_t retry_num;
    uint8_t retry_factor;
    uint8_t ack_timeout;
    uint8_t dscp;
    uint8_t cc_pattern_idx;
    uint16_t data_udp_start;
    uint16_t ack_udp_start;
    uint8_t udp_range;
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
} uvs_admin_tp_mod_cfg_t; // same as tpsa_tp_mod_cfg_t

typedef struct uvs_admin_rc_cfg {
    uint32_t rc_cnt;
    uint32_t rc_depth;
    uint32_t slice;
} uvs_admin_rc_cfg_t;

#ifdef __cplusplus
}
#endif

#endif // UVS_ADMIN_TYPES_H
