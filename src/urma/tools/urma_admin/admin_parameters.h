/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: parse parameters header file for urma_admin
 * Author: Qian Guoxin
 * Create: 2023-01-04
 * Note:
 * History: 2023-01-04   create file
 */

#ifndef ADMIN_PARAMETERS_H
#define ADMIN_PARAMETERS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "urma_cmd.h"
#include "urma_types.h"
#include "urma_types_str.h"

#define MAX_NODE_NUM            (16)
#define EID_LEN                 (16)
#define MAX_PORT_NUM            (9)
#define IODIE_NUM               (2)
#define URMA_ADMIN_MAX_DEV_NAME 64
#define URMA_ADMIN_MAX_NS_PATH  128 /* /proc/$pid/ns/net */
#define OWN_UE_IDX              (0xffff)

/* refer to enum ubcore_stats_key_type */
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

/* refer to enum ubcore_res_key_type */
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

/* refer to struct ubcore_stats_key and struct ubcore_res_key */
typedef struct tool_query_key {
    uint32_t type;
    uint32_t key;
    uint32_t key_ext;
    uint32_t key_cnt;
} tool_query_key_t;

/* refer to struct ubcore_stats_com_val */
typedef struct tool_stats_val {
    uint64_t tx_pkt;
    uint64_t rx_pkt;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_pkt_err;
    uint64_t rx_pkt_err;
} tool_stats_val_t;

/* refer to struct ubcore_res_upi_val */
typedef struct tool_res_upi_val {
    uint32_t upi;
} tool_res_upi_val_t;

typedef union urma_vtp_cfg_flag {
    struct {
        uint32_t clan_tp : 1;
        uint32_t migrate : 1;
        uint32_t reserve : 30;
    } bs;
    uint32_t value;
} urma_vtp_cfg_flag_t;

/* refer to struct ubcore_res_vtp_val */
typedef struct tool_res_vtp_val {
    uint16_t ue_idx;
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
        uint32_t loopback : 1;
        uint32_t spray_en : 1;
        uint32_t reserved : 30;
    } bs;
    uint32_t value;
} tool_utp_cfg_flag_t;

/* refer to struct ubcore_res_utp_val */
typedef struct tool_res_utp_val {
    uint32_t utpn;
    uint16_t data_udp_start;
    uint8_t udp_range;
    tool_utp_cfg_flag_t flag;
} tool_res_utp_val_t;

/* refer to struct ubcore_res_jfs_val */
typedef struct tool_res_jfs_val {
    uint32_t jfs_id;
    uint8_t state;
    uint32_t depth;
    uint8_t pri;
    uint32_t jfc_id;
} tool_res_jfs_val_t;

/* refer to struct ubcore_res_jfr_val */
typedef struct tool_res_jfr_val {
    uint32_t jfr_id;
    uint8_t state;
    uint32_t depth;
    uint32_t jfc_id;
} tool_res_jfr_val_t;

/* refer to struct ubcore_res_jetty_val */
typedef struct tool_res_jetty_val {
    uint32_t jetty_id;
    uint32_t send_jfc_id;
    uint32_t recv_jfc_id;
    uint32_t jfr_id;
    uint32_t jfs_depth;
    uint8_t state;
    uint8_t pri;
} tool_res_jetty_val_t;

/* refer to struct ubcore_res_jetty_group_val */
typedef struct tool_res_jetty_grp_val {
    uint16_t jetty_cnt;
    uint32_t *jetty_list;
} tool_res_jetty_grp_val_t;

/* refer to struct ubcore_res_jfc_val */
typedef struct tool_res_jfc_val {
    uint32_t jfc_id;
    uint8_t state;
    uint32_t depth;
} tool_res_jfc_val_t;

/* refer to struct ubcore_res_rc_val */
typedef struct tool_res_rc_val {
    uint32_t type;
    uint32_t rc_id;
    uint16_t depth;
    uint8_t state;
} tool_res_rc_val_t;

typedef struct tool_ubva {
    urma_eid_t eid;
    uint64_t va;
} tool_ubva_t;

/* refer to struct ubcore_seg_info */
typedef struct tool_seg_info {
    tool_ubva_t ubva;
    uint64_t len;
    uint32_t token_id;
} tool_seg_info_t;

/* refer to struct ubcore_res_seg_val */
typedef struct tool_res_seg_val {
    uint32_t seg_cnt;
    tool_seg_info_t *seg_list;
} tool_res_seg_val_t;

typedef struct tool_iodie_info {
    char primary_eid[EID_LEN];
    char port_eid[MAX_PORT_NUM][EID_LEN];
    char peer_port_eid[MAX_PORT_NUM][EID_LEN];
    int socket_id;
} tool_iodie_info_t;

typedef struct tool_topo_info {
    char bonding_eid[EID_LEN];
    tool_iodie_info_t io_die_info[IODIE_NUM];
    bool is_cur_node;
} tool_topo_info_t;

typedef struct tool_topo_map {
    tool_topo_info_t topo_infos[MAX_NODE_NUM];
    uint32_t node_num;
} tool_topo_map_t;

/* refer to struct ubcore_res_dev_val */
typedef struct tool_res_dev_val {
    uint32_t seg_cnt;
    tool_seg_info_t *seg_list; /* token_id of segment list */
    uint32_t jfs_cnt;
    uint32_t *jfs_list; /* jfs_id list */
    uint32_t jfr_cnt;
    uint32_t *jfr_list; /* jfr_id list */
    uint32_t jfc_cnt;
    uint32_t *jfc_list; /* jfc_id list */
    uint32_t jetty_cnt;
    uint32_t *jetty_list; /* jetty_id list */
    uint32_t jetty_group_cnt;
    uint32_t *jetty_group_list; /* jetty_group_id list */
    uint32_t rc_cnt;
    uint32_t *rc_list; /* RC */
    uint32_t vtp_cnt;
    uint32_t *vtp_list; /* vtp */
    uint32_t tp_cnt;
    uint32_t *tp_list; /* RC */
    uint32_t tpg_cnt;
    uint32_t *tpg_list; /* RM */
    uint32_t utp_cnt;
    uint32_t *utp_list; /* UM */
} tool_res_dev_val_t;

typedef struct tool_config {
    int argc;
    char **argv;
    bool specify_device;
    bool whole_info;
    bool help;
    char dev_name[URMA_ADMIN_MAX_DEV_NAME]; /* ubep device name */
    urma_eid_t eid;
    bool dynamic_eid_mode;
    uint16_t ue_idx;
    /* eid start */
    uint16_t idx;                    /* eid idx */
    char ns[URMA_ADMIN_MAX_NS_PATH]; /* /proc/$pid/ns/net */
    /* eid end */
    tool_query_key_t key;
    uint8_t ns_mode; /* 0: exclusive, 1: shared */
    uint32_t min_rsvd_jetty_id;
    uint32_t max_rsvd_jetty_id;
} tool_config_t;

int admin_str_to_eid(const char *buf, urma_eid_t *eid);
int admin_str_to_u8(const char *buf, uint8_t *u8);
int admin_str_to_u16(const char *buf, uint16_t *u16);
int admin_str_to_u32(const char *buf, uint32_t *u32);
int admin_str_to_u64(const char *buf, uint64_t *u64);
int admin_parse_args(int argc, char *argv[], tool_config_t *cfg);

typedef tool_config_t admin_config_t;

typedef struct admin_cmd {
    char *name;
    int (*func)(admin_config_t *cfg);
} admin_cmd_t;

void usage(const char *argv0);
int admin_exec_cmd(admin_config_t *cfg, const admin_cmd_t *cmds);

bool is_1650(const char *dev_name);

#endif
