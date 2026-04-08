/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: ioctl command header file for urma_admin
 * Author: Chen Yutao
 * Create: 2023-03-14
 * Note:
 * History: 2023-03-14   create file
 */

#ifndef ADMIN_CMD_H
#define ADMIN_CMD_H

#include "ub_list.h"

#include "admin_parameters.h"

#define MAX_CMDLINE_LEN 896 /* must less than MAX_LOG_LEN */

typedef struct admin_core_cmd_show_utp {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint32_t utpn;
    } in;
    struct {
        uint64_t addr;
        uint32_t len;
    } out;
} admin_core_cmd_show_utp_t;

typedef struct admin_cmd_query_stats {
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
} admin_cmd_query_stats_t;

typedef struct admin_cmd_query_res {
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
} admin_cmd_query_res_t;

typedef struct admin_core_cmd_update_eid {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint32_t eid_index;
        int ns_fd;
    } in;
} admin_core_cmd_update_eid_t;

typedef struct admin_core_cmd_set_eid_mode {
    struct {
        char dev_name[URMA_MAX_NAME];
        bool eid_mode;
    } in;
} admin_core_cmd_set_eid_mode_t;

typedef struct admin_core_cmd_topo_info {
    struct {
        int node_idx;
    } in;
    struct {
        uint32_t node_num;
        tool_topo_info_t topo_info;
    } out;
} admin_core_cmd_topo_info_t;

typedef struct admin_urma_topo_physical_dev {
    char dev_name[URMA_MAX_NAME];
    uint32_t chip_id;
    uint32_t primary_eid_idx;
    uint32_t port_eid_idx[PORT_NUM];
} admin_urma_topo_physical_dev_t;

typedef struct admin_urma_topo_bonding_dev {
    char dev_name[URMA_MAX_NAME];
    uint32_t bonding_eid_idx;
    admin_urma_topo_physical_dev_t physical_devs[IODIE_NUM];
} admin_urma_topo_bonding_dev_t;

typedef struct admin_core_cmd_topo_bonding_dev {
    struct {
        urma_eid_t agg_eid;
    } in;
    struct {
        admin_urma_topo_bonding_dev_t bonding_dev;
    } out;
} admin_core_cmd_topo_bonding_dev_t;

typedef struct admin_core_cmd_sl_info {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint32_t SL;
        uint32_t priority;
    } in;
} admin_core_cmd_sl_info_t;

#define UBCORE_GENL_FAMILY_NAME    "UBCORE_GENL"
#define UBCORE_GENL_FAMILY_VERSION 1

enum {
    UBCORE_ATTR_UNSPEC,
    UBCORE_HDR_COMMAND,
    UBCORE_HDR_ARGS_LEN,
    UBCORE_HDR_ARGS_ADDR,
    UBCORE_ATTR_NS_MODE,
    UBCORE_ATTR_DEV_NAME,
    UBCORE_ATTR_NS_FD,
    UBCORE_ATTR_EID_IDX,
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

typedef enum admin_agg_cmd {
    CMD_AGG_ADD = 4,
    CMD_AGG_DEL,
} admin_agg_cmd_t;

struct admin_cmd_hdr {
    uint32_t command;
    uint32_t args_len;
    uint64_t args_addr;
};

#define ADMIN_AGG_CMD_MAGIC 'B'
#define ADMIN_AGG_CMD _IOWR(ADMIN_AGG_CMD_MAGIC, 1, struct admin_cmd_hdr)

struct cmd_agg_add_arg {
    struct {
        urma_eid_t agg_eid;
        char dev_name[URMA_ADMIN_MAX_DEV_NAME];
    } in;
};

struct cmd_agg_del_arg {
    struct {
        urma_eid_t agg_eid;
    } in;
};

typedef struct admin_device_info {
    char dev_name[URMA_ADMIN_MAX_DEV_NAME];
    urma_device_attr_t dev_attr;
    urma_transport_type_t tp_type;
    urma_eid_info_t *eid_list;
    char net_dev_name[URMA_ADMIN_MAX_DEV_NAME];
} admin_device_info_t;

bool is_ubc(const char *dev_name);
int exec_cmd(admin_config_t *cfg, const admin_cmd_t *cmds);
int admin_nl_expose_dev_ns(const char *dev_name, int ns_fd);
int admin_nl_unexpose_dev_ns(const char *dev_name, int ns_fd);
int admin_nl_set_eid_ns(const char *dev_name, uint32_t eid_idx, int ns_fd);
int admin_cmd_get_topo_info(tool_topo_map_t *topo_map);
int admin_cmd_get_topo_bonding_dev_by_eid(const urma_eid_t *agg_eid,
                                          admin_urma_topo_bonding_dev_t *out);
int admin_get_device_name_by_eid(const urma_eid_t *eid, char *dev_name, size_t dev_name_len);
int admin_get_eid_list_by_eid(urma_eid_t *eid, urma_eid_info_t **eid_info_list,
                              char *dev_name);

// Legacy command
int admin_cmd_show_stats_legacy(admin_config_t *cfg);
int admin_cmd_show_res_legacy(admin_config_t *cfg);
int admin_cmd_list_res_legacy(admin_config_t *cfg);
int admin_cmd_add_eid_legacy(admin_config_t *cfg);
int admin_cmd_del_eid_legacy(admin_config_t *cfg);
int admin_cmd_set_eid_mode_legacy(admin_config_t *cfg);
int admin_cmd_set_ns_mode_legacy(admin_config_t *cfg);
int admin_cmd_set_dev_ns_legacy(admin_config_t *cfg);

// New command
int admin_cmd_main(admin_config_t *cfg);

int admin_cmd_agg(admin_config_t *cfg);
int admin_cmd_dev(admin_config_t *cfg);
int admin_cmd_eid(admin_config_t *cfg);
int admin_cmd_show(admin_config_t *cfg);

#endif
