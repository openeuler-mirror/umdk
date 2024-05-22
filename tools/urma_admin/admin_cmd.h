/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: ioctl command header file for urma_admin
 * Author: Chen Yutao
 * Create: 2023-03-14
 * Note:
 * History: 2023-03-14   create file
 */

#ifndef ADMIN_CMD_H
#define ADMIN_CMD_H

#include "admin_parameters.h"

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

#define UBCORE_GENL_FAMILY_NAME		"UBCORE_GENL"
#define UBCORE_GENL_FAMILY_VERSION	1

enum {
    UBCORE_ATTR_UNSPEC,
    UBCORE_HDR_COMMAND,
    UBCORE_HDR_ARGS_LEN,
    UBCORE_HDR_ARGS_ADDR,
    UBCORE_ATTR_NS_MODE,
    UBCORE_ATTR_DEV_NAME,
    UBCORE_ATTR_NS_FD,
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

int admin_show_utp(const tool_config_t *cfg);
int admin_show_stats(const tool_config_t *cfg);
int admin_show_res(const tool_config_t *cfg);
int admin_add_eid(const tool_config_t *cfg);
int admin_del_eid(const tool_config_t *cfg);
int admin_set_eid_mode(const tool_config_t *cfg);
int admin_set_ns_mode(const tool_config_t *cfg);
int admin_set_dev_ns(const tool_config_t *cfg);
#endif