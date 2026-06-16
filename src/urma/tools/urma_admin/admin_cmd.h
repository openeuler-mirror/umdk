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

typedef struct admin_stats {
    uint64_t tx_pkt;
    uint64_t rx_pkt;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_pkt_err;
    uint64_t rx_pkt_err;
} admin_stats_t;

typedef struct admin_cmd_query_stats {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint32_t type;
        uint32_t key;
    } in;
    admin_stats_t out;
} admin_cmd_query_stats_t;

typedef struct admin_stats_show_ctx {
    admin_stats_t stats;
    int ret;
    bool received;
} admin_stats_show_ctx_t;

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

typedef struct admin_show_physical_dev_ctx {
    admin_urma_topo_bonding_dev_t bonding_dev;
    int ret;
    bool received;
} admin_show_physical_dev_ctx_t;

typedef struct admin_core_cmd_sl_info {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint32_t SL;
        uint32_t priority;
    } in;
} admin_core_cmd_sl_info_t;

/* record types streamed back during a tpid show dumpit, mirror of kernel enum */
enum admin_tpid_show_rec_type {
    ADMIN_TPID_SHOW_REC_LIST_HDR = 0,
    ADMIN_TPID_SHOW_REC_TP_LIST,
    ADMIN_TPID_SHOW_REC_TPID_STATE,
    ADMIN_TPID_SHOW_REC_REUSE_ENTRY,
};

/* netlink attributes carried by the tpid show dumpit messages */
enum {
    ADMIN_TPID_SHOW_ATTR_UNSPEC = 0,
    ADMIN_TPID_SHOW_ATTR_REC_TYPE,          /* u32: admin_tpid_show_rec_type */
    /* common fields */
    ADMIN_TPID_SHOW_ATTR_LOCAL_EID,         /* binary, EID_LEN */
    ADMIN_TPID_SHOW_ATTR_PEER_EID,          /* binary, EID_LEN */
    ADMIN_TPID_SHOW_ATTR_TRANS_MODE,        /* u32 */
    ADMIN_TPID_SHOW_ATTR_SHARE_MODE,        /* u32 */
    ADMIN_TPID_SHOW_ATTR_TP_TYPE,           /* u32 */
    ADMIN_TPID_SHOW_ATTR_LINK_TYPE,         /* u32 */
    ADMIN_TPID_SHOW_ATTR_REF_CNT,           /* u32 */
    ADMIN_TPID_SHOW_ATTR_TP_HANDLE,         /* u64 */
    /* LIST_HDR specific */
    ADMIN_TPID_SHOW_ATTR_TP_LIST_CNT,       /* u32 */
    /* TPID_STATE specific */
    ADMIN_TPID_SHOW_ATTR_FOUND,             /* u8 */
    ADMIN_TPID_SHOW_ATTR_STATUS,            /* u32 */
    ADMIN_TPID_SHOW_ATTR_ALLOCED,           /* u8 */
    /* REUSE_ENTRY specific */
    ADMIN_TPID_SHOW_ATTR_STAG,              /* u64 */
    ADMIN_TPID_SHOW_ATTR_DTAG,              /* u64 */
    ADMIN_TPID_SHOW_ATTR_REUSE_STATE,       /* u32 */
    ADMIN_TPID_SHOW_ATTR_USE_CNT,           /* s32 */
    ADMIN_TPID_SHOW_ATTR_PEER_TP_HANDLE,    /* u64 */
    ADMIN_TPID_SHOW_ATTR_TX_PSN,            /* u32 */
    ADMIN_TPID_SHOW_ATTR_IS_REF,            /* u8 */
    ADMIN_TPID_SHOW_ATTR_LOCAL_CNA,         /* binary EID_SIZE */
	ADMIN_TPID_SHOW_ATTR_PEER_CNA,          /* binary EID_SIZE */
    ADMIN_TPID_SHOW_ATTR_MAX_PLUS,
};
#define ADMIN_TPID_SHOW_ATTR_MAX (ADMIN_TPID_SHOW_ATTR_MAX_PLUS - 1)

/* mirror of union ubcore_tp_handle */
typedef union admin_tp_handle {
    struct {
        uint64_t tpid : 24;
        uint64_t tpn_start : 24;
        uint64_t tp_cnt : 5;
        uint64_t ctp : 1;
        uint64_t rtp : 1;
        uint64_t utp : 1;
        uint64_t uboe : 1;
        uint64_t pre_defined : 1;
        uint64_t dynamic_defined : 1;
        uint64_t trans_mode : 3;
        uint64_t reserved : 2;
    } bs;
    uint64_t value;
} admin_tp_handle_t;

#define UBCORE_GENL_FAMILY_NAME    "UBCORE_GENL"
#define UBAGG_GENL_FAMILY_NAME     "UBAGG_GENL"
#define GENL_FAMILY_VERSION  1

typedef enum genl_family_enum {
    UBCORE_GENL,
    UBAGG_GENL,
    GENL_FAMILY_COUNT
} genl_family_t;

enum {
    UBCORE_ATTR_UNSPEC,
    UBCORE_HDR_COMMAND,
    UBCORE_HDR_ARGS_LEN,
    UBCORE_HDR_ARGS_ADDR,
    UBCORE_ATTR_DEV_NS_MODE,
    UBCORE_ATTR_DEV_NAME,
    UBCORE_ATTR_NS_FD,
    UBCORE_ATTR_EID_IDX,
    UBCORE_ATTR_EID = 15,
    UBCORE_ATTR_MAIN_UE_EID,
    UBCORE_ATTR_EID_NUM,
    UBCORE_ATTR_EID_LIST,
    UBCORE_ATTR_STATUS,
    UBCORE_ATTR_EID_NS_MODE,
    UBCORE_ATTR_SL,
    UBCORE_ATTR_PRIORITY,
    UBCORE_ATTR_PERF_STAT,
    UBCORE_ATTR_TOOL_QUERY_KEY,
    UBCORE_ATTR_TOOL_QUERY_KEY_TYPE,
    UBCORE_ATTR_TOOL_QUERY_KEY_EXT,
    UBCORE_ATTR_TOOL_QUERY_KEY_CNT,
    UBCORE_ATTR_STATS,
    UBCORE_ATTR_TPID_QUERY_FLAG,   /* u8: non-zero = query single tpid state */
    UBCORE_ATTR_TPID,              /* u64: tpid to query (valid with QUERY_FLAG) */
    UBCORE_ATTR_AFTER_LAST
};

typedef enum ubagg_genl_attr {
    UBAGG_ATTR_UNSPEC,
    UBAGG_HDR_ARGS_ADDR = 4,
    UBAGG_ATTR_EID,
    UBAGG_ATTR_BONDING_PHYSICAL_DEVICE,
    UBAGG_ATTR_AFTER_LAST
} ubagg_genl_attr_t;

typedef enum ubagg_genl_cmd {
    UBAGG_NL_CMD_UNSPEC,
    UBAGG_NL_GET_TOPO,
    UBAGG_NL_GET_SLAVE_EID,
    UBAGG_NL_USER_PAYLOAD,
    UBAGG_NL_GET_PHYSICAL_DEVICE,
    UBAGG_NL_CMD_GET_V2P_RES,
    UBAGG_NL_CMD_MAX,
} ubagg_genl_cmd_t;

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
int admin_nl_set_dev_sharing(bool enabled);
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
int admin_cmd_main_ue_eid(admin_config_t *cfg);
int admin_cmd_show(admin_config_t *cfg);
int admin_cmd_system(admin_config_t *cfg);
int admin_cmd_perf(admin_config_t *cfg);
int admin_cmd_show_dev_jfc(admin_config_t *cfg);
int admin_cmd_show_dev_jfs(admin_config_t *cfg);
int admin_cmd_show_dev_jfr(admin_config_t *cfg);
int admin_cmd_show_dev_jetty(admin_config_t *cfg);
int admin_cmd_show_dev_jetty_group(admin_config_t *cfg);
int admin_cmd_show_dev_rc(admin_config_t *cfg);
int admin_cmd_show_dev_seg(admin_config_t *cfg);

#endif
