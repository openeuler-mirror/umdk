/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: Public header file of urma cmd
 * Author: Qian Guoxin, Yan Fangfang
 * Create: 2021-11-12
 * Note:
 * History: 2021-11-12: Create file
 * History: 2022-07-25: Yan Fangfang Change the prefix ubp_ioctl_ to urma_cmd_
 */

#ifndef URMA_CMD_H
#define URMA_CMD_H

#include <linux/types.h>

#include "urma_types.h"

typedef struct urma_cmd_hdr {
    uint32_t command;
    uint32_t args_len;
    uint64_t args_addr;
} urma_cmd_hdr_t;

#define URMA_CMD_MAX_ARGS_SIZE 4096
#define URMA_CMD_EID_SIZE      (16)

/* only for ubcore device ioctl */
#define URMA_CORE_CMD_MAGIC    'C'
#define URMA_CORE_CMD          _IOWR(URMA_CORE_CMD_MAGIC, 1, urma_cmd_hdr_t)
#define URMA_MAX_UASID         (1 << 24)
#define URMA_CMD_TP_ATTR_BYTES 128

typedef enum urma_core_cmd {
    URMA_CORE_CMD_QUERY_STATS = 1,
    URMA_CORE_CMD_QUERY_RES,
    URMA_CORE_CMD_ADD_EID,
    URMA_CORE_CMD_DEL_EID,
    URMA_CORE_CMD_SET_EID_MODE,
    URMA_CORE_SET_NS_MODE,
    URMA_CORE_SET_DEV_NS,
    URMA_CORE_SET_DEV_SHARING_MODE,
    URMA_CORE_EXPOSE_DEV_NS,
    URMA_CORE_UNEXPOSE_DEV_NS,
    URMA_CORE_SET_DEV_EID_NS,
    URMA_CORE_GET_TOPO_INFO,
} urma_core_cmd_t;

/* only for uburma device ioctl */
#define URMA_CMD_MAGIC 'U'
#define URMA_CMD       _IOWR(URMA_CMD_MAGIC, 1, urma_cmd_hdr_t)

typedef enum urma_cmd {
    URMA_CMD_CREATE_CTX = 1,
    URMA_CMD_ALLOC_TOKEN_ID,
    URMA_CMD_FREE_TOKEN_ID,
    URMA_CMD_REGISTER_SEG,
    URMA_CMD_UNREGISTER_SEG,
    URMA_CMD_IMPORT_SEG,
    URMA_CMD_UNIMPORT_SEG,
    URMA_CMD_CREATE_JFS,
    URMA_CMD_MODIFY_JFS,
    URMA_CMD_QUERY_JFS,
    URMA_CMD_DELETE_JFS,
    URMA_CMD_CREATE_JFR,
    URMA_CMD_MODIFY_JFR,
    URMA_CMD_QUERY_JFR,
    URMA_CMD_DELETE_JFR,
    URMA_CMD_CREATE_JFC,
    URMA_CMD_MODIFY_JFC,
    URMA_CMD_DELETE_JFC,
    URMA_CMD_CREATE_JFCE,
    URMA_CMD_IMPORT_JFR,
    URMA_CMD_UNIMPORT_JFR,
    URMA_CMD_CREATE_JETTY,
    URMA_CMD_MODIFY_JETTY,
    URMA_CMD_QUERY_JETTY,
    URMA_CMD_DELETE_JETTY,
    URMA_CMD_IMPORT_JETTY,
    URMA_CMD_UNIMPORT_JETTY,
    URMA_CMD_ADVISE_JFR,
    URMA_CMD_UNADVISE_JFR,
    URMA_CMD_ADVISE_JETTY,
    URMA_CMD_UNADVISE_JETTY,
    URMA_CMD_BIND_JETTY,
    URMA_CMD_UNBIND_JETTY,
    URMA_CMD_CREATE_JETTY_GRP,
    URMA_CMD_DESTROY_JETTY_GRP,
    URMA_CMD_USER_CTL,
    URMA_CMD_GET_EID_LIST,
    URMA_CMD_GET_NETADDR_LIST,
    URMA_CMD_MODIFY_TP,
    URMA_CMD_QUERY_DEV_ATTR,
    URMA_CMD_IMPORT_JETTY_ASYNC,
    URMA_CMD_UNIMPORT_JETTY_ASYNC,
    URMA_CMD_BIND_JETTY_ASYNC,
    URMA_CMD_UNBIND_JETTY_ASYNC,
    URMA_CMD_CREATE_NOTIFIER,
    URMA_CMD_GET_TP_LIST,
    URMA_CMD_IMPORT_JETTY_EX,
    URMA_CMD_IMPORT_JFR_EX,
    URMA_CMD_BIND_JETTY_EX,
    URMA_CMD_DELETE_JFS_BATCH,
    URMA_CMD_DELETE_JFR_BATCH,
    URMA_CMD_DELETE_JFC_BATCH,
    URMA_CMD_DELETE_JETTY_BATCH,
    URMA_CMD_SET_TP_ATTR,
    URMA_CMD_GET_TP_ATTR,
    URMA_CMD_EXCHANGE_TP_INFO,
    URMA_CMD_MAX
} urma_cmd_t;

#ifndef URMA_CMD_UDRV_PRIV
#define URMA_CMD_UDRV_PRIV
typedef struct urma_cmd_udrv_priv {
    uint64_t in_addr;
    uint32_t in_len;
    uint64_t out_addr;
    uint32_t out_len;
} urma_cmd_udrv_priv_t;
#endif

typedef struct urma_cmd_create_ctx {
    struct {
        uint8_t eid[URMA_CMD_EID_SIZE];
        uint32_t eid_index;
    } in;
    struct {
        int async_fd;
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_create_ctx_t;

typedef struct urma_cmd_alloc_token_id {
    struct {
        urma_token_id_flag_t flag;
    } in;
    struct {
        uint32_t token_id;
        uint64_t handle; /* handle of the allocated token_id obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_alloc_token_id_t;

typedef struct urma_cmd_free_token_id {
    struct {
        uint64_t handle; /* handle of the allocated token_id obj in kernel */
        uint32_t token_id;
    } in;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_free_token_id_t;

typedef struct urma_cmd_register_seg {
    struct {
        uint64_t va;
        uint64_t len;
        uint32_t token_id;
        uint64_t token_id_handle;
        uint32_t token;
        uint32_t flag;
    } in;
    struct {
        uint32_t token_id;
        uint64_t handle; /* handle of the allocated seg obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_register_seg_t;

typedef struct urma_cmd_unregister_seg {
    struct {
        uint64_t handle; /* handle of seg, used to find seg obj in kernel */
    } in;
} urma_cmd_unregister_seg_t;

typedef struct urma_cmd_import_seg {
    struct {
        uint8_t eid[URMA_CMD_EID_SIZE];
        uint64_t va;
        uint64_t len;
        uint32_t flag;
        uint32_t token;
        uint32_t token_id;
        uint64_t mva;
    } in;
    struct {
        uint64_t handle; /* handle of the allocated tseg obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_import_seg_t;

typedef struct urma_cmd_unimport_seg {
    struct {
        uint64_t handle; /* handle of the seg to be unimported */
    } in;
} urma_cmd_unimport_seg_t;

typedef struct urma_cmd_create_jfr {
    struct {
        uint32_t depth;
        uint32_t flag;
        uint32_t trans_mode;
        uint8_t max_sge;
        uint8_t min_rnr_timer;
        uint32_t jfc_id;
        uint64_t jfc_handle;
        uint32_t token;
        uint32_t id;
        uint64_t urma_jfr; /* urma jfr pointer */
    } in;
    struct {
        uint32_t id;
        uint32_t depth;
        uint8_t max_sge;
        uint64_t handle; /* handle of the allocated jfr obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_create_jfr_t;

typedef struct urma_cmd_modify_jfr {
    struct {
        uint64_t handle; /* handle of jfr, used to find jfr obj in kernel */
        uint32_t mask;   /* see urma_jfr_attr_mask_t */
        uint32_t rx_threshold;
        uint32_t state;
    } in;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_modify_jfr_t;

typedef struct urma_cmd_query_jfr {
    struct {
        uint64_t handle; /* handle of the allocated jfr obj in kernel */
    } in;
    struct {
        uint32_t depth;
        uint32_t flag;
        uint32_t trans_mode;
        uint8_t max_sge;
        uint8_t min_rnr_timer;
        uint32_t token;
        uint32_t id;

        uint32_t rx_threshold;
        uint32_t state;
    } out;
} urma_cmd_query_jfr_t;

typedef struct urma_cmd_delete_jfr {
    struct {
        uint64_t handle; /* handle of jfr, used to find jfr obj in kernel */
    } in;
    struct {
        uint32_t async_events_reported;
    } out;
} urma_cmd_delete_jfr_t;

typedef struct urma_cmd_delete_jfr_batch {
    struct {
        uint32_t async_events_reported;
        uint32_t bad_jfr_index;
    } out;
    struct {
        uint32_t jfr_num;
        uint64_t jfr_ptr;
    } in;
} urma_cmd_delete_jfr_batch_t;

typedef struct urma_cmd_create_jfs {
    struct {
        uint32_t depth;
        uint32_t flag;
        uint32_t trans_mode;
        uint8_t priority;
        uint8_t max_sge;
        uint8_t max_rsge;
        uint32_t max_inline_data;
        uint8_t retry_cnt;
        uint8_t rnr_retry;
        uint8_t err_timeout;
        uint32_t jfc_id;
        uint64_t jfc_handle;
        uint64_t urma_jfs; /* urma jfs pointer */
    } in;
    struct {
        uint32_t id;
        uint32_t depth;
        uint8_t max_sge;
        uint8_t max_rsge;
        uint32_t max_inline_data;
        uint64_t handle; /* handle of the allocated jfs obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_create_jfs_t;

typedef struct urma_cmd_modify_jfs {
    struct {
        uint64_t handle; /* handle of jfs, used to find jfs obj in kernel */
        uint32_t mask;   /* see urma_jfr_attr_mask_t */
        uint32_t state;  /* urma_jetty_state_t */
    } in;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_modify_jfs_t;

typedef struct urma_cmd_query_jfs {
    struct {
        uint64_t handle; /* handle of the allocated jfs obj in kernel */
    } in;
    struct {
        uint32_t depth;
        uint32_t flag;
        uint32_t trans_mode;
        uint8_t priority;
        uint8_t max_sge;
        uint8_t max_rsge;
        uint32_t max_inline_data;
        uint8_t retry_cnt;
        uint8_t rnr_retry;
        uint8_t err_timeout;

        uint32_t state;
    } out;
} urma_cmd_query_jfs_t;

typedef struct urma_cmd_delete_jfs {
    struct {
        uint64_t handle; /* handle of jfs, used to find jfs obj in kernel */
    } in;
    struct {
        uint32_t async_events_reported;
    } out;
} urma_cmd_delete_jfs_t;

typedef struct urma_cmd_delete_jfs_batch {
    struct {
        uint32_t async_events_reported;
        uint32_t bad_jfs_index;
    } out;
    struct {
        uint32_t jfs_num;
        uint64_t jfs_ptr;
    } in;
} urma_cmd_delete_jfs_batch_t;

typedef struct urma_cmd_create_jfc {
    struct {
        uint32_t depth; /* in terms of CQEBB */
        uint32_t flag;
        int jfce_fd;
        uint64_t urma_jfc; /* urma jfc pointer */
        uint32_t ceqn;     /* [Optional] event queue id, no greater than urma_device_cap_t->ceq_cnt
                            * set to 0 by default */
    } in;
    struct {
        uint32_t id;
        uint32_t depth;
        uint64_t handle; /* handle of the allocated jfc obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_create_jfc_t;

typedef struct urma_cmd_modify_jfc {
    struct {
        uint64_t handle; /* handle of jfc, used to find jfc obj in kernel */
        uint32_t mask;   /* see urma_jfc_attr_mask_t */
        uint16_t moderate_count;
        uint16_t moderate_period; /* in micro seconds */
    } in;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_modify_jfc_t;

typedef struct urma_cmd_delete_jfc {
    struct {
        uint64_t handle; /* handle of jfc, used to find jfc obj in kernel */
    } in;
    struct {
        uint32_t comp_events_reported;
        uint32_t async_events_reported;
    } out;
} urma_cmd_delete_jfc_t;

typedef struct urma_cmd_delete_jfc_batch {
    struct {
        uint32_t comp_events_reported;
        uint32_t async_events_reported;
        uint32_t bad_jfc_index;
    } out;
    struct {
        uint32_t jfc_num;
        uint64_t jfc_ptr;
    } in;
} urma_cmd_delete_jfc_batch_t;

typedef struct urma_cmd_create_jfce {
    struct {
        int fd;
    } out;
} urma_cmd_create_jfce_t;

typedef struct urma_cmd_import_jfr {
    struct {
        /* correspond to urma_jfr_id */
        uint8_t eid[URMA_CMD_EID_SIZE];
        uint32_t id;
        uint32_t flag;
        /* correspond to urma_token_t */
        uint32_t token;
        uint32_t trans_mode;
        uint32_t tp_type;
    } in;
    struct {
        uint32_t tpn;
        uint64_t handle; /* handle of the allocated tjfr obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_import_jfr_t;

typedef struct urma_cmd_import_jfr_ex {
    struct {
        /* correspond to urma_jfr_id */
        uint8_t eid[URMA_CMD_EID_SIZE];
        uint32_t id;
        uint32_t flag; /* refer to urma_import_jetty_flag_t */
        /* correspond to urma_token_t */
        uint32_t token;
        uint32_t trans_mode;
        uint32_t tp_type;
        /* correspond to urma_active_tp_cfg_t */
        uint64_t tp_handle;
        uint64_t peer_tp_handle;
        uint64_t tag;
        uint32_t tx_psn;
        uint32_t rx_psn;
    } in;
    struct {
        uint32_t tpn;
        uint32_t reserved;
        uint64_t handle; /* handle of the allocated tjfr obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_import_jfr_ex_t;

typedef struct urma_cmd_unimport_jfr {
    struct {
        uint64_t handle; /* handle of tjfr, used to find tjfr obj in kernel */
    } in;
} urma_cmd_unimport_jfr_t;

typedef struct urma_cmd_create_jetty {
    struct {
        uint32_t id; /* user may assign id */
        uint32_t jetty_flag;

        uint32_t jfs_depth;
        uint32_t jfs_flag;
        uint32_t trans_mode;
        uint8_t priority;
        uint8_t max_send_sge;
        uint8_t max_send_rsge;
        uint32_t max_inline_data;
        uint8_t rnr_retry;
        uint8_t err_timeout;
        uint32_t send_jfc_id;
        uint64_t send_jfc_handle; /* handle of the related send jfc */

        uint32_t jfr_depth;
        uint32_t jfr_flag;
        uint8_t max_recv_sge;
        uint8_t min_rnr_timer;

        uint32_t recv_jfc_id;
        uint64_t recv_jfc_handle; /* handle of the related recv jfc */
        uint32_t token;

        uint32_t jfr_id;     /* shared jfr */
        uint64_t jfr_handle; /* handle of the shared jfr */

        uint64_t jetty_grp_handle; /* handle of the related jetty group */
        uint8_t is_jetty_grp;

        uint64_t urma_jetty; /* urma jetty pointer */
    } in;
    struct {
        uint32_t id;     /* jetty id allocated by ubcore */
        uint64_t handle; /* handle of the allocated jetty obj in kernel */
        uint32_t jfs_depth;
        uint32_t jfr_depth;
        uint8_t max_send_sge;
        uint8_t max_send_rsge;
        uint8_t max_recv_sge;
        uint32_t max_inline_data;
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_create_jetty_t;

typedef struct urma_cmd_modify_jetty {
    struct {
        uint64_t handle; /* handle of jetty, used to find jetty obj in kernel */
        uint32_t mask;   /* see urma_jetty_attr_mask_t */
        uint32_t rx_threshold;
        uint32_t state;
    } in;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_modify_jetty_t;

typedef struct urma_cmd_query_jetty {
    struct {
        uint64_t handle; /* handle of the allocated jetty obj in kernel */
    } in;
    struct {
        uint32_t id; /* user may assign id */
        uint32_t jetty_flag;

        uint32_t jfs_depth;
        uint32_t jfr_depth;
        uint32_t jfs_flag;
        uint32_t jfr_flag;
        uint32_t trans_mode;
        uint8_t max_send_sge;
        uint8_t max_send_rsge;
        uint8_t max_recv_sge;
        uint32_t max_inline_data;
        uint8_t priority;
        uint8_t retry_cnt;
        uint8_t rnr_retry;
        uint8_t err_timeout;
        uint8_t min_rnr_timer;
        uint32_t jfr_id;
        uint32_t token;

        uint32_t rx_threshold;
        uint32_t state;
    } out;
} urma_cmd_query_jetty_t;

typedef struct urma_cmd_delete_jetty {
    struct {
        uint64_t handle; /* handle of jetty, used to find jetty obj in kernel */
    } in;
    struct {
        uint32_t async_events_reported;
    } out;
} urma_cmd_delete_jetty_t;

typedef struct urma_cmd_delete_jetty_batch {
    struct {
        uint32_t async_events_reported;
        uint32_t bad_jetty_index;
    } out;
    struct {
        uint32_t jetty_num;
        uint64_t jetty_ptr;
    } in;
} urma_cmd_delete_jetty_batch_t;

typedef struct urma_cmd_import_jetty {
    struct {
        /* correspond to urma_jetty_id */
        uint8_t eid[URMA_CMD_EID_SIZE];
        uint32_t id;
        uint32_t flag;
        /* correspond to urma_token_t */
        uint32_t token;
        uint32_t trans_mode;
        uint32_t policy;
        uint32_t type;
        uint32_t tp_type;
    } in;
    struct {
        uint32_t tpn;
        uint64_t handle; /* handle of the allocated tjetty obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_import_jetty_t;

typedef struct urma_cmd_import_jetty_ex {
    struct {
        /* correspond to urma_jetty_id */
        uint8_t eid[URMA_CMD_EID_SIZE];
        uint32_t id;
        uint32_t flag;
        /* correspond to urma_token_t */
        uint32_t token;
        uint32_t trans_mode;
        uint32_t policy;
        uint32_t type;
        uint32_t tp_type;
        /* correspond to urma_active_tp_cfg_t */
        uint64_t tp_handle;
        uint64_t peer_tp_handle;
        uint64_t tag;
        uint32_t tx_psn;
        uint32_t rx_psn;
    } in;
    struct {
        uint32_t tpn;
        uint32_t reserved;
        uint64_t handle; /* handle of the allocated tjetty obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_import_jetty_ex_t;

typedef struct urma_cmd_unimport_jetty {
    struct {
        uint64_t handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
} urma_cmd_unimport_jetty_t;

typedef struct urma_cmd_advise_jetty {
    struct {
        uint64_t jetty_handle;  /* handle of jetty, used to find jetty obj in kernel */
        uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_advise_jetty_t;

typedef struct urma_cmd_bind_jetty {
    struct {
        uint64_t jetty_handle;  /* handle of jetty, used to find jetty obj in kernel */
        uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
    struct {
        uint32_t tpn;
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_bind_jetty_t;

typedef struct urma_cmd_bind_jetty_ex {
    struct {
        uint64_t jetty_handle;  /* handle of jetty, used to find jetty obj in kernel */
        uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
        /* correspond to urma_active_tp_cfg_t */
        uint64_t tp_handle;
        uint64_t peer_tp_handle;
        uint64_t tag;
        uint32_t tx_psn;
        uint32_t rx_psn;
    } in;
    struct {
        uint32_t tpn;
        uint32_t reserved;
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_bind_jetty_ex_t;

typedef struct urma_cmd_unbind_jetty {
    struct {
        uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
    } in;
} urma_cmd_unbind_jetty_t;

typedef struct urma_cmd_unadvise_jetty {
    struct {
        uint64_t jetty_handle;  /* handle of jetty, used to find jetty obj in kernel */
        uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
} urma_cmd_unadvise_jetty_t;

typedef struct urma_cmd_create_jetty_grp {
    struct {
        char name[URMA_MAX_NAME];
        uint32_t token;
        uint32_t id;
        uint32_t policy;
        uint32_t flag;
        uint64_t urma_jetty_grp; /* urma jetty group pointer */
    } in;
    struct {
        uint32_t id;     /* jetty group id allocated by ubcore */
        uint64_t handle; /* handle of the allocated jetty group obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_create_jetty_grp_t;

typedef struct urma_cmd_delete_jetty_grp {
    struct {
        uint64_t handle; /* handle of jetty group, used to find jetty group obj in kernel */
    } in;
    struct {
        uint32_t async_events_reported;
    } out;
} urma_cmd_delete_jetty_grp_t;

typedef struct urma_cmd_get_eid_list {
    struct {
        uint32_t max_eid_cnt;
    } in;
    struct {
        uint32_t eid_cnt;
        urma_eid_info_t eid_list[URMA_MAX_EID_CNT];
    } out;
} urma_cmd_get_eid_list_t;

typedef struct urma_cmd_user_ctl {
    struct {
        uint64_t addr;
        uint32_t len;
        uint32_t opcode;
    } in; /* struct [in] should be consistent with [urma_user_ctl_in_t] */
    struct {
        uint64_t addr;
        uint32_t len;
        uint32_t reserved;
    } out; /* struct [out] should be consistent with [urma_user_ctl_out_t] */
    struct {
        uint64_t in_addr;
        uint32_t in_len;
        uint64_t out_addr;
        uint32_t out_len;
    } udrv; /* struct [udrv] should be consistent with [urma_udrv_t] */
} urma_cmd_user_ctl_t;

typedef enum urma_cmd_net_addr_type {
    URMA_CMD_NET_ADDR_TYPE_IPV4 = 0,
    URMA_CMD_NET_ADDR_TYPE_IPV6
} urma_cmd_net_addr_type_t;

union urma_cmd_net_addr_union {
    uint8_t raw[URMA_CMD_EID_SIZE];
    struct {
        uint64_t reserved1;
        uint32_t reserved2;
        uint32_t addr;
    } in4;
    struct {
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
};

typedef struct urma_cmd_net_addr {
    urma_cmd_net_addr_type_t type;
    union urma_cmd_net_addr_union net_addr;
    uint64_t vlan;               /* available for UBOE */
    uint8_t mac[URMA_MAC_BYTES]; /* available for UBOE */
    uint32_t prefix_len;
} urma_cmd_net_addr_t;

typedef struct urma_cmd_net_addr_info {
    urma_cmd_net_addr_t netaddr;
    uint32_t index;
} urma_cmd_net_addr_info_t;

typedef struct urma_cmd_get_net_addr_list {
    struct {
        uint32_t max_netaddr_cnt;
    } in;
    struct {
        uint32_t netaddr_cnt;
        uint64_t addr; /* containing the array of urma_cmd_net_addr_info_t */
        uint64_t len;
    } out;
} urma_cmd_get_net_addr_list_t;

typedef struct urma_cmd_modify_tp {
    struct {
        uint32_t tpn;
        urma_tp_cfg_t tp_cfg;
        urma_tp_attr_t attr;
        urma_tp_attr_mask_t mask;
    } in;
} urma_cmd_modify_tp_t; /* this struct should be consistent [struct uburma_cmd_modify_tp] */

typedef struct urma_cmd_query_device_attr {
    struct {
        char dev_name[URMA_MAX_DEV_NAME];
    } in;
    struct {
        urma_device_attr_t attr;
    } out;
} urma_cmd_query_device_attr_t;

typedef struct urma_cmd_import_jetty_async {
    struct {
        /* correspond to urma_jetty_id */
        uint8_t eid[URMA_CMD_EID_SIZE];
        uint32_t id;
        uint32_t flag;
        /* correspond to urma_token_t */
        uint32_t token;
        uint32_t trans_mode;
        uint32_t policy;
        uint32_t type;
        uint64_t urma_tjetty; /* urma tjetty pointer */
        uint64_t user_ctx;
        int fd;
        int timeout;
    } in;
    struct {
        uint32_t tpn;
        uint64_t handle; /* handle of the allocated tjetty obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_import_jetty_async_t;

typedef struct urma_cmd_unimport_jetty_async {
    struct {
        uint64_t handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
} urma_cmd_unimport_jetty_async_t;

typedef struct urma_cmd_bind_jetty_async {
    struct {
        uint64_t jetty_handle;  /* handle of jetty, used to find jetty obj in kernel */
        uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
        uint64_t urma_tjetty;   /* urma tjetty pointer */
        uint64_t urma_jetty;    /* urma jetty pointer */
        int fd;
        uint64_t user_ctx;
        int timeout;
    } in;
    struct {
        uint32_t tpn;
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_bind_jetty_async_t;

typedef struct urma_cmd_unbind_jetty_async {
    struct {
        uint64_t jetty_handle;  /* handle of jetty, used to find jetty obj in kernel */
        uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
} urma_cmd_unbind_jetty_async_t;

typedef struct urma_cmd_create_notifier {
    struct {
        int fd;
    } out;
} urma_cmd_create_notifier_t;

/* only for event ioctl */
#define MAX_JFCE_EVENT_CNT   16
#define MAX_NOTIFY_CNT       16
#define URMA_EVENT_CMD_MAGIC 'E'

#define JFCE_CMD_WAIT_EVENT      0
#define URMA_CMD_WAIT_JFC        _IOWR(URMA_EVENT_CMD_MAGIC, JFCE_CMD_WAIT_EVENT, urma_cmd_hdr_t)
#define JFAE_CMD_GET_ASYNC_EVENT 0
#define URMA_CMD_GET_ASYNC_EVENT _IOWR(URMA_EVENT_CMD_MAGIC, JFAE_CMD_GET_ASYNC_EVENT, urma_cmd_hdr_t)
#define NOTIFIER_CMD_WAIT_NOTIFY 0
#define URMA_CMD_WAIT_NOTIFY     _IOWR(URMA_EVENT_CMD_MAGIC, NOTIFIER_CMD_WAIT_NOTIFY, urma_cmd_hdr_t)

typedef struct urma_cmd_jfce_wait {
    struct {
        uint32_t max_event_cnt;
        int time_out;
    } in;
    struct {
        uint32_t event_cnt;
        uint64_t event_data[MAX_JFCE_EVENT_CNT];
    } out;
} urma_cmd_jfce_wait_t;

typedef struct urma_cmd_async_event {
    uint32_t event_type;
    uint64_t event_data;
    uint32_t pad;
} urma_cmd_async_event_t;

typedef struct urma_cmd_notify {
    urma_notify_type_t type;
    urma_status_t status;
    uint64_t user_ctx;
    uint64_t urma_jetty;
    uint32_t vtpn;
} urma_cmd_notify_t;

typedef struct urma_cmd_wait_notify {
    struct {
        uint32_t cnt;
        int timeout;
    } in;
    struct {
        uint32_t cnt;
        urma_cmd_notify_t notify[MAX_NOTIFY_CNT];
    } out;
} urma_cmd_wait_notify_t;

#define URMA_CMD_MAX_TP_NUM 128

typedef struct urma_cmd_get_tp_list {
    struct {
        uint32_t flag;
        uint32_t trans_mode;
        uint8_t local_eid[URMA_CMD_EID_SIZE];
        uint8_t peer_eid[URMA_CMD_EID_SIZE];
        uint32_t tp_cnt;
        uint32_t reserved;
    } in;
    struct {
        uint32_t tp_cnt;
        uint32_t reserved;
        uint64_t tp_handle[URMA_CMD_MAX_TP_NUM];
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_get_tp_list_t;

typedef struct urma_cmd_exchange_tp_info_t {
    struct {
        struct urma_get_tp_cfg get_tp_cfg;
        uint64_t tp_handle;
        uint32_t tx_psn;
    } in;
    struct {
        uint64_t peer_tp_handle;
        uint32_t rx_psn;
    } out;
} urma_cmd_exchange_tp_info_t;

typedef struct urma_cmd_set_tp_attr {
    struct {
        uint64_t tp_handle;
        uint8_t tp_attr_cnt;
        uint32_t tp_attr_bitmap;
        uint8_t tp_attr[URMA_CMD_TP_ATTR_BYTES];
    } in;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_set_tp_attr_t;

typedef struct urma_cmd_get_tp_attr {
    struct {
        uint64_t tp_handle;
    } in;
    struct {
        uint8_t tp_attr_cnt;
        uint32_t tp_attr_bitmap;
        uint8_t tp_attr[URMA_CMD_TP_ATTR_BYTES];
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_get_tp_attr_t;

#endif
