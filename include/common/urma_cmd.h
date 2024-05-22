/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
#define URMA_CMD_EID_SIZE (16)

/* only for ubcore device ioctl */
#define URMA_CORE_CMD_MAGIC 'C'
#define URMA_CORE_CMD _IOWR(URMA_CORE_CMD_MAGIC, 1, urma_cmd_hdr_t)
#define URMA_MAX_UASID  (1 << 24)

typedef enum urma_core_cmd {
    URMA_CORE_CMD_SHOW_UTP = 1,
    URMA_CORE_CMD_QUERY_STATS,
    URMA_CORE_CMD_QUERY_RES,
    URMA_CORE_CMD_ADD_EID,
    URMA_CORE_CMD_DEL_EID,
    URMA_CORE_CMD_SET_EID_MODE,
    URMA_CORE_SET_NS_MODE,
    URMA_CORE_SET_DEV_NS,
} urma_core_cmd_t;

/* only for uburma device ioctl */
#define URMA_CMD_MAGIC 'U'
#define URMA_CMD _IOWR(URMA_CMD_MAGIC, 1, urma_cmd_hdr_t)

typedef enum urma_cmd {
    URMA_CMD_CREATE_CTX = 1,
    URMA_CMD_DESTROY_CTX,
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
    URMA_CMD_USER_CTL
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
        uint64_t handle;          /* handle of jfr, used to find jfr obj in kernel */
        uint32_t mask;            /* see urma_jfr_attr_mask_t */
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
        uint64_t handle;          /* handle of jfs, used to find jfs obj in kernel */
        uint32_t mask;            /* see urma_jfr_attr_mask_t */
        uint32_t state;           /* urma_jetty_state_t */
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
        uint64_t handle;          /* handle of jfc, used to find jfc obj in kernel */
        uint32_t mask;            /* see urma_jfc_attr_mask_t */
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
        /* correspond to urma_token_t */
        uint32_t token;
        uint32_t trans_mode;
    } in;
    struct {
        uint32_t tpn;
        uint64_t handle; /* handle of the allocated tjfr obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_import_jfr_t;

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

        uint32_t jfr_id; /* shared jfr */
        uint64_t jfr_handle; /* handle of the shared jfr */

        uint64_t jetty_grp_handle; /* handle of the related jetty group */
        uint8_t  is_jetty_grp;

        uint64_t urma_jetty; /* urma jetty pointer */
    } in;
    struct {
        uint32_t id; /* jetty id allocated by ubcore */
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
        uint64_t handle;          /* handle of jetty, used to find jetty obj in kernel */
        uint32_t mask;            /* see urma_jetty_attr_mask_t */
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
    } in;
    struct {
        uint32_t tpn;
        uint64_t handle; /* handle of the allocated tjetty obj in kernel */
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_import_jetty_t;

typedef struct urma_cmd_unimport_jetty {
    struct {
        uint64_t handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
} urma_cmd_unimport_jetty_t;

typedef struct urma_cmd_advise_jetty {
    struct {
        uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
        uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_advise_jetty_t;

typedef struct urma_cmd_bind_jetty {
    struct {
        uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
        uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
    struct {
        uint32_t tpn;
    } out;
    urma_cmd_udrv_priv_t udata;
} urma_cmd_bind_jetty_t;

typedef struct urma_cmd_unbind_jetty {
    struct {
        uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
    } in;
} urma_cmd_unbind_jetty_t;

typedef struct urma_cmd_unadvise_jetty {
    struct {
        uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
        uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
    } in;
} urma_cmd_unadvise_jetty_t;

typedef struct urma_cmd_create_jetty_grp {
    struct {
        char name[URMA_MAX_NAME];
        uint32_t token;
        uint32_t id;
        uint32_t policy;
        uint64_t urma_jetty_grp; /* urma jetty group pointer */
    } in;
    struct {
        uint32_t id; /* jetty group id allocated by ubcore */
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
    } out;  /* struct [out] should be consistent with [urma_user_ctl_out_t] */
    struct {
        uint64_t in_addr;
        uint32_t in_len;
        uint64_t out_addr;
        uint32_t out_len;
    } udrv; /* struct [udrv] should be consistent with [urma_udrv_t] */
} urma_cmd_user_ctl_t;

/* only for event ioctl */
#define MAX_JFCE_EVENT_CNT 16
#define URMA_EVENT_CMD_MAGIC 'E'
#define JFCE_CMD_WAIT_EVENT  0
#define JFAE_CMD_GET_ASYNC_EVENT  0
#define URMA_CMD_WAIT_JFC _IOWR(URMA_EVENT_CMD_MAGIC, JFCE_CMD_WAIT_EVENT, urma_cmd_jfce_wait_t)
#define URMA_CMD_GET_ASYNC_EVENT _IOWR(URMA_EVENT_CMD_MAGIC, JFAE_CMD_GET_ASYNC_EVENT, urma_cmd_async_event_t)

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

#endif
