/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: URMA EX API
 * Author: Ouyang changchun, Qian Guoxin
 * Create: 2023-02-03
 * Note:
 * History: 2023-02-03   Create File
 */
#ifndef URMA_EX_API_H
#define URMA_EX_API_H

#include <stdint.h>

#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urma_user_control_opcode {
    URMA_USER_CTL_SET_CTX_TM                   = 0,
    URMA_USER_CTL_IGNORE_JETTY_IN_CR,
    URMA_USER_CTL_SET_AI_MODE,
    URMA_USER_CTL_IP_NON_BLOCK_SEND,                       /* only available for IP mode */
    URMA_USER_CTL_POST_SEND_AND_RET_DB         = 10,
    URMA_USER_CTL_UPDATE_JFS_CI                = 11,
    URMA_USER_CTL_CONFIG_POE_CHANNEL           = 20,
    URMA_USER_CTL_QUERY_POE_CHANNEL            = 21,
    URMA_USER_CTL_CREATE_JFC_EX                = 22,
    URMA_USER_CTL_DELETE_JFC_EX               = 23
} urma_user_ctl_ops_t;

typedef struct urma_post_and_ret_db_user_out {
    uint64_t db_addr;
    uint64_t db_data;
} urma_post_and_ret_db_user_out_t;

typedef enum urma_ib_tm {
    URMA_IB_RC,
    URMA_IB_XRC,
    URMA_IB_UD
} urma_ib_tm_t;

typedef struct urma_set_tm_context {
    urma_context_t *ctx;
    urma_ib_tm_t tm_mode;
} urma_set_tm_ctx_t;

typedef enum urma_user_ctl_jfc_init_attr_mask {
    URMA_USER_CTL_JFC_INIT_ATTR_MASK_CREATE_FLAGS = 1
} urma_user_ctl_jfc_init_attr_mask_t;

typedef enum urma_user_ctl_jfc_create_flag {
    URMA_USER_CTL_JFC_CREATE_ENABLE_POE_MODE = 1,     /* conflict with notify */
    URMA_USER_CTL_JFC_CREATE_ENABLE_NOTIFY = 1 << 1
} urma_user_ctl_jfc_create_flag_t;

typedef enum urma_user_ctl_jfc_notify_mode {
    URMA_USER_CTL_JFC_NOTIFY_MODE_64B_ALIGN = 0,
    URMA_USER_CTL_JFC_NOTIFY_MODE_4B_ALIGN = 1,
    URMA_USER_CTL_JFC_NOTIFY_MODE_DDR_64B_ALIGN = 2,
    URMA_USER_CTL_JFC_NOTIFY_MODE_DDR_4B_ALIGN = 3,
    URMA_USER_CTL_JFC_NOTIFY_MODE_GUARD = 4           /* Invalid for user */
} urma_user_ctl_jfc_notify_mode_t;

typedef struct urma_user_ctl_jfc_notify_init_attr {
    uint64_t notify_addr;
    uint8_t notify_mode;     /* use urma_jfc_notify_mode */
    uint8_t reserved[7];
} urma_user_ctl_jfc_notify_init_attr_t;

typedef struct urma_user_ctl_jfc_init_attr {
    uint64_t comp_mask;       /* use urma_user_ctl_jfc_init_attr_mask_t */
    uint64_t create_flag; /* use urma_user_ctl_jfc_create_flag_t */
    uint8_t poe_channel;     /* poe channel to use */
    uint8_t reserved[7];
    urma_user_ctl_jfc_notify_init_attr_t notify_init_attr;
} urma_user_ctl_jfc_init_attr_t;

typedef struct urma_user_ctl_create_jfc_ex_in {
    urma_jfc_cfg_t *cfg;
    urma_user_ctl_jfc_init_attr_t *attr;
} urma_user_ctl_create_jfc_ex_in_t;

typedef struct urma_user_ctl_create_jfc_ex_out {
    urma_jfc_t *jfc;
} urma_user_ctl_create_jfc_ex_out_t;

typedef struct urma_user_ctl_delete_jfc_ex_in {
    urma_jfc_t *jfc;
} urma_user_ctl_delete_jfc_ex_in_t;

typedef struct urma_user_ctl_poe_init_attr {
    uint64_t comp_mask;       /* reserved for extension, now must be 0 */
    uint64_t poe_addr;        /* 0 for disable */
} urma_user_ctl_poe_init_attr_t;

typedef struct urma_user_ctl_cfg_poe_channel_in {
    urma_user_ctl_poe_init_attr_t *init_attr;
    uint8_t poe_channel;
} urma_user_ctl_cfg_poe_channel_in_t;

typedef struct urma_user_ctl_query_poe_channel_in {
    uint8_t poe_channel;
} urma_user_ctl_query_poe_channel_in_t;

typedef struct urma_user_ctl_query_poe_channel_out {
    urma_user_ctl_poe_init_attr_t *init_attr;
} urma_user_ctl_query_poe_channel_out_t;

typedef struct urma_user_ctl_update_jfs_ci_in {
    urma_jfs_t *jfs;
    uint32_t wqe_cnt;
} urma_user_ctl_update_jfs_ci_in_t;

typedef struct urma_user_ctl_ip_io_send_in {
    uint32_t io_thread_num;
} urma_user_ctl_ip_io_send_in_t; /* only preset */

/**
 * post a request to read, write, atomic or send data.
 * @param[in] jfs: the jfs created before, which is used to put command;
 * @param[in] wr: the posting request all information.
 * @param[out] bad_wr: the first of failure request.
 * @param[in] user_in: extended parameters.
 * @param[out] user_out: result of execution;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jfs_wr_ex(const urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr,
    const urma_user_ctl_in_t *user_in, urma_user_ctl_out_t *user_out);

/**
 * post a request to read, write, atomic or send data.
 * @param[in] jetty: the jetty created before, which is used to put command;
 * @param[in] wr: the posting request all information.
 * @param[out] bad_wr: the first of failure request.
 * @param[in] user_in: extended parameters.
 * @param[out] user_out: result of execution;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jetty_wr_ex(const urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr,
    const urma_user_ctl_in_t *user_in, urma_user_ctl_out_t *user_out);

// Called by the user to determine the use of a different transmission mode
urma_status_t urma_ib_set_transport_mode(urma_context_t *ctx, urma_ib_tm_t mode);

#ifdef __cplusplus
}
#endif
#endif