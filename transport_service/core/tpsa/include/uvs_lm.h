/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa live migration header file
 * Author: LI Yuxing
 * Create: 2023-8-16
 * Note:
 * History:
 */

#ifndef UVS_LM_H
#define UVS_LM_H

#include <linux/types.h>
#include "urma_types.h"
#include "tpsa_table.h"
#include "tpsa_sock.h"
#include "tpsa_ioctl.h"
#include "uvs_tp_manage.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLOCK_SEC_TO_NSEC (1000000000)
#define CLOCK_TIME_OUT_NSEC (100000000)

int uvs_lm_swap_tpg(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, char *dev_name);
int uvs_lm_handle_ready_rollback(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, char *dev_name);
int uvs_lm_handle_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_lm_handle_notify(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_lm_config_migrate_state_local(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, tpsa_mig_state_t state);
int uvs_lm_handle_async_event(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_lm_handle_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_lm_handle_rollback(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_lm_handle_rollback_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_lm_handle_query_status(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_lm_vtp_table_full_migrate(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req);
int uvs_lm_vtp_table_iterative_migrate(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req);
int uvs_lm_vtp_table_lmmsg_copy(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req);
int uvs_lm_for_um_vtp_table(um_vtp_table_t *um_vtp_table, tpsa_sock_msg_t *req);
int uvs_lm_for_rc_vtp_table(rc_vtp_table_t *rc_vtp_table, tpsa_sock_msg_t *req);
int uvs_lm_for_rm_vtp_table(rm_vtp_table_t *rm_vtp_table, tpsa_sock_msg_t *req);
int uvs_lm_query_vtp_entry_status(tpsa_nl_msg_t *msg, uvs_ctx_t *ctx, vtp_node_state_t *node_status);

#ifdef __cplusplus
}
#endif

#endif