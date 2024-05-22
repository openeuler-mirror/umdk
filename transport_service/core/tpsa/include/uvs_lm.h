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

typedef struct uvs_lm_vtp_info {
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    uint32_t local_jetty;
    uint32_t peer_jetty;
    uint32_t upi;
} uvs_lm_vtp_info_t;

int uvs_lm_swap_tpg(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
                    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx);
int uvs_lm_refresh_tpg(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
                       tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx);
int uvs_lm_handle_ready_rollback(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg,
    vport_key_t *vport_key, tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx);
int uvs_lm_handle_mig_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_lm_handle_notify(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_lm_config_migrate_state_local(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, tpsa_mig_state_t state);
int uvs_lm_handle_async_event(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_lm_handle_mig_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_lm_handle_rollback(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_lm_handle_rollback_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_lm_handle_query_mig_status(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_lm_query_vtp_entry_status(tpsa_nl_msg_t *msg, uvs_ctx_t *ctx, vtp_node_state_t *node_status,
                                  tpsa_lm_vtp_entry_t *lm_vtp_entry);
int uvs_lm_send_mig_req(uvs_ctx_t *ctx, live_migrate_table_entry_t *cur, fe_table_entry_t *fe_entry);
int uvs_lm_handle_stop_proc_vtp_msg(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_lm_start_transfer_create_msg(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg, vport_key_t *key);
void uvs_lm_clean_up_resource(uvs_ctx_t *ctx);
void uvs_lm_clean_vport(uvs_ctx_t *ctx, vport_key_t *vport_key);
int uvs_lm_config_migentry(uvs_ctx_t *ctx, uvs_ueid_t *dueid, tpsa_mig_state_t status);
int uvs_lm_rollback_process(tpsa_table_t *table_ctx, uvs_ueid_t *dueid, vport_key_t *vport_key);
int uvs_lm_handle_dst_delete(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx);
void uvs_lm_set_dip_info(uvs_net_addr_info_t *dst, uvs_net_addr_info_t *src);
int uvs_lm_handle_src_delete(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx);
int uvs_lm_thrid_restore_vtp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif