/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa tp connection management header
 * Author: LI Yuxing
 * Create: 2023-08-21
 * Note:
 * History:
 */

#ifndef UVS_TP_MANAGE_H
#define UVS_TP_MANAGE_H

#include "ub_hmap.h"
#include "tpsa_nl.h"
#include "urma_types.h"
#include "tpsa_types.h"
#include "tpsa_table.h"
#include "tpsa_tbl_manage.h"
#include "tpsa_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct uvs_map_param {
    uint16_t fe_idx;
    tpsa_net_addr_t sip;
    uint32_t *vtpn;
} uvs_map_param_t;

typedef struct uvs_create_utp_param {
    utp_table_key_t key;
    uint32_t *vtpn;
} uvs_create_utp_param_t;

typedef struct uvs_create_ctp_param {
    ctp_table_key_t key;
    tpsa_net_addr_t sip;
    uint32_t prefix_len;
    uint32_t *vtpn;
} uvs_create_ctp_param_t;

typedef struct uvs_nl_resp_info {
    bool resp;
    tpsa_nl_resp_status_t status;
    uint32_t vtpn;
} uvs_nl_resp_info_t;

typedef struct uvs_ctx {
    tpsa_global_cfg_t *global_cfg_ctx;
    tpsa_table_t *table_ctx;
    tpsa_sock_ctx_t *sock_ctx;
    tpsa_nl_ctx_t *nl_ctx;
    tpsa_ioctl_ctx_t *ioctl_ctx;
} uvs_ctx_t;

typedef struct uvs_vport_ctx {
    vport_key_t key;
    vport_param_t param;
}uvs_vport_ctx_t;

typedef struct uvs_cp_ctx {
    urma_eid_t tpsa_eid;
} uvs_cp_ctx_t;


/* All should be validly initalized */
typedef struct uvs_tp_msg_ctx {
    uvs_vport_ctx_t vport_ctx;
    uvs_end_point_t src;
    uvs_end_point_t dst;
    uvs_cp_ctx_t peer;
} uvs_tp_msg_ctx_t;

/* response nl msg */
int uvs_response_create_fast(tpsa_nl_msg_t *msg, tpsa_nl_ctx_t *nl_ctx,
                             tpsa_nl_resp_status_t status, uint32_t vtpn);
int uvs_response_create(uint32_t vtpn, tpsa_sock_msg_t *msg, tpsa_nl_ctx_t *nl_ctx);
int uvs_response_destroy_fast(tpsa_nl_msg_t *msg, tpsa_nl_ctx_t *nl_ctx,
                              tpsa_nl_resp_status_t status);

/* table operation */
void uvs_table_remove_initiator(int32_t *vtpn, int32_t *tpgn, tpsa_tpg_table_index_t *tpg_idx,
                                tpsa_vtp_table_index_t *vtp_idx, tpsa_table_t *table_ctx);
int uvs_handle_table_sync(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);

/* tp connection management */
int uvs_map_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_create_param_t *cparam, uint32_t number,
                tpsa_net_addr_t *sip, uint32_t *vtpn);
int uvs_um_map_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx, uvs_map_param_t *uparam,
                   tpsa_create_param_t *cparam, utp_table_entry_t *utp_table_entry);
int uvs_destroy_utp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx,
                    utp_table_key_t *key, uint32_t utp_idx);
int uvs_create_utp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx,
                   tpsa_create_param_t *cparam, uvs_create_utp_param_t *uparam);
int uvs_create_ctp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx,
                   tpsa_create_param_t *cparam,
                   uvs_create_ctp_param_t *uparam);
int uvs_destroy_ctp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx,
                    ctp_table_key_t *key, tpsa_net_addr_t *sip, uint32_t ctp_idx);

int uvs_create_um_vtp_base(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx,
                           tpsa_create_param_t *cparam, uint32_t *vtpn);

int uvs_create_um_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, uvs_tp_msg_ctx_t *tp_msg_ctx, uint32_t *upi);
int uvs_destroy_um_vtp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_transport_mode_t trans_mode);

int uvs_sync_table(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, urma_eid_t *peer_tpsa_eid);
int uvs_rc_valid_check(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, bool isLoopback);
int uvs_create_vtp_reuse_tpg(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, tpsa_net_addr_t *sip,
                             tpsa_vtp_table_param_t *vtp_table_data);

int uvs_create_vtp_base(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_create_param_t *cparam,
                        tpsa_tpg_table_index_t *tpg_idx, uvs_nl_resp_info_t *nl_resp);
int uvs_create_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_create_vtp_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_create_vtp_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_create_vtp_ack(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_create_vtp_finish(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_destroy_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_destroy_target_vtp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_destroy_vtp_base(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, uvs_tp_msg_ctx_t *tp_msg_ctx,
                         int32_t vtpn, int32_t tpgn);

bool uvs_is_loopback(tpsa_transport_mode_t trans_mode, uvs_end_point_t *local, uvs_end_point_t *peer);
bool uvs_is_sig_loop(tpsa_transport_mode_t trans_mode, uvs_end_point_t *local, uvs_end_point_t *peer);
int uvs_destroy_vtp_and_tpg(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, uvs_tp_msg_ctx_t *tp_msg_ctx,
                            int32_t vtpn, int32_t tpgn);

#ifdef __cplusplus
}
#endif

#endif