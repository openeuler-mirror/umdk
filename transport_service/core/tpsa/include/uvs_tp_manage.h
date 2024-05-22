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
    uvs_net_addr_info_t sip;
    uint32_t *vtpn;
} uvs_map_param_t;

typedef struct uvs_create_utp_param {
    utp_table_key_t key;
    uint32_t *vtpn;
} uvs_create_utp_param_t;

typedef struct uvs_create_ctp_param {
    ctp_table_key_t key;
    uvs_net_addr_info_t sip;
    uint32_t *vtpn;
} uvs_create_ctp_param_t;

typedef struct uvs_nl_resp_info {
    bool resp;
    int status;
    uint32_t vtpn;
} uvs_nl_resp_info_t;

typedef struct uvs_ctx {
    tpsa_global_cfg_t *global_cfg_ctx;
    tpsa_table_t *table_ctx;
    tpsa_sock_ctx_t *sock_ctx;
    tpsa_genl_ctx_t *genl_ctx;
    tpsa_ioctl_ctx_t *ioctl_ctx;
    uvs_socket_init_attr_t tpsa_attr;
} uvs_ctx_t;

typedef struct uvs_vport_ctx {
    vport_key_t key;
    vport_param_t param;
}uvs_vport_ctx_t;

typedef struct uvs_cp_ctx {
    uvs_net_addr_t uvs_ip;
} uvs_cp_ctx_t;

/* All should be validly initalized */
typedef struct uvs_tp_msg_ctx {
    uint32_t upi;
    enum tpsa_transport_type trans_type;
    tpsa_transport_mode_t trans_mode;
    uint32_t sub_trans_mode;
    uint32_t rc_share_tp;

    /* local site info */
    struct tpsa_ta_data ta_data; /* only valid when trans_type is IB */
    uvs_vport_ctx_t vport_ctx;
    uvs_end_point_t src;

    /* remote site info */
    uvs_end_point_t dst;
    uvs_cp_ctx_t peer;
} uvs_tp_msg_ctx_t;

/* tp msg ctx */
int uvs_get_tp_msg_ctx_local_site(tpsa_sock_msg_t *msg, vport_key_t *vport_key, struct tpsa_ta_data *ta_data,
                                  tpsa_table_t *table_ctx, uvs_tp_msg_ctx_t *tp_msg_ctx);
int uvs_get_tp_msg_ctx_peer_site(tpsa_sock_msg_t *msg, tpsa_table_t *table_ctx, struct tpsa_ta_data *ta_data,
                                 uvs_tp_msg_ctx_t *tp_msg_ctx);
/* response nl msg */
int uvs_response_create_fast(tpsa_nl_msg_t *msg, tpsa_genl_ctx_t *genl_ctx,
                             int status, uint32_t vtpn);
int uvs_response_destroy_fast(tpsa_nl_msg_t *msg, tpsa_genl_ctx_t *genl_ctx,
                              int status);
int uvs_response_destroy(uint32_t vtpn, tpsa_sock_msg_t *msg, tpsa_genl_ctx_t *genl_ctx);

/* table operation */
void uvs_table_remove_vtp_tpg(int32_t *vtpn, int32_t *tpgn, tpsa_tpg_table_index_t *tpg_idx,
                              tpsa_vtp_table_index_t *vtp_idx, tpsa_table_t *table_ctx);

/* tp connection management */
int uvs_map_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_create_param_t *cparam, uint32_t number,
                uvs_net_addr_info_t *sip, uint32_t *vtpn);
void uvs_unmap_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_create_param_t *cparam, uvs_net_addr_info_t *sip);
int uvs_um_map_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx, uvs_map_param_t *uparam,
                   tpsa_create_param_t *cparam, utp_table_entry_t *utp_table_entry);
void uvs_destroy_utp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx,
                     utp_table_key_t *key, uint32_t utp_idx);
int uvs_create_utp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx,
                   tpsa_create_param_t *cparam, uvs_create_utp_param_t *uparam);
int uvs_create_ctp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx,
                   tpsa_create_param_t *cparam,
                   uvs_create_ctp_param_t *uparam);
int uvs_destroy_ctp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx,
                    ctp_table_key_t *key, uvs_net_addr_info_t *sip, uint32_t ctp_idx);

int uvs_create_um_vtp_base(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx,
                           tpsa_create_param_t *cparam, uint32_t *vtpn);

int uvs_create_um_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, uvs_tp_msg_ctx_t *tp_msg_ctx);
int uvs_destroy_um_vtp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx);

int uvs_sync_table(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, uint32_t src_vtpn, uvs_net_addr_info_t *sip);
int uvs_rc_valid_check(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, bool isLoopback);
uvs_mtu_t uvs_get_mtu_with_sip_mtu(uvs_ctx_t *ctx, uvs_mtu_t sip_mtu);
int uvs_create_vtp_reuse_tpg(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, uvs_net_addr_info_t *sip,
                             tpsa_vtp_table_param_t *vtp_table_data, uvs_nl_resp_info_t *nl_resp);

int uvs_create_vtp_base(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_create_param_t *cparam,
                        tpsa_tpg_table_index_t *tpg_idx, uvs_nl_resp_info_t *nl_resp);
int uvs_create_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_handle_create_vtp_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_create_vtp_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_create_vtp_ack(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_create_vtp_finish(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_hanlde_create_fail_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_destroy_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_handle_destroy_vtp_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_destory_vtp_finish(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);

int uvs_handle_table_sync(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);
int uvs_handle_table_sync_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg);

int uvs_destroy_initial_vtp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_resp_id_t *nl_resp_id);
int uvs_destroy_rm_rc_vtp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, uint32_t location,
                          int32_t *vtpn, int32_t *tpgn);

bool uvs_is_loopback(tpsa_transport_mode_t trans_mode, uvs_end_point_t *local, uvs_end_point_t *peer);
bool uvs_is_sig_loop(tpsa_transport_mode_t trans_mode, uvs_end_point_t *local, uvs_end_point_t *peer);
bool uvs_is_clan_domain(uvs_ctx_t *ctx, vport_key_t *vport_key, vport_param_t *vport_param,
                        uvs_net_addr_info_t *sip, uvs_net_addr_info_t *dip);

int uvs_destroy_vtp_and_tpg(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, int32_t vtpn, int32_t tpgn,
                            uint32_t location);
void destroy_tpg_error_process(tpsa_tpg_table_index_t *tpg_idx,
                               tpsa_table_t *table_ctx, tpsa_tpg_info_t *find_tpg_info,
                               tpg_exception_state_t tpg_state);
int uvs_lm_destroy_vtp_in_migrating(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx);
int uvs_lm_destroy_vtp_in_ready(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx);

int tpsa_sock_send_destroy_req(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx,
                               uvs_direction_t direction, bool live_migrate,
                               tpsa_resp_id_t *resp_id);
int uvs_create_resp_to_lm_src(uvs_ctx_t *ctx, vport_key_t fe_key);
#ifdef __cplusplus
}
#endif

#endif