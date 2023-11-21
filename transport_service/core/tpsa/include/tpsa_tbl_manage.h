/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa table management header file
 * Author: LI Yuxing
 * Create: 2023-08-17
 * Note:
 * History:
 */

#ifndef TPSA_TBL_MANAGE_H
#define TPSA_TBL_MANAGE_H

#include "urma_types.h"
#include "ub_hmap.h"
#include "ub_hash.h"
#include "uvs_lm_table.h"
#include "tpsa_net.h"
#include "tpsa_nl.h"
#include "tpsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * tpsa_table
 */
typedef struct tpsa_table {
    fe_table_t fe_table;
    rm_tpg_table_t rm_tpg_table;
    rc_tpg_table_t rc_tpg_table;
    utp_table_t utp_table;
    ctp_table_t ctp_table;
    vport_table_t vport_table;
    live_migrate_table_t live_migrate_table;
    jetty_peer_table_t jetty_peer_table;
    rm_wait_table_t rm_wait_table;
    rc_wait_table_t rc_wait_table;
    sip_table_t sip_table;
    dip_table_t dip_table;
    tp_state_table_t tp_state_table;
    tpg_state_table_t tpg_state_table;
    tpf_dev_table_t tpf_dev_table;
} tpsa_table_t;

int tpsa_table_init(tpsa_table_t *tpsa_table);
void tpsa_table_uninit(tpsa_table_t *tpsa_table);

tpsa_ueid_t *tpsa_lookup_vport_table_ueid(vport_key_t *key, uint32_t eid_index, vport_table_t *table);
int tpsa_get_upi(char *dev_name, uint16_t fe_idx, uint32_t eid_index, vport_table_t *table);

/* vtp table */
int tpsa_lookup_vtp_table(uint32_t location, tpsa_msg_t *msg, tpsa_table_t *table_ctx);
int tpsa_remove_vtp_table(tpsa_transport_mode_t trans_mode, tpsa_vtp_table_index_t *vtp_idx,
                          tpsa_table_t *table_ctx);
int tpsa_add_rm_vtp_table(tpsa_create_param_t *cparam, tpsa_vtp_table_param_t *vtp_table_data,
                          tpsa_table_t *table_ctx, bool isLoopback);
int tpsa_add_rc_vtp_table(tpsa_create_param_t *cparam, tpsa_vtp_table_param_t *vtp_table_data,
                          tpsa_table_t *table_ctx, bool isLoopback);
int tpsa_update_vtp_table(tpsa_sock_msg_t *msg, uint32_t location, uint32_t vtpn,
                          uint32_t tpgn, tpsa_table_t *table_ctx);
int tpsa_vtp_tpgn_swap(tpsa_transport_mode_t trans_mode, tpsa_vtp_table_index_t *vtp_idx,
                       tpsa_table_t *table_ctx, uint32_t *vice_tpgn);
int tpsa_vtp_node_status_change(tpsa_transport_mode_t trans_mode, tpsa_vtp_table_index_t *vtp_idx,
                                tpsa_table_t *table_ctx);
int tpsa_get_vtp_idx(uint16_t fe_idx, char *dev_name, tpsa_vtp_table_index_t *vtp_idx, tpsa_table_t *table_ctx);

/* dip table */
void tpsa_lookup_dip_table(dip_table_t *dip_table, urma_eid_t remote_eid, urma_eid_t *peer_tps, tpsa_net_addr_t *dip);

/* tpg table */
tpsa_tpg_status_t tpsa_lookup_tpg_table(tpsa_tpg_table_index_t *tpg_idx, tpsa_transport_mode_t trans_mode,
                                        tpsa_table_t *table_ctx, tpsa_tpg_info_t *tpsa_tpg_info);
int tpsa_add_rm_tpg_table(tpsa_tpg_table_param_t *param, rm_tpg_table_t *table);
int tpsa_add_rc_tpg_table(urma_eid_t peer_eid, uint32_t peer_jetty, tpsa_tpg_table_param_t *param,
                          rc_tpg_table_t *table);
int tpsa_remove_rm_tpg_table(rm_tpg_table_entry_t *entry, rm_tpg_table_t *table);
int tpsa_remove_rc_tpg_table(rc_tpg_table_entry_t *entry, tpsa_tpg_table_index_t *tpg_idx, rc_tpg_table_t *table);
int tpsa_update_tpg_table(tpsa_sock_msg_t *msg, uint32_t location, tpsa_table_t *table_ctx);

/* tpf dev table */
int tpsa_lookup_tpf_dev_table(char *dev_name, tpf_dev_table_t *table, tpf_dev_table_entry_t *return_entry);

/* vport table */
int tpsa_lookup_vport_table(vport_key_t *key, vport_table_t *table, vport_table_entry_t *return_entry);

/* sip table */
void tpsa_lookup_sip_table(uint32_t sip_idx, sip_table_entry_t *sip_entry, sip_table_t *table);

int tpsa_lookup_vport_sip(vport_key_t *fe_key, tpsa_table_t *table_ctx, sip_table_entry_t *sip_entry);

/* jetty peer table */
int tpsa_worker_jetty_peer_table_add(tpsa_table_t *table_ctx, tpsa_transport_mode_t trans_mode,
                                     jetty_peer_table_param_t *param);
int tpsa_worker_jetty_peer_table_remove(tpsa_table_t *table_ctx, tpsa_transport_mode_t trans_mode,
                                        uint32_t local_jetty, urma_eid_t *local_eid);
/* table operation */
int uvs_table_add(tpsa_create_param_t *cparam, tpsa_table_t *table_ctx, tpsa_tpg_table_param_t *tpg,
    tpsa_vtp_table_param_t *vtp_table_data);
int uvs_table_update(uint32_t vtpn, uint32_t tpgn, uint32_t location,
                     tpsa_sock_msg_t *msg, tpsa_table_t *table_ctx);

/* wait table */
int uvs_add_wait(tpsa_table_t *table_ctx, tpsa_create_param_t *cparam, uint32_t location);

/*
 * rc vtp table opts(Encapsulate the operations of primary and secondary tables)
 */
rc_vtp_table_entry_t *rc_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key, rc_vtp_table_key_t *vtp_key);
int rc_fe_vtp_table_add(fe_table_t *fe_table, vport_key_t *fe_key, rc_vtp_table_key_t *vtp_key,
                        tpsa_vtp_table_param_t *vtp_table_data);
int rc_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx);

/*
 * rm vtp table opts(Encapsulate the operations of primary and secondary tables)
 */
rm_vtp_table_entry_t *rm_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key, rm_vtp_table_key_t *vtp_key);
int rm_fe_vtp_table_add(fe_table_t *fe_table, vport_key_t *fe_key, rm_vtp_table_key_t *vtp_key,
                        tpsa_vtp_table_param_t *vtp_table_data);
int rm_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx);

/*
 * um vtp table opts(Encapsulate the operations of primary and secondary tables)
 */
um_vtp_table_entry_t *um_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key, um_vtp_table_key_t *vtp_key);
int um_fe_vtp_table_add(fe_table_t *fe_table, vport_key_t *fe_key, um_vtp_table_key_t *vtp_key,
                        tpsa_um_vtp_table_param_t *uparam);

/*
* clan vtp table opts
*/
clan_vtp_table_entry_t *clan_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key,
                                                 clan_vtp_table_key_t *vtp_key);
int clan_fe_vtp_table_add(fe_table_t *fe_table, vport_key_t *fe_key, clan_vtp_table_key_t *vtp_key,
                          tpsa_clan_vtp_table_param_t *uparam);

#ifdef __cplusplus
}
#endif

#endif