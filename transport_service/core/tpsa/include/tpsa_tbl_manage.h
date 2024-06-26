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
    deid_vtp_table_t deid_vtp_table;
    rm_tpg_table_t rm_tpg_table;
    rc_tpg_table_t rc_tpg_table;
    utp_table_t utp_table;
    ctp_table_t ctp_table;
    vport_table_t vport_table;
    live_migrate_table_t live_migrate_table;
    jetty_peer_table_t jetty_peer_table;
    rm_wait_table_t rm_wait_table;
    rc_wait_table_t rc_wait_table;
    dip_table_t dip_table;
    tp_state_table_t tp_state_table;
    tpg_state_table_t tpg_state_table;
    tpf_dev_table_t tpf_dev_table;
    struct ub_list alarm_list; /* store alarm */
} tpsa_table_t;

int tpsa_table_init(tpsa_table_t *tpsa_table);
void tpsa_table_uninit(tpsa_table_t *tpsa_table);

int tpsa_lookup_vport_table_ueid(vport_key_t *key, vport_table_t *table, uint32_t eid_index, tpsa_ueid_t *ueid);
int tpsa_update_vport_table_ueid(vport_table_t *table, vport_key_t *key, uint32_t eid_index,
    bool is_add, tpsa_ueid_t *find_ueid);

int tpsa_get_upi(vport_key_t *key, vport_table_t *table, uint32_t eid_index, uint32_t *upi);
int tpsa_lookup_upi_by_eid(vport_key_t *key, vport_table_t *table, urma_eid_t *local_eid, uint32_t *upi);

int tpsa_remove_vtp_table(tpsa_transport_mode_t trans_mode, tpsa_vtp_table_index_t *vtp_idx,
    tpsa_table_t *table_ctx, tpsa_tpg_table_index_t *tpg_idx);
int tpsa_add_rm_vtp_table(tpsa_create_param_t *cparam, tpsa_vtp_table_param_t *vtp_table_data,
                          tpsa_table_t *table_ctx, bool isLoopback);
int tpsa_lookup_rm_vtp_table(tpsa_table_t *table_ctx, vport_key_t *fe_key,
                             urma_eid_t *seid, urma_eid_t *deid, uint32_t *vtpn);

int tpsa_add_rc_vtp_table(tpsa_create_param_t *cparam, tpsa_vtp_table_param_t *vtp_table_data,
                          tpsa_table_t *table_ctx, bool isLoopback);
int tpsa_lookup_rc_vtp_table(tpsa_table_t *table_ctx, vport_key_t *fe_key,
                             uvs_end_point_t *src, uvs_end_point_t *dst, uint32_t *vtpn);

int tpsa_update_vtp_table(tpsa_sock_msg_t *msg, uint32_t location, uint32_t vtpn,
                          uint32_t tpgn, tpsa_table_t *table_ctx);
int tpsa_vtp_tpgn_swap(tpsa_table_t *table_ctx, uint32_t *vice_tpgn, tpsa_lm_vtp_entry_t *lm_vtp_entry);
int tpsa_vtp_node_status_change(vtp_node_state_t state, tpsa_lm_vtp_entry_t *lm_vtp_entry);
int tpsa_get_vtp_idx(uint16_t fe_idx, char *dev_name, size_t dev_name_len, tpsa_vtp_table_index_t *vtp_idx,
                     tpsa_table_t *table_ctx);
/* fe table */
void tpsa_update_fe_rebooted(fe_table_t *fe_table, vport_key_t *vport_key, bool fe_rebooted);
void uvs_update_fe_table_clean_res(fe_table_t *fe_table);
bool uvs_is_fe_in_cleaning_proc(fe_table_t *fe_table, vport_key_t *key);

/* dip table */
int tpsa_lookup_dip_table(dip_table_t *dip_table, urma_eid_t remote_eid, uint32_t upi,
    uvs_net_addr_t *peer_uvs_ip, uvs_net_addr_info_t *dip);
int tpsa_update_rm_tpg_table_tp_cnt(tpg_table_update_index_t *tpg_update_idx,
    tpsa_table_t *table_ctx, bool share_mode);

/* tpg table */
tpsa_tpg_status_t tpsa_lookup_tpg_table(tpsa_tpg_table_index_t *tpg_idx, tpsa_transport_mode_t trans_mode,
                                        tpsa_table_t *table_ctx, tpsa_tpg_info_t *tpsa_tpg_info);
int tpsa_add_rm_tpg_table(tpsa_tpg_table_param_t *param, rm_tpg_table_t *table);
int tpsa_add_rc_tpg_table(urma_eid_t peer_eid, uint32_t peer_jetty, tpsa_tpg_table_param_t *param,
                          rc_tpg_table_t *table);
int tpsa_remove_rm_tpg_table(rm_tpg_table_t *table, rm_tpg_table_key_t *key, tpsa_tpg_info_t *find_tpg_info);
int tpsa_remove_rc_tpg_table(tpsa_table_t *table_ctx, rc_tpg_table_key_t *key, tpsa_tpg_info_t *find_tpg_info);
int tpsa_update_tpg_table(tpsa_sock_msg_t *msg, uint32_t location, tpsa_table_t *table_ctx,
                          uvs_tp_state_t tp_state, uvs_net_addr_info_t *sip);

/* tpg state table */
int uvs_add_tpg_state_table(tpsa_table_t *table_ctx, tpg_state_table_entry_t *add_entry);

/* tpf dev table */
int tpsa_lookup_tpf_dev_table(char *dev_name, tpf_dev_table_t *table, tpf_dev_table_entry_t *return_entry);

/* vport table */
int tpsa_lookup_vport_table(vport_key_t *key, vport_table_t *table, vport_table_entry_t *return_entry);
int tpsa_lookup_vport_table_with_eid_idx(vport_key_t *key, vport_table_t *table, uint32_t eid_idx,
    vport_table_entry_t *return_entry);
int tpsa_vport_del_check(vport_table_entry_t *entry);
int tpsa_vport_find_del_port_key(vport_table_t *table, uvs_vport_info_key_t *key);
vport_table_entry_t *tpsa_vport_lookup_by_port_key_no_look(vport_table_t *table,
    uvs_vport_info_key_t *key);
int tpsa_lookup_vport_param(vport_key_t *key, vport_table_t *table, vport_param_t *vport_param);
int tpsa_lookup_vport_param_with_eid_idx(vport_key_t *key, vport_table_t *table,
    uint32_t eid_idx, vport_param_t *vport_param, uvs_lm_tp_ctx_t *lm_ctx);
void tpsa_fill_vport_param(vport_table_entry_t *entry, vport_param_t *vport_param);
void tpsa_lookup_vport_and_fill_lm_ctx(vport_key_t *key, vport_table_t *table, uvs_lm_tp_ctx_t *lm_ctx);

/* sip table */
int tpsa_sip_table_lookup(tpf_dev_table_t *tpf_dev_table, char *tpf_name, uint32_t sip_idx,
    sip_table_entry_t *target_entry);
int tpsa_sip_table_add(tpf_dev_table_t *tpf_dev_table, uint32_t sip_idx, sip_table_entry_t *entry_add);
int tpsa_sip_table_del(tpf_dev_table_t *tpf_dev_table, char *tpf_key, uint32_t sip_idx);
int tpsa_sip_table_query_unused_idx(tpsa_table_t *table_ctx, char *tpf_key, uint32_t *sip_idx);
int tpsa_sip_lookup_by_entry(tpsa_table_t *table_ctx, char *tpf_key, sip_table_entry_t *add_entry,
                             uint32_t *sip_idx);
sip_table_entry_t *tpsa_get_sip_entry_list(tpsa_table_t *table_ctx, char *tpf_key, uint32_t *max_sip_cnt);
void tpsa_free_sip_entry_list(sip_table_entry_t *sip_entry_list);

/* table operation */
int uvs_table_add(tpsa_create_param_t *cparam, tpsa_table_t *table_ctx, tpsa_tpg_table_param_t *tpg,
    tpsa_vtp_table_param_t *vtp_table_data);
int uvs_table_update(uint32_t vtpn, uint32_t tpgn, uint32_t location, tpsa_sock_msg_t *msg,
                     tpsa_table_t *table_ctx, uvs_tp_state_t tp_state, uvs_net_addr_info_t *sip);

/* wait table */
int uvs_add_wait(tpsa_table_t *table_ctx, tpsa_create_param_t *cparam, uint32_t location);

/*
 * rc vtp table opts(Encapsulate the operations of primary and secondary tables)
 */
rc_vtp_table_entry_t *rc_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key, rc_vtp_table_key_t *vtp_key);
int rc_fe_vtp_table_add(tpsa_table_t *table_ctx, vport_key_t *fe_key, rc_vtp_table_key_t *vtp_key,
                        tpsa_vtp_table_param_t *vtp_table_data);
int rc_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx);

/*
 * rm vtp table opts(Encapsulate the operations of primary and secondary tables)
 */
rm_vtp_table_entry_t *rm_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key, rm_vtp_table_key_t *vtp_key);
int rm_fe_vtp_table_add(tpsa_table_t *table_ctx, vport_key_t *fe_key, rm_vtp_table_key_t *vtp_key,
                        tpsa_vtp_table_param_t *vtp_table_data);
int rm_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx, tpsa_tpg_table_index_t *tpg_idx);
int tpsa_update_rm_vtp_table(tpsa_sock_msg_t *msg, uint32_t location, uint32_t vtpn,
    uint32_t tpgn, tpsa_table_t *table_ctx, tpsa_tpg_info_t *tpg_param);

/*
 * um vtp table opts(Encapsulate the operations of primary and secondary tables)
 */
um_vtp_table_entry_t *um_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key, um_vtp_table_key_t *vtp_key);
int um_fe_vtp_table_add(tpsa_table_t *table_ctx, vport_key_t *fe_key, um_vtp_table_key_t *vtp_key,
                        tpsa_um_vtp_table_param_t *uparam);

/*
* clan vtp table opts
*/
clan_vtp_table_entry_t *clan_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key,
                                                 clan_vtp_table_key_t *vtp_key);
int clan_fe_vtp_table_add(fe_table_t *fe_table, vport_key_t *fe_key, clan_vtp_table_key_t *vtp_key,
                          tpsa_clan_vtp_table_param_t *uparam);

int tpsa_rc_tpg_swap(tpsa_table_t *table_ctx, uint32_t *vice_tpgn, tpsa_lm_vtp_entry_t *lm_vtp_entry);
int tpsa_rm_vtp_tpgn_swap(uint32_t *vice_tpgn, tpsa_lm_vtp_entry_t *lm_vtp_entry);

#ifdef __cplusplus
}
#endif

#endif