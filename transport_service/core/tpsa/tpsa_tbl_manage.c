/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa table management file
 * Author: LI Yuxing
 * Create: 2023-8-17
 * Note:
 * History:
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/resource.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <errno.h>

#include "tpsa_log.h"
#include "uvs_api.h"
#include "uvs_private_api.h"
#include "tpsa_worker.h"
#include "tpsa_tbl_manage.h"

int tpsa_lookup_vport_table_ueid(vport_key_t *key, vport_table_t *table, uint32_t eid_index, tpsa_ueid_t *ueid)
{
    (void)pthread_rwlock_rdlock(&table->rwlock);
    vport_table_entry_t *entry = vport_table_lookup(table, key);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to lookup vport table, dev_name:%s, fe_idx:%hu.\n", key->tpf_name, key->fe_idx);
        (void)pthread_rwlock_unlock(&table->rwlock);
        return -1;
    }

    if (eid_index >= entry->ueid_max_cnt || entry->ueid[eid_index].is_valid == false) {
        TPSA_LOG_ERR("Failed to lookup eid by index, idx:%u, max_idx:%u, %u.\n",
            eid_index, entry->ueid_max_cnt, entry->ueid[eid_index].is_valid);
        (void)pthread_rwlock_unlock(&table->rwlock);
        return -1;
    }

    *ueid = entry->ueid[eid_index];
    (void)pthread_rwlock_unlock(&table->rwlock);
    return 0;
}

int tpsa_get_upi(vport_key_t *key, vport_table_t *table, uint32_t eid_index, uint32_t *upi)
{
    tpsa_ueid_t ueid;
    int ret = tpsa_lookup_vport_table_ueid(key, table, eid_index, &ueid);
    if (ret != 0) {
        return ret;
    }
    *upi = ueid.upi;
    return 0;
}

void tpsa_update_fe_rebooted(fe_table_t *fe_table, vport_key_t *vport_key, bool fe_rebooted)
{
    (void)pthread_rwlock_wrlock(&fe_table->rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(fe_table, vport_key);
    if (fe_entry == NULL) {
        (void)pthread_rwlock_unlock(&fe_table->rwlock);
        return;
    }

    fe_entry->fe_rebooted = fe_rebooted;
    fe_table->clean_res = fe_table->clean_res || fe_rebooted;
    (void)pthread_rwlock_unlock(&fe_table->rwlock);

    TPSA_LOG_INFO("update fe dev_name:%s, fe_idx:%u rebooted, vf_rebooted:%d\n",
        fe_entry->key.tpf_name, fe_entry->key.fe_idx, fe_rebooted);
}

bool uvs_is_fe_in_cleaning_proc(fe_table_t *fe_table, vport_key_t *key)
{
    bool fe_cleaning = false;

    (void)pthread_rwlock_rdlock(&fe_table->rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(fe_table, key);
    if (fe_entry != NULL) {
        fe_cleaning = fe_cleaning || fe_entry->fe_rebooted;
    }
    (void)pthread_rwlock_unlock(&fe_table->rwlock);
    return fe_cleaning;
}

bool uvs_is_need_clean_fe(fe_table_t *fe_table)
{
    bool clean_res = false;
    (void)pthread_rwlock_rdlock(&fe_table->rwlock);
    clean_res = fe_table->clean_res;
    (void)pthread_rwlock_unlock(&fe_table->rwlock);
    return clean_res;
}

void uvs_update_fe_table_clean_res(fe_table_t *fe_table)
{
    bool clean_res = false;

    (void)pthread_rwlock_wrlock(&fe_table->rwlock);
    fe_table_entry_t *cur, *next;
    HMAP_FOR_EACH_SAFE(cur, next, node, &fe_table->hmap) {
        clean_res = clean_res || cur->fe_rebooted;
    }

    fe_table->clean_res = clean_res;
    (void)pthread_rwlock_unlock(&fe_table->rwlock);
}

int tpsa_lookup_upi_by_eid(vport_key_t *key, vport_table_t *table, urma_eid_t *local_eid, uint32_t *upi)
{
    (void)pthread_rwlock_rdlock(&table->rwlock);
    vport_table_entry_t *entry = vport_table_lookup(table, key);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to lookup vport table, tpf_name: %s, fe_idx: %hu.\n", key->tpf_name, key->fe_idx);
        (void)pthread_rwlock_unlock(&table->rwlock);
        return -1;
    }

    for (int i = 0; i < TPSA_EID_IDX_TABLE_SIZE; i++) {
        if (entry->ueid[i].is_valid && memcmp(&entry->ueid[i].eid, local_eid, sizeof(urma_eid_t)) == 0) {
            *upi = entry->ueid[i].upi;
            (void)pthread_rwlock_unlock(&table->rwlock);
            return 0;
        }
    }
    (void)pthread_rwlock_unlock(&table->rwlock);
    return -1;
}

/* rc_fe_vtp lookup/add opts */
rc_vtp_table_entry_t *rc_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key, rc_vtp_table_key_t *vtp_key)
{
    if (fe_table == NULL) {
        return NULL;
    }
    /* first, look up fe_table to get the second table of rc_vtp_table */
    (void)pthread_rwlock_wrlock(&fe_table->rwlock);
    fe_table_entry_t *entry = fe_table_lookup(fe_table, fe_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("Can't find fe entry in rc_fe_vtp_table_lookup, dev_name:%s, fe_idx:%hu",
            fe_key->tpf_name, fe_key->fe_idx);
        (void)pthread_rwlock_unlock(&fe_table->rwlock);
        return NULL;
    }
    (void)pthread_rwlock_unlock(&fe_table->rwlock);

    /* second, according to the vtp_table of specific fe, to look up the node */
    rc_vtp_table_entry_t *vtp_entry = NULL;
    vtp_entry = rc_vtp_table_lookup(&entry->rc_vtp_table, vtp_key);
    return vtp_entry;
}

int rc_fe_vtp_table_add(tpsa_table_t *table_ctx, vport_key_t *fe_key, rc_vtp_table_key_t *vtp_key,
                        tpsa_vtp_table_param_t *vtp_table_data)
{
    if (table_ctx == NULL || fe_key == NULL || vtp_key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* If the primary table does not exist, need to create the primary table and initialize the secondary table */
    (void)pthread_rwlock_wrlock(&table_ctx->fe_table.rwlock);
    fe_table_entry_t *entry = fe_table_lookup(&table_ctx->fe_table, fe_key);
    if (entry == NULL) {
        entry = fe_table_add(&table_ctx->fe_table, fe_key);
        if (entry == NULL) {
            (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
            TPSA_LOG_ERR("fe table add failed");
            return TPSA_ADD_NOMEM;
        }
    }

    if (rc_vtp_table_add(&table_ctx->deid_vtp_table, entry, vtp_key, vtp_table_data) != 0) {
        (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
        return TPSA_ADD_NOMEM;
    }
    (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
    TPSA_LOG_INFO("rc_vtp add table, eid:" EID_FMT ", id:%u",
            EID_ARGS(vtp_key->dst_eid), vtp_key->jetty_id);

    return 0;
}

static int rc_loopback_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx)
{
    int32_t vtpn = 0;
    uint32_t eid_idx;

    vport_key_t vport_key = {0};
    if (vport_table_lookup_by_ueid_return_key(&table_ctx->vport_table, vtp_idx->upi, &vtp_idx->peer_eid,
        &vport_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("upi %u, eid_idx is %u, eid:" EID_FMT "\n", vtp_idx->upi, eid_idx, EID_ARGS(vtp_idx->peer_eid));
        return -1;
    }

    (void)pthread_rwlock_wrlock(&table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&table_ctx->fe_table, &vport_key);
    if (fe_entry == NULL) {
        TPSA_LOG_INFO("key dev:%s fe_idx %hu not exist in fe_table", vport_key.tpf_name, vport_key.fe_idx);
        (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
        return TPSA_LOOKUP_NULL;
    }
    (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);

    /* for loopback but seid != deid, delete the server vtp node */
    rc_vtp_table_key_t vtp_key = {
        .dst_eid = vtp_idx->local_eid,
        .jetty_id = vtp_idx->local_jetty,
    };
    rc_vtp_table_entry_t *vtp_entry = rc_vtp_table_lookup(&fe_entry->rc_vtp_table, &vtp_key);
    if (vtp_entry == NULL) {
        TPSA_LOG_WARN("Can't remove null entry from rc_vtp table, in rc_loopback_vtp_table_remove");
        return TPSA_LOOKUP_NULL;
    }

    deid_vtp_table_key_t deid_key = {
        .dst_eid = vtp_key.dst_eid,
        .upi = vtp_entry->upi,
        .trans_mode = TPSA_TP_RC,
    };

    if (vtp_idx->sig_loop == true) {
        /* Before deleting vtp entry, need to delete the corresponding node in the linked list. */
        deid_rc_vtp_list_remove(&table_ctx->deid_vtp_table, &deid_key, &vtp_key);
        vtpn = (int32_t)vtp_entry->vtpn;
        TPSA_LOG_INFO("when is sigle loop, destroy dumplex vtp node, vtpn %u", vtpn);
        ub_hmap_remove(&fe_entry->rc_vtp_table.hmap, &vtp_entry->node);
        free(vtp_entry);
        return vtpn;
    }

    /* If location is duplex, only need to modify the location, but cannot delete the vtp node */
    if (vtp_entry->location == TPSA_DUPLEX) {
        vtp_entry->location = TPSA_INITIATOR;
        TPSA_LOG_INFO("when location is duplex, remove target %d from rc_vtp table", vtp_idx->location);
        return TPSA_REMOVE_SERVER;
    }

    /* Before deleting vtp entry, need to delete the corresponding node in the linked list. */
    deid_rc_vtp_list_remove(&table_ctx->deid_vtp_table, &deid_key, &vtp_key);

    ub_hmap_remove(&fe_entry->rc_vtp_table.hmap, &vtp_entry->node);
    free(vtp_entry);
    return TPSA_REMOVE_SERVER;
}

int rc_noloopback_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx)
{
    int32_t vtpn = 0;
    rc_vtp_table_key_t vtp_key = {
        .dst_eid = vtp_idx->peer_eid,
        .jetty_id = vtp_idx->peer_jetty,
    };

    (void)pthread_rwlock_wrlock(&table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&table_ctx->fe_table, &vtp_idx->fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_WARN("key dev:%s fe_idx %hu not exist in fe table",
            vtp_idx->fe_key.tpf_name, vtp_idx->fe_key.fe_idx);
        (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
        return TPSA_LOOKUP_NULL;
    }
    (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);

    rc_vtp_table_entry_t *vtp_entry = rc_vtp_table_lookup(&fe_entry->rc_vtp_table, &vtp_key);
    if (vtp_entry == NULL) {
        TPSA_LOG_WARN("Can't remove null entry from rc_vtp table, eid:" EID_FMT ", id:%u",
            EID_ARGS(vtp_key.dst_eid), vtp_key.jetty_id);
        return TPSA_LOOKUP_NULL;
    }

    /* for server, not alloc vtpn, so return TPSA_REMOVE_SERVER to avoid destroying vtp */
    vtpn = (vtp_idx->location == TPSA_TARGET) ? TPSA_REMOVE_SERVER : (int32_t)vtp_entry->vtpn;

    /* If location is duplex, only need to modify the location, but cannot delete the vtp node */
    if (vtp_entry->location == TPSA_DUPLEX) {
        TPSA_LOG_INFO("when location is duplex, remove location %d from rc_vtp table", vtp_idx->location);
        vtp_entry->location = (vtp_idx->location == TPSA_TARGET) ? TPSA_INITIATOR : TPSA_TARGET;
        if (vtp_entry->location == TPSA_TARGET) {
            vtp_entry->vtpn = UINT32_MAX;
        }
        return vtpn;
    }

    /* Before deleting vtp entry, need to delete the corresponding node in the linked list. */
    deid_vtp_table_key_t deid_key = {
        .dst_eid = vtp_key.dst_eid,
        .upi = vtp_entry->upi,
        .trans_mode = TPSA_TP_RC,
    };
    deid_rc_vtp_list_remove(&table_ctx->deid_vtp_table, &deid_key, &vtp_key);

    ub_hmap_remove(&fe_entry->rc_vtp_table.hmap, &vtp_entry->node);
    free(vtp_entry);

    return vtpn;
}

int rc_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx)
{
    int32_t vtpn = 0;

    if (vtp_idx->isLoopback == true) {
        /* fisrt, if seid ==deid, return valid vtpn value; if seid != deis,delete the target vtp node,but not return */
        vtp_idx->location = TPSA_TARGET;
        vtpn = rc_loopback_vtp_table_remove(table_ctx, vtp_idx);
        if ((vtpn != TPSA_REMOVE_SERVER && vtpn != TPSA_LOOKUP_NULL) || (vtpn == TPSA_LOOKUP_NULL)) {
            /* when is loopback and seid == deid, return vtpn */
            return vtpn;
        }
        /* senond, delete the client vtp node */
        vtp_idx->location = TPSA_INITIATOR;
        vtpn = rc_noloopback_vtp_table_remove(table_ctx, vtp_idx);
        TPSA_LOG_ERR("when is loopback and seid!=deid, destroy client and server vtp node");
    } else {
        TPSA_LOG_INFO("remove rc vtp src eid " EID_FMT " sjetty: %u, dst eid " EID_FMT " djetty: %u\n",
                      EID_ARGS(vtp_idx->local_eid), vtp_idx->local_jetty,
                      EID_ARGS(vtp_idx->peer_eid), vtp_idx->peer_jetty);
        vtpn = rc_noloopback_vtp_table_remove(table_ctx, vtp_idx);
    }

    return vtpn;
}

/* rm_fe_vtp lookup/add opts */
rm_vtp_table_entry_t *rm_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key, rm_vtp_table_key_t *vtp_key)
{
    /* first, look up fe_table to get the second table of rm_vtp_table */
    (void)pthread_rwlock_wrlock(&fe_table->rwlock);
    fe_table_entry_t *entry = fe_table_lookup(fe_table, fe_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("Can't find fe entry in fe table, dev: %s, fe_idx: %hu", fe_key->tpf_name, fe_key->fe_idx);
        (void)pthread_rwlock_unlock(&fe_table->rwlock);
        return NULL;
    }
    (void)pthread_rwlock_unlock(&fe_table->rwlock);

    /* second, according to the vtp_table of specific fe, to look up the node */
    rm_vtp_table_entry_t *vtp_entry = NULL;
    (void)pthread_rwlock_wrlock(&entry->rm_vtp_table.vtp_table_lock);
    vtp_entry = rm_vtp_table_lookup(&entry->rm_vtp_table, vtp_key);
    (void)pthread_rwlock_unlock(&entry->rm_vtp_table.vtp_table_lock);
    return vtp_entry;
}

int rm_fe_vtp_table_add(tpsa_table_t *table_ctx, vport_key_t *fe_key, rm_vtp_table_key_t *vtp_key,
                        tpsa_vtp_table_param_t *vtp_table_data)
{
    if (table_ctx == NULL || fe_key == NULL || vtp_key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* If the primary table does not exist, need to create the primary table and initialize the secondary table */
    fe_table_entry_t *entry = fe_table_lookup(&table_ctx->fe_table, fe_key);
    if (entry == NULL) {
        entry = fe_table_add(&table_ctx->fe_table, fe_key);
        if (entry == NULL) {
            TPSA_LOG_ERR("fe table add failed");
            return TPSA_ADD_NOMEM;
        }
    }

    if (rm_vtp_table_add(&table_ctx->deid_vtp_table, entry, vtp_key, vtp_table_data) != 0) {
        return TPSA_ADD_NOMEM;
    }

    return 0;
}

static int rm_loopback_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx)
{
    int32_t vtpn = 0;
    uint32_t eid_idx;

    vport_key_t fe_key = {0};
    if (vport_table_lookup_by_ueid_return_key(&table_ctx->vport_table, vtp_idx->upi, &vtp_idx->peer_eid,
        &fe_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("upi %u,eid_idx is %u,eid:" EID_FMT "\n", vtp_idx->upi, eid_idx, EID_ARGS(vtp_idx->peer_eid));
        return TPSA_LOOKUP_NULL;
    }

    (void)pthread_rwlock_wrlock(&table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&table_ctx->fe_table, &fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_INFO("key dev:%s fe_idx %hu not exist in fe_table", fe_key.tpf_name, fe_key.fe_idx);
        (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
        return TPSA_LOOKUP_NULL;
    }
    (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);

    rm_vtp_table_key_t vtp_key = {
        .src_eid = vtp_idx->peer_eid,
        .dst_eid = vtp_idx->local_eid,
    };

    rm_vtp_table_entry_t *vtp_entry = rm_vtp_table_lookup(&fe_entry->rm_vtp_table, &vtp_key);
    if (vtp_entry == NULL) {
        TPSA_LOG_WARN("Can't remove null entry from rm_vtp table, int rm_loopback_vtp_table_remove");
        return TPSA_LOOKUP_NULL;
    }

    vtp_idx->share_mode = vtp_entry->share_mode;
    if (!vtp_entry->share_mode) {
        if (vtp_entry->tpg_param != NULL) {
            (void)memcpy(&vtp_idx->tpg_param,
                vtp_entry->tpg_param, sizeof(tpsa_tpg_info_t));
            if (vtp_entry->use_cnt > 0) {
                vtp_entry->use_cnt--;
                TPSA_LOG_INFO("use cnt decrease by 1 is %u\n", vtp_entry->use_cnt);
            } else {
                TPSA_LOG_ERR("failed to maintain rm vtp cnt, now is %u\n", vtp_entry->use_cnt);
            }

            vtp_idx->use_cnt = vtp_entry->use_cnt;
            TPSA_LOG_INFO("remove vtp in non_share_mode, tpgn = %u, use_cnt decrease by 1 is %u\n",
                vtp_idx->tpg_param.tpgn, vtp_idx->use_cnt);
        } else {
            TPSA_LOG_WARN("unexpected situation");
        }
    }

    deid_vtp_table_key_t deid_key = {
        .dst_eid = vtp_key.dst_eid,
        .upi = vtp_entry->upi,
        .trans_mode = TPSA_TP_RM,
    };

    /* for loopback but seid == deid, delete the deplex vtp node */
    if (vtp_idx->sig_loop == true) {
        /* Before deleting vtp entry, need to delete the corresponding node in the linked list. */
        deid_rm_vtp_list_remove(&table_ctx->deid_vtp_table, &deid_key, &vtp_key);
        TPSA_LOG_INFO("when is loopback and seid==deid, destroy dumplex vtp node");
        vtpn = (int32_t)vtp_entry->vtpn;
        ub_hmap_remove(&fe_entry->rm_vtp_table.hmap, &vtp_entry->node);
        free(vtp_entry);
        return vtpn;
    }

    /* If location is duplex, only need to modify the location, but cannot delete the vtp node */
    if (vtp_entry->location == TPSA_DUPLEX) {
        vtp_entry->location = TPSA_INITIATOR;
        TPSA_LOG_INFO("when location is duplex, remove target %d from rc_vtp table", vtp_idx->location);
        return TPSA_REMOVE_SERVER;
    }

    /* Before deleting vtp entry, need to delete the corresponding node in the linked list. */
    deid_rm_vtp_list_remove(&table_ctx->deid_vtp_table, &deid_key, &vtp_key);
    ub_hmap_remove(&fe_entry->rm_vtp_table.hmap, &vtp_entry->node);

    if (vtp_entry->tpg_param != NULL) {
        free(vtp_entry->tpg_param);
        vtp_entry->tpg_param = NULL;
    }

    free(vtp_entry);
    return TPSA_REMOVE_SERVER;
}

int rm_noloopback_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx)
{
    int32_t vtpn = 0;
    rm_vtp_table_key_t vtp_key = {
        .src_eid = vtp_idx->local_eid,
        .dst_eid = vtp_idx->peer_eid,
    };

    (void)pthread_rwlock_wrlock(&table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&table_ctx->fe_table, &vtp_idx->fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_WARN("dev:%s fe_idx%hu not exist in fe table", vtp_idx->fe_key.tpf_name, vtp_idx->fe_key.fe_idx);
        (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
        return TPSA_LOOKUP_NULL;
    }
    (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);

    rm_vtp_table_entry_t *vtp_entry = rm_vtp_table_lookup(&fe_entry->rm_vtp_table, &vtp_key);
    if (vtp_entry == NULL) {
        TPSA_LOG_WARN("Can't remove null entry from rm_vtp table");
        return TPSA_LOOKUP_NULL;
    }

    vtp_idx->share_mode = vtp_entry->share_mode;
    if (!vtp_entry->share_mode) {
        if (vtp_entry->tpg_param != NULL) {
            (void)memcpy(&vtp_idx->tpg_param,
                vtp_entry->tpg_param, sizeof(tpsa_tpg_info_t));
            if (vtp_entry->use_cnt > 0) {
                vtp_entry->use_cnt--;
                TPSA_LOG_INFO("use cnt decrease by 1 is %u\n", vtp_entry->use_cnt);
            } else {
                TPSA_LOG_ERR("failed to maintain rm vtp cnt, now is %u\n", vtp_entry->use_cnt);
            }
            vtp_idx->use_cnt = vtp_entry->use_cnt;
            TPSA_LOG_INFO("remove vtp in non share mode, tpgn = %u, use_cnt decrease by 1 is %u\n",
                vtp_idx->tpg_param.tpgn, vtp_idx->use_cnt);
        } else {
            TPSA_LOG_WARN("unexpected situation");
        }
    }

    /* for server, not alloc vtpn, so return TPSA_REMOVE_SERVER to avoid destroying vtp */
    vtpn = (vtp_idx->location == TPSA_TARGET) ? TPSA_REMOVE_SERVER : (int32_t)vtp_entry->vtpn;

    /* If location is duplex, only need to modify the location, but cannot delete the vtp node */
    if (vtp_entry->location == TPSA_DUPLEX) {
        TPSA_LOG_INFO("when location is duplex, remove location %d from rm_vtp table", vtp_idx->location);
        vtp_entry->location = (vtp_idx->location == TPSA_TARGET) ? TPSA_INITIATOR : TPSA_TARGET;
        return vtpn;
    }

    /* Before deleting vtp entry, need to delete the corresponding node in the linked list. */
    deid_vtp_table_key_t deid_key = {
        .dst_eid = vtp_key.dst_eid,
        .upi = vtp_entry->upi,
        .trans_mode = TPSA_TP_RM,
    };
    deid_rm_vtp_list_remove(&table_ctx->deid_vtp_table, &deid_key, &vtp_key);

    ub_hmap_remove(&fe_entry->rm_vtp_table.hmap, &vtp_entry->node);
    if (vtp_entry->tpg_param != NULL) {
        free(vtp_entry->tpg_param);
        vtp_entry->tpg_param = NULL;
    }
    free(vtp_entry);

    return vtpn;
}

int rm_vtp_table_remove(tpsa_table_t *table_ctx, tpsa_vtp_table_index_t *vtp_idx)
{
    int32_t vtpn = 0;

    if (vtp_idx->isLoopback == true) {
        /* fisrt, if seid ==deid, return valid vtpn value; if seid != deid,delete the target vtp node,but not return */
        vtp_idx->location = TPSA_TARGET;
        vtpn = rm_loopback_vtp_table_remove(table_ctx, vtp_idx);
        if ((vtpn != TPSA_REMOVE_SERVER && vtpn != TPSA_LOOKUP_NULL) || (vtpn == TPSA_LOOKUP_NULL)) {
            /* when is loopback and seid == deid, return vtpn */
            return vtpn;
        }
        /* for scene seid != deid , also need to delete the client vtp node */
        vtp_idx->location = TPSA_INITIATOR;
        vtpn = rm_noloopback_vtp_table_remove(table_ctx, vtp_idx);
        TPSA_LOG_ERR("when is loopback and seid!=deid, destroy client and server vtp node");
    } else {
        TPSA_LOG_INFO("remove rm vtp src eid " EID_FMT " dst eid " EID_FMT "\n",
                      EID_ARGS(vtp_idx->local_eid), EID_ARGS(vtp_idx->peer_eid));
        vtpn = rm_noloopback_vtp_table_remove(table_ctx, vtp_idx);
    }

    return vtpn;
}

/* um_fe_vtp lookup/add opts */
um_vtp_table_entry_t *um_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key, um_vtp_table_key_t *vtp_key)
{
    /* first, look up fe_table to get the second table of rm_vtp_table */
    (void)pthread_rwlock_wrlock(&fe_table->rwlock);
    fe_table_entry_t *entry = fe_table_lookup(fe_table, fe_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("Can't find fe entry in fe table in um_fe_vtp_table_lookup, fe_idx: %d, tpf_name: %s",
            fe_key->fe_idx, fe_key->tpf_name);
        (void)pthread_rwlock_unlock(&fe_table->rwlock);
        return NULL;
    }
    (void)pthread_rwlock_unlock(&fe_table->rwlock);

    /* second, according to the vtp_table of specific fe, to look up the node */
    um_vtp_table_entry_t *vtp_entry = NULL;
    vtp_entry = um_vtp_table_lookup(&entry->um_vtp_table, vtp_key);
    return vtp_entry;
}

int um_fe_vtp_table_add(tpsa_table_t *table_ctx, vport_key_t *fe_key, um_vtp_table_key_t *vtp_key,
                        tpsa_um_vtp_table_param_t *uparam)
{
    if (table_ctx == NULL || fe_key == NULL || vtp_key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* If the primary table does not exist, need to create the primary table and initialize the secondary table */
    fe_table_entry_t *entry = fe_table_lookup(&table_ctx->fe_table, fe_key);
    if (entry == NULL) {
        entry = fe_table_add(&table_ctx->fe_table, fe_key);
        if (entry == NULL) {
            TPSA_LOG_ERR("fe table add failed");
            return TPSA_ADD_NOMEM;
        }
    }

    if (um_vtp_table_add(&table_ctx->deid_vtp_table, entry, vtp_key, uparam) != 0) {
        return TPSA_ADD_NOMEM;
    }

    return 0;
}

/* fe_vtp_table remove */

void fe_vtp_table_destroy(fe_table_t *fe_table)
{
    fe_table_entry_t *fe_cur, *fe_next;

    (void)pthread_rwlock_wrlock(&fe_table->rwlock);
    HMAP_FOR_EACH_SAFE(fe_cur, fe_next, node, &fe_table->hmap) {
        rm_vtp_table_destroy(&fe_cur->rm_vtp_table);
        rc_vtp_table_destroy(&fe_cur->rc_vtp_table);
        um_vtp_table_destroy(&fe_cur->um_vtp_table);
        clan_vtp_table_destroy(&fe_cur->clan_vtp_table);

        ub_hmap_remove(&fe_table->hmap, &fe_cur->node);
        free(fe_cur);
    }

    ub_hmap_destroy(&fe_table->hmap);
    (void)pthread_rwlock_unlock(&fe_table->rwlock);
    (void)pthread_rwlock_destroy(&fe_table->rwlock);

    return;
}

clan_vtp_table_entry_t *clan_fe_vtp_table_lookup(fe_table_t *fe_table, vport_key_t *fe_key,
                                                 clan_vtp_table_key_t *vtp_key)
{
    /* first, look up fe_table to get the second table of clan_vtp_table */
    (void)pthread_rwlock_wrlock(&fe_table->rwlock);
    fe_table_entry_t *entry = fe_table_lookup(fe_table, fe_key);

    if (entry == NULL) {
        TPSA_LOG_WARN("Can't find fe entry in fe table in clan fe vtp table lookup");
        (void)pthread_rwlock_unlock(&fe_table->rwlock);
        return NULL;
    }
    (void)pthread_rwlock_unlock(&fe_table->rwlock);

    /* second, according to the clan_vtp_table of specific fe, to look up the node */
    clan_vtp_table_entry_t *vtp_entry = NULL;
    vtp_entry = clan_vtp_table_lookup(&entry->clan_vtp_table, vtp_key);
    return vtp_entry;
}

/* clan fe vtp_table ops */
int clan_fe_vtp_table_add(fe_table_t *fe_table, vport_key_t *fe_key, clan_vtp_table_key_t *vtp_key,
                          tpsa_clan_vtp_table_param_t *uparam)
{
    if (fe_table == NULL || fe_key == NULL || vtp_key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* If the primary table does not exist, need to create the primary table and initialize the secondary table */
    fe_table_entry_t *entry = fe_table_lookup(fe_table, fe_key);
    if (entry == NULL) {
        entry = fe_table_add(fe_table, fe_key);
        if (entry == NULL) {
            TPSA_LOG_ERR("clan vtp table add failed");
            return TPSA_ADD_NOMEM;
        }
    }

    if (clan_vtp_table_add(&entry->clan_vtp_table, vtp_key, uparam->vtpn, uparam->ctp_idx) != 0) {
        return TPSA_ADD_NOMEM;
    }

    return 0;
}

int tpsa_lookup_rm_vtp_table(tpsa_table_t *table_ctx, vport_key_t *fe_key,
                             uvs_end_point_t *src, uvs_end_point_t *dst, uint32_t *vtpn)
{
    rm_vtp_table_key_t vtp_key = {
        .src_eid = src->eid,
        .dst_eid = dst->eid,
    };

    rm_vtp_table_entry_t *entry = rm_fe_vtp_table_lookup(&table_ctx->fe_table, fe_key, &vtp_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("Can't find vtp entry in vtp table");
        return TPSA_LOOKUP_NULL;
    }
    if (!entry->valid) {
        TPSA_LOG_DEBUG("entry is not valid");
        return TPSA_LOOKUP_IN_PROGRESS;
    }

    /* if the vtpn is UINT32_MAX, meas that this FE as a server has established a link with the dest FE */
    if (entry->vtpn == UINT32_MAX) {
        TPSA_LOG_DEBUG("found entry's vtpn equals UINT32_MAX");
        return TPSA_LOOKUP_NULL;
    }

    *vtpn = entry->vtpn;
    return 0;
}

int tpsa_lookup_rc_vtp_table(tpsa_table_t *table_ctx, vport_key_t *fe_key,
                             uvs_end_point_t *src, uvs_end_point_t *dst, uint32_t *vtpn)
{
    rc_vtp_table_key_t vtp_key = {
        .dst_eid = dst->eid,
        .jetty_id = dst->jetty_id,
    };

    rc_vtp_table_entry_t *entry = rc_fe_vtp_table_lookup(&table_ctx->fe_table, fe_key, &vtp_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("Can't find vtp entry in vtp table");
        return TPSA_LOOKUP_NULL;
    }
    if (!entry->valid) {
        return TPSA_LOOKUP_IN_PROGRESS;
    }

    if (memcmp(&entry->src_eid, &src->eid, sizeof(urma_eid_t)) != 0 || entry->src_jetty_id != src->jetty_id) {
        TPSA_LOG_WARN("peer jetty %u, eid: " EID_FMT " already bind by src jetty %u, eid:" EID_FMT "\n",
            dst->jetty_id, EID_ARGS(dst->eid),
            entry->src_jetty_id, EID_ARGS(src->eid));
        return TPSA_RC_JETTY_ALREADY_BIND;
    }

    /* if the vtpn is UINT32_MAX, meas that this FE as a server has established a link with the dest FE */
    if (entry->vtpn == UINT32_MAX) {
        return TPSA_LOOKUP_NULL;
    }

    *vtpn = entry->vtpn;
    return 0;
}

int tpsa_remove_vtp_table(tpsa_transport_mode_t trans_mode, tpsa_vtp_table_index_t *vtp_idx, tpsa_table_t *table_ctx)
{
    int32_t vtpn = 0;

    TPSA_LOG_INFO("remove dev:%s fe_idx %hu\n", vtp_idx->fe_key.tpf_name, vtp_idx->fe_key.fe_idx);

    (void)pthread_rwlock_wrlock(&table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&table_ctx->fe_table, &vtp_idx->fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_WARN("dev:%s fe_idx %hu not exist in fe_table", vtp_idx->fe_key.tpf_name, vtp_idx->fe_key.fe_idx);
        (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
        return TPSA_LOOKUP_NULL;
    }
    (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);

    if (trans_mode == TPSA_TP_RM) {
        vtpn = rm_vtp_table_remove(table_ctx, vtp_idx);
    } else if (trans_mode == TPSA_TP_RC) {
        vtpn = rc_vtp_table_remove(table_ctx, vtp_idx);
    }

    /* If all secondary tables are empty, remove the corresponding node of the first-level table */
    fe_table_remove(&table_ctx->fe_table, fe_entry);

    return vtpn;
}

static void tpsa_increase_use_cnt_in_non_share_mode(rm_vtp_table_entry_t *entry)
{
    if (entry->tpg_param != NULL && !entry->share_mode) {
        entry->use_cnt++;
        TPSA_LOG_INFO("entry use_cnt increase by 1 is %u and tpgn %u",
            entry->use_cnt, entry->tpg_param->tpgn);
    }
}

/*  when add client vtp node, there are only three scenarios:
*   1. the client vtp node is being added by others, corresponding the entry->value is false
*   2. the client node has been added
*   3. when add the clent node ,the server node already exists
*/
int tpsa_noloopback_add_rm_vtp_table(tpsa_vtp_table_param_t *vtp_table_data, tpsa_table_t *table_ctx,
                                     vport_key_t *fe_key, rm_vtp_table_key_t *vtp_key, tpsa_create_param_t *cparam)
{
    rm_vtp_table_entry_t *entry = rm_fe_vtp_table_lookup(&table_ctx->fe_table, fe_key, vtp_key);

    if (entry == NULL) {
        TPSA_LOG_INFO("when vtp node not exist, add vtp node, location is: %u", vtp_table_data->location);
        TPSA_LOG_DEBUG("adding rm entry with tpgn: %u", vtp_table_data->tpg_param.tpgn);
        if (rm_fe_vtp_table_add(table_ctx, fe_key, vtp_key, vtp_table_data) != 0) {
            return TPSA_ADD_NOMEM;
        }
        return 0;
    } else if (!entry->valid) {
        TPSA_LOG_WARN("Error: Add duplicate invalid entry to rm vtp table. Maybe duplicate create vtp");
        return TPSA_ADD_INVALID;
    }

    if (entry->location == TPSA_DUPLEX) {
        TPSA_LOG_INFO("duplex vtp node already exists, no need to add it repeatedly");
    } else if (entry->vtpn == UINT32_MAX && entry->location == TPSA_TARGET) {
        entry->vtpn = vtp_table_data->vtpn;
        entry->location = TPSA_DUPLEX;
        TPSA_LOG_INFO("Add vtp client node when server node exist, only change the value of vtpn and location");
        tpsa_increase_use_cnt_in_non_share_mode(entry);
    } else {
        TPSA_LOG_INFO("Add vtp server node when client node exist, only change the location to duplex");
        entry->location = TPSA_DUPLEX;
        tpsa_increase_use_cnt_in_non_share_mode(entry);
    }

    if (cparam->live_migrate && entry->tpgn != UINT32_MAX) {
        if (entry->node_status != STATE_NORMAL) {
            TPSA_LOG_ERR("Wrong status when add vice tpgn");
            return TPSA_ADD_INVALID;
        } else {
            entry->vice_tpgn = vtp_table_data->tpg_param.tpgn;
            entry->node_status = STATE_READY;
            TPSA_LOG_INFO("Live migration rm add vice tpgn:%u", entry->vice_tpgn);
        }
    }

    return 0;
}

int tpsa_loopback_add_rm_vtp_table(tpsa_vtp_table_param_t *vtp_table_data, tpsa_table_t *table_ctx,
                                   tpsa_create_param_t *cparam)
{
    int ret = -1;
    rm_vtp_table_key_t vtp_key = {
        .src_eid = cparam->local_eid,
        .dst_eid = cparam->peer_eid,
    };
    vport_key_t fe_key = {0};
    uint32_t eid_idx;

    fe_key.fe_idx = cparam->fe_idx;
    (void)memcpy(fe_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);

    /* if is isLoopback and seid == deid, modify the location to TPSA_DUPLEX and add a vtp node */
    if (cparam->sig_loop == true) {
        TPSA_LOG_INFO("when is sigle loop, create dumplex vtp node, fe_idx is %hu\n", cparam->fe_idx);
        vtp_table_data->location = TPSA_DUPLEX;
        TPSA_LOG_DEBUG("adding rm entry with tpgn: %u", vtp_table_data->tpg_param.tpgn);
        return tpsa_noloopback_add_rm_vtp_table(vtp_table_data, table_ctx, &fe_key, &vtp_key, cparam);
    }

    /* if is isLoopback and seid != deid, first add a vtp node for client */
    TPSA_LOG_INFO("when is not sigle loop, create client vtp node, fe_idx is %hu\n", fe_key.fe_idx);
    TPSA_LOG_DEBUG("adding rm entry with tpgn: %u", vtp_table_data->tpg_param.tpgn);
    ret = tpsa_noloopback_add_rm_vtp_table(vtp_table_data, table_ctx, &fe_key, &vtp_key, cparam);
    if (ret != 0) {
        TPSA_LOG_ERR("tpsa add client vtp node failed, ret %d", ret);
        return ret;
    }

    if (vport_table_lookup_by_ueid_return_key(&table_ctx->vport_table, cparam->upi, &cparam->peer_eid,
        &fe_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport_table_lookup_by_ueid,  upi %u eid:" EID_FMT "\n",
            cparam->upi, EID_ARGS(cparam->peer_eid));
        return -1;
    }

    /*
        if is isLoopback and seid != deid, server also need to add vtp node
        In this case, the vtpn value in the vtp node to be added on the server is invalid.
    */
    vtp_key.src_eid = cparam->peer_eid;
    vtp_key.dst_eid = cparam->local_eid;
    vtp_table_data->location = TPSA_TARGET;
    vtp_table_data->vtpn = UINT32_MAX;
    vtp_table_data->valid = true;
    vtp_table_data->local_jetty = cparam->peer_jetty;
    vtp_table_data->eid_index = eid_idx;
    TPSA_LOG_INFO("when is not sigle loop, create server vtp node, fe_idx is %hu\n", fe_key.fe_idx);
    ret = tpsa_noloopback_add_rm_vtp_table(vtp_table_data, table_ctx, &fe_key, &vtp_key, cparam);
    if (ret != 0) {
        TPSA_LOG_ERR("tpsa add server vtp node failed when isloopback, ret %d", ret);
        return ret;
    }

    return 0;
}

int tpsa_add_rm_vtp_table(tpsa_create_param_t *cparam, tpsa_vtp_table_param_t *vtp_table_data,
                          tpsa_table_t *table_ctx, bool isLoopback)
{
    vtp_table_data->local_jetty = cparam->local_jetty;
    vtp_table_data->eid_index = cparam->eid_index;

    if (isLoopback == false) {
        rm_vtp_table_key_t vtp_key = {
            .src_eid = cparam->local_eid,
            .dst_eid = cparam->peer_eid,
        };

        vport_key_t fe_key = {0};
        fe_key.fe_idx = cparam->fe_idx;
        (void)memcpy(fe_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);
        TPSA_LOG_DEBUG("adding rm entry with tpgn: %u", vtp_table_data->tpg_param.tpgn);
        return tpsa_noloopback_add_rm_vtp_table(vtp_table_data, table_ctx, &fe_key, &vtp_key, cparam);
    }

    return tpsa_loopback_add_rm_vtp_table(vtp_table_data, table_ctx, cparam);
}

int tpsa_noloopback_add_rc_vtp_table(tpsa_vtp_table_param_t *vtp_table_data, tpsa_table_t *table_ctx,
                                     vport_key_t *fe_key, rc_vtp_table_key_t *vtp_key, tpsa_create_param_t *cparam)
{
    rc_vtp_table_entry_t *entry = rc_fe_vtp_table_lookup(&table_ctx->fe_table, fe_key, vtp_key);

    if (entry == NULL) {
        TPSA_LOG_INFO("when vtp node not exist, add vtp node, location is: %u", vtp_table_data->location);
        if (rc_fe_vtp_table_add(table_ctx, fe_key, vtp_key, vtp_table_data) != 0) {
            return TPSA_ADD_NOMEM;
        }
        return 0;
    } else if (!entry->valid) {
        TPSA_LOG_WARN("Error: Add duplicate invalid entry to rc tpg table. Maybe duplicate create vtp");
        return TPSA_ADD_INVALID;
    }

    if (entry->location == TPSA_DUPLEX) {
        TPSA_LOG_INFO("duplex vtp node already exists, no need to add it repeatedly");
    } else if (entry->vtpn == UINT32_MAX && entry->location == TPSA_TARGET) {
        entry->vtpn = vtp_table_data->vtpn;
        entry->location = TPSA_DUPLEX;
        TPSA_LOG_INFO("Add vtp client node when server node exist, only change the value of vtpn and location");
    } else {
        TPSA_LOG_INFO("Add vtp server node when client node exist, only change the location to duplex");
        entry->location = TPSA_DUPLEX;
    }

    if (cparam->live_migrate && entry->tpgn != UINT32_MAX) {
        if (entry->node_status != STATE_NORMAL) {
            TPSA_LOG_ERR("Wrong status when add vice tpgn");
            return TPSA_ADD_INVALID;
        } else {
            entry->vice_tpgn = vtp_table_data->tpg_param.tpgn;
            entry->node_status = STATE_READY;
            TPSA_LOG_INFO("Live migration rc add vice tpgn:%u", entry->vice_tpgn);
        }
    }

    return 0;
}

int tpsa_loopback_add_rc_vtp_table(tpsa_vtp_table_param_t *vtp_table_data, tpsa_table_t *table_ctx,
                                   tpsa_create_param_t *cparam)
{
    int ret = -1;
    rc_vtp_table_key_t vtp_key = {
        .dst_eid = cparam->peer_eid,
        .jetty_id = cparam->peer_jetty,
    };
    vport_key_t fe_key = {0};
    uint32_t eid_idx;

    fe_key.fe_idx = cparam->fe_idx;
    (void)memcpy(fe_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);

    /* if is isLoopback and seid == deid, modify the location to TPSA_DUPLEX */
    if (cparam->sig_loop == true) {
        TPSA_LOG_INFO("when is loopback and seid==deid, local_jetty= peer_jetty, create dumplex vtp node," \
            "fe_idx is %hu\n", cparam->fe_idx);
        vtp_table_data->location = TPSA_DUPLEX;
        return tpsa_noloopback_add_rc_vtp_table(vtp_table_data, table_ctx, &fe_key, &vtp_key, cparam);
    }

    /* if is isLoopback and seid != deid, first add a vtp node for client */
    TPSA_LOG_INFO("when is not sigle loopback, first create client vtp node, fe_idx is %hu\n", fe_key.fe_idx);
    ret = tpsa_noloopback_add_rc_vtp_table(vtp_table_data, table_ctx, &fe_key, &vtp_key, cparam);
    if (ret != 0) {
        TPSA_LOG_ERR("tpsa add client vtp node failed, ret %d", ret);
        return ret;
    }

    if (vport_table_lookup_by_ueid_return_key(&table_ctx->vport_table, cparam->upi, &cparam->peer_eid,
        &fe_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport_table_lookup_by_ueid,  upi %u eid:" EID_FMT "\n",
            cparam->upi, EID_ARGS(cparam->peer_eid));
        return -1;
    }

    /* if is isLoopback and seid != deid, server also need to add vtp node */
    vtp_key.dst_eid = cparam->local_eid;
    vtp_key.jetty_id = cparam->local_jetty;
    vtp_table_data->location = TPSA_TARGET;
    vtp_table_data->vtpn = UINT32_MAX;
    vtp_table_data->valid = true;
    vtp_table_data->local_eid = cparam->peer_eid;
    vtp_table_data->local_jetty = cparam->peer_jetty;
    vtp_table_data->eid_index = eid_idx;
    TPSA_LOG_INFO("when is not sigle loopback, second create server vtp node, fe_idx is %hu\n", fe_key.fe_idx);
    ret = tpsa_noloopback_add_rc_vtp_table(vtp_table_data, table_ctx, &fe_key, &vtp_key, cparam);
    if (ret != 0) {
        TPSA_LOG_ERR("tpsa add server vtp node failed when isloopback, ret %d", ret);
        return ret;
    }

    return 0;
}

int tpsa_add_rc_vtp_table(tpsa_create_param_t *cparam, tpsa_vtp_table_param_t *vtp_table_data,
                          tpsa_table_t *table_ctx, bool isLoopback)
{
    vtp_table_data->local_jetty = cparam->local_jetty;
    vtp_table_data->eid_index = cparam->eid_index;
    vtp_table_data->local_eid = cparam->local_eid;

    if (isLoopback == false) {
        rc_vtp_table_key_t vtp_key = {
            .dst_eid = cparam->peer_eid,
            .jetty_id = cparam->peer_jetty,
        };
        vport_key_t fe_key = {0};
        fe_key.fe_idx = cparam->fe_idx;
        (void)memcpy(fe_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);
        return tpsa_noloopback_add_rc_vtp_table(vtp_table_data, table_ctx, &fe_key, &vtp_key, cparam);
    }

    return tpsa_loopback_add_rc_vtp_table(vtp_table_data, table_ctx, cparam);
}

static int tpsa_update_rm_vtp_table_exist(rm_vtp_table_entry_t *entry, uint32_t location, uint32_t vtpn,
                                          uint32_t tpgn, bool live_migrate)
{
    TPSA_LOG_DEBUG("found rm vtp table already existed");
    if (entry->vtpn == UINT32_MAX) {
        entry->vtpn = vtpn;
    }

    if (live_migrate && entry->tpgn != UINT32_MAX) {
        if (entry->node_status != STATE_NORMAL) {
            TPSA_LOG_ERR("Wrong status when update vice tpgn");
            return TPSA_ADD_INVALID;
        } else {
            entry->vice_tpgn = tpgn;
            entry->node_status = STATE_READY;
            TPSA_LOG_INFO("Live migration rm add vice tpgn process");
        }
    } else {
        entry->tpgn = tpgn;
    }

    entry->valid = true;
    if (entry->location != location) {
        entry->location = TPSA_DUPLEX;

        tpsa_increase_use_cnt_in_non_share_mode(entry);
    }

    return 0;
}

int tpsa_update_rm_vtp_table(tpsa_sock_msg_t *msg, uint32_t location, uint32_t vtpn,
    uint32_t tpgn, tpsa_table_t *table_ctx, tpsa_tpg_info_t *tpg_param)
{
    tpsa_vtp_table_param_t vtp_table_data = {0};
    vtp_table_data.vtpn = vtpn;
    vtp_table_data.tpgn = tpgn;
    vtp_table_data.valid = true;
    vtp_table_data.location = location;
    vtp_table_data.local_jetty = msg->local_jetty;
    vtp_table_data.eid_index = UINT32_MAX;
    vtp_table_data.upi = msg->upi;
    vtp_table_data.local_eid = msg->local_eid;
    vtp_table_data.share_mode = true;
    if (tpg_param != NULL) {
        vtp_table_data.tpg_param = *tpg_param;
        vtp_table_data.share_mode = false;
        TPSA_LOG_INFO("update rm vtp table in non_share_mode and vtpn = %u, tpgn = %u",
            vtp_table_data.vtpn, vtp_table_data.tpg_param.tpgn);
    }

    vport_key_t fe_key;
    rm_vtp_table_key_t vtp_key;
    uint32_t eid_idx;

    if (location == TPSA_INITIATOR) {
        fe_key.fe_idx = msg->content.finish.src_function_id;
        (void)memcpy(fe_key.tpf_name, msg->content.finish.dev_name, UVS_MAX_DEV_NAME);
        vtp_key.src_eid = msg->local_eid;
        vtp_key.dst_eid = msg->peer_eid;
    } else {
        if (vport_table_lookup_by_ueid_return_key(&table_ctx->vport_table, msg->upi, &msg->peer_eid,
            &fe_key, &eid_idx) != 0) {
            TPSA_LOG_INFO("vport_table_lookup_by_ueid,  upi %u eid:" EID_FMT "\n", msg->upi, EID_ARGS(msg->peer_eid));
            return -1;
        }
        vtp_key.src_eid = msg->peer_eid;
        vtp_key.dst_eid = msg->local_eid;
        vtp_table_data.local_eid = msg->peer_eid;
        vtp_table_data.local_jetty = msg->peer_jetty;
        vtp_table_data.eid_index = eid_idx;
    }

    TPSA_LOG_INFO("update vtp dev:%s fe_idx %hu\n", fe_key.tpf_name, fe_key.fe_idx);
    TPSA_LOG_INFO("update vtp src eid " EID_FMT " dst eid " EID_FMT "\n",
                  EID_ARGS(vtp_key.src_eid), EID_ARGS(vtp_key.dst_eid));

    rm_vtp_table_entry_t *entry = rm_fe_vtp_table_lookup(&table_ctx->fe_table, &fe_key, &vtp_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("RM VTP table have no this entry. Update is ADD now. and tpgn = %u\n",
            vtp_table_data.tpg_param.tpgn);
        if (rm_fe_vtp_table_add(table_ctx, &fe_key, &vtp_key, &vtp_table_data) != 0) {
            return TPSA_ADD_NOMEM;
        }
    } else {
        TPSA_LOG_DEBUG("rm vtp is already exist and tpgn = %u\n", entry->tpg_param->tpgn);
        if (tpsa_update_rm_vtp_table_exist(entry, location, vtpn, tpgn, msg->live_migrate) < 0) {
            TPSA_LOG_ERR("Fail to update rm vtp table");
            return TPSA_ADD_INVALID;
        }
    }

    return 0;
}

static int tpsa_update_rc_vtp_table_exist(rc_vtp_table_entry_t *entry, uint32_t location, uint32_t vtpn,
                                          uint32_t tpgn, bool live_migrate)
{
    entry->vtpn = (entry->vtpn == UINT32_MAX) ? vtpn : entry->vtpn;

    if (live_migrate && entry->tpgn != UINT32_MAX) {
        if (entry->node_status != STATE_NORMAL) {
            TPSA_LOG_ERR("Wrong status when update vice tpgn");
            return TPSA_ADD_INVALID;
        } else {
            entry->vice_tpgn = tpgn;
            entry->node_status = STATE_READY;
            TPSA_LOG_INFO("Live migration rc add vice tpgn process");
        }
    } else {
        entry->tpgn = tpgn;
    }
    entry->valid = true;
    entry->location = (entry->location != location) ? TPSA_DUPLEX : entry->location;

    return 0;
}

static int tpsa_update_rc_vtp_table(tpsa_sock_msg_t *msg, uint32_t location, uint32_t vtpn,
                                    uint32_t tpgn, tpsa_table_t *table_ctx)
{
    rc_vtp_table_key_t vtp_key;
    uint32_t eid_idx;
    tpsa_vtp_table_param_t vtp_table_data = {0};
    vtp_table_data.vtpn = vtpn;
    vtp_table_data.tpgn = tpgn;
    vtp_table_data.valid = true;
    vtp_table_data.location = location;
    vtp_table_data.local_jetty = msg->local_jetty;
    vtp_table_data.eid_index = UINT32_MAX;
    vtp_table_data.upi = msg->upi;
    vtp_table_data.local_eid = msg->local_eid;
    vtp_table_data.share_mode = true; /* RC only use share_mode */

    vport_key_t fe_key;
    if (location == TPSA_INITIATOR) {
        fe_key.fe_idx = msg->content.finish.src_function_id;
        (void)memcpy(fe_key.tpf_name, msg->content.finish.dev_name, UVS_MAX_DEV_NAME);
        vtp_key.dst_eid = msg->peer_eid;
        vtp_key.jetty_id = msg->peer_jetty;
    } else {
        if (vport_table_lookup_by_ueid_return_key(&table_ctx->vport_table, msg->upi, &msg->peer_eid,
            &fe_key, &eid_idx) != 0) {
            TPSA_LOG_INFO("vport_table_lookup_by_ueid,  upi %u eid:" EID_FMT "\n",
                msg->upi, EID_ARGS(msg->peer_eid));
            return -1;
        }
        vtp_key.dst_eid = msg->local_eid;
        vtp_key.jetty_id = msg->local_jetty;
        vtp_table_data.local_eid = msg->peer_eid;
        vtp_table_data.local_jetty = msg->peer_jetty;
        vtp_table_data.eid_index = eid_idx;
    }

    rc_vtp_table_entry_t *entry = rc_fe_vtp_table_lookup(&table_ctx->fe_table, &fe_key, &vtp_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("RC VTP table have no this entry. Update is ADD now.\n");

        if (rc_fe_vtp_table_add(table_ctx, &fe_key, &vtp_key, &vtp_table_data) != 0) {
            return TPSA_ADD_NOMEM;
        }
    } else {
        if (tpsa_update_rc_vtp_table_exist(entry, location, vtpn, tpgn, msg->live_migrate) < 0) {
            TPSA_LOG_ERR("Fail to update rc vtp table");
            return TPSA_ADD_INVALID;
        }
    }

    return 0;
}

int tpsa_update_vtp_table(tpsa_sock_msg_t *msg, uint32_t location, uint32_t vtpn,
                          uint32_t tpgn, tpsa_table_t *table_ctx)
{
    int res = -1;
    if (msg->trans_mode == TPSA_TP_RM) {
        res = tpsa_update_rm_vtp_table(msg, location, vtpn, tpgn, table_ctx, NULL);
        if (res < 0) {
            TPSA_LOG_ERR("Fail to update rm vtp table");
            return res;
        }
    } else if (msg->trans_mode == TPSA_TP_RC) {
        res = tpsa_update_rc_vtp_table(msg, location, vtpn, tpgn, table_ctx);
        if (res < 0) {
            TPSA_LOG_ERR("Fail to update rc vtp table");
            return res;
        }
    }

    return 0;
}
static int tpsa_rc_vtp_node_status_change(vtp_node_state_t state, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    rc_vtp_table_entry_t *vtp_entry = lm_vtp_entry->content.rc_entry;
    if (vtp_entry == NULL) {
        TPSA_LOG_ERR("Can't find vtp entry in rc vtp table");
        return -1;
    }

    vtp_entry->node_status = state;

    return 0;
}

static int tpsa_rm_vtp_node_status_change(vtp_node_state_t state, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    rm_vtp_table_entry_t *vtp_entry = lm_vtp_entry->content.rm_entry;
    if (vtp_entry == NULL) {
        TPSA_LOG_ERR("Can't find vtp entry in rm vtp table");
        return -1;
    }

    vtp_entry->node_status = state;

    return 0;
}

int tpsa_vtp_node_status_change(vtp_node_state_t state, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    int ret;

    if (lm_vtp_entry->trans_mode == TPSA_TP_RM) {
        ret = tpsa_rm_vtp_node_status_change(state, lm_vtp_entry);
    } else {
        ret = tpsa_rc_vtp_node_status_change(state, lm_vtp_entry);
    }

    return ret;
}

int tpsa_rm_vtp_tpgn_swap(uint32_t *vice_tpgn, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    rm_vtp_table_entry_t *vtp_entry = lm_vtp_entry->content.rm_entry;
    if (vtp_entry == NULL || vtp_entry->vice_tpgn == UINT32_MAX) {
        TPSA_LOG_ERR("Can't find vtp entry in rm vtp table, or vice tpgn not exist");
        return -1;
    }

    *vice_tpgn = vtp_entry->vice_tpgn;

    uint32_t tmp = vtp_entry->tpgn;
    vtp_entry->tpgn = vtp_entry->vice_tpgn;
    vtp_entry->vice_tpgn = tmp;

    if (vtp_entry->node_status == STATE_READY) {
        vtp_entry->node_status = STATE_MIGRATING;
    } else { /* status is MIGRATING */
        vtp_entry->node_status = STATE_ROLLBACK;
    }

    return 0;
}

static int tpsa_rc_tpg_table_tpn_swap(tpsa_table_t *table_ctx, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    rc_vtp_table_entry_t *rc_entry = lm_vtp_entry->content.rc_entry;
    rc_tpg_table_key_t tpg_key = {
        .deid = rc_entry->key.dst_eid,
        .djetty_id = rc_entry->key.jetty_id,
    };

    rc_tpg_table_entry_t *tpg_entry = rc_tpg_table_lookup(&table_ctx->rc_tpg_table, &tpg_key);
    if (tpg_entry == NULL || tpg_entry->vice_tpgn == UINT32_MAX) {
        TPSA_LOG_ERR("Can't find tpg entry in rc tpg table or alternative tpg not exists");
        return TPSA_LOOKUP_NULL;
    }

    uint32_t tmp = tpg_entry->tpgn;
    tpg_entry->tpgn = tpg_entry->vice_tpgn;
    tpg_entry->vice_tpgn = tmp;

    uint32_t tmp_tpn[TPSA_MAX_TP_CNT_IN_GRP];
    (void)memcpy(tmp_tpn, tpg_entry->tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
    (void)memcpy(tpg_entry->tpn, tpg_entry->vice_tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
    (void)memcpy(tpg_entry->vice_tpn, tmp_tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));

    return 0;
}

static int tpsa_rc_vtp_tpgn_swap(uint32_t *vice_tpgn, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    rc_vtp_table_entry_t *vtp_entry = lm_vtp_entry->content.rc_entry;
    if (vtp_entry == NULL || vtp_entry->vice_tpgn == UINT32_MAX) {
        TPSA_LOG_ERR("Can't find vtp entry in rc vtp table or not exist vice tpg");
        return -1;
    }

    *vice_tpgn = vtp_entry->vice_tpgn;

    uint32_t tmp = vtp_entry->tpgn;
    vtp_entry->tpgn = vtp_entry->vice_tpgn;
    vtp_entry->vice_tpgn = tmp;

    if (vtp_entry->node_status == STATE_READY) {
        vtp_entry->node_status = STATE_MIGRATING;
    } else { /* status is MIGRATING */
        vtp_entry->node_status = STATE_ROLLBACK;
    }

    return 0;
}

int tpsa_rc_tpg_swap(tpsa_table_t *table_ctx, uint32_t *vice_tpgn, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    int ret;

    /* first, in vtp table, swap the tpgn and vice_tpgn */
    ret = tpsa_rc_vtp_tpgn_swap(vice_tpgn, lm_vtp_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("tpg swap failed in rc vtp table.\n");
        return ret;
    }

    /* second, in rc tpg table, swap the tpn and vice_tpn */
    ret = tpsa_rc_tpg_table_tpn_swap(table_ctx, lm_vtp_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("tpg swap failed in rc tpg table.\n");
        return ret;
    }

    return 0;
}

int tpsa_vtp_tpgn_swap(tpsa_table_t *table_ctx, uint32_t *vice_tpgn, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    int ret;

    if (lm_vtp_entry->trans_mode == TPSA_TP_RM) {
        ret = tpsa_rm_vtp_tpgn_swap(vice_tpgn, lm_vtp_entry);
    } else {
        ret = tpsa_rc_tpg_swap(table_ctx, vice_tpgn, lm_vtp_entry);
    }

    return ret;
}

int tpsa_get_vtp_idx(uint16_t fe_idx, char *dev_name, size_t dev_name_len, tpsa_vtp_table_index_t *vtp_idx,
                     tpsa_table_t *table_ctx)
{
    vport_key_t fe_key = {0};
    fe_key.fe_idx = fe_idx;
    (void)memcpy(fe_key.tpf_name, dev_name, dev_name_len);

    (void)pthread_rwlock_wrlock(&table_ctx->fe_table.rwlock);
    fe_table_entry_t *entry = fe_table_lookup(&table_ctx->fe_table, &fe_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("Can't find fe entry in fe table, dev: %s, fe_idx: %hu", fe_key.tpf_name, fe_key.fe_idx);
        (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
        return TPSA_LOOKUP_NULL;
    }
    (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);

    if (entry->rm_vtp_table.hmap.count != 0) {
        rm_vtp_table_entry_t *vtp_cur, *vtp_next;
        HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &entry->rm_vtp_table.hmap) {
            vtp_idx->local_eid = vtp_cur->key.src_eid;
            vtp_idx->upi = vtp_cur->upi;

            return 0;
        }
    } else if (entry->rc_vtp_table.hmap.count != 0) {
        rc_vtp_table_entry_t *vtp_cur, *vtp_next;
        HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &entry->rc_vtp_table.hmap) {
            vtp_idx->local_eid = vtp_cur->src_eid;
            vtp_idx->upi = vtp_cur->upi;

            return 0;
        }
    }

    TPSA_LOG_ERR("Can't find vtp table entry in fe table.");
    return TPSA_LOOKUP_NULL;
}

static int tpsa_cloud_ops_check_dip(void)
{
    uvs_user_ops_t* gaea_ops = NULL;

    uvs_ops_mutex_lock();
    gaea_ops = get_uvs_user_ops(USER_OPS_GAEA);
    if (gaea_ops != NULL && gaea_ops->lookup_netaddr_by_ueid != NULL) {
        uvs_ops_mutex_unlock();
        TPSA_LOG_INFO("Detect cloud dip situation.");
        return 0;
    }
    uvs_ops_mutex_unlock();
    return -1;
}

/* cloud dip table */
static int tpsa_cloud_lookup_dip_table(urma_eid_t remote_eid, uint32_t upi,
    uvs_net_addr_t *peer_uvs_ip, uvs_net_addr_info_t *dip)
{
    uvs_user_ops_t* gaea_ops = NULL;
    uvs_dip_info_t loc_dip;
    uvs_ueid_t ueid = {0};
    uvs_eid_t eid;
    int ret = 0;

    (void)memcpy(eid.raw, remote_eid.raw, sizeof(uint8_t) * UVS_EID_SIZE);

    ueid.eid = eid;
    ueid.upi = upi;

    (void)memset(&loc_dip, 0, sizeof(uvs_dip_info_t));
    uvs_ops_mutex_lock();
    gaea_ops = get_uvs_user_ops(USER_OPS_GAEA);
    if (gaea_ops == NULL) {
        uvs_ops_mutex_unlock();
        return -1;
    }

    ret = gaea_ops->lookup_netaddr_by_ueid(&ueid, &loc_dip);
    uvs_ops_mutex_unlock();
    (void)memcpy(peer_uvs_ip, &loc_dip.net_addr, sizeof(uvs_net_addr_t));

    dip->type = loc_dip.type;
    (void)memcpy(&dip->net_addr, &loc_dip.net_addr, sizeof(uvs_net_addr_t));
    dip->vlan = loc_dip.vlan;
    (void)memcpy(dip->mac, loc_dip.mac, sizeof(uint8_t) * ETH_ADDR_LEN);

    return ret;
}

/* dip table */
void tpsa_lookup_dip_table(dip_table_t *dip_table, urma_eid_t remote_eid, uint32_t upi,
    uvs_net_addr_t *peer_uvs_ip, uvs_net_addr_info_t *dip)
{
    dip_table_entry_t *remote_underlay = NULL;
    dip_table_key_t key = {0};
    int ret;

    (void)memcpy(peer_uvs_ip, &remote_eid, sizeof(urma_eid_t));
    key.deid = remote_eid;
    key.upi = upi;

    if (tpsa_cloud_ops_check_dip() == 0) {
        ret = tpsa_cloud_lookup_dip_table(remote_eid, upi, peer_uvs_ip, dip);
        if (ret != 0) {
            TPSA_LOG_WARN("Failed to get remote underlay info in cloud situation. "
                "Return value is input eid.\n");
        }
        return;
    }

    (void)pthread_rwlock_wrlock(&dip_table->rwlock);
    remote_underlay = dip_table_lookup(dip_table, &key);
    if (remote_underlay == NULL) {
        TPSA_LOG_WARN("Failed to get remote underlay info. Return value is input eid.\n");
    } else {
        *peer_uvs_ip = remote_underlay->peer_uvs_ip;
        *dip = remote_underlay->netaddr;
    }
    (void)pthread_rwlock_unlock(&dip_table->rwlock);
}

/* tpg table */
static tpsa_tpg_status_t tpsa_lookup_rm_tpg_table(uvs_net_addr_info_t *dip, tpsa_table_t *table_ctx,
    tpsa_tpg_info_t *tpsa_tpg_info)
{
    rm_tpg_table_key_t k = {
        .dip = *dip,
    };

    rm_tpg_table_entry_t *entry = rm_tpg_table_lookup(&table_ctx->rm_tpg_table, &k);
    if (entry != NULL) {
        tpsa_tpg_info->tpgn = entry->tpgn;
        tpsa_tpg_info->tp_cnt = entry->tp_cnt;
        (void)memcpy(tpsa_tpg_info->tpn, entry->tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
        return entry->status;
    }

    TPSA_LOG_WARN("Can't find tpg entry in rm tpg table");
    return TPSA_TPG_LOOKUP_NULL;
}

static tpsa_tpg_status_t tpsa_lookup_rc_tpg_table(tpsa_tpg_table_index_t *tpg_idx,
    tpsa_table_t *table_ctx, tpsa_tpg_info_t *tpsa_tpg_info)
{
    rc_tpg_table_key_t k = {
        .deid = tpg_idx->peer_eid,
        .djetty_id = tpg_idx->djetty_id,
    };

    rc_tpg_table_entry_t *entry = rc_tpg_table_lookup(&table_ctx->rc_tpg_table, &k);
    if (entry != NULL) {
        if (memcmp(&entry->leid, &tpg_idx->local_eid, sizeof(urma_eid_t)) != 0 ||
            entry->ljetty_id != tpg_idx->ljetty_id) {
            TPSA_LOG_WARN("djetty %u, " EID_FMT ", already connect by sjetty %u, " EID_FMT "",
                tpg_idx->djetty_id, EID_ARGS(entry->leid), entry->ljetty_id,
                EID_ARGS(tpg_idx->local_eid));
            return TPSA_TPG_LOOKUP_ALREADY_BIND;
        }
        tpsa_tpg_info->tpgn = entry->tpgn;
        tpsa_tpg_info->tp_cnt = entry->tp_cnt;
        (void)memcpy(tpsa_tpg_info->tpn, entry->tpn,
            TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
        return entry->status;
    }

    /* handle loopback scenario */
    if (tpg_idx->isLoopback) {
        k.deid = tpg_idx->local_eid;
        k.djetty_id = tpg_idx->ljetty_id;

        entry = rc_tpg_table_lookup(&table_ctx->rc_tpg_table, &k);
        if (entry != NULL) {
            /* loopback need check djetty == entry ljetty in rc */
            if (memcmp(&entry->leid, &tpg_idx->peer_eid, sizeof(urma_eid_t)) != 0 ||
                entry->ljetty_id != tpg_idx->djetty_id) {
                TPSA_LOG_WARN("djetty %u, " EID_FMT ", already connect by sjetty %u, " EID_FMT "",
                    entry->ljetty_id, EID_ARGS(entry->leid), tpg_idx->djetty_id,
                    EID_ARGS(tpg_idx->peer_eid));
                return TPSA_TPG_LOOKUP_ALREADY_BIND;
            }
            tpsa_tpg_info->tpgn = entry->tpgn;
            (void)memcpy(tpsa_tpg_info->tpn, entry->tpn,
                TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
            return entry->status;
        }
    }

    TPSA_LOG_WARN("Can't find tpg entry in rc tpg table");
    return TPSA_TPG_LOOKUP_NULL;
}

tpsa_tpg_status_t tpsa_lookup_tpg_table(tpsa_tpg_table_index_t *tpg_idx, tpsa_transport_mode_t trans_mode,
                                        tpsa_table_t *table_ctx, tpsa_tpg_info_t *tpsa_tpg_info)
{
    if (trans_mode == TPSA_TP_RM) {
        return tpsa_lookup_rm_tpg_table(&tpg_idx->dip, table_ctx, tpsa_tpg_info);
    } else if (trans_mode == TPSA_TP_RC) {
        return tpsa_lookup_rc_tpg_table(tpg_idx, table_ctx, tpsa_tpg_info);
    }

    TPSA_LOG_WARN("Wrong trans_mode input when lookup tpg table. return NULL");
    return TPSA_TPG_LOOKUP_NULL;
}

int tpsa_add_rm_tpg_table(tpsa_tpg_table_param_t *param, rm_tpg_table_t *table)
{
    rm_tpg_table_key_t k = {
        .dip = param->dip,
    };

    rm_tpg_table_entry_t *entry = rm_tpg_table_lookup(table, &k);
    if (entry != NULL) {
        if (entry->status == TPSA_TPG_LOOKUP_IN_PROGRESS) {
            TPSA_LOG_ERR("Error: Add duplicate invalid entry to rm tpg table. Maybe duplicate create vtp");
            return TPSA_ADD_INVALID;
        } else {
            entry->use_cnt += 1;
        }
    } else {
        if (rm_tpg_table_add(table, &k, param) != 0) {
            return TPSA_ADD_NOMEM;
        }
    }

    return 0;
}

int tpsa_add_rc_tpg_table(urma_eid_t peer_eid, uint32_t peer_jetty, tpsa_tpg_table_param_t *param,
                          rc_tpg_table_t *table)
{
    rc_tpg_table_key_t k = {
        .deid = peer_eid,
        .djetty_id = peer_jetty,
    };

    rc_tpg_table_entry_t *entry = rc_tpg_table_lookup(table, &k);
    if (entry != NULL) {
        /* for lm, need to add alternative channels */
        if (param->live_migrate == true && entry->vice_tpgn == UINT32_MAX) {
            TPSA_LOG_INFO("In lm sescenario, add alternative tpg %u in rc_tpg_table.\n", entry->vice_tpgn);
            entry->vice_tpgn = param->tpgn;
            (void)memcpy(entry->vice_tpn, param->tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
            return 0;
        }

        if (entry->status == TPSA_TPG_LOOKUP_IN_PROGRESS) {
            TPSA_LOG_ERR("Error: Add duplicate invalid entry to rc tpg table. Maybe duplicate create vtp");
            return TPSA_ADD_INVALID;
        } else {
            entry->use_cnt += 1;
        }

        return 0;
    } else if (param->isLoopback) {
        /* handle loopback */
        k.deid = param->leid;
        k.djetty_id = param->ljetty_id;

        entry = rc_tpg_table_lookup(table, &k);
        if (entry != NULL) {
            if (entry->status == TPSA_TPG_LOOKUP_IN_PROGRESS) {
                TPSA_LOG_ERR("Error: Add duplicate invalid entry to rc tpg table. Maybe duplicate create vtp");
                return TPSA_ADD_INVALID;
            } else {
                entry->use_cnt += 1;
            }

            return 0;
        }

        k.deid = peer_eid;
        k.djetty_id = peer_jetty;
    }

    if (rc_tpg_table_add(table, &k, param) != 0) {
        return TPSA_ADD_NOMEM;
    }

    return 0;
}

int tpsa_remove_rm_tpg_table(rm_tpg_table_t *table, rm_tpg_table_key_t *key, tpsa_tpg_info_t *find_tpg_info)
{
    rm_tpg_table_entry_t *entry = rm_tpg_table_lookup(table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("Rmv tpg, Can't find entry, key dip: " EID_FMT "", EID_ARGS(key->dip.net_addr));
        return TPSA_REMOVE_NULL;
    }

    find_tpg_info->tpgn = entry->tpgn;
    find_tpg_info->tp_cnt = entry->tp_cnt;
    memcpy(find_tpg_info->tpn, entry->tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));

    if (entry->use_cnt != 0) {
        entry->use_cnt -= 1;
    }
    if (entry->use_cnt > 0) {
        TPSA_LOG_INFO("tpgn %d is in use, use count is %d.", entry->tpgn, entry->use_cnt);
        return TPSA_REMOVE_DUPLICATE;
    }

    ub_hmap_remove(&table->hmap, &entry->node);
    free(entry);
    return 0;
}

int tpsa_remove_rc_tpg_table(tpsa_table_t *table_ctx, rc_tpg_table_key_t *key, tpsa_tpg_info_t *find_tpg_info)
{
    rc_tpg_table_entry_t *entry = rc_tpg_table_lookup(&table_ctx->rc_tpg_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key djetty %d, deid " EID_FMT " not exist in rc_tpg", key->djetty_id, EID_ARGS(key->deid));
        return TPSA_REMOVE_NULL;
    }

    find_tpg_info->tpgn = entry->tpgn;
    find_tpg_info->tp_cnt = entry->tp_cnt;
    memcpy(find_tpg_info->tpn, entry->tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));

    if (entry->use_cnt != 0) {
        entry->use_cnt -= 1;
    }
    if (entry->use_cnt > 0) {
        TPSA_LOG_INFO("tpgn %d is in use, use count update to %d.", entry->tpgn, entry->use_cnt);
        return TPSA_REMOVE_DUPLICATE;
    }

    jetty_peer_table_key_t jetty_peer_key;
    jetty_peer_key.ljetty_id = entry->ljetty_id;
    jetty_peer_key.seid = entry->leid;
    (void)jetty_peer_table_remove(&table_ctx->jetty_peer_table, &jetty_peer_key);

    ub_hmap_remove(&table_ctx->rc_tpg_table.hmap, &entry->node);
    free(entry);
    return 0;
}

static int tpsa_update_rm_tpg_table(tpsa_sock_msg_t *msg, uint32_t location, tpsa_table_t *table_ctx)
{
    uvs_net_addr_t peer_uvs_ip = {0};
    uvs_net_addr_info_t dip;

    (void)memset(&dip, 0, sizeof(uvs_net_addr_info_t));
    if (location == TPSA_TARGET) {
        tpsa_lookup_dip_table(&table_ctx->dip_table, msg->local_eid, msg->upi, &peer_uvs_ip, &dip);
    } else {
        tpsa_lookup_dip_table(&table_ctx->dip_table, msg->peer_eid, msg->upi, &peer_uvs_ip, &dip);
    }

    rm_tpg_table_key_t k = {
        .dip = dip,
    };

    rm_tpg_table_entry_t *entry = rm_tpg_table_lookup(&table_ctx->rm_tpg_table, &k);
    if (entry == NULL) {
        TPSA_LOG_WARN("RM TPG table have no this entry. Update is ADD now.\n");

        tpsa_tpg_table_param_t param = {0};
        param.type = 0;
        param.tpgn = msg->local_tpgn;
        param.status = TPSA_TPG_LOOKUP_EXIST;
        param.use_cnt = 1;
        param.ljetty_id = msg->local_jetty;
        if (location == TPSA_TARGET) {
            param.tpgn = msg->peer_tpgn;
            param.ljetty_id = msg->peer_jetty;
        }

        if (rm_tpg_table_add(&table_ctx->rm_tpg_table, &k, &param) != 0) {
            return TPSA_ADD_NOMEM;
        }

        return 0;
    }

    if (entry->status == TPSA_TPG_LOOKUP_EXIST) {
        entry->use_cnt += 1;
    } else {
        entry->tpgn = msg->local_tpgn;
        entry->type = 0;
        entry->status = TPSA_TPG_LOOKUP_EXIST;

        if (location == TPSA_TARGET) {
            entry->tpgn = msg->peer_tpgn;
        }
    }

    return 0;
}

static int tpsa_update_rc_tpg_table(tpsa_sock_msg_t *msg, uint32_t location, tpsa_table_t *table_ctx)
{
    rc_tpg_table_key_t k = {
        .deid = msg->peer_eid,
        .djetty_id = msg->peer_jetty,
    };

    if (location == TPSA_TARGET) {
        k.deid = msg->local_eid;
        k.djetty_id = msg->local_jetty;
    }

    rc_tpg_table_entry_t *entry = rc_tpg_table_lookup(&table_ctx->rc_tpg_table, &k);
    if (entry == NULL) {
        TPSA_LOG_WARN("RC TPG table have no this entry. Update is ADD now.\n");

        tpsa_tpg_table_param_t param = {0};
        param.tpgn = msg->local_tpgn;
        param.status = TPSA_TPG_LOOKUP_EXIST;
        param.use_cnt = 1;
        param.ljetty_id = msg->local_jetty;
        param.leid = msg->local_eid;
        param.live_migrate = msg->live_migrate;

        if (location == TPSA_TARGET) {
            param.tpgn = msg->peer_tpgn;
            param.ljetty_id = msg->peer_jetty;
            param.leid = msg->peer_eid;
        }

        if (rc_tpg_table_add(&table_ctx->rc_tpg_table, &k, &param) != 0) {
            return TPSA_ADD_NOMEM;
        }

        return 0;
    }

    if (entry->status == TPSA_TPG_LOOKUP_EXIST) {
        entry->use_cnt += 1;
    } else {
        entry->tpgn = msg->local_tpgn;
        entry->type = 0;
        entry->status = TPSA_TPG_LOOKUP_EXIST;

        if (location == TPSA_TARGET) {
            entry->tpgn = msg->peer_tpgn;
        }
    }

    return 0;
}

int tpsa_update_tpg_table(tpsa_sock_msg_t *msg, uint32_t location, tpsa_table_t *table_ctx)
{
    int res = -1;
    if (msg->trans_mode == TPSA_TP_RM) {
        res = tpsa_update_rm_tpg_table(msg, location, table_ctx);
        if (res < 0) {
            TPSA_LOG_ERR("Fail to update rm tpg table");
            return res;
        }
    } else if (msg->trans_mode == TPSA_TP_RC) {
        res = tpsa_update_rc_tpg_table(msg, location, table_ctx);
        if (res < 0) {
            TPSA_LOG_ERR("Fail to update rc tpg table");
            return res;
        }
    }

    return 0;
}

/* tpf dev table */
int tpsa_lookup_tpf_dev_table(char *dev_name, tpf_dev_table_t *table, tpf_dev_table_entry_t *return_entry)
{
    tpf_dev_table_key_t k = {0};
    (void)memcpy(k.dev_name, dev_name, UVS_MAX_DEV_NAME);

    tpf_dev_table_entry_t *entry = tpf_dev_table_lookup(table, &k);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to lookup tpf dev table with device name %s\n", dev_name);
        return -1;
    }
    *return_entry = *entry;

    return 0;
}


/* vport table */
int tpsa_lookup_vport_table(vport_key_t *key, vport_table_t *table, vport_table_entry_t *return_entry)
{
    (void)pthread_rwlock_rdlock(&table->rwlock);
    vport_table_entry_t *entry = vport_table_lookup(table, key);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to lookup vport table to get sip_idx, dev:%s fe_idx:%hu\n", key->tpf_name, key->fe_idx);
        (void)pthread_rwlock_unlock(&table->rwlock);
        return -1;
    }

    *return_entry = *entry;
    (void)pthread_rwlock_unlock(&table->rwlock);

    return 0;
}

void tpsa_fill_vport_param(vport_table_entry_t *entry, vport_param_t *vport_param)
{
    vport_param->sip_idx = entry->sip_idx;
    vport_param->rc_cfg = entry->rc_cfg;
    vport_param->tp_cnt = entry->tp_cnt;
    vport_param->tp_cfg = entry->tp_cfg;
    vport_param->pattern = entry->pattern;
}

int tpsa_lookup_vport_param(vport_key_t *key, vport_table_t *table, vport_param_t *vport_param)
{
    (void)pthread_rwlock_rdlock(&table->rwlock);
    vport_table_entry_t *entry = vport_table_lookup(table, key);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to lookup vport table to vport param, dev:%s fe_idx:%hu\n", key->tpf_name, key->fe_idx);
        (void)pthread_rwlock_unlock(&table->rwlock);
        return -1;
    }
    tpsa_fill_vport_param(entry, vport_param);
    (void)pthread_rwlock_unlock(&table->rwlock);

    return 0;
}

int uvs_add_tpg_state_table(tpsa_table_t *table_ctx, tpg_state_table_entry_t *add_entry)
{
    tpg_state_table_entry_t *tpg_entry = tpg_state_table_lookup(&table_ctx->tpg_state_table, &add_entry->key);
    if (tpg_entry != NULL) {
        TPSA_LOG_WARN("tpg %u already exist process \n", add_entry->key.tpgn);
        return 0;
    }

    tpg_entry = tpg_state_table_add(&table_ctx->tpg_state_table, &add_entry->key, add_entry);
    if (tpg_entry == NULL) {
        return -1;
    }

    return 0;
}

int uvs_table_add(tpsa_create_param_t *cparam, tpsa_table_t *table_ctx, tpsa_tpg_table_param_t *tpg,
    tpsa_vtp_table_param_t *vtp_table_data)
{
    /*
        vtp_table_data data is used to be added to the table, and it should not be changed
        so use local variable instead
    */
    tpsa_vtp_table_param_t vtp_table_data_tmp = *vtp_table_data;
    vtp_table_data_tmp.tpg_param.tp_cnt = tpg->tp_cnt;
    vtp_table_data_tmp.tpg_param.tpgn = tpg->tpgn;
    (void)memcpy(vtp_table_data_tmp.tpg_param.tpn,
        tpg->tpn, sizeof(uint32_t) * TPSA_MAX_TP_CNT_IN_GRP);
    if (cparam->trans_mode == TPSA_TP_RM) {
        if (tpsa_add_rm_vtp_table(cparam, &vtp_table_data_tmp, table_ctx, tpg->isLoopback)) {
            TPSA_LOG_ERR("Failed to add rm vtp table\n");
            return -1;
        }
        TPSA_LOG_DEBUG("Added rm vtp with seid = " EID_FMT " and deid = " EID_FMT" \n",
            EID_ARGS(cparam->local_eid), EID_ARGS(cparam->peer_eid));
    } else if (cparam->trans_mode == TPSA_TP_RC) {
        if (tpsa_add_rc_vtp_table(cparam, &vtp_table_data_tmp, table_ctx, tpg->isLoopback)) {
            TPSA_LOG_ERR("Failed to add rc vtp table\n");
            return -1;
        }
    }

    if (!vtp_table_data->share_mode) {
        TPSA_LOG_INFO("now is in non_share_mode and update with tpgn %u",
            vtp_table_data_tmp.tpg_param.tpgn);
        return 0;
    }

    if (cparam->trans_mode == TPSA_TP_RM) {
        if (tpsa_add_rm_tpg_table(tpg, &table_ctx->rm_tpg_table)) {
            TPSA_LOG_ERR("Failed to add rm tpg table\n");
            return -1;
        }
    } else if (cparam->trans_mode == TPSA_TP_RC) {
        if (tpsa_add_rc_tpg_table(cparam->peer_eid, cparam->peer_jetty, tpg, &table_ctx->rc_tpg_table)) {
            TPSA_LOG_ERR("Failed to add rc tpg table\n");
            return -1;
        }

        jetty_peer_table_param_t parm = {
            .seid = cparam->local_eid,
            .deid = cparam->peer_eid,
            .ljetty_id = cparam->local_jetty,
            .djetty_id = cparam->peer_jetty
        };

        if (jetty_peer_table_add(&table_ctx->jetty_peer_table, &parm) != 0) {
            TPSA_LOG_ERR("Failed to add rc jetty peer table\n");
            return -1;
        }
    }

    return 0;
}

/* location is only allowed to be initiator or target, NO DUPLEX! */
int uvs_table_update(uint32_t vtpn, uint32_t tpgn, uint32_t location,
                     tpsa_sock_msg_t *msg, tpsa_table_t *table_ctx)
{
    TPSA_LOG_INFO("Update vtp table when resp receive. vtpn: %u\n", vtpn);
    if (tpsa_update_vtp_table(msg, location, vtpn, tpgn, table_ctx)) {
        TPSA_LOG_ERR("Failed to update vtp table\n");
        return -1;
    }

    TPSA_LOG_INFO("Update tpg table when resp receive. tpgn: %d\n", tpgn);
    if (tpsa_update_tpg_table(msg, location, table_ctx)) {
        TPSA_LOG_ERR("Failed to update tpg table\n");
        return -1;
    }

    return 0;
}

/* wait table */
int uvs_add_wait_rm(tpsa_table_t *table_ctx, tpsa_create_param_t *cparam, uint32_t location)
{
    rm_wait_table_entry_t wait_entry = {0};
    rm_wait_table_key_t wait_key;

    (void)memset(&wait_key, 0, sizeof(rm_wait_table_key_t));
    wait_key.dip = cparam->dip;
    (void)memcpy(&wait_entry.cparam, cparam, sizeof(tpsa_create_param_t));

    if (rm_wait_table_add(&table_ctx->rm_wait_table, &wait_key, &wait_entry) < 0) {
        TPSA_LOG_ERR("Fail to add rm wait table");
        return -1;
    }

    return 0;
}

int uvs_add_wait_rc(tpsa_table_t *table_ctx, tpsa_create_param_t *cparam, uint32_t location)
{
    rc_wait_table_entry_t wait_entry = {0};
    rc_wait_table_key_t wait_key = {0};

    wait_key.deid = cparam->peer_eid;
    wait_key.djetty_id = cparam->peer_jetty;

    (void)memcpy(&wait_entry.cparam, cparam, sizeof(tpsa_create_param_t));

    if (rc_wait_table_add(&table_ctx->rc_wait_table, &wait_key, &wait_entry) < 0) {
        TPSA_LOG_ERR("Fail to add rc wait table");
        return -1;
    }

    return 0;
}

int uvs_add_wait(tpsa_table_t *table_ctx, tpsa_create_param_t *cparam, uint32_t location)
{
    if (cparam->trans_mode == TPSA_TP_RM) {
        if (uvs_add_wait_rm(table_ctx, cparam, location) < 0) {
            TPSA_LOG_ERR("Fail to add rm wait table in uvs_add_wait");
            return -1;
        }
    } else {
        if (uvs_add_wait_rc(table_ctx, cparam, location) < 0) {
            TPSA_LOG_ERR("Fail to add rc wait table in uvs_add_wait");
            return -1;
        }
    }

    return 0;
}

int tpsa_table_init(tpsa_table_t *tpsa_table)
{
    int ret;

    ret = fe_table_create(&tpsa_table->fe_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create fe_table %d", ret);
        return ret;
    }

    ret = rm_tpg_table_create(&tpsa_table->rm_tpg_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create dip_tgp_table %d", ret);
        goto free_fe_table;
    }

    ret = rc_tpg_table_create(&tpsa_table->rc_tpg_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create rc_tpg_table %d", ret);
        goto free_rm_tpg;
    }

    ret = utp_table_create(&tpsa_table->utp_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create utp_table %d", ret);
        goto free_rc_tpg;
    }

    ret = vport_table_create(&tpsa_table->vport_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create vport_table %d", ret);
        goto free_utp_table;
    }

    ret = live_migrate_table_create(&tpsa_table->live_migrate_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create live_migrate_table %d", ret);
        goto free_vport_table;
    }

    ret = rm_wait_table_create(&tpsa_table->rm_wait_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create rm_wait_table %d", ret);
        goto free_live_migrate_table;
    }

    ret = rc_wait_table_create(&tpsa_table->rc_wait_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create rc_wait_table %d", ret);
        goto free_rm_wait_table;
    }

    ret = jetty_peer_table_create(&tpsa_table->jetty_peer_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create jetty_peer_table %d", ret);
        goto free_rc_wait_table;
    }

    ret = tp_state_table_create(&tpsa_table->tp_state_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create tp_state_table %d", ret);
        goto free_jetty_peer;
    }

    ret = tpf_dev_table_create(&tpsa_table->tpf_dev_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create cc table %d", ret);
        goto free_tp_state_table;
    }

    ret = ctp_table_create(&tpsa_table->ctp_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create ctp table :%d", ret);
        goto free_tpf_dev_table;
    }

    ret = tpg_state_table_create(&tpsa_table->tpg_state_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create tpg state table  :%d", ret);
        goto free_ctp_table;
    }

    ret = deid_vtp_table_create(&tpsa_table->deid_vtp_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create deid vtp table");
        goto free_tpg_state_table;
    }

    ret = dip_table_create(&tpsa_table->dip_table);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create dip_table %d", ret);
        goto free_deid_vtp_table;
    }

    wait_restored_list_create(&tpsa_table->wait_restored_list);
    TPSA_LOG_INFO("tpsa table init success");
    return 0;

free_deid_vtp_table:
    deid_vtp_table_destroy(&tpsa_table->deid_vtp_table);
free_tpg_state_table:
    tpg_state_table_destroy(&tpsa_table->tpg_state_table);
free_ctp_table:
    ctp_table_destroy(&tpsa_table->ctp_table);
free_tpf_dev_table:
    tpf_dev_table_destroy(&tpsa_table->tpf_dev_table);
free_tp_state_table:
    tp_state_table_destroy(&tpsa_table->tp_state_table);
free_jetty_peer:
    jetty_peer_table_destroy(&tpsa_table->jetty_peer_table);
free_rc_wait_table:
    rc_wait_table_destroy(&tpsa_table->rc_wait_table);
free_rm_wait_table:
    rm_wait_table_destroy(&tpsa_table->rm_wait_table);
free_live_migrate_table:
    live_migrate_table_destroy(&tpsa_table->live_migrate_table);
free_vport_table:
    vport_table_destroy(&tpsa_table->vport_table);
free_utp_table:
    utp_table_destroy(&tpsa_table->utp_table);
free_rc_tpg:
    rc_tpg_table_destroy(&tpsa_table->rc_tpg_table);
free_rm_tpg:
    rm_tpg_table_destroy(&tpsa_table->rm_tpg_table);
free_fe_table:
    fe_vtp_table_destroy(&tpsa_table->fe_table);

    return ret;
}

void tpsa_table_uninit(tpsa_table_t *tpsa_table)
{
    wait_restored_list_destroy(&tpsa_table->wait_restored_list);
    dip_table_destroy(&tpsa_table->dip_table);
    tp_state_table_destroy(&tpsa_table->tp_state_table);
    jetty_peer_table_destroy(&tpsa_table->jetty_peer_table);
    rm_wait_table_destroy(&tpsa_table->rm_wait_table);
    rc_wait_table_destroy(&tpsa_table->rc_wait_table);
    live_migrate_table_destroy(&tpsa_table->live_migrate_table);
    vport_table_destroy(&tpsa_table->vport_table);
    utp_table_destroy(&tpsa_table->utp_table);
    rc_tpg_table_destroy(&tpsa_table->rc_tpg_table);
    rm_tpg_table_destroy(&tpsa_table->rm_tpg_table);
    fe_vtp_table_destroy(&tpsa_table->fe_table);
    tpf_dev_table_destroy(&tpsa_table->tpf_dev_table);
    ctp_table_destroy(&tpsa_table->ctp_table);
    tpg_state_table_destroy(&tpsa_table->tpg_state_table);
    deid_vtp_table_destroy(&tpsa_table->deid_vtp_table);
}
