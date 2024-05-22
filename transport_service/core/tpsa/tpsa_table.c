/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa table header file
 * Author: Ji Lei
 * Create: 2023-07-03
 * Note:
 * History: 2023-07-03 tpsa table create search implement
 */

#include <errno.h>
#include "ub_hash.h"
#include "tpsa_log.h"
#include "tpsa_tbl_manage.h"
#include "tpsa_worker.h"
#include "tpsa_table.h"

/* deid_vtp_table alloc/create/add/remove/destroy opts */
int deid_vtp_table_create(deid_vtp_table_t *deid_vtp_table)
{
    if (ub_hmap_init(&deid_vtp_table->hmap, TPSA_DEID_VTP_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("deid vtp table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

static deid_vtp_table_entry_t *alloc_deid_vtp_table_entry(const deid_vtp_table_key_t *key)
{
    int ret = 0;

    deid_vtp_table_entry_t *entry = (deid_vtp_table_entry_t *)calloc(1,
        sizeof(deid_vtp_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    /* vtp list init to store the vtp entry with the same deid */
    ub_list_init(&entry->vtp_list);
    ret = pthread_spin_init(&entry->vtp_list_lock, PTHREAD_PROCESS_PRIVATE);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to init spinlock, err: %d.\n", errno);
    }

    return entry;
}

deid_vtp_table_entry_t *deid_vtp_table_lookup(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key)
{
    deid_vtp_table_entry_t *target = NULL;
    HMAP_FIND(deid_vtp_table, key, sizeof(*key), target);
    return target;
}

static deid_vtp_table_entry_t *deid_vtp_table_add(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key)
{
    if (deid_vtp_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }

    deid_vtp_table_entry_t *entry = alloc_deid_vtp_table_entry(key);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa deid_vtp_table entry");
        return NULL;
    }

    HMAP_INSERT(deid_vtp_table, entry, key, sizeof(*key));
    return entry;
}

static void deid_vtp_table_remove(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_entry_t *entry)
{
    if (ub_list_is_empty(&entry->vtp_list)) {
        (void)pthread_spin_destroy(&entry->vtp_list_lock);
        ub_hmap_remove(&deid_vtp_table->hmap, &entry->node);
        free(entry);
    }
}

/* vtp_list add/remove/destroy */
static void vtp_list_destroy(struct ub_list *list, pthread_spinlock_t *lock)
{
    deid_vtp_node_t *cur, *next;

    (void)pthread_spin_lock(lock);
    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        ub_list_remove(&cur->node);
        free(cur);
    }
    (void)pthread_spin_unlock(lock);

    /* destroy the lock */
    (void)pthread_spin_destroy(lock);
}

static int vtp_list_add(struct ub_list *list, tpsa_lm_vtp_entry_t *lm_vtp_entry, pthread_spinlock_t *lock)
{
    deid_vtp_node_t *node = (deid_vtp_node_t *)calloc(1, sizeof(deid_vtp_node_t));
    if (node == NULL) {
        return -ENOMEM;
    }
    node->entry = *lm_vtp_entry;
    (void)pthread_spin_lock(lock);
    ub_list_push_back(list, &node->node);
    (void)pthread_spin_unlock(lock);

    return 0;
}

static deid_vtp_node_t *rm_vtp_list_lookup(struct ub_list *list, rm_vtp_table_key_t *key, pthread_spinlock_t *lock)
{
    deid_vtp_node_t *cur, *next;
    deid_vtp_node_t *node = NULL;

    (void)pthread_spin_lock(lock);
    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        rm_vtp_table_entry_t *rm_entry = cur->entry.content.rm_entry;
        if (memcmp(&rm_entry->key, key, sizeof(rm_vtp_table_key_t)) != 0) {
            continue;
        }
        node = cur;
        break;
    }
    (void)pthread_spin_unlock(lock);

    return node;
}

static deid_vtp_node_t *rc_vtp_list_lookup(struct ub_list *list, rc_vtp_table_key_t *key, pthread_spinlock_t *lock)
{
    deid_vtp_node_t *cur, *next;
    deid_vtp_node_t *node = NULL;

    (void)pthread_spin_lock(lock);
    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        rc_vtp_table_entry_t *rc_entry = cur->entry.content.rc_entry;
        if (memcmp(&rc_entry->key, key, sizeof(rc_vtp_table_key_t)) != 0) {
            continue;
        }
        node = cur;
        break;
    }
    (void)pthread_spin_unlock(lock);

    return node;
}

deid_vtp_node_t *um_vtp_list_lookup(struct ub_list *list, um_vtp_table_key_t *key, pthread_spinlock_t *lock)
{
    deid_vtp_node_t *cur, *next;
    deid_vtp_node_t *node = NULL;

    (void)pthread_spin_lock(lock);
    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        um_vtp_table_entry_t *um_entry = cur->entry.content.um_entry;
        if (memcmp(&um_entry->key, key, sizeof(um_vtp_table_key_t)) != 0) {
            continue;
        }
        node = cur;
        break;
    }
    (void)pthread_spin_unlock(lock);

    return node;
}

void vtp_list_remove(struct ub_list *list, deid_vtp_node_t *node, pthread_spinlock_t *lock)
{
    (void)pthread_spin_lock(lock);
    ub_list_remove(&node->node);
    free(node);
    (void)pthread_spin_unlock(lock);
}

int deid_vtp_list_add(deid_vtp_table_t *deid_vtp_table, tpsa_lm_vtp_entry_t *lm_vtp_entry,
                      deid_vtp_table_key_t *deid_key)
{
    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(deid_vtp_table, deid_key);
    if (deid_entry == NULL) {
        deid_entry = deid_vtp_table_add(deid_vtp_table, deid_key);
        if (deid_entry == NULL) {
            TPSA_LOG_ERR("deid_vtp_table_add failed");
            return TPSA_ADD_NOMEM;
        }
    }
    if (vtp_list_add(&deid_entry->vtp_list, lm_vtp_entry, &deid_entry->vtp_list_lock) != 0) {
        return TPSA_ADD_NOMEM;
    }

    return 0;
}

void deid_rm_vtp_list_remove(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key, rm_vtp_table_key_t *vtp_key)
{
    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(deid_vtp_table, key);
    if (deid_entry == NULL) {
        TPSA_LOG_WARN("deid node exist in vtp table but not exist in deid_vtp table.");
        return;
    }

    deid_vtp_node_t *list_node = rm_vtp_list_lookup(&deid_entry->vtp_list, vtp_key, &deid_entry->vtp_list_lock);
    if (list_node == NULL) {
        TPSA_LOG_WARN("vtp entry exist in vtp table but not exist in deid_vtp list.");
        return;
    }

    vtp_list_remove(&deid_entry->vtp_list, list_node, &deid_entry->vtp_list_lock);

    /* If the linked list is already empty at this time, the hash node needs to be released as well. */
    deid_vtp_table_remove(deid_vtp_table, deid_entry);

    return;
}

void deid_rc_vtp_list_remove(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key, rc_vtp_table_key_t *vtp_key)
{
    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(deid_vtp_table, key);
    if (deid_entry == NULL) {
        TPSA_LOG_WARN("deid node exist in vtp table but not exist in deid_vtp table.");
        return;
    }

    deid_vtp_node_t *list_node = rc_vtp_list_lookup(&deid_entry->vtp_list, vtp_key, &deid_entry->vtp_list_lock);
    if (list_node == NULL) {
        TPSA_LOG_WARN("vtp entry exist in vtp table but not exist in deid_vtp list.");
        return;
    }

    vtp_list_remove(&deid_entry->vtp_list, list_node, &deid_entry->vtp_list_lock);

    /* If the linked list is already empty at this time, the hash node needs to be released as well. */
    deid_vtp_table_remove(deid_vtp_table, deid_entry);

    return;
}
void deid_um_vtp_list_remove(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key, um_vtp_table_key_t *vtp_key)
{
    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(deid_vtp_table, key);
    if (deid_entry == NULL) {
        TPSA_LOG_WARN("deid node exist in vtp table but not exist in deid_vtp table.");
        return;
    }

    deid_vtp_node_t *list_node = um_vtp_list_lookup(&deid_entry->vtp_list, vtp_key, &deid_entry->vtp_list_lock);
    if (list_node == NULL) {
        TPSA_LOG_WARN("vtp entry exist in vtp table but not exist in deid_vtp list.");
        return;
    }

    vtp_list_remove(&deid_entry->vtp_list, list_node, &deid_entry->vtp_list_lock);

    /* If the linked list is already empty at this time, the hash node needs to be released as well. */
    deid_vtp_table_remove(deid_vtp_table, deid_entry);

    return;
}

void deid_vtp_table_destroy(deid_vtp_table_t *deid_vtp_table)
{
    deid_vtp_table_entry_t *cur, *next;

    HMAP_FOR_EACH_SAFE(cur, next, node, &deid_vtp_table->hmap) {
        vtp_list_destroy(&cur->vtp_list, &cur->vtp_list_lock);
        ub_hmap_remove(&deid_vtp_table->hmap, &cur->node);
        free(cur);
    }

    ub_hmap_destroy(&deid_vtp_table->hmap);
    return;
}

/* rm_vtp_table alloc/create/add/remove/destroy opts */
static rm_vtp_table_entry_t *alloc_rm_vtp_table_entry(const rm_vtp_table_key_t *key,
                                                      tpsa_vtp_table_param_t *vtp_table_data)
{
    rm_vtp_table_entry_t *entry = (rm_vtp_table_entry_t *)calloc(1, sizeof(rm_vtp_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    entry->vtpn = vtp_table_data->vtpn;
    entry->tpgn = vtp_table_data->tpgn;
    entry->vice_tpgn = UINT32_MAX;
    entry->valid = vtp_table_data->valid;
    entry->location = vtp_table_data->location;
    entry->src_jetty_id = vtp_table_data->local_jetty;
    entry->eid_index = vtp_table_data->eid_index;
    entry->migration_status = false;
    entry->upi = vtp_table_data->upi;
    entry->node_status = STATE_NORMAL;
    entry->share_mode = vtp_table_data->share_mode;
    if (!vtp_table_data->share_mode) {
        entry->use_cnt = 1;
    }

    return entry;
}

static int rm_vtp_table_create(rm_vtp_table_t *rm_vtp_table)
{
    if (ub_hmap_init(&rm_vtp_table->hmap, TPSA_RM_VTP_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("rm_vtp_table init failed.\n");
        return -ENOMEM;
    }

    (void)pthread_rwlock_init(&rm_vtp_table->vtp_table_lock, NULL);
    return 0;
}

void rm_vtp_table_destroy(rm_vtp_table_t *rm_vtp_table)
{
    (void)pthread_rwlock_wrlock(&rm_vtp_table->vtp_table_lock);
    HMAP_DESTROY(rm_vtp_table, rm_vtp_table_entry_t);
    (void)pthread_rwlock_unlock(&rm_vtp_table->vtp_table_lock);
    (void)pthread_rwlock_destroy(&rm_vtp_table->vtp_table_lock);
    return;
}

rm_vtp_table_entry_t *rm_vtp_table_lookup(rm_vtp_table_t *rm_vtp_table, rm_vtp_table_key_t *key)
{
    rm_vtp_table_entry_t *target = NULL;
    HMAP_FIND(rm_vtp_table, key, sizeof(*key), target);
    return target;
}

int rm_vtp_table_add(deid_vtp_table_t *deid_vtp_table, fe_table_entry_t *entry,
                     rm_vtp_table_key_t *key, tpsa_vtp_table_param_t *vtp_table_data)
{
    if (entry == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    TPSA_LOG_DEBUG("fe_key.fe_idx = %hu and tpf_name %s",
        entry->key.fe_idx, entry->key.tpf_name);

    TPSA_LOG_DEBUG("vtp src eid = " EID_FMT " and dst eid" EID_FMT "\n",
        EID_ARGS(key->src_eid), EID_ARGS(key->dst_eid));

    rm_vtp_table_entry_t *rm_entry = alloc_rm_vtp_table_entry(key, vtp_table_data);
    if (rm_entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa rm_vtp_table entry");
        return -ENOMEM;
    }

    tpsa_lm_vtp_entry_t lm_vtp_entry;
    lm_vtp_entry.trans_mode = TPSA_TP_RM;
    lm_vtp_entry.content.rm_entry = rm_entry;
    deid_vtp_table_key_t deid_key = {
        .dst_eid = key->dst_eid,
        .upi = rm_entry->upi,
        .trans_mode = TPSA_TP_RM,
    };
    /* Synchronize rm_entry to deid_vtp table */
    if (deid_vtp_list_add(deid_vtp_table, &lm_vtp_entry, &deid_key) != 0) {
        TPSA_LOG_ERR("deid vtp list add is failed");
        free(rm_entry);
        return -1;
    }

    HMAP_INSERT(&entry->rm_vtp_table, rm_entry, key, sizeof(*key));
    return 0;
}

/* rc_vtp_table alloc/create/add/remove/destroy opts */
static int rc_vtp_table_create(rc_vtp_table_t *rc_vtp_table)
{
    if (ub_hmap_init(&rc_vtp_table->hmap, TPSA_RC_VTP_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("rc_vtp_table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

static rc_vtp_table_entry_t *alloc_rc_vtp_table_entry(const rc_vtp_table_key_t *key,
                                                      tpsa_vtp_table_param_t *vtp_table_data)
{
    rc_vtp_table_entry_t *entry = (rc_vtp_table_entry_t *)calloc(1, sizeof(rc_vtp_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    entry->vtpn = vtp_table_data->vtpn;
    entry->tpgn = vtp_table_data->tpgn;
    entry->vice_tpgn = UINT32_MAX;
    entry->valid = vtp_table_data->valid;
    entry->location = vtp_table_data->location;
    entry->src_eid = vtp_table_data->local_eid;
    entry->src_jetty_id = vtp_table_data->local_jetty;
    entry->eid_index = vtp_table_data->eid_index;
    entry->migration_status = false;
    entry->upi = vtp_table_data->upi;
    entry->node_status = STATE_NORMAL;

    return entry;
}

void rc_vtp_table_destroy(rc_vtp_table_t *rc_vtp_table)
{
    HMAP_DESTROY(rc_vtp_table, rc_vtp_table_entry_t);
    return;
}

rc_vtp_table_entry_t *rc_vtp_table_lookup(rc_vtp_table_t *rc_vtp_table, rc_vtp_table_key_t *key)
{
    if (rc_vtp_table == NULL) {
        return NULL;
    }
    rc_vtp_table_entry_t *target = NULL;
    HMAP_FIND(rc_vtp_table, key, sizeof(*key), target);
    return target;
}

int rc_vtp_table_add(deid_vtp_table_t *deid_vtp_table, fe_table_entry_t *entry,
                     rc_vtp_table_key_t *key, tpsa_vtp_table_param_t *vtp_table_data)
{
    if (entry == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    rc_vtp_table_entry_t *rc_entry = alloc_rc_vtp_table_entry(key, vtp_table_data);
    if (rc_entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa rc_vtp_table entry");
        return -ENOMEM;
    }

    tpsa_lm_vtp_entry_t lm_vtp_entry;
    lm_vtp_entry.trans_mode = TPSA_TP_RC;
    lm_vtp_entry.content.rc_entry = rc_entry;

    deid_vtp_table_key_t deid_key = {
        .dst_eid = key->dst_eid,
        .upi = rc_entry->upi,
        .trans_mode = TPSA_TP_RC,
    };
    /* Synchronize rm_entry to deid_vtp table */
    if (deid_vtp_list_add(deid_vtp_table, &lm_vtp_entry, &deid_key) != 0) {
        TPSA_LOG_ERR("deid vtp list add is failed");
        free(rc_entry);
        return -ENOMEM;
    }

    HMAP_INSERT(&entry->rc_vtp_table, rc_entry, key, sizeof(*key));
    return 0;
}

/* um_vtp_table alloc/create/add/remove/destroy opts */
static um_vtp_table_entry_t *alloc_um_vtp_table_entry(const um_vtp_table_key_t *key, tpsa_um_vtp_table_param_t *uparam)
{
    um_vtp_table_entry_t *entry = (um_vtp_table_entry_t *)calloc(1, sizeof(um_vtp_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    entry->vtpn = uparam->vtpn;
    entry->utp_idx = uparam->utp_idx;
    entry->upi = uparam->upi;
    entry->use_cnt = 1;
    entry->migration_status = false;
    entry->node_status = STATE_NORMAL;
    entry->eid_index = uparam->eid_index;

    return entry;
}

static int um_vtp_table_create(um_vtp_table_t *um_vtp_table)
{
    if (ub_hmap_init(&um_vtp_table->hmap, TPSA_UM_VTP_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("um_vtp_table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void um_vtp_table_destroy(um_vtp_table_t *um_vtp_table)
{
    HMAP_DESTROY(um_vtp_table, um_vtp_table_entry_t);
    return;
}

um_vtp_table_entry_t *um_vtp_table_lookup(um_vtp_table_t *um_vtp_table, um_vtp_table_key_t *key)
{
    um_vtp_table_entry_t *target = NULL;
    HMAP_FIND(um_vtp_table, key, sizeof(*key), target);
    return target;
}

int um_vtp_table_add(deid_vtp_table_t *deid_vtp_table, fe_table_entry_t *entry, um_vtp_table_key_t *key,
                     tpsa_um_vtp_table_param_t *uparam)
{
    if (entry == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    um_vtp_table_entry_t *um_entry = alloc_um_vtp_table_entry(key, uparam);
    if (um_entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa um_vtp_table entry");
        return -ENOMEM;
    }

    tpsa_lm_vtp_entry_t lm_vtp_entry;
    lm_vtp_entry.trans_mode = TPSA_TP_UM;
    lm_vtp_entry.content.um_entry = um_entry;

    deid_vtp_table_key_t deid_key = {
        .dst_eid = key->dst_eid,
        .upi = um_entry->upi,
        .trans_mode = TPSA_TP_UM,
    };
    /* Synchronize rm_entry to deid_vtp table */
    if (deid_vtp_list_add(deid_vtp_table, &lm_vtp_entry, &deid_key) != 0) {
        TPSA_LOG_ERR("deid vtp list add is failed");
        free(um_entry);
        return -1;
    }

    HMAP_INSERT(&entry->um_vtp_table, um_entry, key, sizeof(*key));
    return 0;
}

void um_vtp_table_remove(fe_table_t *fe_table, deid_vtp_table_t *deid_vtp_table,
                         vport_key_t *fe_key, um_vtp_table_key_t *vtp_key)
{
    fe_table_entry_t *fe_entry = fe_table_lookup(fe_table, fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_ERR("fe entry is not exist when um vtp table remove");
        return;
    }

    um_vtp_table_entry_t *entry = um_vtp_table_lookup(&fe_entry->um_vtp_table, vtp_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key " EID_FMT ", " EID_FMT ", not exist in um_vtp_table",
                      EID_ARGS(vtp_key->src_eid), EID_ARGS(vtp_key->dst_eid));
        return;
    }

    /* Before deleting vtp entry, need to delete the corresponding node in the linked list. */
    deid_vtp_table_key_t deid_key = {
        .dst_eid = vtp_key->dst_eid,
        .upi = entry->upi,
        .trans_mode = TPSA_TP_UM,
    };
    deid_um_vtp_list_remove(deid_vtp_table, &deid_key, vtp_key);

    /* delete the vtp entry from um_vtp_table. */
    ub_hmap_remove(&fe_entry->um_vtp_table.hmap, &entry->node);
    free(entry);
    fe_table_remove(fe_table, fe_entry);
}

static clan_vtp_table_entry_t *alloc_clan_vtp_table_entry(const clan_vtp_table_key_t *key,
                                                          uint32_t vtpn, uint32_t ctp_idx)
{
    clan_vtp_table_entry_t *entry = (clan_vtp_table_entry_t *)calloc(1, sizeof(clan_vtp_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }

    entry->key = *key;
    entry->vtpn = vtpn;
    entry->ctp_idx = ctp_idx;
    entry->use_cnt = 1;
    entry->migration_status = false;

    return entry;
}

static int clan_vtp_table_create(clan_vtp_table_t *clan_vtp_table)
{
    if (ub_hmap_init(&clan_vtp_table->hmap, TPSA_CLAN_VTP_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("clan vtp table init failed");
        return -ENOMEM;
    }

    return 0;
}

void clan_vtp_table_destroy(clan_vtp_table_t *clan_vtp_table)
{
    HMAP_DESTROY(clan_vtp_table, clan_vtp_table_entry_t);
    return;
}

clan_vtp_table_entry_t *clan_vtp_table_lookup(clan_vtp_table_t *clan_vtp_table, clan_vtp_table_key_t *key)
{
    clan_vtp_table_entry_t *target = NULL;
    HMAP_FIND(clan_vtp_table, key, sizeof(*key), target);
    return target;
}

int clan_vtp_table_add(clan_vtp_table_t *clan_vtp_table, clan_vtp_table_key_t *key,
                       uint32_t vtpn, uint32_t ctp_idx)
{
    if (clan_vtp_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    clan_vtp_table_entry_t *entry = alloc_clan_vtp_table_entry(key, vtpn, ctp_idx);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa clan vtp table add");
        return -ENOMEM;
    }

    HMAP_INSERT(clan_vtp_table, entry, key, sizeof(*key));
    return 0;
}

void clan_vtp_table_remove(fe_table_t *fe_table, vport_key_t *fe_key, clan_vtp_table_key_t *vtp_key)
{
    fe_table_entry_t *fe_entry = fe_table_lookup(fe_table, fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_ERR("fe entry is not exist when clan_vtp_table_remove");
        return;
    }

    clan_vtp_table_entry_t *entry = clan_vtp_table_lookup(&fe_entry->clan_vtp_table, vtp_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key des ip " EID_FMT ", not exist in clan vtp table", EID_ARGS(vtp_key->dst_eid));
        return;
    }

    ub_hmap_remove(&fe_entry->clan_vtp_table.hmap, &entry->node);
    free(entry);
    fe_table_remove(fe_table, fe_entry);
}

/* fe_table alloc/create/add/remove/destroy opts */
static fe_table_entry_t *alloc_fe_table_entry(const vport_key_t *key)
{
    fe_table_entry_t *entry = (fe_table_entry_t *)calloc(1, sizeof(fe_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;

    entry->fe_rebooted = false;
    entry->stop_proc_vtp = false;
    entry->link_ready = false;
    entry->full_migrate = true;
    entry->time_start.tv_sec = 0;
    entry->time_start.tv_nsec = 0;
    entry->vtp_migrate_num = 0;

    /* when adding a node for first_level table, we should initialize the second-level table  */
    if (rm_vtp_table_create(&entry->rm_vtp_table) != 0) {
        TPSA_LOG_ERR("Failed to create rm_vtp_table");
        goto free_fe_entry;
    }

    if (rc_vtp_table_create(&entry->rc_vtp_table) != 0) {
        TPSA_LOG_ERR("Failed to create rc_vtp_table");
        goto free_rm_vtp_table;
    }

    if (um_vtp_table_create(&entry->um_vtp_table) != 0) {
        TPSA_LOG_ERR("Failed to create um_vtp_table");
        goto free_rc_vtp_table;
    }

    if (clan_vtp_table_create(&entry->clan_vtp_table) != 0) {
        TPSA_LOG_ERR("Failed to create clan vtp table");
        goto free_um_vtp_table;
    }

    return entry;

free_um_vtp_table:
    um_vtp_table_destroy(&entry->um_vtp_table);
free_rc_vtp_table:
    rc_vtp_table_destroy(&entry->rc_vtp_table);
free_rm_vtp_table:
    rm_vtp_table_destroy(&entry->rm_vtp_table);
free_fe_entry:
    free(entry);
    return NULL;
}

int fe_table_create(fe_table_t *fe_table)
{
    if (fe_table == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }
    if (ub_hmap_init(&fe_table->hmap, TPSA_FE_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("fe_table init failed.\n");
        return -ENOMEM;
    }
    fe_table->clean_res = false;
    (void)pthread_rwlock_init(&fe_table->rwlock, NULL);
    return 0;
}

fe_table_entry_t *fe_table_lookup(fe_table_t *fe_table, vport_key_t *key)
{
    if (fe_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }
    fe_table_entry_t *target = NULL;
    HMAP_FIND(fe_table, key, sizeof(*key), target);
    return target;
}

fe_table_entry_t *fe_table_add(fe_table_t *fe_table, vport_key_t *key)
{
    if (fe_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }

    fe_table_entry_t *entry = alloc_fe_table_entry(key);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa fe_table entry");
        return NULL;
    }

    HMAP_INSERT(fe_table, entry, key, sizeof(*key));
    return entry;
}

void fe_table_remove(fe_table_t *fe_table, fe_table_entry_t *fe_entry)
{
    if (fe_entry != NULL && fe_entry->rm_vtp_table.hmap.count == 0 && fe_entry->rc_vtp_table.hmap.count == 0 &&
        fe_entry->um_vtp_table.hmap.count == 0 && fe_entry->clan_vtp_table.hmap.count == 0) {
        ub_hmap_destroy(&fe_entry->rm_vtp_table.hmap);
        ub_hmap_destroy(&fe_entry->rc_vtp_table.hmap);
        ub_hmap_destroy(&fe_entry->um_vtp_table.hmap);
        ub_hmap_destroy(&fe_entry->clan_vtp_table.hmap);

        ub_hmap_remove(&fe_table->hmap, &fe_entry->node);
        free(fe_entry);
        fe_entry = NULL;
    }
}

/* rm_tpg_table alloc/create/add/remove/destroy opts */
static rm_tpg_table_entry_t *alloc_rm_tpg_table_entry(const rm_tpg_table_key_t *key,
    tpsa_tpg_table_param_t *param)
{
    rm_tpg_table_entry_t *entry = (rm_tpg_table_entry_t *)calloc(1, sizeof(rm_tpg_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    entry->type = param->type;
    entry->tpgn = param->tpgn;
    entry->tp_cnt = param->tp_cnt;
    (void)memcpy(entry->tp, param->tp,
        TPSA_MAX_TP_CNT_IN_GRP * sizeof(tp_entry_t));
    entry->status = param->status;
    entry->use_cnt = 1;
    return entry;
}

int rm_tpg_table_create(rm_tpg_table_t *rm_tpg_table)
{
    if (ub_hmap_init(&rm_tpg_table->hmap, TPSA_RM_TPG_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("rm_tpg_table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void rm_tpg_table_destroy(rm_tpg_table_t *rm_tpg_table)
{
    HMAP_DESTROY(rm_tpg_table, rm_tpg_table_entry_t);
    return;
}

rm_tpg_table_entry_t *rm_tpg_table_lookup(rm_tpg_table_t *rm_tpg_table, rm_tpg_table_key_t *key)
{
    rm_tpg_table_entry_t *target = NULL;
    HMAP_FIND(rm_tpg_table, key, sizeof(rm_tpg_table_key_t), target);
    return target;
}

int rm_tpg_table_update_tp_cnt(rm_tpg_table_t *rm_tpg_table, uvs_net_addr_info_t *sip,
                               uvs_net_addr_info_t *dip, uint32_t tp_cnt)
{
    if (rm_tpg_table == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    rm_tpg_table_key_t k = {.sip = sip->net_addr, .dip = dip->net_addr};

    /* Do not update if the entry doesn't exist */
    rm_tpg_table_entry_t *entry = rm_tpg_table_lookup(rm_tpg_table, &k);
    if (entry == NULL) {
        TPSA_LOG_WARN("Can't find tpg entry in rm tpg table");
        return -EINVAL;
    }
    entry->tp_cnt = tp_cnt;
    return 0;
}

int rm_tpg_table_add(rm_tpg_table_t *rm_tpg_table, rm_tpg_table_key_t *key,
    tpsa_tpg_table_param_t *param)
{
    if (rm_tpg_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* Do not add if the map entry already exists */
    if (rm_tpg_table_lookup(rm_tpg_table, key) != NULL) {
        TPSA_LOG_WARN("key sip " EID_FMT " dip " EID_FMT " already exist in rm_tpg_table",
            EID_ARGS(key->sip), EID_ARGS(key->dip));
        return 0;
    }

    rm_tpg_table_entry_t *entry = alloc_rm_tpg_table_entry(key, param);
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa rm_tpg_table entry");
        return -ENOMEM;
    }

    HMAP_INSERT(rm_tpg_table, entry, key, sizeof(*key));
    return 0;
}

int rm_tpg_table_remove(rm_tpg_table_t *rm_tpg_table, rm_tpg_table_key_t *key)
{
    rm_tpg_table_entry_t *entry = rm_tpg_table_lookup(rm_tpg_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key sip: " EID_FMT " dip: " EID_FMT " not exist in rm rpg table",
            EID_ARGS(key->sip), EID_ARGS(key->dip));
        return -ENXIO;
    }
    ub_hmap_remove(&rm_tpg_table->hmap, &entry->node);
    free(entry);
    return 0;
}

rm_tpg_table_entry_t **rm_tpg_table_get_all(rm_tpg_table_t *rm_tpg_table, uint32_t *tpg_cnt)
{
    rm_tpg_table_entry_t **tpg_list = NULL;
    rm_tpg_table_entry_t *cur;
    uint32_t cnt = 0;
    uint32_t i = 0;

    cnt = ub_hmap_count(&rm_tpg_table->hmap);
    if (cnt == 0) {
        *tpg_cnt = cnt;
        return NULL;
    }

    tpg_list = (rm_tpg_table_entry_t **)calloc(1, cnt * sizeof(rm_tpg_table_entry_t *));
    if (tpg_list == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa rm_tpg_table entry");
        return NULL;
    }

    HMAP_FOR_EACH(cur, node, &rm_tpg_table->hmap) {
        tpg_list[i++] = cur;
    }

    *tpg_cnt = cnt;
    return tpg_list;
}

/* rc_tpg_table alloc/create/add/remove/destroy opts */
static rc_tpg_table_entry_t *alloc_rc_tpg_table_entry(const rc_tpg_table_key_t *key,
    tpsa_tpg_table_param_t *param)
{
    rc_tpg_table_entry_t *entry = (rc_tpg_table_entry_t *)calloc(1, sizeof(rc_tpg_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    entry->type = param->type;
    entry->tpgn = param->tpgn;
    entry->vice_tpgn = UINT32_MAX;
    entry->tp_cnt = param->tp_cnt;
    (void)memcpy(entry->tp, param->tp, TPSA_MAX_TP_CNT_IN_GRP * sizeof(tp_entry_t));
    entry->status = param->status;
    entry->ljetty_id = param->ljetty_id;
    entry->leid = param->leid;
    entry->use_cnt = 1;
    return entry;
}

int rc_tpg_table_create(rc_tpg_table_t *rc_tpg_table)
{
    if (ub_hmap_init(&rc_tpg_table->hmap, TPSA_RC_TPG_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("rc_tpg_table init failed.\n");
        return -ENOMEM;
    }
    return 0;
}

void rc_tpg_table_destroy(rc_tpg_table_t *rc_tpg_table)
{
    HMAP_DESTROY(rc_tpg_table, rc_tpg_table_entry_t);
    return;
}

rc_tpg_table_entry_t *rc_tpg_table_lookup(rc_tpg_table_t *rc_tpg_table,
    rc_tpg_table_key_t *key)
{
    rc_tpg_table_entry_t *target = NULL;
    HMAP_FIND(rc_tpg_table, key, sizeof(rc_tpg_table_key_t), target);
    return target;
}

int rc_tpg_table_add(rc_tpg_table_t *rc_tpg_table, rc_tpg_table_key_t *key,
    tpsa_tpg_table_param_t *param)
{
    if (rc_tpg_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* Do not add if the entry already exists */
    if (rc_tpg_table_lookup(rc_tpg_table, key) != NULL) {
        TPSA_LOG_WARN("key djetty %d, deid " EID_FMT " already exist in rc_tpg",
            key->djetty_id, EID_ARGS(key->deid));
        return 0;
    }

    rc_tpg_table_entry_t *entry = alloc_rc_tpg_table_entry(key, param);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(rc_tpg_table, entry, key, sizeof(*key));
    return 0;
}

/* utp_table alloc/create/add/remove/destroy opts */
static utp_table_entry_t *alloc_utp_table_entry(const utp_table_key_t *key,
    uint32_t utp_idx)
{
    utp_table_entry_t *entry = (utp_table_entry_t *)calloc(1, sizeof(utp_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    entry->utp_idx = utp_idx;
    entry->use_cnt = 1;
    return entry;
}

int utp_table_create(utp_table_t *utp_table)
{
    if (ub_hmap_init(&utp_table->hmap, TPSA_UTP_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("utp_table init failed.\n");
        return -ENOMEM;
    }
    return 0;
}

void utp_table_destroy(utp_table_t *utp_table)
{
    HMAP_DESTROY(utp_table, utp_table_entry_t);
    return;
}

utp_table_entry_t *utp_table_lookup(utp_table_t *utp_table,
    utp_table_key_t *key)
{
    utp_table_entry_t *target = NULL;
    HMAP_FIND(utp_table, key, sizeof(*key), target);
    return target;
}

int utp_table_add(utp_table_t *utp_table, utp_table_key_t *key,
    uint32_t utp_idx)
{
    if (utp_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* Do not add if the entry already exists */
    if (utp_table_lookup(utp_table, key) != NULL) {
        TPSA_LOG_WARN("key sip: " EID_FMT ", dip: " EID_FMT " already exist in utp_table",
            EID_ARGS(key->sip.net_addr), EID_ARGS(key->dip.net_addr));
        return 0;
    }

    utp_table_entry_t *entry = alloc_utp_table_entry(key, utp_idx);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(utp_table, entry, key, sizeof(*key));
    return 0;
}

utp_table_entry_t **utp_table_get_all(utp_table_t *utp_table, uint32_t *utp_cnt)
{
    utp_table_entry_t **utp_list = NULL;
    utp_table_entry_t *cur;
    uint32_t cnt = 0;
    uint32_t i = 0;

    HMAP_FOR_EACH(cur, node, &utp_table->hmap) {
        cnt++;
    }

    if (cnt == 0) {
        *utp_cnt = cnt;
        return NULL;
    }

    utp_list = (utp_table_entry_t **)calloc(1, cnt * sizeof(utp_table_entry_t *));
    if (utp_list == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa utp_table entry");
        return NULL;
    }

    HMAP_FOR_EACH(cur, node, &utp_table->hmap) {
        utp_list[i++] = cur;
    }

    *utp_cnt = cnt;
    return utp_list;
}

int utp_table_remove(utp_table_t *utp_table, utp_table_key_t *key)
{
    utp_table_entry_t *entry = utp_table_lookup(utp_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key sip: " EID_FMT ", dip: " EID_FMT " not exist in utp_table",
            key->sip.net_addr, EID_ARGS(key->dip.net_addr));
        return -ENXIO;
    }
    ub_hmap_remove(&utp_table->hmap, &entry->node);
    free(entry);
    return 0;
}

/* ctp_table alloc/create/add/remove/destroy opts */
static ctp_table_entry_t *alloc_ctp_table_entry(const ctp_table_key_t *key, uint32_t ctp_idx)
{
    ctp_table_entry_t *entry = (ctp_table_entry_t *)calloc(1, sizeof(ctp_table_entry_t));

    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    entry->ctp_idx = ctp_idx;
    entry->use_cnt = 1;

    return entry;
}

int ctp_table_create(ctp_table_t *ctp_table)
{
    if (ub_hmap_init(&ctp_table->hmap, TPSA_CTP_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("ctp table init failed");
        return -ENOMEM;
    }

    return 0;
}

void ctp_table_destroy(ctp_table_t *ctp_table)
{
    HMAP_DESTROY(ctp_table, ctp_table_entry_t);
    return;
}

ctp_table_entry_t *ctp_table_lookup(ctp_table_t *ctp_table, ctp_table_key_t *key)
{
    ctp_table_entry_t *target = NULL;
    HMAP_FIND(ctp_table, key, sizeof(*key), target);
    return target;
}

int ctp_table_add(ctp_table_t *ctp_table, ctp_table_key_t *key, uint32_t ctp_idx)
{
    if (ctp_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* Do not add if the entry already exist */
    if (ctp_table_lookup(ctp_table, key) != NULL) {
        TPSA_LOG_WARN("key dip: " EID_FMT " already exist in ctp_table", EID_ARGS(key->dip.net_addr));
        return 0;
    }

    ctp_table_entry_t *entry = alloc_ctp_table_entry(key, ctp_idx);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(ctp_table, entry, key, sizeof(*key));
    return 0;
}

int ctp_table_remove(ctp_table_t *ctp_table, ctp_table_key_t *key)
{
    ctp_table_entry_t *entry = ctp_table_lookup(ctp_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key dip: " EID_FMT " not exist in ctp table", EID_ARGS(key->dip.net_addr));
        return -ENXIO;
    }

    ub_hmap_remove(&ctp_table->hmap, &entry->node);
    free(entry);
    return 0;
}

tpf_dev_table_entry_t *tpf_dev_table_lookup(tpf_dev_table_t *tpf_dev_table, tpf_dev_table_key_t *key)
{
    tpf_dev_table_entry_t *target = NULL;
    HMAP_FIND(tpf_dev_table, key, sizeof(*key), target);
    return target;
}

static tpf_dev_table_entry_t *alloc_tpf_dev_table_entry(const tpf_dev_table_key_t *key,
    tpf_dev_table_entry_t *add_entry)
{
    tpf_dev_table_entry_t *entry = (tpf_dev_table_entry_t *)calloc(1, sizeof(tpf_dev_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    sip_table_t *sip_table = (sip_table_t *)calloc(1, sizeof(sip_table_t));
    if (sip_table == NULL) {
        free(entry);
        return NULL;
    }
    entry->key = *key;
    (void)memcpy(entry->netdev_name, add_entry->netdev_name, UVS_MAX_DEV_NAME);
    entry->cc_entry_cnt = add_entry->cc_entry_cnt;
    entry->dev_fea = add_entry->dev_fea;
    (void)memcpy(entry->cc_array, add_entry->cc_array, sizeof(tpsa_cc_entry_t) * entry->cc_entry_cnt);
    entry->sip_table = sip_table;

    return entry;
}

int tpf_dev_table_add(tpf_dev_table_t *tpf_dev_table, tpf_dev_table_key_t *key, tpf_dev_table_entry_t *add_entry)
{
    if (tpf_dev_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&tpf_dev_table->rwlock);
    /* Do not add if the entry already exists */
    if (tpf_dev_table_lookup(tpf_dev_table, key) != NULL) {
        TPSA_LOG_ERR("tpf dev table with dev name %s already exist\n", key->dev_name);
        (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
        return 0;
    }

    tpf_dev_table_entry_t *entry = alloc_tpf_dev_table_entry(key, add_entry);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
        return -ENOMEM;
    }

    HMAP_INSERT(tpf_dev_table, entry, key, sizeof(*key));
    (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);

    TPSA_LOG_INFO("success add tpf dev table with dev name %s\n", key->dev_name);
    return 0;
}

int tpf_dev_table_remove(tpf_dev_table_t *tpf_dev_table, tpf_dev_table_key_t *key)
{
    if (tpf_dev_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&tpf_dev_table->rwlock);
    /* Find entry first */
    tpf_dev_table_entry_t *entry = tpf_dev_table_lookup(tpf_dev_table, key);
    if (entry == NULL) {
        TPSA_LOG_ERR("tpf dev table with dev name %s not exist\n", key->dev_name);
        (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
        return -EINVAL;
    }

    ub_hmap_remove(&tpf_dev_table->hmap, &entry->node);
    free(entry);
    (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);

    TPSA_LOG_INFO("success remove tpf dev table with dev name %s\n", key->dev_name);
    return 0;
}

int tpf_dev_table_create(tpf_dev_table_t *tpf_dev_table)
{
    if (ub_hmap_init(&tpf_dev_table->hmap, TPSA_TPF_DEV_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("tpf_dev_table init failed.\n");
        return -ENOMEM;
    }

    (void)pthread_rwlock_init(&tpf_dev_table->rwlock, NULL);
    return 0;
}

void tpf_dev_table_destroy(tpf_dev_table_t *tpf_dev_table)
{
    tpf_dev_table_entry_t *cur, *next;

    (void)pthread_rwlock_wrlock(&tpf_dev_table->rwlock);
    HMAP_FOR_EACH_SAFE(cur, next, node, &tpf_dev_table->hmap) {
        ub_hmap_remove(&tpf_dev_table->hmap, &cur->node);
        free(cur->sip_table);
        free(cur);
    }
    (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
    (void)pthread_rwlock_destroy(&tpf_dev_table->rwlock);
    ub_hmap_destroy(&tpf_dev_table->hmap);
    return;
}

/* vport_table alloc/create/add/remove/destroy opts */
static vport_table_entry_t *alloc_vport_table_entry(vport_table_entry_t *add_entry)
{
    vport_table_entry_t *entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    (void)memcpy(entry, add_entry, sizeof(vport_table_entry_t));
    return entry;
}

int vport_table_create(vport_table_t *vport_table)
{
    if (ub_hmap_init(&vport_table->hmap, TPSA_VPORT_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("vport_table init failed.\n");
        return -ENOMEM;
    }
    if (ub_hmap_init(&vport_table->eid_hmap, TPSA_EID_IDX_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("eid table init failed.\n");
        ub_hmap_destroy(&vport_table->hmap);
        return -ENOMEM;
    }
    if (ub_hmap_init(&vport_table->port_hmap, TPSA_VPORT_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("port table init failed.\n");
        ub_hmap_destroy(&vport_table->eid_hmap);
        ub_hmap_destroy(&vport_table->hmap);
        return -ENOMEM;
    }

    (void)pthread_rwlock_init(&vport_table->rwlock, NULL);
    vport_table->clean_res = false;

    return 0;
}

void vport_table_destroy(vport_table_t *vport_table)
{
    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    HMAP_DESTROY_INNER(&vport_table->hmap, vport_table_entry_t);
    HMAP_DESTROY_INNER(&vport_table->eid_hmap, ueid_table_entry_t);
    HMAP_DESTROY_INNER(&vport_table->port_hmap, port_table_entry_t);
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    (void)pthread_rwlock_destroy(&vport_table->rwlock);
    return;
}

/*
 * entry may del by other thread. The caller must lock the table
 * before lookup the entry and release the lock after the entry is used up.
 */
vport_table_entry_t *vport_table_lookup(vport_table_t *vport_table, vport_key_t *key)
{
    vport_table_entry_t *target = NULL;
    HMAP_FIND(vport_table, key, sizeof(*key), target);
    return target;
}

int ueid_table_find_nolock(vport_table_t *vport_table, urma_eid_t *eid, uint32_t upi,
                           vport_key_t *vport_key, uint32_t *eid_idx)
{
    ueid_key_t ueid_key = { .eid = *eid, .upi = upi };
    ueid_table_entry_t *target = NULL;

    HMAP_FIND_INNER(&vport_table->eid_hmap, &ueid_key, sizeof(ueid_key), target);
    if (target == NULL) {
        TPSA_LOG_WARN("can't find ueid eid " EID_FMT ", upi %u ", EID_ARGS(ueid_key.eid), ueid_key.upi);
        return -1;
    }

    *vport_key = target->vport_key;
    *eid_idx = target->eid_idx;
    return 0;
}

int port_table_find_nolock(vport_table_t *vport_table, uvs_vport_info_key_t *port_key,
                           vport_key_t *vport_key, uint32_t *eid_idx)
{
    port_table_entry_t *target = NULL;

    HMAP_FIND_INNER(&vport_table->port_hmap, port_key, sizeof(*port_key), target);
    if (target == NULL) {
        TPSA_LOG_WARN("failed to find port_key %s", port_key->name);
        return -1;
    }

    *vport_key = target->vport_key;
    *eid_idx = target->eid_idx;
    return 0;
}

int vport_set_deleting(vport_table_t *vport_table, vport_key_t *key, sem_t *sem)
{
    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    vport_table_entry_t *entry = vport_table_lookup(vport_table, key);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return -1;
    }
    entry->deleting = true;
    vport_table->clean_res = true;
    if (entry->sem != NULL && sem != NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_ERR("key dev_name:%s, fe_idx %hu is deleting by another thread", key->tpf_name, key->fe_idx);
        return -1;
    }
    entry->sem = sem;

    if (entry->ueid[0].entry != NULL) {
        free(entry->ueid[0].entry);
        entry->ueid[0].entry = NULL;
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    TPSA_LOG_INFO("key dev_name:%s, fe_idx %hu set to delete", key->tpf_name, key->fe_idx);
    return 0;
}

void vport_update_clean_res(vport_table_t *vport_table)
{
    bool clean_res = false;

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    vport_table_entry_t *cur, *next;
    HMAP_FOR_EACH_SAFE(cur, next, node, &vport_table->hmap) {
        clean_res = clean_res || cur->deleting;
    }

    vport_table->clean_res = clean_res;
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
}

bool vport_in_cleaning_proc(vport_table_t *vport_table, vport_key_t *key)
{
    bool vport_cleaning = false;
    (void)pthread_rwlock_rdlock(&vport_table->rwlock);
    vport_table_entry_t *entry = vport_table_lookup(vport_table, key);
    if (entry != NULL) {
        vport_cleaning = entry->deleting;
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    return vport_cleaning;
}

int ueid_table_add(vport_table_t *vport_table, vport_key_t *vport_key, uint32_t upi,
                   urma_eid_t eid, uint32_t eid_idx)
{
    ueid_key_t key = { .eid = eid, .upi = upi };

    ueid_table_entry_t *ueid_entry = NULL;
    HMAP_FIND_INNER(&vport_table->eid_hmap, &key, sizeof(key), ueid_entry);
    if (ueid_entry != NULL) {
        TPSA_LOG_INFO("ueid exist! eid " EID_FMT ", upi:%u, dev:%s, fe_idx:%u, ",
            EID_ARGS(key.eid), key.upi, ueid_entry->vport_key.tpf_name, ueid_entry->vport_key.fe_idx);
        return -1;
    }

    ueid_entry = (ueid_table_entry_t *)calloc(1, sizeof(ueid_table_entry_t));
    if (ueid_entry == NULL) {
        return -1;
    }

    ueid_entry->key = key;
    ueid_entry->vport_key = *vport_key;
    ueid_entry->eid_idx = eid_idx;
    HMAP_INSERT_INEER(&vport_table->eid_hmap, ueid_entry, &key, sizeof(key));
    return 0;
}

void ueid_table_rmv(vport_table_t *vport_table, urma_eid_t *eid, uint32_t upi)
{
    ueid_key_t key = { .eid = *eid, .upi = upi };

    ueid_table_entry_t *ueid_entry = NULL;
    HMAP_FIND_INNER(&vport_table->eid_hmap, &key, sizeof(key), ueid_entry);
    if (ueid_entry == NULL) {
        TPSA_LOG_WARN("ueid not exist! eid " EID_FMT ", upi:%u", EID_ARGS(key.eid), key.upi);
        return;
    }

    ub_hmap_remove(&vport_table->eid_hmap, &ueid_entry->node);
    free(ueid_entry);
}

int ueid_table_add_by_vport(vport_table_t *vport_table, vport_table_entry_t *add_entry)
{
    uint32_t i = 0;
    int ret = 0;

    for (;i < add_entry->ueid_max_cnt && i < TPSA_EID_IDX_TABLE_SIZE; i++) {
        if (!add_entry->ueid[i].is_valid) {
            continue;
        }
        ret = ueid_table_add(vport_table, &add_entry->key, add_entry->ueid[i].upi,
                             add_entry->ueid[i].eid, i);
        if (ret != 0) {
            break;
        }
    }

    if (ret != 0) {
        for (uint32_t j = 0; j < i && j < TPSA_EID_IDX_TABLE_SIZE; j++) {
            if (!add_entry->ueid[j].is_valid) {
                continue;
            }
            ueid_table_rmv(vport_table, &add_entry->ueid[j].eid, add_entry->ueid[j].upi);
        }
    }

    return ret;
}

void ueid_table_rmv_by_vport(vport_table_t *vport_table, vport_table_entry_t *vport_entry)
{
    for (uint32_t i = 0; i < vport_entry->ueid_max_cnt && i < TPSA_EID_IDX_TABLE_SIZE; i++) {
        if (!vport_entry->ueid[i].is_valid) {
            continue;
        }
        ueid_table_rmv(vport_table, &vport_entry->ueid[i].eid, vport_entry->ueid[i].upi);
    }
}

int port_table_add(vport_table_t *vport_table, vport_key_t *vport_key,
                   uvs_vport_info_key_t *port_key, uint32_t eid_idx)
{
    port_table_entry_t *port_entry = NULL;
    port_table_entry_t *exist_entry = NULL;
    HMAP_FIND_INNER(&vport_table->port_hmap, port_key, sizeof(uvs_vport_info_key_t), exist_entry);
    if (exist_entry != NULL) {
        TPSA_LOG_INFO("port exist! port key %s", port_key->name);
        return -1;
    }

    port_entry = (port_table_entry_t *)calloc(1, sizeof(port_table_entry_t));
    if (port_entry == NULL) {
        return -1;
    }

    port_entry->key = *port_key;
    port_entry->vport_key = *vport_key;
    port_entry->eid_idx = eid_idx;
    HMAP_INSERT_INEER(&vport_table->port_hmap, port_entry, port_key, sizeof(uvs_vport_info_key_t));
    return 0;
}

void port_table_rmv(vport_table_t *vport_table, uvs_vport_info_key_t *port_key)
{
    port_table_entry_t *port_entry = NULL;
    HMAP_FIND_INNER(&vport_table->port_hmap, port_key, sizeof(uvs_vport_info_key_t), port_entry);
    if (port_entry == NULL) {
        TPSA_LOG_WARN("port entry not exist! port name %s", port_key->name);
        return;
    }

    ub_hmap_remove(&vport_table->port_hmap, &port_entry->node);
    free(port_entry);
}

static int vport_table_clean_ueid(vport_table_entry_t *cur, uint32_t eid_idx,
    vport_table_t *vport_table)
{
    uint32_t i = eid_idx;
    tpsa_worker_t *uvs_worker = uvs_get_worker();

    if (cur->ueid[i].used && tpsa_ioctl_op_ueid(&uvs_worker->ioctl_ctx, TPSA_CMD_DEALLOC_EID,
        &cur->key, &cur->ueid[i], i) != 0) {
        TPSA_LOG_INFO("failed to dealloc eid, tpf_name %s, fe_idx %u\n",
            cur->key.tpf_name, cur->key.fe_idx);
        TPSA_LOG_INFO("failed to dealloc eid, eid " EID_FMT ", upi %u\n",
            EID_ARGS(cur->ueid[i].eid), cur->ueid[i].upi);
        return -1;
    }
    cur->ueid[i].used = false;
    if (cur->ueid[i].entry != NULL) {
        free(cur->ueid[i].entry);
        cur->ueid[i].entry = NULL;
    }
    cur->ueid[i].is_valid = false;
    ueid_table_rmv(vport_table, &cur->ueid[i].eid, cur->ueid[i].upi);
    if (cur->type == UVS_PORT_TYPE_UBSUBPORT) {
        TPSA_LOG_INFO("find and del subport by name %s\n", cur->port_key.name);
    }
    return 0;
}

int vport_table_find_del_by_info_key(vport_table_t *vport_table,
    uvs_vport_info_key_t *port_key)
{
    vport_table_entry_t *cur = NULL;
    vport_table_entry_t *next = NULL;
    int ret = -1;

    HMAP_FOR_EACH_SAFE(cur, next, node, &vport_table->hmap) {
        for (uint32_t i = 0; i < cur->ueid_max_cnt; i++) {
            if (cur->ueid[i].is_valid && cur->ueid[i].entry != NULL &&
                memcmp(&cur->ueid[i].entry->port_key, port_key,
                sizeof(uvs_vport_info_key_t)) == 0) {
                ret = vport_table_clean_ueid(cur, i, vport_table);
                break;
            }
        }
    }
    if (ret != 0) {
        TPSA_LOG_ERR("cannot find port by name %s\n", port_key->name);
    }
    return ret;
}

vport_table_entry_t *vport_table_lookup_by_info_key(vport_table_t *vport_table,
    uvs_vport_info_key_t *port_key)
{
    vport_table_entry_t *cur = NULL;
    vport_table_entry_t *next = NULL;
    vport_table_entry_t *target = NULL;
    HMAP_FOR_EACH_SAFE(cur, next, node, &vport_table->hmap) {
        if (memcmp(&cur->port_key, port_key, sizeof(uvs_vport_info_key_t)) == 0) {
            target = cur;
            TPSA_LOG_INFO("found vport by name %s\n", cur->port_key.name);
            break;
        }
        for (uint32_t i = 0; i < cur->ueid_max_cnt; i++) {
            if (cur->ueid[i].is_valid && cur->ueid[i].entry != NULL &&
                memcmp(&cur->ueid[i].entry->port_key, port_key,
                sizeof(uvs_vport_info_key_t)) == 0) {
                target = cur->ueid[i].entry;
                TPSA_LOG_INFO("found subport by name %s\n", cur->port_key.name);
                break;
            }
        }
    }
    if (target == NULL) {
        TPSA_LOG_ERR("cannot find port by name %s\n", port_key->name);
    }
    return target;
}

int vport_table_add(vport_table_t *vport_table, vport_table_entry_t *add_entry)
{
    if (vport_table == NULL || add_entry == NULL ||
        add_entry->ueid_max_cnt > TPSA_EID_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    /* Do not add if the entry already exists */
    if (vport_table_lookup(vport_table, &add_entry->key) != NULL) {
        TPSA_LOG_INFO("vport:%s-%hu already exist and deleting state %u\n", add_entry->key.tpf_name,
            add_entry->key.fe_idx, add_entry->deleting);
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return -EEXIST;
    }

    vport_table_entry_t *entry = alloc_vport_table_entry(add_entry);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return -ENOMEM;
    }
    entry->deleting = false;
    if (ueid_table_add_by_vport(vport_table, add_entry) != 0) {
        free(entry);
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_INFO("fail to add fe_idx: %s-%hu\n", add_entry->key.tpf_name, add_entry->key.fe_idx);
        return -EINVAL;
    }

    HMAP_INSERT(vport_table, entry, &entry->key, sizeof(vport_key_t));
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    TPSA_LOG_INFO("success add fe_idx: %s-%hu sip_idx %u\n", entry->key.tpf_name, entry->key.fe_idx, entry->sip_idx);
    return 0;
}

int vport_table_remove(vport_table_t *vport_table, vport_key_t *key)
{
    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    vport_table_entry_t *entry = vport_table_lookup(vport_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key dev_name:%s, fe_idx %hu not exist", key->tpf_name, key->fe_idx);
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del dev_name:%s fe_idx %hu sip_idx %u\n", key->tpf_name, key->fe_idx, entry->sip_idx);

    ueid_table_rmv_by_vport(vport_table, entry);

    ub_hmap_remove(&vport_table->hmap, &entry->node);

    if (entry->sem != NULL) {
        (void)sem_post(entry->sem);
    }
    free(entry);
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    return 0;
}

/* Deprecated, use vport_table_lookup_by_ueid_return_key instead */
int vport_table_lookup_by_ueid(vport_table_t *vport_table, uint32_t upi, urma_eid_t *eid,
    vport_table_entry_t *ret_entry)
{
    vport_table_entry_t *cur;
    uint32_t i;
    int ret = -1;

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    HMAP_FOR_EACH(cur, node, &vport_table->hmap) {
        for (i = 0; i < cur->ueid_max_cnt; i++) {
            if ((memcmp(&cur->ueid[i].eid, eid, sizeof(urma_eid_t)) == 0) && (cur->ueid[i].upi == upi)) {
                *ret_entry = *cur;
                ret = 0;
                break;
            }
        }
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    return ret;
}

int vport_table_lookup_by_ueid_return_key(vport_table_t *vport_table, uint32_t upi, urma_eid_t *eid,
                                          vport_key_t *key, uint32_t *eid_index)
{
    int ret = -1;
    (void)pthread_rwlock_rdlock(&vport_table->rwlock);
    ret = ueid_table_find_nolock(vport_table, eid, upi, key, eid_index);
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    return ret;
}

/* jetty peer table create/add/remove/lookup/destroy opts */
static jetty_peer_table_entry_t *alloc_jetty_peer_table_entry(const jetty_peer_table_key_t *key,
                                                              jetty_peer_table_param_t *parm)
{
    jetty_peer_table_entry_t *entry = (jetty_peer_table_entry_t *)calloc(1, sizeof(jetty_peer_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    entry->djetty_id = parm->djetty_id;
    entry->deid = parm->deid;

    return entry;
}

int jetty_peer_table_create(jetty_peer_table_t *jetty_peer_table)
{
    if (ub_hmap_init(&jetty_peer_table->hmap, TPSA_JETTY_PEER_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("jetty_peer_table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void jetty_peer_table_destroy(jetty_peer_table_t *jetty_peer_table)
{
    HMAP_DESTROY(jetty_peer_table, jetty_peer_table_entry_t);
    return;
}

jetty_peer_table_entry_t *jetty_peer_table_lookup(jetty_peer_table_t *jetty_peer_table,
                                                  jetty_peer_table_key_t *key)
{
    jetty_peer_table_entry_t *target = NULL;
    HMAP_FIND(jetty_peer_table, key, sizeof(*key), target);
    return target;
}

int jetty_peer_table_add(jetty_peer_table_t *jetty_peer_table, jetty_peer_table_param_t *parm)
{
    if (jetty_peer_table == NULL || parm == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    jetty_peer_table_key_t key = {
        .ljetty_id = parm->ljetty_id,
        .seid = parm->seid,
    };

    /* Do not add if the entry already exists */
    if (jetty_peer_table_lookup(jetty_peer_table, &key) != NULL) {
        TPSA_LOG_ERR("sjetty %u seid:" EID_FMT " already exist\n", key.ljetty_id, EID_ARGS(key.seid));
        return 0;
    }

    jetty_peer_table_entry_t *entry = alloc_jetty_peer_table_entry(&key, parm);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(jetty_peer_table, entry, &key, sizeof(key));
    TPSA_LOG_INFO("success add sjetty %u, seid:" EID_FMT ", djetty %u, deid:" EID_FMT "\n",
        parm->ljetty_id, EID_ARGS(parm->seid), parm->djetty_id, EID_ARGS(parm->deid));
    return 0;
}

void jetty_peer_table_remove(jetty_peer_table_t *jetty_peer_table, jetty_peer_table_key_t *key)
{
    jetty_peer_table_entry_t *entry = jetty_peer_table_lookup(jetty_peer_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key sjetty_id %u seid:" EID_FMT " not exist", key->ljetty_id, EID_ARGS(key->seid));
        return;
    }

    TPSA_LOG_INFO("success del sjetty %u, seid:" EID_FMT ", djetty %u, deid:" EID_FMT "\n",
        key->ljetty_id, EID_ARGS(key->seid), entry->djetty_id, EID_ARGS(entry->deid));

    ub_hmap_remove(&jetty_peer_table->hmap, &entry->node);
    free(entry);
}

/* rm_wait_table create/add/remove/lookup/destroy opts */
static rm_wait_table_entry_t *alloc_rm_wait_table_entry(const rm_wait_table_key_t *key,
                                                        rm_wait_table_entry_t *add_entry)
{
    rm_wait_table_entry_t *entry = (rm_wait_table_entry_t *)calloc(1, sizeof(rm_wait_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    (void)memcpy(&entry->cparam, &add_entry->cparam, sizeof(tpsa_create_param_t));

    return entry;
}

int rm_wait_table_create(rm_wait_table_t *rm_wait_table)
{
    if (ub_hmap_init(&rm_wait_table->hmap, TPSA_RM_WAIT_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("rm_wait_table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void rm_wait_table_destroy(rm_wait_table_t *rm_wait_table)
{
    HMAP_DESTROY(rm_wait_table, rm_wait_table_entry_t);
    return;
}

rm_wait_table_entry_t *rm_wait_table_lookup(rm_wait_table_t *rm_table, rm_wait_table_key_t *key)
{
    rm_wait_table_entry_t *target = NULL;
    HMAP_FIND(rm_table, key, sizeof(*key), target);
    return target;
}

int rm_wait_table_add(rm_wait_table_t *rm_table, rm_wait_table_key_t *key,
                      rm_wait_table_entry_t *add_entry)
{
    if (rm_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    rm_wait_table_entry_t *entry = alloc_rm_wait_table_entry(key, add_entry);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(rm_table, entry, key, sizeof(*key));
    TPSA_LOG_INFO("add one entry to rm_wait_table: dip " EID_FMT "\n", EID_ARGS(key->dip));
    return 0;
}

int rm_wait_table_remove(rm_wait_table_t *rm_table, rm_wait_table_key_t *key)
{
    rm_wait_table_entry_t *entry = rm_wait_table_lookup(rm_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key dip " EID_FMT " not exist", EID_ARGS(key->dip));
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del dip " EID_FMT "\n", EID_ARGS(key->dip));

    ub_hmap_remove(&rm_table->hmap, &entry->node);
    free(entry);
    return 0;
}

int rm_wait_table_pop(rm_wait_table_t *rm_table, rm_wait_table_key_t *key,
                      rm_wait_table_entry_t *pop_entry)
{
    rm_wait_table_entry_t *entry = rm_wait_table_lookup(rm_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key dip " EID_FMT " not exist", EID_ARGS(key->dip));
        return -ENXIO;
    }

    *pop_entry = *entry;

    ub_hmap_remove(&rm_table->hmap, &entry->node);
    free(entry);
    return 0;
}

/* rc_wait_table create/add/remove/lookup/destroy opts */
static rc_wait_table_entry_t *alloc_rc_wait_table_entry(const rc_wait_table_key_t *key,
                                                        rc_wait_table_entry_t *add_entry)
{
    rc_wait_table_entry_t *entry = (rc_wait_table_entry_t *)calloc(1, sizeof(rc_wait_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = *key;
    (void)memcpy(&entry->cparam, &add_entry->cparam, sizeof(tpsa_create_param_t));

    return entry;
}

int rc_wait_table_create(rc_wait_table_t *rc_wait_table)
{
    if (ub_hmap_init(&rc_wait_table->hmap, TPSA_RC_WAIT_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("rc_wait_table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

void rc_wait_table_destroy(rc_wait_table_t *rc_wait_table)
{
    HMAP_DESTROY(rc_wait_table, rc_wait_table_entry_t);
    return;
}

rc_wait_table_entry_t *rc_wait_table_lookup(rc_wait_table_t *rc_table, rc_wait_table_key_t *key)
{
    rc_wait_table_entry_t *target = NULL;
    HMAP_FIND(rc_table, key, sizeof(*key), target);
    return target;
}

int rc_wait_table_add(rc_wait_table_t *rc_table, rc_wait_table_key_t *key,
                      rc_wait_table_entry_t *add_entry)
{
    if (rc_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    rc_wait_table_entry_t *entry = alloc_rc_wait_table_entry(key, add_entry);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(rc_table, entry, key, sizeof(*key));
    TPSA_LOG_INFO("add one entry to rc_wait_table: deid " EID_FMT " djetty %d\n",
                  EID_ARGS(key->deid), key->djetty_id);
    return 0;
}

int rc_wait_table_remove(rc_wait_table_t *rc_table, rc_wait_table_key_t *key)
{
    rc_wait_table_entry_t *entry = rc_wait_table_lookup(rc_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key deid " EID_FMT " djetty %d not exist",
                      EID_ARGS(key->deid), key->djetty_id);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del deid " EID_FMT " djetty %d \n",
                  EID_ARGS(key->deid), key->djetty_id);

    ub_hmap_remove(&rc_table->hmap, &entry->node);
    free(entry);
    return 0;
}

int rc_wait_table_pop(rc_wait_table_t *rc_table, rc_wait_table_key_t *key,
                      rc_wait_table_entry_t *pop_entry)
{
    rc_wait_table_entry_t *entry = rc_wait_table_lookup(rc_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key deid " EID_FMT " djetty %d not exist",
                      EID_ARGS(key->deid), key->djetty_id);
        return -ENXIO;
    }

    *pop_entry = *entry;

    ub_hmap_remove(&rc_table->hmap, &entry->node);
    free(entry);
    return 0;
}

int dip_update_list_add(struct ub_list *list, dip_table_key_t *key,
    uvs_net_addr_info_t *old_dip, uvs_net_addr_info_t *new_dip)
{
    dip_update_entry_t *entry = (dip_update_entry_t *)calloc(1, sizeof(dip_update_entry_t));
    if (entry == NULL) {
        return -ENOMEM;
    }
    entry->key = *key;
    entry->new_dip = *new_dip;
    entry->old_dip = *old_dip;
    ub_list_push_back(list, &entry->node);
    return 0;
}

void dip_update_list_rmv(dip_update_entry_t *entry)
{
    ub_list_remove(&entry->node);
    free(entry);
}

dip_update_entry_t *dip_update_list_lookup(struct ub_list *list, dip_table_key_t *key)
{
    dip_update_entry_t *cur, *next;
    dip_update_entry_t *target = NULL;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        if (memcmp(&cur->key, key, sizeof(dip_table_key_t)) != 0) {
            continue;
        }
        target = cur;
        break;
    }
    return target;
}

void dip_update_list_clear(struct ub_list *list)
{
    dip_update_entry_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        ub_list_remove(&cur->node);
        free(cur);
    }
}

int dip_table_create(dip_table_t *dip_table)
{
    if (ub_hmap_init(&dip_table->hmap, TPSA_DIP_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("dip_table init failed.\n");
        return -ENOMEM;
    }

    dip_table->tbl_refresh = false;
    ub_list_init(&dip_table->dip_update_list);
    (void)pthread_rwlock_init(&dip_table->rwlock, NULL);

    return 0;
}

void dip_table_destroy(dip_table_t *dip_table)
{
    (void)pthread_rwlock_wrlock(&dip_table->rwlock);
    dip_table->tbl_refresh = false;
    dip_update_list_clear(&dip_table->dip_update_list);
    HMAP_DESTROY(dip_table, dip_table_entry_t);
    (void)pthread_rwlock_unlock(&dip_table->rwlock);
    (void)pthread_rwlock_destroy(&dip_table->rwlock);
    return;
}

static dip_table_entry_t *alloc_dip_table_entry(const dip_table_key_t *key,
    dip_table_entry_t *add_entry)
{
    dip_table_entry_t *entry = (dip_table_entry_t *)calloc(1, sizeof(dip_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->key = add_entry->key;
    entry->peer_uvs_ip = add_entry->peer_uvs_ip;
    entry->netaddr = add_entry->netaddr;

    return entry;
}

dip_table_entry_t *dip_table_lookup(dip_table_t *dip_table, dip_table_key_t *key)
{
    dip_table_entry_t *cur;
    dip_table_entry_t *target = NULL;

    uint32_t hash = ub_hash_bytes(key, sizeof(dip_table_key_t), 0);
    HMAP_FOR_EACH_WITH_HASH(cur, node, hash, &dip_table->hmap) {
        if (memcmp(&cur->key, key, sizeof(dip_table_key_t)) == 0) {
            target = cur;
            break;
        }
    }
    return target;
}

int dip_table_add(dip_table_t *dip_table, dip_table_key_t *key, dip_table_entry_t *add_entry)
{
    if (dip_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&dip_table->rwlock);
    /* Do not add if the entry already exists */
    if (dip_table_lookup(dip_table, key) != NULL) {
        TPSA_LOG_INFO("dip with eid " EID_FMT " and upi %u alread exist\n",
            EID_ARGS(key->deid), key->upi);
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        return -EEXIST;
    }

    dip_table_entry_t *entry = alloc_dip_table_entry(key, add_entry);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        return -1;
    }

    HMAP_INSERT(dip_table, entry, key, sizeof(*key));
    (void)pthread_rwlock_unlock(&dip_table->rwlock);

    TPSA_LOG_INFO("success add dip EID " EID_FMT " and upi %u\n",
        EID_ARGS(key->deid), key->upi);
    return 0;
}

int dip_table_remove(dip_table_t *dip_table, dip_table_key_t *key)
{
    (void)pthread_rwlock_wrlock(&dip_table->rwlock);
    dip_table_entry_t *entry = dip_table_lookup(dip_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("dip " EID_FMT " and upi %u not exist",
            EID_ARGS(key->deid), key->upi);
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del dip " EID_FMT " and upi %u\n",
        EID_ARGS(key->deid), key->upi);

    ub_hmap_remove(&dip_table->hmap, &entry->node);
    free(entry);
    (void)pthread_rwlock_unlock(&dip_table->rwlock);
    return 0;
}

int dip_table_add_update_list(dip_table_t *dip_table, dip_table_key_t *key,
    uvs_net_addr_info_t *old_dip, uvs_net_addr_info_t *new_dip)
{
    int ret = 0;
    dip_update_entry_t *entry = dip_update_list_lookup(&dip_table->dip_update_list, key);
    if (entry != NULL) { // this should not happen
        ret = -EEXIST;
        TPSA_LOG_ERR("Dip table update list exist! eid: " EID_FMT ", upi:%u\n", EID_ARGS(key->deid), key->upi);
        return ret;
    }

    ret = dip_update_list_add(&dip_table->dip_update_list, key, old_dip, new_dip);
    if (ret != 0) {
        TPSA_LOG_ERR("Dip table update list fail! eid: " EID_FMT ", upi:%u\n", EID_ARGS(key->deid), key->upi);
        return ret;
    }
    dip_table->tbl_refresh = true;
    return ret;
}

int dip_table_rmv_update_list(dip_table_t *dip_table, dip_table_key_t *key)
{
    dip_update_entry_t *entry = dip_update_list_lookup(&dip_table->dip_update_list, key);
    if (entry == NULL) {
        TPSA_LOG_ERR("Dip table update list not exist! eid: " EID_FMT ", upi:%u\n", EID_ARGS(key->deid), key->upi);
        return -1;
    }

    dip_update_list_rmv(entry);
    return 0;
}

void dip_table_clear_update_list(dip_table_t *dip_table)
{
    dip_update_list_clear(&dip_table->dip_update_list);
}

int dip_table_modify(dip_table_t *dip_table, dip_table_key_t *old_key,
    dip_table_entry_t *new_entry, dip_table_modify_mask_t mask)
{
    dip_table_entry_t *old_entry = NULL;

    (void)pthread_rwlock_wrlock(&dip_table->rwlock);
    old_entry = dip_table_lookup(dip_table, old_key);
    if (old_entry == NULL) {
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        TPSA_LOG_ERR("can not find dip by key: " EID_FMT " and upi %u\n",
            EID_ARGS(old_key->deid), old_key->upi);
        return -ENXIO;
    }

    if (memcmp(&old_entry->netaddr, &new_entry->netaddr, sizeof(uvs_net_addr_info_t)) != 0) {
        /* Mark refresh old_entry */
        if (dip_table_add_update_list(dip_table, &old_entry->key, &old_entry->netaddr, &new_entry->netaddr) != 0) {
            (void)pthread_rwlock_unlock(&dip_table->rwlock);
            TPSA_LOG_ERR("can not update dip by key: " EID_FMT " and upi %u\n",
                EID_ARGS(old_key->deid), old_key->upi);
            return -1;
        }
    }

    ub_hmap_remove(&dip_table->hmap, &old_entry->node);

    old_entry->key.deid = (mask.bs.eid == 0 ? old_entry->key.deid : new_entry->key.deid);
    old_entry->key.upi = (mask.bs.upi == 0 ? old_entry->key.upi : new_entry->key.upi);
    old_entry->peer_uvs_ip = (mask.bs.uvs_ip == 0 ? old_entry->peer_uvs_ip : new_entry->peer_uvs_ip);
    old_entry->netaddr = (mask.bs.net_addr == 0 ? old_entry->netaddr : new_entry->netaddr);

    HMAP_INSERT(dip_table, old_entry, &old_entry->key, sizeof(dip_table_key_t));
    (void)pthread_rwlock_unlock(&dip_table->rwlock);
    return 0;
}

/*
 * entry may del by other thread. The caller must lock the table
 * before lookup the entry and release the lock after the entry is used up.
 */

/* sip table */
int tpsa_sip_table_lookup(tpf_dev_table_t *tpf_dev_table, char *tpf_name, uint32_t sip_idx,
    sip_table_entry_t *target_entry)
{
    tpf_dev_table_entry_t tpf_dev_table_entry;
    sip_table_entry_t *entry;
    sip_table_t *sip_table;

    if (sip_idx >= TPSA_SIP_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }
    (void)pthread_rwlock_rdlock(&tpf_dev_table->rwlock);
    if (tpsa_lookup_tpf_dev_table(tpf_name, tpf_dev_table, &tpf_dev_table_entry) != 0) {
        (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
        TPSA_LOG_ERR("Failed to lookup tpf_dev: %s\n", tpf_name);
        return -1;
    }
    sip_table = tpf_dev_table_entry.sip_table;
    if (sip_table->entries[sip_idx].used == false) {
        (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
        TPSA_LOG_ERR("No valid sip found");
        return -1;
    }
    entry = &sip_table->entries[sip_idx];
    (void)memcpy(target_entry, entry, sizeof(sip_table_entry_t));
    (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
    return 0;
}

int tpsa_sip_table_add(tpf_dev_table_t *tpf_dev_table, uint32_t sip_idx, sip_table_entry_t *entry_add)
{
    tpf_dev_table_entry_t tpf_dev_table_entry;
    sip_table_entry_t *entry;
    int ret;

    if (sip_idx >= TPSA_SIP_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }
    (void)pthread_rwlock_wrlock(&tpf_dev_table->rwlock);
    ret = tpsa_lookup_tpf_dev_table(entry_add->dev_name, tpf_dev_table, &tpf_dev_table_entry);
    if (ret != 0) {
        (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
        TPSA_LOG_ERR("No available tpf table found");
        return -ENXIO;
    }
    entry = &tpf_dev_table_entry.sip_table->entries[sip_idx];
    if (entry->used == true) {
        (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
        TPSA_LOG_ERR("sip_index: [%s-%u] already exist", entry_add->dev_name, sip_idx);
        return -EEXIST;
    }

    (void)memcpy(entry, entry_add, sizeof(sip_table_entry_t));
    entry->used = true;
    (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
    TPSA_LOG_INFO("success add sip_idx: [%s-%u] to table\n", entry_add->dev_name, sip_idx);
    return 0;
}

int tpsa_sip_table_del(tpf_dev_table_t *tpf_dev_table, char *tpf_key, uint32_t sip_idx)
{
    tpf_dev_table_entry_t tpf_dev_table_entry;
    sip_table_entry_t *entry;

    if (sip_idx >= TPSA_SIP_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }
    (void)pthread_rwlock_wrlock(&tpf_dev_table->rwlock);
    if (tpsa_lookup_tpf_dev_table(tpf_key, tpf_dev_table, &tpf_dev_table_entry) == 0) {
        entry = &tpf_dev_table_entry.sip_table->entries[sip_idx];
        if (entry->used == true) {
            (void)memset(entry, 0, sizeof(sip_table_entry_t));
            (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
            TPSA_LOG_INFO("success del sip_idx: [%s-%u] from table\n", tpf_key, sip_idx);
            return 0;
        }
    }
    (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
    TPSA_LOG_ERR("sip_idx: [%s-%u] not exist", tpf_key, sip_idx);
    return -ENXIO;
}

int tpsa_sip_table_query_unused_idx(tpsa_table_t *table_ctx, char *tpf_key, uint32_t *sip_idx)
{
    tpf_dev_table_entry_t return_entry;
    uint32_t index = 0;
    int ret = -1;

    (void)pthread_rwlock_rdlock(&table_ctx->tpf_dev_table.rwlock);
    ret = tpsa_lookup_tpf_dev_table(tpf_key, &table_ctx->tpf_dev_table, &return_entry);
    if (ret != 0) {
        (void)pthread_rwlock_unlock(&table_ctx->tpf_dev_table.rwlock);
        TPSA_LOG_ERR("tpf table not found");
        return -1;
    }
    sip_table_t *sip_table = return_entry.sip_table;
    while (index < TPSA_SIP_IDX_TABLE_SIZE && sip_table->entries[index].used == true) {
        index++;
    }
    (void)pthread_rwlock_unlock(&table_ctx->tpf_dev_table.rwlock);

    if (index == TPSA_SIP_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("failed to add sip entry to sip table\n");
        return -1;
    }
    *sip_idx = index;

    return 0;
}

int tpsa_sip_lookup_by_entry(tpsa_table_t *table_ctx, char *tpf_key, sip_table_entry_t *add_entry,
                             uint32_t *sip_idx)
{
    tpf_dev_table_entry_t return_entry;
    uint32_t index;
    int ret = -1;

    (void)pthread_rwlock_rdlock(&table_ctx->tpf_dev_table.rwlock);
    ret = tpsa_lookup_tpf_dev_table(tpf_key, &table_ctx->tpf_dev_table, &return_entry);
    if (ret != 0) {
        (void)pthread_rwlock_unlock(&table_ctx->tpf_dev_table.rwlock);
        TPSA_LOG_ERR("tpf table not found");
        return -1;
    }

    sip_table_t *sip_table = return_entry.sip_table;
    for (index = 0; index < TPSA_SIP_IDX_TABLE_SIZE; index++) {
        if (sip_table->entries[index].used == false) {
            continue;
        }

        if (memcmp(&sip_table->entries[index], add_entry, sizeof(sip_table_entry_t)) == 0) {
            *sip_idx = index;
            (void)pthread_rwlock_unlock(&table_ctx->tpf_dev_table.rwlock);
            return EEXIST;
        }
    }

    (void)pthread_rwlock_unlock(&table_ctx->tpf_dev_table.rwlock);

    return 0;
}

sip_table_entry_t *tpsa_get_sip_entry_list(tpsa_table_t *table_ctx, char *tpf_key, uint32_t *max_sip_cnt)
{
    tpf_dev_table_entry_t return_entry;
    sip_table_entry_t *sip_entry_list;
    uint32_t valid_cnt = 0;
    uint32_t sip_idx = 0;
    int ret = -1;

    sip_entry_list = (sip_table_entry_t *)calloc(1, sizeof(sip_table_entry_t) * TPSA_SIP_IDX_TABLE_SIZE);
    if (sip_entry_list == NULL) {
        return NULL;
    }
    (void)pthread_rwlock_rdlock(&table_ctx->tpf_dev_table.rwlock);
    ret = tpsa_lookup_tpf_dev_table(tpf_key, &table_ctx->tpf_dev_table, &return_entry);
    if (ret != 0) {
        (void)pthread_rwlock_unlock(&table_ctx->tpf_dev_table.rwlock);
        free(sip_entry_list);
        TPSA_LOG_ERR("tpf table not found");
        return NULL;
    }
    sip_table_t *sip_table = return_entry.sip_table;
    for (sip_idx = 0; sip_idx < TPSA_SIP_IDX_TABLE_SIZE; ++sip_idx) {
        if (sip_table->entries[sip_idx].used == false) {
            continue;
        }
        (void)memcpy(&sip_entry_list[valid_cnt], &sip_table->entries[sip_idx],
            sizeof(sip_table_entry_t));
        valid_cnt++;
    }
    *max_sip_cnt = valid_cnt;
    (void)pthread_rwlock_unlock(&table_ctx->tpf_dev_table.rwlock);

    return sip_entry_list;
}

void tpsa_free_sip_entry_list(sip_table_entry_t *sip_entry_list)
{
    if (sip_entry_list != NULL) {
        free(sip_entry_list);
    }
}

static tpsa_ueid_t *vport_ueid_tbl_lookup_entry(vport_table_entry_t *entry, uint32_t ueid_index)
{
    if (ueid_index >= entry->ueid_max_cnt || entry->ueid[ueid_index].is_valid == false) {
        TPSA_LOG_ERR("eid index does not exist, idx: %u, max_cnt: %u.\n",
            ueid_index, entry->ueid_max_cnt);
        return NULL;
    }
    return &entry->ueid[ueid_index];
}

int vport_ueid_tbl_add_entry(vport_table_entry_t *entry, tpsa_ueid_cfg_t *ueid,
    vport_table_entry_t *port_entry)
{
    /* No need to check null_ptr for port_entry as it cannot be NULL currently */
    uint32_t eid_idx = ueid->eid_index;

    if (eid_idx >= entry->ueid_max_cnt) {
        TPSA_LOG_ERR("The eid index is an invalid value, max_eid_cnt: %u.\n", entry->ueid_max_cnt);
        return -EINVAL;
    }
    if (entry->ueid[eid_idx].is_valid == true) {
        TPSA_LOG_ERR("eid_idx: %u has been mapped ueid: (eid " EID_FMT " upi %u)\n", eid_idx,
            EID_ARGS(entry->ueid[eid_idx].eid), entry->ueid[eid_idx].upi);
        return -EEXIST;
    }
    for (uint32_t i = 0; i < entry->ueid_max_cnt; i++) {
        if (entry->ueid[i].is_valid == true &&
            entry->ueid[i].upi == ueid->upi &&
            memcmp(&entry->ueid[i].eid, &ueid->eid, sizeof(urma_eid_t)) == 0) {
            TPSA_LOG_ERR("ueid: (eid " EID_FMT " upi %u) has mapped eid_idx: %u\n",
                EID_ARGS(entry->ueid[i].eid), entry->ueid[i].upi, i);
            return -EEXIST;
        }
    }
    entry->ueid[eid_idx].eid = ueid->eid;
    entry->ueid[eid_idx].upi = ueid->upi;
    entry->ueid[eid_idx].uuid = ueid->uuid;
    entry->ueid[eid_idx].is_valid = true;
    entry->ueid[eid_idx].used = false;
    TPSA_LOG_INFO("parent entry: name %s, tpf_name %s, fe_idx %u\n",
        entry->port_key.name, entry->key.tpf_name, entry->key.fe_idx);
    TPSA_LOG_INFO("add port entry: name %s, eid_idx %u, upi %u, eid " EID_FMT "\n",
        port_entry->port_key.name, eid_idx, entry->ueid[eid_idx].upi,
        EID_ARGS(entry->ueid[eid_idx].eid));
    entry->ueid[eid_idx].entry = port_entry;

    return 0;
}

int vport_ueid_tbl_del_entry(vport_table_entry_t *entry, uint32_t ueid_index)
{
    if (ueid_index >= entry->ueid_max_cnt || entry->ueid[ueid_index].is_valid == false) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }
    if (entry->ueid[ueid_index].entry != NULL) {
        free(entry->ueid[ueid_index].entry);
        entry->ueid[ueid_index].entry = NULL;
    }
    return 0;
}

tpsa_ueid_t *vport_table_lookup_ueid(vport_table_t *vport_table, vport_key_t *key, uint32_t ueid_index)
{
    vport_table_entry_t *entry;
    tpsa_ueid_t *ueid = NULL;

    if (vport_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    entry = vport_table_lookup(vport_table, key);
    if (entry != NULL) {
        ueid = vport_ueid_tbl_lookup_entry(entry, ueid_index);
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    if (entry == NULL || ueid == NULL) {
        TPSA_LOG_ERR("vport entry does not exist or ueid entry is empty.\n");
        return NULL;
    }
    TPSA_LOG_INFO("fe_idx[%hu] lookup ueid_index %u\n", key->fe_idx, ueid_index);
    return ueid;
}

int vport_table_add_ueid(vport_table_t *vport_table, vport_key_t *key, tpsa_ueid_cfg_t *ueid)
{
    vport_table_entry_t *entry = NULL;
    if (vport_table == NULL || key == NULL || ueid == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }
    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    entry = vport_table_lookup(vport_table, key);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_ERR("failed to find vport table\n");
        return -EINVAL;
    }
    vport_table_entry_t *port_entry = NULL;
    port_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (port_entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_ERR("failed to calloc port entry\n");
        return -EINVAL;
    }
    (void)memcpy(port_entry,
        entry, sizeof(vport_table_entry_t));
    if (vport_ueid_tbl_add_entry(entry, ueid, port_entry) != 0) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_ERR("failed to add ueid entry.\n");
        free(port_entry);
        return -EINVAL;
    }
    if (ueid_table_add(vport_table, key, ueid->upi, ueid->eid,
                       ueid->eid_index) != 0) {
        entry->ueid[ueid->eid_index].entry = NULL;
        entry->ueid[ueid->eid_index].is_valid = false;
        free(port_entry);
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_ERR("failed to add ueid, dev_name:%s fe_idx:%d\n", key->tpf_name, key->fe_idx);
        return -EINVAL;
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    TPSA_LOG_INFO("fe_idx[%hu] add ueid_index %d\n", key->fe_idx, ueid->eid_index);
    return 0;
}

int vport_table_del_ueid(vport_table_t *vport_table, vport_key_t *key, uint32_t eid_index)
{
    vport_table_entry_t *entry = NULL;
    int ret = 0;

    if (vport_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    entry = vport_table_lookup(vport_table, key);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_ERR("vport entry does not exist or ueid entry is empty.\n");
        return -EINVAL;
    }

    tpsa_ueid_t *ueid = vport_ueid_tbl_lookup_entry(entry, eid_index);
    if (ueid != NULL) {
        ueid_table_rmv(vport_table, &ueid->eid, ueid->upi);
        ueid = NULL;
    }

    if (eid_index >= entry->ueid_max_cnt || entry->ueid[eid_index].is_valid == false) {
        TPSA_LOG_ERR("Invalid parameter with eid_idx %u", eid_index);
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return -EINVAL;
    }

    ret = vport_table_clean_ueid(entry, eid_index, vport_table);
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    if (ret != 0) {
        TPSA_LOG_ERR("Failed to clean ueid with tpf_name %s, fe_idx %u, eid_idx %u",
            entry->key.tpf_name, entry->key.fe_idx, eid_index);
        return -EINVAL;
    }

    TPSA_LOG_INFO("fe_idx[%hu] del ueid_index %u\n", key->fe_idx, eid_index);
    return 0;
}

int vport_set_lm_location(vport_table_t *vport_table, vport_key_t *key, tpsa_lm_location_t location)
{
    vport_table_entry_t *vport_entry = NULL;

    if (vport_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter\n");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    vport_entry = vport_table_lookup(vport_table, key);
    if (vport_entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_ERR("Fail to find vport entry by fe_idx[%u] tpf_name[%s].\n", key->fe_idx, key->tpf_name);
        return -ENODATA;
    }

    vport_entry->lm_attr.lm_location = location;

    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    return 0;
}

/* tp state table alloc/create/add/remove/lookup/destroy opts */
static tp_state_table_entry_t *alloc_tp_state_table_entry(const tp_state_table_key_t *key,
                                                          tp_state_table_entry_t *add_entry)
{
    tp_state_table_entry_t *entry = (tp_state_table_entry_t *)calloc(1, sizeof(tp_state_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }

    entry->key = *key;
    entry->tp_exc_state = add_entry->tp_exc_state;
    entry->tpgn = add_entry->tpgn;
    entry->tpn = add_entry->tpn;
    entry->tx_psn = add_entry->tx_psn;
    entry->rx_psn = add_entry->rx_psn;
    entry->data_udp_start = add_entry->data_udp_start;
    entry->ack_udp_start = add_entry->ack_udp_start;
    entry->peer_tpn = add_entry->peer_tpn;
    entry->dip = add_entry->dip;
    entry->peer_uvs_ip = add_entry->peer_uvs_ip;
    entry->sus2err_clock_cycle = add_entry->sus2err_clock_cycle;
    entry->sus2err_cnt = add_entry->sus2err_cnt;

    return entry;
}

int tp_state_table_create(tp_state_table_t *tp_state_table)
{
    if (ub_hmap_init(&tp_state_table->hmap, TPSA_STATE_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("tp state table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

tp_state_table_entry_t *tp_state_table_lookup(tp_state_table_t *tp_state_table, tp_state_table_key_t *key)
{
    tp_state_table_entry_t *target = NULL;
    HMAP_FIND(tp_state_table, key, sizeof(*key), target);
    return target;
}

tp_state_table_entry_t *tp_state_table_add(tp_state_table_t *tp_state_table, tp_state_table_key_t *key,
                                           tp_state_table_entry_t *add_entry)
{
    if (tp_state_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }

    tp_state_table_entry_t *entry = alloc_tp_state_table_entry(key, add_entry);
    if (entry == NULL) {
        return NULL;
    }

    HMAP_INSERT(tp_state_table, entry, key, sizeof(*key));
    TPSA_LOG_DEBUG("success add tp %u eid " EID_FMT " state %d\n", key->tpn,
        EID_ARGS(key->sip), (int)add_entry->tp_exc_state);
    return entry;
}

int tp_state_table_add_with_duplication_check(tp_state_table_t *tp_state_table, tp_state_table_key_t *key,
                                              tp_state_table_entry_t *add_entry)
{
    if (tp_state_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* Do not add if the entry already exists */
    if (tp_state_table_lookup(tp_state_table, key) != NULL) {
        TPSA_LOG_ERR("tpn %u, eid " EID_FMT ", already exist, \n", key->tpn, EID_ARGS(key->sip));
        return 0;
    }

    tp_state_table_entry_t *entry = alloc_tp_state_table_entry(key, add_entry);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(tp_state_table, entry, key, sizeof(*key));
    TPSA_LOG_INFO("success add tp %u eid " EID_FMT " state %d\n", key->tpn,
        EID_ARGS(key->sip), (int)add_entry->tp_exc_state);
    return 0;
}

int tp_state_table_remove(tp_state_table_t *tp_state_table, tp_state_table_key_t *key)
{
    tp_state_table_entry_t *entry = tp_state_table_lookup(tp_state_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("tpn %d not exist", key->tpn);
        return -ENXIO;
    }

    TPSA_LOG_DEBUG("success del tp %u eid " EID_FMT " state %d\n", key->tpn,
        EID_ARGS(key->sip), (int)entry->tp_exc_state);

    if (entry->sus2err_clock_cycle != NULL) {
        free(entry->sus2err_clock_cycle);
    }
    ub_hmap_remove(&tp_state_table->hmap, &entry->node);
    free(entry);

    return 0;
}

void tp_state_table_destroy(tp_state_table_t *tp_state_table)
{
    HMAP_DESTROY(tp_state_table, tp_state_table_entry_t);
    return;
}

/* tpg state table alloc/create/add/remove/lookup/destroy opts */
static tpg_state_table_entry_t *alloc_tpg_state_table_entry(const tpg_state_table_key_t *key,
                                                            tpg_state_table_entry_t *add_entry)
{
    tpg_state_table_entry_t *entry = (tpg_state_table_entry_t *)calloc(1, sizeof(tpg_state_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }

    entry->key = *key;
    entry->tpg_exc_state = add_entry->tpg_exc_state;
    entry->dip = add_entry->dip;
    entry->peer_uvs_ip = add_entry->peer_uvs_ip;
    entry->tpgn = add_entry->tpgn;
    entry->tp_cnt = add_entry->tp_cnt;
    entry->tp_flush_cnt = add_entry->tp_flush_cnt;
    (void)memcpy(entry->tp, add_entry->tp, sizeof(add_entry->tp));
    return entry;
}

int tpg_state_table_create(tpg_state_table_t *tpg_state_table)
{
    if (ub_hmap_init(&tpg_state_table->hmap, TPSA_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("tpg state table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

tpg_state_table_entry_t *tpg_state_table_lookup(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key)
{
    tpg_state_table_entry_t *target = NULL;
    HMAP_FIND(tpg_state_table, key, sizeof(*key), target);
    return target;
}

int tpg_state_find_tpg_info(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key, tpsa_tpg_info_t *tpg_info)
{
    tpg_state_table_entry_t *target = NULL;

    target = tpg_state_table_lookup(tpg_state_table, key);
    if (target == NULL) {
        TPSA_LOG_ERR("Fail to find tpg state entry tpgn:%d, sip: " EID_FMT "", key->tpgn, key->sip);
        return -1;
    }

    tpg_info->tpgn = target->tpgn;
    tpg_info->tp_cnt = target->tp_cnt;
    memcpy(tpg_info->tp, target->tp, sizeof(target->tp));
    return 0;
}

int tpg_state_table_update_tp_cnt(tpg_state_table_t *tpg_state_table, tpg_table_update_index_t *tpg_idx)
{
    if (tpg_state_table == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }
    tpg_state_table_key_t k = {.tpgn = (uint32_t)tpg_idx->tpgn, .sip = tpg_idx->sip.net_addr};
    /* Do not update if the entry doesn't exist */
    tpg_state_table_entry_t *entry = tpg_state_table_lookup(tpg_state_table, &k);
    if (entry == NULL) {
        TPSA_LOG_ERR("Fail to find tpg state entry tpgn:%d", k.tpgn);
        return -1;
    }
    entry->tp_cnt = tpg_idx->tp_cnt;
    entry->tp_flush_cnt = tpg_idx->tp_cnt;
    return 0;
}

tpg_state_table_entry_t *tpg_state_table_add(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key,
                                             tpg_state_table_entry_t *add_entry)
{
    if (tpg_state_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }

    tpg_state_table_entry_t *entry = alloc_tpg_state_table_entry(key, add_entry);
    if (entry == NULL) {
        TPSA_LOG_WARN("tpg_entry alloc failed \n");
        return NULL;
    }

    HMAP_INSERT(tpg_state_table, entry, key, sizeof(*key));
    TPSA_LOG_INFO("success add tpg %u eid " EID_FMT " state %u\n", key->tpgn,
        EID_ARGS(key->sip), (uint32_t)entry->tpg_exc_state);
    return entry;
}

void tpg_state_table_remove(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key)
{
    tpg_state_table_entry_t *entry = tpg_state_table_lookup(tpg_state_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("tpn %d not exist", key->tpgn);
        return;
    }

    TPSA_LOG_INFO("success del tp %u eid " EID_FMT " state %d\n", key->tpgn, EID_ARGS(key->sip),
                  (int)entry->tpg_exc_state);

    ub_hmap_remove(&tpg_state_table->hmap, &entry->node);
    free(entry);
}

int uvs_update_tpg_state_flush_cnt(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key, uint32_t flush_cnt)
{
    tpg_state_table_entry_t *entry = tpg_state_table_lookup(tpg_state_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("tpn %d not exist", key->tpgn);
        return -ENXIO;
    }

    entry->tp_flush_cnt = flush_cnt;
    return 0;
}

void tpg_state_table_destroy(tpg_state_table_t *tpg_state_table)
{
    HMAP_DESTROY(tpg_state_table, tpg_state_table_entry_t);
    return;
}

int find_sip_by_vport_key(vport_table_t *vport_table, vport_key_t *vport_key, tpf_dev_table_t *tpf_dev_table,
    sip_table_entry_t *sip_entry)
{
    int ret = 0;
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Failed to alloc vport_entry.\n");
        return -ENOMEM;
    }
    ret = tpsa_lookup_vport_table(vport_key, vport_table, vport_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("Can not find vport_table by fe_idx [%u], tpf_name [%s]\n", vport_key->fe_idx,
            vport_key->tpf_name);
        goto free_vport;
    }

    ret = tpsa_sip_table_lookup(tpf_dev_table, vport_key->tpf_name, vport_entry->sip_idx, sip_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("Can not find sip by tpf_name [%s] and sip_idx [%u]\n", vport_key->tpf_name,
            vport_entry->sip_idx);
        goto free_vport;
    }

free_vport:
    free(vport_entry);
    return ret;
}