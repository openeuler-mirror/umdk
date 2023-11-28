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
#include "tpsa_table.h"

/* deid_vtp_table alloc/create/add/remove/destroy opts */
static int deid_vtp_table_create(deid_vtp_table_t *deid_vtp_table)
{
    if (ub_hmap_init(&deid_vtp_table->hmap, TPSA_FE_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("deid_vtp_table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

static deid_vtp_table_entry_t *alloc_deid_vtp_table_entry(const deid_vtp_table_key_t *key)
{
    deid_vtp_table_entry_t *entry = calloc(1, sizeof(deid_vtp_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc deid_vtp_table entry\n");
        return NULL;
    }
    entry->key = *key;
    /* vtp list init to store the vtp entry with the same deid */
    ub_list_init(&entry->vtp_list);
    (void)pthread_spin_init(&entry->vtp_list_lock, PTHREAD_PROCESS_PRIVATE);

    return entry;
}

deid_vtp_table_entry_t *deid_vtp_table_lookup(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key)
{
    deid_vtp_table_entry_t *target = NULL;
    HMAP_FIND(deid_vtp_table, key, sizeof(*key), target);
    return target;
}

deid_vtp_table_entry_t *deid_vtp_table_add(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key)
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

void deid_vtp_table_remove(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_entry_t *entry)
{
    if (ub_list_is_empty(&entry->vtp_list)) {
        (void)pthread_spin_destroy(&entry->vtp_list_lock);
        ub_hmap_remove(&deid_vtp_table->hmap, &entry->node);
        free(entry);
    }
}

/* vtp_list add/remove/destroy */
void vtp_list_destroy(struct ub_list *list, pthread_spinlock_t *lock)
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

int vtp_list_add(struct ub_list *list, void *entry, pthread_spinlock_t *lock)
{
    deid_vtp_node_t *node = calloc(1, sizeof(deid_vtp_node_t));
    if (node == NULL) {
        TPSA_LOG_ERR("Failed to calloc deid vtp list node");
        return -ENOMEM;
    }
    node->entry = entry;
    (void)pthread_spin_lock(lock);
    ub_list_push_back(list, &node->node);
    (void)pthread_spin_unlock(lock);

    return 0;
}

deid_vtp_node_t *rm_vtp_list_lookup(struct ub_list *list, rm_vtp_table_key_t *key, pthread_spinlock_t *lock)
{
    deid_vtp_node_t *cur, *next;
    deid_vtp_node_t *node = NULL;

    (void)pthread_spin_lock(lock);
    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        rm_vtp_table_entry_t *rm_entry = (rm_vtp_table_entry_t *)cur->entry;
        if (memcmp(&rm_entry->key, key, sizeof(rm_vtp_table_key_t)) != 0) {
            continue;
        }
        node = cur;
        break;
    }
    (void)pthread_spin_unlock(lock);

    return node;
}

deid_vtp_node_t *rc_vtp_list_lookup(struct ub_list *list, rc_vtp_table_key_t *key, pthread_spinlock_t *lock)
{
    deid_vtp_node_t *cur, *next;
    deid_vtp_node_t *node = NULL;

    (void)pthread_spin_lock(lock);
    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        rc_vtp_table_entry_t *rc_entry = (rc_vtp_table_entry_t *)cur->entry;
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
        um_vtp_table_entry_t *um_entry = (um_vtp_table_entry_t *)cur->entry;
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

int deid_vtp_list_add(fe_table_entry_t *entry, void *rm_entry,
                      urma_eid_t dst_eid, tpsa_transport_mode_t trans_mode)
{
    deid_vtp_table_key_t deid_key = {
        .dst_eid = dst_eid,
        .trans_mode = trans_mode,
    };

    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(&entry->deid_vtp_table, &deid_key);
    if (deid_entry == NULL) {
        deid_entry = deid_vtp_table_add(&entry->deid_vtp_table, &deid_key);
        if (deid_entry == NULL) {
            TPSA_LOG_ERR("deid_vtp_table_add failed");
            return TPSA_ADD_NOMEM;
        }
    }
    if (vtp_list_add(&deid_entry->vtp_list, rm_entry, &deid_entry->vtp_list_lock) != 0) {
        return TPSA_ADD_NOMEM;
    }

    return 0;
}

void deid_rm_vtp_list_remove(fe_table_entry_t *fe_entry, deid_vtp_table_key_t *key, rm_vtp_table_key_t *vtp_key)
{
    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(&fe_entry->deid_vtp_table, key);
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
    deid_vtp_table_remove(&fe_entry->deid_vtp_table, deid_entry);

    return;
}

void deid_rc_vtp_list_remove(fe_table_entry_t *fe_entry, deid_vtp_table_key_t *key, rc_vtp_table_key_t *vtp_key)
{
    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(&fe_entry->deid_vtp_table, key);
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
    deid_vtp_table_remove(&fe_entry->deid_vtp_table, deid_entry);

    return;
}
void deid_um_vtp_list_remove(fe_table_entry_t *fe_entry, deid_vtp_table_key_t *key, um_vtp_table_key_t *vtp_key)
{
    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(&fe_entry->deid_vtp_table, key);
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
    deid_vtp_table_remove(&fe_entry->deid_vtp_table, deid_entry);

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
    rm_vtp_table_entry_t *entry = calloc(1, sizeof(rm_vtp_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc rm_vtp_table entry\n");
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

    return entry;
}

static int rm_vtp_table_create(rm_vtp_table_t *rm_vtp_table)
{
    if (ub_hmap_init(&rm_vtp_table->hmap, TPSA_VTP_TABLE_SIZE) != 0) {
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

int rm_vtp_table_add(fe_table_entry_t *entry, rm_vtp_table_key_t *key,
                     tpsa_vtp_table_param_t *vtp_table_data)
{
    if (entry == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    rm_vtp_table_entry_t *rm_entry = alloc_rm_vtp_table_entry(key, vtp_table_data);
    if (rm_entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa rm_vtp_table entry");
        return -ENOMEM;
    }

    /* Synchronize rm_entry to deid_vtp table */
    if (deid_vtp_list_add(entry, (void *)rm_entry, key->dst_eid, TPSA_TP_RM) != 0) {
        TPSA_LOG_ERR("deid_vtp_list_add is failed");
        free(rm_entry);
        return -1;
    }

    HMAP_INSERT(&entry->rm_vtp_table, rm_entry, key, sizeof(*key));
    return 0;
}

/* rc_vtp_table alloc/create/add/remove/destroy opts */
static int rc_vtp_table_create(rc_vtp_table_t *rc_vtp_table)
{
    if (ub_hmap_init(&rc_vtp_table->hmap, TPSA_VTP_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("rc_vtp_table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

static rc_vtp_table_entry_t *alloc_rc_vtp_table_entry(const rc_vtp_table_key_t *key,
                                                      tpsa_vtp_table_param_t *vtp_table_data)
{
    rc_vtp_table_entry_t *entry = calloc(1, sizeof(rc_vtp_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc rc_vtp_table entry");
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

int rc_vtp_table_add(fe_table_entry_t *entry, rc_vtp_table_key_t *key, tpsa_vtp_table_param_t *vtp_table_data)
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

    /* Synchronize rm_entry to deid_vtp table */
    if (deid_vtp_list_add(entry, (void *)rc_entry, key->dst_eid, TPSA_TP_RC) != 0) {
        TPSA_LOG_ERR("deid_vtp_list_add is failed");
        free(rc_entry);
        return -1;
    }

    HMAP_INSERT(&entry->rc_vtp_table, rc_entry, key, sizeof(*key));
    return 0;
}

/* um_vtp_table alloc/create/add/remove/destroy opts */
static um_vtp_table_entry_t *alloc_um_vtp_table_entry(const um_vtp_table_key_t *key,
                                                      uint32_t vtpn, uint32_t utp_idx)
{
    um_vtp_table_entry_t *entry = calloc(1, sizeof(um_vtp_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc um_vtp_table entry");
        return NULL;
    }
    entry->key = *key;
    entry->vtpn = vtpn;
    entry->utp_idx = utp_idx;
    entry->use_cnt = 1;
    entry->migration_status = false;
    entry->node_status = STATE_NORMAL;

    return entry;
}

static int um_vtp_table_create(um_vtp_table_t *um_vtp_table)
{
    if (ub_hmap_init(&um_vtp_table->hmap, TPSA_VTP_TABLE_SIZE) != 0) {
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

int um_vtp_table_add(fe_table_entry_t *entry, um_vtp_table_key_t *key,
                     uint32_t vtpn, uint32_t utp_idx)
{
    if (entry == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    um_vtp_table_entry_t *um_entry = alloc_um_vtp_table_entry(key, vtpn, utp_idx);
    if (um_entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpsa um_vtp_table entry");
        return -ENOMEM;
    }

    /* Synchronize rm_entry to deid_vtp table */
    if (deid_vtp_list_add(entry, (void *)um_entry, key->dst_eid, TPSA_TP_UM) != 0) {
        TPSA_LOG_ERR("deid_vtp_list_add is failed");
        free(um_entry);
        return -1;
    }

    HMAP_INSERT(&entry->um_vtp_table, um_entry, key, sizeof(*key));
    return 0;
}

int um_vtp_table_remove(fe_table_t *fe_table, vport_key_t *fe_key, um_vtp_table_key_t *vtp_key)
{
    fe_table_entry_t *fe_entry = fe_table_lookup(fe_table, fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_ERR("fe entry is not exist when um_vtp_table_remove");
        return -ENXIO;
    }

    um_vtp_table_entry_t *entry = um_vtp_table_lookup(&fe_entry->um_vtp_table, vtp_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key "EID_FMT", "EID_FMT", not exist in um_vtp_table",
                      EID_ARGS(vtp_key->src_eid), EID_ARGS(vtp_key->dst_eid));
        return -ENXIO;
    }

    /* Before deleting vtp entry, need to delete the corresponding node in the linked list. */
    deid_vtp_table_key_t deid_key = {
        .dst_eid = vtp_key->dst_eid,
        .trans_mode = TPSA_TP_UM,
    };
    deid_um_vtp_list_remove(fe_entry, &deid_key, vtp_key);

    /* delete the vtp entry from um_vtp_table. */
    ub_hmap_remove(&fe_entry->um_vtp_table.hmap, &entry->node);
    free(entry);
    fe_table_remove(fe_table, fe_entry);

    return 0;
}

static clan_vtp_table_entry_t *alloc_clan_vtp_table_entry(const clan_vtp_table_key_t *key,
                                                          uint32_t vtpn, uint32_t ctp_idx)
{
    clan_vtp_table_entry_t *entry = calloc(1, sizeof(clan_vtp_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc clan vtp table entry");
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
    if (ub_hmap_init(&clan_vtp_table->hmap, TPSA_VTP_TABLE_SIZE) != 0) {
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

int clan_vtp_table_remove(fe_table_t *fe_table, vport_key_t *fe_key, clan_vtp_table_key_t *vtp_key)
{
    fe_table_entry_t *fe_entry = fe_table_lookup(fe_table, fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_ERR("fe entry is not exist when clan_vtp_table_remove");
        return -ENXIO;
    }

    clan_vtp_table_entry_t *entry = clan_vtp_table_lookup(&fe_entry->clan_vtp_table, vtp_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key des ip "EID_FMT", not exist in clan vtp table", EID_ARGS(vtp_key->dst_eid));
        return -ENXIO;
    }

    ub_hmap_remove(&fe_entry->clan_vtp_table.hmap, &entry->node);
    free(entry);
    fe_table_remove(fe_table, fe_entry);

    return 0;
}

/* fe_table alloc/create/add/remove/destroy opts */
static fe_table_entry_t *alloc_fe_table_entry(const vport_key_t *key)
{
    fe_table_entry_t *entry = calloc(1, sizeof(fe_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc fe_table entry");
    }
    entry->key = *key;

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

    if (deid_vtp_table_create(&entry->deid_vtp_table) != 0) {
        TPSA_LOG_ERR("Failed to create deid vtp table");
        goto free_clan_vtp_table;
    }

    return entry;

free_clan_vtp_table:
    clan_vtp_table_destroy(&entry->clan_vtp_table);
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
    if (ub_hmap_init(&fe_table->hmap, TPSA_FE_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("fe_table init failed.\n");
        return -ENOMEM;
    }

    (void)pthread_rwlock_init(&fe_table->rwlock, NULL);
    return 0;
}

fe_table_entry_t *fe_table_lookup(fe_table_t *fe_table, vport_key_t *key)
{
    if (fe_table == NULL) {
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
        fe_entry->um_vtp_table.hmap.count == 0 && fe_entry->clan_vtp_table.hmap.count == 0 &&
        fe_entry->deid_vtp_table.hmap.count == 0) {
        ub_hmap_destroy(&fe_entry->rm_vtp_table.hmap);
        ub_hmap_destroy(&fe_entry->rc_vtp_table.hmap);
        ub_hmap_destroy(&fe_entry->um_vtp_table.hmap);
        ub_hmap_destroy(&fe_entry->clan_vtp_table.hmap);
        ub_hmap_destroy(&fe_entry->deid_vtp_table.hmap);

        ub_hmap_remove(&fe_table->hmap, &fe_entry->node);
        free(fe_entry);
    }
}

/* rm_tpg_table alloc/create/add/remove/destroy opts */
static rm_tpg_table_entry_t *alloc_rm_tpg_table_entry(const rm_tpg_table_key_t *key,
    tpsa_tpg_table_param_t *param)
{
    rm_tpg_table_entry_t *entry = calloc(1, sizeof(rm_tpg_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc rm_tpg_table entry");
        return NULL;
    }
    entry->key = *key;
    entry->type = param->type;
    entry->tpgn = param->tpgn;
    (void)memcpy(entry->tpn, param->tpn,
        TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
    entry->status = param->status;
    entry->use_cnt = 1;
    return entry;
}

int rm_tpg_table_create(rm_tpg_table_t *rm_tpg_table)
{
    if (ub_hmap_init(&rm_tpg_table->hmap, TPSA_TABLE_SIZE) != 0) {
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

int rm_tpg_table_add(rm_tpg_table_t *rm_tpg_table, rm_tpg_table_key_t *key,
    tpsa_tpg_table_param_t *param)
{
    if (rm_tpg_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    /* Do not add if the map entry already exists */
    if (rm_tpg_table_lookup(rm_tpg_table, key) != NULL) {
        TPSA_LOG_WARN("key "EID_FMT" already exist in rm_tpg_table", EID_ARGS(key->dip.eid));
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
        TPSA_LOG_WARN("key "EID_FMT" not exist in rm_tpg_table", EID_ARGS(key->dip.eid));
        return -ENXIO;
    }

    ub_hmap_remove(&rm_tpg_table->hmap, &entry->node);
    free(entry);
    return 0;
}

/* rc_tpg_table alloc/create/add/remove/destroy opts */
static rc_tpg_table_entry_t *alloc_rc_tpg_table_entry(const rc_tpg_table_key_t *key,
    tpsa_tpg_table_param_t *param)
{
    rc_tpg_table_entry_t *entry = calloc(1, sizeof(rc_tpg_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc rc_tpg_table entry");
        return NULL;
    }
    entry->key = *key;
    entry->type = param->type;
    entry->tpgn = param->tpgn;
    entry->vice_tpgn = UINT32_MAX;
    (void)memcpy(entry->tpn, param->tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
    entry->status = param->status;
    entry->ljetty_id = param->ljetty_id;
    entry->leid = param->leid;
    entry->use_cnt = 1;
    return entry;
}

int rc_tpg_table_create(rc_tpg_table_t *rc_tpg_table)
{
    if (ub_hmap_init(&rc_tpg_table->hmap, TPSA_TABLE_SIZE) != 0) {
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
        TPSA_LOG_WARN("key djetty %d, deid "EID_FMT" already exist in rc_tpg",
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

int rc_tpg_table_remove(rc_tpg_table_t *rc_tpg_table, rc_tpg_table_key_t *key)
{
    rc_tpg_table_entry_t *entry = rc_tpg_table_lookup(rc_tpg_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key djetty %d, deid "EID_FMT" not exist in rc_tpg",
            key->djetty_id, EID_ARGS(key->deid));
        return -ENXIO;
    }
    ub_hmap_remove(&rc_tpg_table->hmap, &entry->node);
    free(entry);
    return 0;
}

/* utp_table alloc/create/add/remove/destroy opts */
static utp_table_entry_t *alloc_utp_table_entry(const utp_table_key_t *key,
    uint32_t utp_idx)
{
    utp_table_entry_t *entry = calloc(1, sizeof(utp_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc rc_tpg_table entry");
        return NULL;
    }
    entry->key = *key;
    entry->utp_idx = utp_idx;
    entry->use_cnt = 1;
    return entry;
}

int utp_table_create(utp_table_t *utp_table)
{
    if (ub_hmap_init(&utp_table->hmap, TPSA_TABLE_SIZE) != 0) {
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
        TPSA_LOG_WARN("key sip: "EID_FMT", dip: "EID_FMT" already exist in utp_table",
            key->sip.eid, EID_ARGS(key->dip.eid));
        return 0;
    }

    utp_table_entry_t *entry = alloc_utp_table_entry(key, utp_idx);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(utp_table, entry, key, sizeof(*key));
    return 0;
}

int utp_table_remove(utp_table_t *utp_table, utp_table_key_t *key)
{
    utp_table_entry_t *entry = utp_table_lookup(utp_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key sip: "EID_FMT", dip: "EID_FMT" not exist in utp_table",
            key->sip.eid, EID_ARGS(key->dip.eid));
        return -ENXIO;
    }
    ub_hmap_remove(&utp_table->hmap, &entry->node);
    free(entry);
    return 0;
}

/* ctp_table alloc/create/add/remove/destroy opts */
static ctp_table_entry_t *alloc_ctp_table_entry(const ctp_table_key_t *key, uint32_t ctp_idx)
{
    ctp_table_entry_t *entry = calloc(1, sizeof(ctp_table_entry_t));

    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc ctp table entry");
    }
    entry->key = *key;
    entry->ctp_idx = ctp_idx;
    entry->use_cnt = 1;

    return entry;
}

int ctp_table_create(ctp_table_t *ctp_table)
{
    if (ub_hmap_init(&ctp_table->hmap, TPSA_TABLE_SIZE) != 0) {
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
        TPSA_LOG_WARN("key dip: "EID_FMT" already exist in ctp_table", EID_ARGS(key->dip.eid));
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
        TPSA_LOG_WARN("key dip: "EID_FMT" not exist in ctp table", EID_ARGS(key->dip.eid));
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
    tpf_dev_table_entry_t *entry = calloc(1, sizeof(tpf_dev_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpf dev table entry");
        return NULL;
    }
    entry->key = *key;
    entry->cc_entry_cnt = add_entry->cc_entry_cnt;
    entry->dev_fea = add_entry->dev_fea;
    (void)memcpy(entry->cc_array, add_entry->cc_array, sizeof(tpsa_cc_entry_t) * entry->cc_entry_cnt);
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
        TPSA_LOG_ERR("tpf dev table with dev name %s alread exist\n", key->dev_name);
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
    (void)pthread_rwlock_wrlock(&tpf_dev_table->rwlock);
    HMAP_DESTROY(tpf_dev_table, tpf_dev_table_entry_t);
    (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
    (void)pthread_rwlock_destroy(&tpf_dev_table->rwlock);
    return;
}

/* vport_table alloc/create/add/remove/destroy opts */
static vport_table_entry_t *alloc_vport_table_entry(vport_table_entry_t *add_entry)
{
    vport_table_entry_t *entry = calloc(1, sizeof(vport_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc vport_table entry");
        return NULL;
    }
    (void)memcpy(entry, add_entry, sizeof(vport_table_entry_t));
    return entry;
}

int vport_table_create(vport_table_t *vport_table)
{
    if (ub_hmap_init(&vport_table->hmap, TPSA_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("vport_table init failed.\n");
        return -ENOMEM;
    }

    (void)pthread_rwlock_init(&vport_table->rwlock, NULL);
    return 0;
}

void vport_table_destroy(vport_table_t *vport_table)
{
    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    HMAP_DESTROY(vport_table, vport_table_entry_t);
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

int vport_table_add(vport_table_t *vport_table, vport_table_entry_t *add_entry)
{
    if (vport_table == NULL || add_entry == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    /* Do not add if the entry already exists */
    if (vport_table_lookup(vport_table, &add_entry->key) != NULL) {
        TPSA_LOG_ERR("vport:%s-%hu alread exist\n", add_entry->key.dev_name, add_entry->key.fe_idx);
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return -1;
    }

    vport_table_entry_t *entry = alloc_vport_table_entry(add_entry);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return -ENOMEM;
    }

    HMAP_INSERT(vport_table, entry, &entry->key, sizeof(vport_key_t));
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    TPSA_LOG_INFO("success add fe_idx: %s-%hu sip_idx %u\n", entry->key.dev_name, entry->key.fe_idx, entry->sip_idx);
    return 0;
}

int vport_table_remove(vport_table_t *vport_table, vport_key_t *key)
{
    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    vport_table_entry_t *entry = vport_table_lookup(vport_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key dev_name:%s, fe_idx %hu not exist", key->dev_name, key->fe_idx);
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del dev_name:%s fe_idx %hu sip_idx %u\n", key->dev_name, key->fe_idx, entry->sip_idx);

    ub_hmap_remove(&vport_table->hmap, &entry->node);
    free(entry);
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    return 0;
}

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

int vport_table_lookup_by_ueid_return_eid_idx(vport_table_t *vport_table, uint32_t upi, urma_eid_t *eid,
    vport_table_entry_t *ret_entry, uint32_t *eid_index)
{
    vport_table_entry_t *cur;
    uint32_t i;
    int ret = -1;

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    HMAP_FOR_EACH(cur, node, &vport_table->hmap) {
        for (i = 0; i < cur->ueid_max_cnt; i++) {
            if ((memcmp(&cur->ueid[i].eid, eid, sizeof(urma_eid_t)) == 0) && (cur->ueid[i].upi == upi)) {
                *ret_entry = *cur;
                *eid_index = i;
                ret = 0;
                TPSA_LOG_INFO("vport table with eid "EID_FMT", upi %u and eid_idx %u has been found",
                    EID_ARGS(*eid), upi, i);
                break;
            }
        }
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    TPSA_LOG_ERR("vport table with eid "EID_FMT", upi %u cannot be been found", EID_ARGS(*eid), upi);
    return ret;
}

int vport_table_lookup_by_ueid_return_key(vport_table_t *vport_table, uint32_t upi, urma_eid_t *eid, vport_key_t *key,
                                          uint32_t *eid_index)
{
    vport_table_entry_t *cur;
    uint32_t i;
    int ret = -1;

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    HMAP_FOR_EACH(cur, node, &vport_table->hmap) {
        for (i = 0; i < cur->ueid_max_cnt; i++) {
            if ((memcmp(&cur->ueid[i].eid, eid, sizeof(urma_eid_t)) == 0) && (cur->ueid[i].upi == upi)) {
                *key = cur->key;
                *eid_index = i;
                ret = 0;
                break;
            }
        }
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    return ret;
}

/* jetty peer table create/add/remove/lookup/destroy opts */
static jetty_peer_table_entry_t *alloc_jetty_peer_table_entry(const jetty_peer_table_key_t *key,
                                                              jetty_peer_table_param_t *parm)
{
    jetty_peer_table_entry_t *entry = calloc(1, sizeof(jetty_peer_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc jetty_peer_table entry");
        return NULL;
    }
    entry->key = *key;
    entry->djetty_id = parm->djetty_id;
    entry->deid = parm->deid;

    return entry;
}

int jetty_peer_table_create(jetty_peer_table_t *jetty_peer_table)
{
    if (ub_hmap_init(&jetty_peer_table->hmap, TPSA_TABLE_SIZE) != 0) {
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
        TPSA_LOG_ERR("sjetty %u seid:"EID_FMT" already exist\n", key.ljetty_id, EID_ARGS(key.seid));
        return 0;
    }

    jetty_peer_table_entry_t *entry = alloc_jetty_peer_table_entry(&key, parm);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(jetty_peer_table, entry, &key, sizeof(key));
    TPSA_LOG_INFO("success add sjetty %u, seid:"EID_FMT", djetty %u, deid:"EID_FMT"\n",
        parm->ljetty_id, EID_ARGS(parm->seid), parm->djetty_id, EID_ARGS(parm->deid));
    return 0;
}

int jetty_peer_table_remove(jetty_peer_table_t *jetty_peer_table, jetty_peer_table_key_t *key)
{
    jetty_peer_table_entry_t *entry = jetty_peer_table_lookup(jetty_peer_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key sjetty_id %u seid:"EID_FMT" not exist", key->ljetty_id, EID_ARGS(key->seid));
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del sjetty %u, seid:"EID_FMT", djetty %u, deid:"EID_FMT"\n",
        key->ljetty_id, EID_ARGS(key->seid), entry->djetty_id, EID_ARGS(entry->deid));

    ub_hmap_remove(&jetty_peer_table->hmap, &entry->node);
    free(entry);
    return 0;
}

/* rm_wait_table create/add/remove/lookup/destroy opts */
static rm_wait_table_entry_t *alloc_rm_wait_table_entry(const rm_wait_table_key_t *key,
                                                        rm_wait_table_entry_t *add_entry)
{
    rm_wait_table_entry_t *entry = calloc(1, sizeof(rm_wait_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc rm_wait_table entry");
        return NULL;
    }
    entry->key = *key;
    (void)memcpy(&entry->vtp_entry, &add_entry->vtp_entry, sizeof(rm_vtp_table_entry_t));
    entry->liveMigrate = add_entry->liveMigrate;
    entry->migrateThird = add_entry->migrateThird;
    entry->fe_idx = add_entry->fe_idx;
    entry->msg_id = add_entry->msg_id;
    entry->nlmsg_seq = add_entry->nlmsg_seq;
    (void)memcpy(entry->dev_name, add_entry->dev_name, TPSA_MAX_DEV_NAME);

    return entry;
}

int rm_wait_table_create(rm_wait_table_t *rm_wait_table)
{
    if (ub_hmap_init(&rm_wait_table->hmap, TPSA_VTP_TABLE_SIZE) != 0) {
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
    TPSA_LOG_INFO("add one entry to rm_wait_table: dip "EID_FMT"\n", EID_ARGS(key->dip.eid));
    return 0;
}

int rm_wait_table_remove(rm_wait_table_t *rm_table, rm_wait_table_key_t *key)
{
    rm_wait_table_entry_t *entry = rm_wait_table_lookup(rm_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key dip "EID_FMT" not exist", EID_ARGS(key->dip.eid));
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del dip "EID_FMT"\n", EID_ARGS(key->dip.eid));

    ub_hmap_remove(&rm_table->hmap, &entry->node);
    free(entry);
    return 0;
}

int rm_wait_table_pop(rm_wait_table_t *rm_table, rm_wait_table_key_t *key,
                      rm_wait_table_entry_t *pop_entry)
{
    rm_wait_table_entry_t *entry = rm_wait_table_lookup(rm_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key dip "EID_FMT" not exist", EID_ARGS(key->dip.eid));
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
    rc_wait_table_entry_t *entry = calloc(1, sizeof(rc_wait_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc rc_wait_table entry");
        return NULL;
    }
    entry->key = *key;
    (void)memcpy(&entry->vtp_entry, &add_entry->vtp_entry, sizeof(rc_vtp_table_entry_t));
    entry->dip = add_entry->dip;
    entry->liveMigrate = add_entry->liveMigrate;
    entry->migrateThird = add_entry->migrateThird;
    entry->fe_idx = add_entry->fe_idx;
    entry->msg_id = add_entry->msg_id;
    entry->nlmsg_seq = add_entry->nlmsg_seq;
    (void)memcpy(entry->dev_name, add_entry->dev_name, TPSA_MAX_DEV_NAME);

    return entry;
}

int rc_wait_table_create(rc_wait_table_t *rc_wait_table)
{
    if (ub_hmap_init(&rc_wait_table->hmap, TPSA_VTP_TABLE_SIZE) != 0) {
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
    TPSA_LOG_INFO("add one entry to rc_wait_table: deid "EID_FMT" djetty %d\n",
                  EID_ARGS(key->deid), key->djetty_id);
    return 0;
}

int rc_wait_table_remove(rc_wait_table_t *rc_table, rc_wait_table_key_t *key)
{
    rc_wait_table_entry_t *entry = rc_wait_table_lookup(rc_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key deid "EID_FMT" djetty %d not exist",
                      EID_ARGS(key->deid), key->djetty_id);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del deid "EID_FMT" djetty %d \n",
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
        TPSA_LOG_WARN("key deid "EID_FMT" djetty %d not exist",
                      EID_ARGS(key->deid), key->djetty_id);
        return -ENXIO;
    }

    *pop_entry = *entry;

    ub_hmap_remove(&rc_table->hmap, &entry->node);
    free(entry);
    return 0;
}

/* sip_table create/add/remove/lookup/destroy opts */
void sip_table_create(sip_table_t *sip_table)
{
    (void)pthread_rwlock_init(&sip_table->rwlock, NULL);
}

void sip_table_destroy(sip_table_t *sip_table)
{
    size_t clean_size = sizeof(sip_table_entry_t) * TPSA_SIP_IDX_TABLE_SIZE;

    (void)pthread_rwlock_wrlock(&sip_table->rwlock);
    (void)memset(sip_table->entries, 0, clean_size);
    (void)pthread_rwlock_unlock(&sip_table->rwlock);
    (void)pthread_rwlock_destroy(&sip_table->rwlock);
    return;
}

int dip_table_create(dip_table_t *dip_table)
{
    if (ub_hmap_init(&dip_table->hmap, TPSA_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("dip_table init failed.\n");
        return -ENOMEM;
    }

    (void)pthread_rwlock_init(&dip_table->rwlock, NULL);
    return 0;
}

void dip_table_destroy(dip_table_t *dip_table)
{
    (void)pthread_rwlock_wrlock(&dip_table->rwlock);
    HMAP_DESTROY(dip_table, dip_table_entry_t);
    (void)pthread_rwlock_unlock(&dip_table->rwlock);
    (void)pthread_rwlock_destroy(&dip_table->rwlock);
    return;
}

static dip_table_entry_t *alloc_dip_table_entry(const urma_eid_t *key,
    dip_table_entry_t *add_entry)
{
    dip_table_entry_t *entry = calloc(1, sizeof(dip_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc dip_table entry");
        return NULL;
    }
    entry->deid = add_entry->deid;
    entry->peer_tps = add_entry->peer_tps;
    entry->underlay_eid = add_entry->underlay_eid;
    entry->netaddr = add_entry->netaddr;

    return entry;
}

dip_table_entry_t *dip_table_lookup(dip_table_t *dip_table, urma_eid_t *key)
{
    dip_table_entry_t *cur;
    dip_table_entry_t *target = NULL;

    uint32_t hash = ub_hash_bytes(key, sizeof(urma_eid_t), 0);
    HMAP_FOR_EACH_WITH_HASH(cur, node, hash, &dip_table->hmap) {
        if (memcmp(&cur->deid, key, sizeof(urma_eid_t)) == 0) {
            target = cur;
            break;
        }
    }
    return target;
}

int dip_table_add(dip_table_t *dip_table, urma_eid_t *key, dip_table_entry_t *add_entry)
{
    if (dip_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&dip_table->rwlock);
    /* Do not add if the entry already exists */
    if (dip_table_lookup(dip_table, key) != NULL) {
        TPSA_LOG_INFO("dip "EID_FMT" alread exist\n", EID_ARGS(*key));
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        return 0;
    }

    dip_table_entry_t *entry = alloc_dip_table_entry(key, add_entry);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        return -1;
    }

    HMAP_INSERT(dip_table, entry, key, sizeof(*key));
    (void)pthread_rwlock_unlock(&dip_table->rwlock);

    TPSA_LOG_INFO("success add dip "EID_FMT"\n", EID_ARGS(*key));
    return 0;
}

int dip_table_remove(dip_table_t *dip_table, urma_eid_t *key)
{
    (void)pthread_rwlock_wrlock(&dip_table->rwlock);
    dip_table_entry_t *entry = dip_table_lookup(dip_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("dip "EID_FMT" not exist", EID_ARGS(*key));
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del dip "EID_FMT"\n", EID_ARGS(*key));

    ub_hmap_remove(&dip_table->hmap, &entry->node);
    free(entry);
    (void)pthread_rwlock_unlock(&dip_table->rwlock);
    return 0;
}

/*
 * entry may del by other thread. The caller must lock the table
 * before lookup the entry and release the lock after the entry is used up.
 */
sip_table_entry_t *sip_table_lookup(sip_table_t *sip_table, uint32_t sip_idx)
{
    if (sip_idx > TPSA_SIP_IDX_TABLE_SIZE - 1) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }

    sip_table_entry_t *entry = &sip_table->entries[sip_idx];
    if (!entry->used) {
        return NULL;
    }

    return entry;
}

int sip_table_add(sip_table_t *sip_table, uint32_t sip_idx, sip_table_entry_t *entry_add)
{
    if (sip_idx > TPSA_SIP_IDX_TABLE_SIZE - 1) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&sip_table->rwlock);
    sip_table_entry_t *entry = &sip_table->entries[sip_idx];
    /* update entry if the it already exists */
    if (entry->used) {
        TPSA_LOG_WARN("key sip %d already exist, update it", sip_idx);
        return -1;
    }

    (void)memcpy(entry, entry_add, sizeof(sip_table_entry_t));
    entry->used = true;
    (void)pthread_rwlock_unlock(&sip_table->rwlock);

    TPSA_LOG_INFO("success add sip_idx %d to table\n", sip_idx);
    return 0;
}

int sip_table_remove(sip_table_t *sip_table, uint32_t sip_idx)
{
    if (sip_idx > TPSA_SIP_IDX_TABLE_SIZE - 1) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&sip_table->rwlock);
    sip_table_entry_t *entry = &sip_table->entries[sip_idx];
    if (entry->used) {
        (void)memset(entry, 0, sizeof(sip_table_entry_t));
        entry->used = false;
        (void)pthread_rwlock_unlock(&sip_table->rwlock);
        TPSA_LOG_INFO("success remove sip_idx %d from table\n", sip_idx);
        return 0;
    }
    (void)pthread_rwlock_unlock(&sip_table->rwlock);
    TPSA_LOG_ERR("key sip_idx %d not exist", sip_idx);
    return -ENXIO;
}

static tpsa_ueid_t *vport_ueid_tbl_lookup_entry(vport_table_entry_t *entry, uint32_t ueid_index)
{
    if (ueid_index >= entry->ueid_max_cnt) {
        TPSA_LOG_ERR("eid index does not exist, idx: %u, max_cnt: %u.\n",
            ueid_index, entry->ueid_max_cnt);
        return NULL;
    }
    return &entry->ueid[ueid_index];
}

static int vport_ueid_tbl_add_entry(vport_table_entry_t *entry, tpsa_ueid_t *ueid)
{
    uint32_t add_index = 0;

    if (entry->ueid_max_cnt >= TPSA_EID_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("The ueid table is full.\n");
        return -1;
    }
    add_index = entry->ueid_max_cnt;
    entry->ueid[add_index] = *ueid;
    entry->ueid_max_cnt++;

    return (int)add_index;
}

static int vport_ueid_tbl_del_entry(vport_table_entry_t *entry, uint32_t ueid_index)
{
    uint32_t i;

    if (entry->ueid_max_cnt == 0) {
        TPSA_LOG_ERR("The ueid table is empty.\n");
        return -1;
    }
    for (i = ueid_index; i < entry->ueid_max_cnt; i++) {
        if (i + 1 < entry->ueid_max_cnt) {
            entry->ueid[i] = entry->ueid[i + 1];
        }
    }
    entry->ueid_max_cnt--;
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
        TPSA_LOG_INFO("vport entry does not exist or ueid entry is empty.\n");
        return NULL;
    }
    TPSA_LOG_INFO("fe_idx[%hu] lookup ueid_index %u\n", key->fe_idx, ueid_index);
    return ueid;
}

int vport_table_add_ueid(vport_table_t *vport_table, vport_key_t *key, tpsa_ueid_t *ueid)
{
    vport_table_entry_t *entry = NULL;
    int ueid_index = 0;

    if (vport_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    entry = vport_table_lookup(vport_table, key);
    if (entry != NULL) {
        ueid_index = vport_ueid_tbl_add_entry(entry, ueid);
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    if (entry == NULL || ueid_index == -1) {
        TPSA_LOG_INFO("vport entry does not exist or ueid entry is full.\n");
        return -1;
    }
    TPSA_LOG_INFO("fe_idx[%hu] add ueid_index %d\n", key->fe_idx, ueid_index);
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
    if (entry != NULL) {
        ret = vport_ueid_tbl_del_entry(entry, eid_index);
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    if (entry == NULL || ret == -1) {
        TPSA_LOG_INFO("vport entry does not exist or ueid entry is empty.\n");
        return -1;
    }
    TPSA_LOG_INFO("fe_idx[%hu] del ueid_index %u\n", key->fe_idx, eid_index);
    return 0;
}

/* tp state table alloc/create/add/remove/lookup/destroy opts */
static tp_state_table_entry_t *alloc_tp_state_table_entry(const tp_state_table_key_t *key,
                                                          tp_state_table_entry_t *add_entry)
{
    tp_state_table_entry_t *entry = calloc(1, sizeof(tp_state_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tp state table entry");
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
    entry->peer_dev_eid = add_entry->peer_dev_eid;
    entry->peer_tpsa_eid = add_entry->peer_tpsa_eid;
    entry->suspend_cnt = add_entry->suspend_cnt;
    (void)memcpy(entry->timestamp, add_entry->timestamp, sizeof(entry->timestamp));
    return entry;
}

int tp_state_table_create(tp_state_table_t *tp_state_table)
{
    if (ub_hmap_init(&tp_state_table->hmap, TPSA_TABLE_SIZE) != 0) {
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
    TPSA_LOG_INFO("success add tp %u eid "EID_FMT" state %d at %llu\n", key->tpn,
        EID_ARGS(key->local_dev_eid), (int)add_entry->tp_exc_state, add_entry->timestamp);
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
        TPSA_LOG_ERR("tpn %u, eid "EID_FMT", already exist, \n", key->tpn, EID_ARGS(key->local_dev_eid));
        return 0;
    }

    tp_state_table_entry_t *entry = alloc_tp_state_table_entry(key, add_entry);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(tp_state_table, entry, key, sizeof(*key));
    TPSA_LOG_INFO("success add tp %u eid "EID_FMT" state %d at %llu\n", key->tpn,
        EID_ARGS(key->local_dev_eid), (int)add_entry->tp_exc_state, add_entry->timestamp);
    return 0;
}

int tp_state_table_remove(tp_state_table_t *tp_state_table, tp_state_table_key_t *key)
{
    tp_state_table_entry_t *entry = tp_state_table_lookup(tp_state_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("tpn %d not exist", key->tpn);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del tp %u eid "EID_FMT" state %d at %llu\n", key->tpn,
        EID_ARGS(key->local_dev_eid), (int)entry->tp_exc_state, entry->timestamp);

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
    tpg_state_table_entry_t *entry = calloc(1, sizeof(tpg_state_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to calloc tpg state table entry");
        return NULL;
    }

    entry->key = *key;
    entry->tpg_exc_state = add_entry->tpg_exc_state;
    entry->tpgn = add_entry->tpgn;
    entry->tp_cnt = add_entry->tp_cnt;
    entry->tp_flush_cnt = add_entry->tp_flush_cnt;
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

tpg_state_table_entry_t *tpg_state_table_add(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key,
                                             tpg_state_table_entry_t *add_entry)
{
    if (tpg_state_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }

    tpg_state_table_entry_t *entry = alloc_tpg_state_table_entry(key, add_entry);
    if (entry == NULL) {
        return NULL;
    }

    HMAP_INSERT(tpg_state_table, entry, key, sizeof(*key));
    TPSA_LOG_INFO("success add tpg %u eid "EID_FMT" state %d\n", key->tpgn,
        EID_ARGS(key->local_dev_eid), entry->tpg_exc_state);
    return entry;
}

int tpg_state_table_remove(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key)
{
    tpg_state_table_entry_t *entry = tpg_state_table_lookup(tpg_state_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("tpn %d not exist", key->tpgn);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del tp %u eid "EID_FMT" state %d\n", key->tpgn, EID_ARGS(key->local_dev_eid),
                  (int)entry->tpg_exc_state);

    ub_hmap_remove(&tpg_state_table->hmap, &entry->node);
    free(entry);
    return 0;
}

void tpg_state_table_destroy(tpg_state_table_t *tpg_state_table)
{
    HMAP_DESTROY(tpg_state_table, tpg_state_table_entry_t);
    return;
}