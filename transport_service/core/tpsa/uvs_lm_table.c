/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa table header file
 * Author: Sun Fang
 * Create: 2023-10-12
 * Note:
 * History: 2023-10-12 uvs table create search implement for live migrate
 */
#include <errno.h>
#include "ub_hash.h"
#include "tpsa_log.h"
#include "ub_hmap.h"
#include "uvs_lm_table.h"

/* live_migrate_table create/add/remove/lookup/destroy opts */
static live_migrate_table_entry_t *alloc_live_migrate_table_entry(const live_migrate_table_key_t *key,
                                                                  live_migrate_table_entry_t *add_entry)
{
    live_migrate_table_entry_t *entry = (live_migrate_table_entry_t *)calloc(1,
        sizeof(live_migrate_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Failed to alloc entry.\n");
        return NULL;
    }
    entry->key = *key;
    (void)memcpy(&entry->uvs_ip, &add_entry->uvs_ip, TPSA_EID_SIZE);

    return entry;
}

int live_migrate_table_create(live_migrate_table_t *live_migrate_table)
{
    if (ub_hmap_init(&live_migrate_table->hmap, TPSA_LIVE_MIGRATE_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("live_migrate_table init failed.\n");
        return -ENOMEM;
    }
    if (ub_hmap_init(&live_migrate_table->delete_vtp_hmap, TPSA_LIVE_MIGRATE_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("live_migrate_table init failed.\n");
        return -ENOMEM;
    }
    (void)pthread_rwlock_init(&live_migrate_table->rwlock, NULL);
    return 0;
}

void lm_wait_sync_table_destroy(live_migrate_table_t *live_migrate_table)
{
    lm_wait_sync_table_entry_t *cur, *next;
    HMAP_FOR_EACH_SAFE(cur, next, node, &live_migrate_table->delete_vtp_hmap) {
        lm_wait_sync_vtp_t *cur_vtp, *next_vtp;
        UB_LIST_FOR_EACH_SAFE(cur_vtp, next_vtp, node, &cur->lm_wait_sync_vtp_list) {
            ub_list_remove(&cur_vtp->node);
            free(cur_vtp);
        }
        ub_hmap_remove(&live_migrate_table->delete_vtp_hmap, &cur->node);
        free(cur);
    }
    ub_hmap_destroy(&live_migrate_table->delete_vtp_hmap);
}

void live_migrate_table_destroy(live_migrate_table_t *live_migrate_table)
{
    (void)pthread_rwlock_wrlock(&live_migrate_table->rwlock);
    HMAP_DESTROY(live_migrate_table, live_migrate_table_entry_t);
    lm_wait_sync_table_destroy(live_migrate_table);
    (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
    (void)pthread_rwlock_destroy(&live_migrate_table->rwlock);
    return;
}

live_migrate_table_entry_t *live_migrate_table_lookup(live_migrate_table_t *live_migrate_table,
                                                      live_migrate_table_key_t *key)
{
    live_migrate_table_entry_t *target = NULL;
    HMAP_FIND(live_migrate_table, key, sizeof(*key), target);
    return target;
}

int live_migrate_table_add(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t *key,
                           live_migrate_table_entry_t *add_entry)
{
    if (live_migrate_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    (void)pthread_rwlock_wrlock(&live_migrate_table->rwlock);
    /* Do not add if the entry already exists */
    if (live_migrate_table_lookup(live_migrate_table, key) != NULL) {
        TPSA_LOG_INFO("live_migrate %hu alread exist\n", key->fe_idx);
        (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
        return -EEXIST;
    }

    live_migrate_table_entry_t *entry = alloc_live_migrate_table_entry(key, add_entry);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
        return -ENOMEM;
    }

    HMAP_INSERT(live_migrate_table, entry, key, sizeof(*key));
    (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);

    TPSA_LOG_INFO("success add fe_idx %hu dip " EID_FMT ", hash node is %u\n", key->fe_idx, EID_ARGS(entry->uvs_ip),
                   live_migrate_table->hmap.count);
    return 0;
}

int live_migrate_table_remove(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t *key)
{
    (void)pthread_rwlock_wrlock(&live_migrate_table->rwlock);
    live_migrate_table_entry_t *entry = live_migrate_table_lookup(live_migrate_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("key fe_idx[%hu], tpf_name[%s] not exist", key->fe_idx, key->tpf_name);
        (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del fe_idx[%hu] tpf_name[%s] dip:" EID_FMT "\n",
        key->fe_idx, key->tpf_name, EID_ARGS(entry->uvs_ip));

    ub_hmap_remove(&live_migrate_table->hmap, &entry->node);
    free(entry);
    (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
    return 0;
}

/* key should be freed after unused. */
int live_migrate_table_return_key(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t **key)
{
    live_migrate_table_entry_t *cur = NULL;

    (void)pthread_rwlock_rdlock(&live_migrate_table->rwlock);
    int cnt = ub_hmap_count(&live_migrate_table->hmap);
    if (cnt == 0) {
        (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
        return 0;
    }

    *key = (live_migrate_table_key_t *)calloc(1, sizeof(live_migrate_table_key_t) * cnt);
    if (*key == NULL) {
        TPSA_LOG_ERR("key calloc failed.\n");
        (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
        return -ENOMEM;
    }

    uint32_t index = 0;
    HMAP_FOR_EACH(cur, node, &live_migrate_table->hmap) {
        (*key)[index++] = cur->key;
    }
    (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
    return cnt;
}

/* tpsa_notify_table */
static tpsa_notify_table_entry_t *alloc_tpsa_notify_table_entry(const tpsa_notify_table_key_t *key,
                                                                tpsa_notify_table_entry_t *add_entry)
{
    tpsa_notify_table_entry_t *entry = (tpsa_notify_table_entry_t *)calloc(1,
        sizeof(tpsa_notify_table_entry_t));
    if (entry == NULL) {
        return NULL;
    }

    entry->key = *key;
    entry->rm_size = add_entry->rm_size;
    entry->rc_size = add_entry->rc_size;
    (void)memcpy(entry->rm_target, add_entry->rm_target, (entry->rm_size * sizeof(rm_vtp_table_entry_t)));
    (void)memcpy(entry->rc_target, add_entry->rc_target, (entry->rc_size * sizeof(rc_vtp_table_entry_t)));

    return entry;
}

int tpsa_notify_table_create(tpsa_notify_table_t *tpsa_notify_table)
{
    if (ub_hmap_init(&tpsa_notify_table->hmap, TPSA_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("tpsa msg table init failed.\n");
        return -ENOMEM;
    }

    return 0;
}

tpsa_notify_table_entry_t *tpsa_notify_table_lookup(tpsa_notify_table_t *tpsa_notify_table,
                                                    tpsa_notify_table_key_t *key)
{
    tpsa_notify_table_entry_t *target = NULL;
    HMAP_FIND(tpsa_notify_table, key, sizeof(*key), target);
    return target;
}

int tpsa_notify_table_add(tpsa_notify_table_t *tpsa_notify_table, tpsa_notify_table_key_t *key,
                          tpsa_notify_table_entry_t *add_entry)
{
    if (tpsa_notify_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -EINVAL;
    }

    tpsa_notify_table_entry_t *entry = alloc_tpsa_notify_table_entry(key, add_entry);
    if (entry == NULL) {
        return -ENOMEM;
    }

    HMAP_INSERT(tpsa_notify_table, entry, key, sizeof(*key));
    TPSA_LOG_INFO("success add tpsa eid " EID_FMT " \n", EID_ARGS(key->peer_uvs_ip));
    return 0;
}

int tpsa_notify_table_update(tpsa_notify_table_t *notify_table, uvs_net_addr_t *peer_uvs_ip,
                             rm_vtp_table_entry_t *rm_entry, rc_vtp_table_entry_t *rc_entry)
{
    if (rm_entry == NULL && rc_entry == NULL) {
        return -EINVAL;
    }

    tpsa_notify_table_key_t key = {
        .peer_uvs_ip = *peer_uvs_ip,
    };

    tpsa_notify_table_entry_t *entry = tpsa_notify_table_lookup(notify_table, &key);
    if (entry == NULL) {
        tpsa_notify_table_entry_t *add_entry = (tpsa_notify_table_entry_t *)calloc(1,
            sizeof(tpsa_notify_table_entry_t));
        if (add_entry == NULL) {
            return -ENOMEM;
        }
        if (rm_entry != NULL) {
            add_entry->rm_size = 1;
            add_entry->rm_target[0] = *rm_entry;
        }

        if (rc_entry != NULL) {
            add_entry->rc_size = 1;
            add_entry->rc_target[0] = *rc_entry;
        }

        if (tpsa_notify_table_add(notify_table, &key, add_entry) < 0) {
            TPSA_LOG_ERR("Fail to add noti table");
            free(add_entry);
            return -1;
        }

        free(add_entry);
    } else {
        if (rm_entry != NULL) {
            uint32_t rm_idx = entry->rm_size;
            entry->rm_target[rm_idx] = *rm_entry;
            entry->rm_size++;
        }

        if (rc_entry != NULL) {
            uint32_t rc_idx = entry->rc_size;
            entry->rc_target[rc_idx] = *rc_entry;
            entry->rc_size++;
        }
    }

    return 0;
}

int tpsa_notify_table_remove(tpsa_notify_table_t *tpsa_notify_table, tpsa_notify_table_key_t *key)
{
    tpsa_notify_table_entry_t *entry = tpsa_notify_table_lookup(tpsa_notify_table, key);
    if (entry == NULL) {
        TPSA_LOG_WARN("eid " EID_FMT " not exist", EID_ARGS(key->peer_uvs_ip));
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del tpsa eid " EID_FMT " \n", EID_ARGS(key->peer_uvs_ip));
    ub_hmap_remove(&tpsa_notify_table->hmap, &entry->node);
    free(entry);
    return 0;
}

void tpsa_notify_table_destroy(tpsa_notify_table_t *tpsa_notify_table)
{
    HMAP_DESTROY(tpsa_notify_table, tpsa_notify_table_entry_t);
    return;
}

lm_wait_sync_table_entry_t *lm_wait_sync_table_lookup(live_migrate_table_t *live_migrate_table,
    live_migrate_table_key_t *key)
{
    lm_wait_sync_table_entry_t *target = NULL;
    HMAP_FIND_INNER(&live_migrate_table->delete_vtp_hmap, key, sizeof(*key), target);
    return target;
}

lm_wait_sync_table_entry_t *lm_wait_sync_table_add(live_migrate_table_t *live_migrate_table,
    live_migrate_table_key_t *key)
{
    if (live_migrate_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }
    lm_wait_sync_table_entry_t *entry = NULL;

    entry = lm_wait_sync_table_lookup(live_migrate_table, key);
    if (entry != NULL) {
        TPSA_LOG_ERR("lm wait sync table entry already exist, add fail, fe_idx[%u], tpf_name[%s].\n",
            key->fe_idx, key->tpf_name);
        return NULL;
    }

    entry = (lm_wait_sync_table_entry_t *)calloc(1, sizeof(lm_wait_sync_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("lm wait sync table fail to alloc entry.\n");
        return NULL;
    }
    entry->key = *key;
    ub_list_init(&entry->lm_wait_sync_vtp_list);
    HMAP_INSERT_INEER(&live_migrate_table->delete_vtp_hmap, entry, key, sizeof(*key));

    TPSA_LOG_INFO("Success add lm wait sync entry, tpf_name[%s], fe_idx[%u].\n", key->tpf_name, key->fe_idx);
    return entry;
}

int lm_wait_sync_table_rmv(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t *key)
{
    if (live_migrate_table == NULL || key == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    lm_wait_sync_table_entry_t *entry = NULL;
    entry = lm_wait_sync_table_lookup(live_migrate_table, key);
    if (entry == NULL) {
        TPSA_LOG_ERR("lm wait sync table entry not exist, tpf_name[%s], fe_idx[%u].\n", key->tpf_name, key->fe_idx);
        return -1;
    }

    lm_wait_sync_vtp_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, &entry->lm_wait_sync_vtp_list) {
        ub_list_remove(&cur->node);
        free(cur);
    }
    ub_hmap_remove(&live_migrate_table->delete_vtp_hmap, &entry->node);
    free(entry);

    TPSA_LOG_INFO("Success delete lm wait sync entry, tpf_name[%s], fe_idx[%u].\n", key->tpf_name, key->fe_idx);
    return 0;
}

int lm_wait_sync_vtp_add(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t *key,
    lm_wait_sync_vtp_t *vtp_node)
{
    if (live_migrate_table == NULL || key == NULL || vtp_node == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    lm_wait_sync_table_entry_t *entry = NULL;
    entry = lm_wait_sync_table_lookup(live_migrate_table, key);
    if (entry == NULL) {
        TPSA_LOG_INFO("lm wait sync table entry not exist, tpf_name[%s], fe_idx[%u], add it.\n",
            key->tpf_name, key->fe_idx);
        entry = lm_wait_sync_table_add(live_migrate_table, key);
        if (entry == NULL) {
            TPSA_LOG_INFO("lm wait sync table add entry failed.\n");
            return -1;
        }
    }

    lm_wait_sync_vtp_t *vtp = (lm_wait_sync_vtp_t *)calloc(1, sizeof(lm_wait_sync_vtp_t));
    if (vtp == NULL) {
        TPSA_LOG_INFO("lm wait sync table alloc vtp node fail\n");
        (void)lm_wait_sync_table_rmv(live_migrate_table, key);
        return -ENOMEM;
    }

    vtp->trans_mode = vtp_node->trans_mode;
    vtp->vtp_entry = vtp_node->vtp_entry;

    TPSA_LOG_INFO("Success add lm wait sync vtp entry, transmode[%u].\n", vtp_node->trans_mode);
    ub_list_push_back(&entry->lm_wait_sync_vtp_list, &vtp->node);
    return 0;
}

int lm_wait_sync_vtp_rmv(lm_wait_sync_vtp_t *vtp_node)
{
    if (vtp_node == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return -EINVAL;
    }

    ub_list_remove(&vtp_node->node);
    free(vtp_node);
    return 0;
}