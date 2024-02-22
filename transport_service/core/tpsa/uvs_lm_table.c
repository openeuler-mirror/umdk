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
        return NULL;
    }
    entry->key = *key;
    entry->live_migrate_flag = add_entry->live_migrate_flag;
    (void)memcpy(&entry->dip, &add_entry->dip, TPSA_EID_SIZE);

    return entry;
}

int live_migrate_table_create(live_migrate_table_t *live_migrate_table)
{
    if (ub_hmap_init(&live_migrate_table->hmap, TPSA_TABLE_SIZE) != 0) {
        TPSA_LOG_ERR("live_migrate_table init failed.\n");
        return -ENOMEM;
    }

    (void)pthread_rwlock_init(&live_migrate_table->rwlock, NULL);
    return 0;
}

void live_migrate_table_destroy(live_migrate_table_t *live_migrate_table)
{
    (void)pthread_rwlock_wrlock(&live_migrate_table->rwlock);
    HMAP_DESTROY(live_migrate_table, live_migrate_table_entry_t);
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

    TPSA_LOG_INFO("success add fe_idx %hu dip " EID_FMT ", hash node is %u\n", key->fe_idx, EID_ARGS(entry->dip),
                   live_migrate_table->hmap.count);
    return 0;
}

int live_migrate_table_remove(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t *key)
{
    (void)pthread_rwlock_wrlock(&live_migrate_table->rwlock);
    live_migrate_table_entry_t *entry = live_migrate_table_lookup(live_migrate_table, key);
    if (entry == NULL || entry->live_migrate_flag == LIVE_MIGRATE_FALSE) {
        TPSA_LOG_WARN("key fe_idx %hu not exist", key->fe_idx);
        (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del fe_idx %hu dip:" EID_FMT "\n", key->fe_idx, EID_ARGS(entry->dip));

    ub_hmap_remove(&live_migrate_table->hmap, &entry->node);
    free(entry);
    (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);
    return 0;
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
    TPSA_LOG_INFO("success add tpsa eid " EID_FMT " \n", EID_ARGS(key->peer_tpsa_eid));
    return 0;
}

int tpsa_notify_table_update(tpsa_notify_table_t *notify_table, urma_eid_t *peer_tpsa_eid,
                             rm_vtp_table_entry_t *rm_entry, rc_vtp_table_entry_t *rc_entry)
{
    if (rm_entry == NULL && rc_entry == NULL) {
        return 0;
    }

    tpsa_notify_table_key_t key = {
        .peer_tpsa_eid = *peer_tpsa_eid,
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
        TPSA_LOG_WARN("eid " EID_FMT " not exist", EID_ARGS(key->peer_tpsa_eid));
        return -ENXIO;
    }

    TPSA_LOG_INFO("success del tpsa eid " EID_FMT " \n", EID_ARGS(key->peer_tpsa_eid));
    ub_hmap_remove(&tpsa_notify_table->hmap, &entry->node);
    free(entry);
    return 0;
}

void tpsa_notify_table_destroy(tpsa_notify_table_t *tpsa_notify_table)
{
    HMAP_DESTROY(tpsa_notify_table, tpsa_notify_table_entry_t);
    return;
}

/*  vf_delete_list add/remove/lookup/destroy opts */
vport_del_list_node_t *vport_del_list_lookup(struct ub_list *list, vport_key_t *key)
{
    vport_del_list_node_t *cur, *next;
    vport_del_list_node_t *node = NULL;

    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        if (memcmp(&cur->vport_key, key, sizeof(vport_key_t)) != 0) {
            continue;
        }
        node = cur;
        break;
    }

    return node;
}

int vport_del_list_add(struct ub_list *list, vport_table_entry_t *entry)
{
    vport_del_list_node_t *node = (vport_del_list_node_t *)calloc(1, sizeof(vport_del_list_node_t));
    if (node == NULL) {
        return -ENOMEM;
    }
    node->vport_key = entry->key;
    node->sip_idx = entry->sip_idx;
    node->tp_cnt = entry->tp_cnt;
    ub_list_push_back(list, &node->node);

    return 0;
}

void vport_del_list_destroy(struct ub_list *list)
{
    vport_del_list_node_t *cur, *next;

    UB_LIST_FOR_EACH_SAFE(cur, next, node, list) {
        ub_list_remove(&cur->node);
        free(cur);
    }
}