/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa table header file
 * Author: Sun Fang
 * Create: 2023-10-12
 * Note:
 * History: 2023-10-12 uvs table create search header for live migrate
 */

#ifndef UVS_LM_TABLE_H
#define UVS_LM_TABLE_H

#include "urma_types.h"
#include "ub_hmap.h"
#include "tpsa_types.h"
#include "tpsa_table.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LIVE_MIGRATE_TRUE 1
#define LIVE_MIGRATE_FALSE 0

/* tpsa_notify_table
   This table is used when live migration.
   tpsa msg table key is tpsa address, entry has two array to store rm and rc
   create msg(as target) respectively;
   This table can help to split notification into tpsa(pf) granularity.
   We can send re-create notification within the same tpsa in a single msg
   with the help of this table */
typedef struct tpsa_notify_table_key {
    uvs_net_addr_t peer_uvs_ip;
} tpsa_notify_table_key_t;

typedef struct tpsa_notify_table_entry {
    struct ub_hmap_node node;
    tpsa_notify_table_key_t key;
    uint32_t rm_size;
    uint32_t rc_size;
    rm_vtp_table_entry_t rm_target[TPSA_VTP_TABLE_SIZE];
    rc_vtp_table_entry_t rc_target[TPSA_VTP_TABLE_SIZE];
} tpsa_notify_table_entry_t;

typedef struct tpsa_notify_table {
    struct ub_hmap hmap;
} tpsa_notify_table_t;

/* Live migration table */
typedef struct live_migrate_table_entry {
    struct ub_hmap_node node;
    live_migrate_table_key_t key;
    uvs_net_addr_t uvs_ip;
} live_migrate_table_entry_t;

typedef struct lm_wait_sync_vtp {
    struct ub_list node;
    tpsa_transport_mode_t trans_mode;
    union {
        rm_vtp_table_entry_t rm_entry;
        rc_vtp_table_entry_t rc_entry;
        um_vtp_table_entry_t um_entry;
    } vtp_entry;
} lm_wait_sync_vtp_t;

typedef struct lm_wait_sync_table_entry {
    struct ub_hmap_node node;
    live_migrate_table_key_t key;
    struct ub_list lm_wait_sync_vtp_list;
} lm_wait_sync_table_entry_t;

typedef struct live_migrate_table {
    struct ub_hmap hmap;
    struct ub_hmap delete_vtp_hmap; // wait sync deletion hmap
    pthread_rwlock_t rwlock;
} live_migrate_table_t;

/*
 * live_migrate table opts
 */
live_migrate_table_entry_t *live_migrate_table_lookup(live_migrate_table_t *live_migrate_table,
                                                      live_migrate_table_key_t *key);
int live_migrate_table_add(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t *key,
                           live_migrate_table_entry_t *add_entry);
int live_migrate_table_remove(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t *key);
int live_migrate_table_return_key(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t **key);
void live_migrate_table_destroy(live_migrate_table_t *live_migrate_table);
int live_migrate_table_create(live_migrate_table_t *live_migrate_table);

/*
 * tpsa notify table opts
 */
int tpsa_notify_table_create(tpsa_notify_table_t *tpsa_notify_table);
tpsa_notify_table_entry_t *tpsa_notify_table_lookup(tpsa_notify_table_t *tpsa_notify_table,
                                                    tpsa_notify_table_key_t *key);
int tpsa_notify_table_add(tpsa_notify_table_t *tpsa_notify_table, tpsa_notify_table_key_t *key,
                          tpsa_notify_table_entry_t *add_entry);
int tpsa_notify_table_update(tpsa_notify_table_t *notify_table, uvs_net_addr_t *peer_uvs_ip,
                             rm_vtp_table_entry_t *rm_entry, rc_vtp_table_entry_t *rc_entry);
int tpsa_notify_table_remove(tpsa_notify_table_t *tpsa_notify_table, tpsa_notify_table_key_t *key);
void tpsa_notify_table_destroy(tpsa_notify_table_t *tpsa_notify_table);

/*
 * lm wait sync delete vtp table opts
 */
lm_wait_sync_table_entry_t *lm_wait_sync_table_add(live_migrate_table_t *live_migrate_table,
    live_migrate_table_key_t *key);
lm_wait_sync_table_entry_t *lm_wait_sync_table_lookup(live_migrate_table_t *live_migrate_table,
    live_migrate_table_key_t *key);
int lm_wait_sync_table_rmv(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t *key);
void lm_wait_sync_table_destroy(live_migrate_table_t *live_migrate_table);
int lm_wait_sync_vtp_add(live_migrate_table_t *live_migrate_table, live_migrate_table_key_t *key,
    lm_wait_sync_vtp_t *vtp_node);
int lm_wait_sync_vtp_rmv(lm_wait_sync_vtp_t *vtp_node);

#ifdef __cplusplus
}
#endif

#endif
