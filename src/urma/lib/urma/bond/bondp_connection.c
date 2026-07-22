/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider virtual connection structure implementation
 * Author: Ma Chuan
 * Create: 2025-03-06
 * Note:
 * History: 2025-03-06  Create file
 */

#include <stdlib.h>

#include "urma_log.h"

#include "bondp_types.h"
#include "ub_hash.h"
#include "ub_util.h"

#include "bondp_connection.h"

typedef struct bondp_conn_node {
    hmap_node_t hmap_node;
    urma_jetty_id_t target_id; /* key */
    bondp_conn_t v_conn;
} bondp_conn_node_t;

static int bdp_v_conn_init(bondp_conn_t *v_conn)
{
    if (bdp_slide_wnd_init(&v_conn->recv_wnd, BONDP_MAX_BITMAP_SIZE, BONDP_RECV_WND_SIZE, 0)) {
        URMA_LOG_ERR("Failed to init slide window in bdp_v_conn_table_add\n");
        return -1;
    }
    return 0;
}

static void bdp_v_conn_uninit(bondp_conn_t *v_conn)
{
    bdp_slide_wnd_uninit(&v_conn->recv_wnd);
}

static bool v_conn_comp(struct ub_hmap_node *node, void *key)
{
    bondp_conn_node_t *v_conn_node = CONTAINER_OF_FIELD(node, bondp_conn_node_t, hmap_node);
    urma_jetty_id_t *jetty_id = (urma_jetty_id_t *)key;
    return v_conn_node->target_id.eid.in6.interface_id == jetty_id->eid.in6.interface_id &&
           v_conn_node->target_id.eid.in6.subnet_prefix == jetty_id->eid.in6.subnet_prefix &&
           v_conn_node->target_id.id == jetty_id->id &&
           v_conn_node->target_id.uasid == jetty_id->uasid;
}

static void v_conn_free(struct ub_hmap_node *node)
{
    bondp_conn_node_t *v_conn_node = CONTAINER_OF_FIELD(node, bondp_conn_node_t, hmap_node);
    bdp_v_conn_uninit(&v_conn_node->v_conn);
    free(v_conn_node);
}

static uint32_t v_conn_hash(void *key)
{
    urma_jetty_id_t *jetty_id = (urma_jetty_id_t *)key;
    return jetty_id->eid.in4.addr + jetty_id->eid.in4.prefix + jetty_id->eid.in4.reserved +
           jetty_id->id + jetty_id->uasid;
}

int bondp_conn_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size, v_conn_comp, v_conn_free, v_conn_hash);
}

int bondp_conn_table_get_or_create(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id, bondp_conn_t **conn)
{
    hmap_node_t *node = NULL;
    uint32_t hash = tbl->hash_f(target_id);
    bondp_conn_node_t *new_node = NULL;

    node = bondp_hash_table_lookup_without_lock(tbl, target_id, hash);
    if (node) {
        *conn = &(CONTAINER_OF_FIELD(node, bondp_conn_node_t, hmap_node)->v_conn);
        return 0;
    }
    new_node = calloc(1, sizeof(bondp_conn_node_t));
    if (new_node == NULL) {
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
    if (bdp_v_conn_init(&new_node->v_conn)) {
        goto FREE_VCONN_NODE;
    }
    new_node->target_id = *target_id;
    bondp_hash_table_add_with_hash(tbl, &new_node->hmap_node, hash);
    *conn = &new_node->v_conn;
    return 0;
FREE_VCONN_NODE:
    free(new_node);
    return BONDP_HASH_MAP_ALLOC_ERROR;
}
