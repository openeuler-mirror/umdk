/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider virtual connection structure implementation
 * Author: Ma Chuan
 * Create: 2025-03-06
 * Note:
 * History: 2025-03-06  Create file
 */
#include "ub_hash.h"
#include "ub_util.h"
#include "urma_log.h"
#include "bondp_types.h"
#include "bondp_connection.h"

#define BDP_V_CONN_HASH_BASIS (0x87820129)

void init_v_conn_on_send(bdp_v_conn_t *v_conn, void *target_vjetty, int target_dev_num)
{
    if (v_conn == NULL || target_vjetty == NULL) {
        URMA_LOG_ERR("Invalid param\n");
        return;
    }
    bondp_target_jetty_t *bdp_tjetty = target_vjetty;
    v_conn->target_vjetty = bdp_tjetty;
    v_conn->target_dev_num = target_dev_num;
    v_conn->non_rqe_idx = 0;
    v_conn->rqe_idx = 0;
    memcpy(v_conn->target_valid, bdp_tjetty->valid, sizeof(bool) * target_dev_num);
}

int bdp_v_conn_init(bdp_v_conn_t *v_conn)
{
    v_conn->target_vjetty = NULL;
    v_conn->target_dev_num = 0;
    v_conn->msn = 0;
    if (bdp_slide_wnd_init(&v_conn->recv_wnd, BONDP_MAX_BITMAP_SIZE, BONDP_RECV_WND_SIZE, 0)) {
        URMA_LOG_ERR("Failed to init slide window in bdp_v_conn_table_add");
        return -1;
    }
    if (bdp_slide_wnd_init(&v_conn->send_wnd, BONDP_MAX_BITMAP_SIZE, BONDP_RECV_WND_SIZE, 0)) {
        URMA_LOG_ERR("Failed to init sender slide window in bdp_v_conn_table_add");
        goto UNINIT_RCV_WND;
    }
    return 0;
UNINIT_RCV_WND:
    bdp_slide_wnd_uninit(&v_conn->recv_wnd);
    return -1;
}

void bdp_v_conn_uninit(bdp_v_conn_t *v_conn)
{
    bdp_slide_wnd_uninit(&v_conn->recv_wnd);
    bdp_slide_wnd_uninit(&v_conn->send_wnd);
}

static bool v_conn_comp(struct ub_hmap_node *node, void *key)
{
    bdp_v_conn_node_t *v_conn_node = CONTAINER_OF_FIELD(node, bdp_v_conn_node_t, hmap_node);
    urma_jetty_id_t *jetty_id = (urma_jetty_id_t *)key;
    return v_conn_node->target_id.eid.in6.interface_id == jetty_id->eid.in6.interface_id &&
        v_conn_node->target_id.eid.in6.subnet_prefix == jetty_id->eid.in6.subnet_prefix &&
        v_conn_node->target_id.id == jetty_id->id &&
        v_conn_node->target_id.uasid == jetty_id->uasid;
}

static void v_conn_free(struct ub_hmap_node *node)
{
    bdp_v_conn_node_t *v_conn_node = CONTAINER_OF_FIELD(node, bdp_v_conn_node_t, hmap_node);
    if (v_conn_node->v_conn.aggr_mode != URMA_AGGR_MODE_STANDALONE) {
 	  	bdp_v_conn_uninit(&v_conn_node->v_conn);
 	}
    free(v_conn_node);
}

static uint32_t v_conn_hash(void *key)
{
    urma_jetty_id_t *jetty_id = (urma_jetty_id_t *)key;
    return jetty_id->eid.in4.addr + jetty_id->eid.in4.prefix + jetty_id->eid.in4.reserved +
        jetty_id->id + jetty_id->uasid;
}

int bdp_v_conn_table_create(bondp_hash_table_t *tbl, uint32_t size)
{
    return bondp_hash_table_create(tbl, size, v_conn_comp, v_conn_free, v_conn_hash);
}

int bdp_v_conn_table_add_on_send(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id,
    void *target_vjetty, int target_dev_num, bdp_v_conn_t **v_conn_out, urma_context_aggr_mode_t aggr_mode)
{
    hmap_node_t *node = NULL;
    uint32_t hash = tbl->hash_f(target_id);
    bdp_v_conn_node_t *v_conn_node = NULL;

    node = bondp_hash_table_lookup_without_lock(tbl, target_id, hash);
    if (node) {
        return BONDP_HASH_MAP_COLLIDE_ERROR;
    }
    v_conn_node = malloc(sizeof(bdp_v_conn_node_t));
    if (v_conn_node == NULL) {
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
    /* When aggr_mode is URMA_AGGR_MODE_STANDALONE, skip initialization */
 	if (aggr_mode != URMA_AGGR_MODE_STANDALONE) {
 	  	if (bdp_v_conn_init(&v_conn_node->v_conn)) {
 	  	  	goto FREE_VCONN_NODE;
 	  	}
 	}
 	v_conn_node->v_conn.aggr_mode = aggr_mode;
    init_v_conn_on_send(&v_conn_node->v_conn, target_vjetty, target_dev_num);
    v_conn_node->target_id = *target_id;
    bondp_hash_table_add_with_hash(tbl, &v_conn_node->hmap_node, hash);
    *v_conn_out = &v_conn_node->v_conn;
    return 0;
FREE_VCONN_NODE:
    free(v_conn_node);
    return BONDP_HASH_MAP_ALLOC_ERROR;
}

int bdp_v_conn_table_add_on_recv(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id, bdp_v_conn_t **v_conn_out,
    urma_context_aggr_mode_t aggr_mode)
{
    hmap_node_t *node = NULL;
    uint32_t hash = tbl->hash_f(target_id);
    bdp_v_conn_node_t *v_conn_node = NULL;

    node = bondp_hash_table_lookup_without_lock(tbl, target_id, hash);
    if (node) {
        return BONDP_HASH_MAP_COLLIDE_ERROR;
    }
    v_conn_node = malloc(sizeof(bdp_v_conn_node_t));
    if (v_conn_node == NULL) {
        return BONDP_HASH_MAP_ALLOC_ERROR;
    }
    /* When aggr_mode is URMA_AGGR_MODE_STANDALONE, skip initialization */
 	if (aggr_mode != URMA_AGGR_MODE_STANDALONE) {
 	  	if (bdp_v_conn_init(&v_conn_node->v_conn)) {
 	  	  	goto FREE_VCONN_NODE;
 	  	}
 	}
 	v_conn_node->v_conn.aggr_mode = aggr_mode;
    v_conn_node->target_id = *target_id;
    bondp_hash_table_add_with_hash(tbl, &v_conn_node->hmap_node, hash);
    *v_conn_out = &v_conn_node->v_conn;
    return 0;
FREE_VCONN_NODE:
    free(v_conn_node);
    return BONDP_HASH_MAP_ALLOC_ERROR;
}

bdp_v_conn_t *bdp_v_conn_table_lookup(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id)
{
    hmap_node_t *node = NULL;
    node = bondp_hash_table_lookup_without_lock(tbl, target_id, tbl->hash_f(target_id));
    if (node == NULL) {
        return NULL;
    }
    return &(CONTAINER_OF_FIELD(node, bdp_v_conn_node_t, hmap_node)->v_conn);
}
