/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider virtual connection structure header
 * Author: Ma Chuan
 * Create: 2025-03-06
 * Note:
 * History: 2025-03-06  Create file
 */
#ifndef BONDP_CONNECTION_H
#define BONDP_CONNECTION_H

#include "bondp_hash_table.h"
#include "bondp_slide_window.h"
#include "bondp_types.h"

#define BONDP_RECV_WND_SIZE   (1U << 12)
#define BONDP_MAX_BITMAP_SIZE (1U << 16)

/** A virtual connection between two vjettys.
 * Virtual connection is used to implement de-duplication between two vjettys.
 */
typedef struct bondp_v_connection {
    /* de-duplication */
    bdp_slide_wnd_t recv_wnd;
    bool is_init;
} bdp_v_conn_t;

typedef struct bdp_v_conn_node {
    hmap_node_t hmap_node;
    urma_jetty_id_t target_id; /* key */
    bdp_v_conn_t v_conn;
} bdp_v_conn_node_t;

int bdp_v_conn_table_create(bondp_hash_table_t *tbl, uint32_t size);

bdp_v_conn_t *bdp_v_conn_table_lookup(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id);

int bdp_v_conn_table_add_on_recv(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id,
                                 bdp_v_conn_t **v_conn_out, bool is_standalone);

#endif // BONDP_CONNECTION_H
