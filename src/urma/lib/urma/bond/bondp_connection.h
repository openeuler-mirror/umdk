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
#include "bdp_queue.h"
#include "wr_buffer.h"

#define BONDP_RECV_WND_SIZE (1U << 12)
#define BONDP_MAX_BITMAP_SIZE (1U << 16)
#define BONDP_MAX_SO_QUEUE_SIZE (65535)

/** A virtual connection between two vjettys.
 * Virtual connection is used to implement de-duplication between two vjettys.
*/
typedef struct bondp_v_connection {
    /* only valid on sender side */
    void *target_vjetty;
    int target_dev_num;
    bool target_valid[URMA_UBAGG_DEV_MAX_NUM];
    int non_rqe_idx;
    int rqe_idx;
    /* ~ only valid on sender side ~ */
    /* de-duplication */
    uint32_t msn;
    bdp_slide_wnd_t recv_wnd;
    /* TA ordering */
    bdp_queue_t send_strong_order_queue; /* Cache SO WRs waiting to be sent */
    bdp_slide_wnd_t send_wnd;
    bdp_queue_t recv_strong_order_cr_queue; /* Cache SO CRs in polling */
    /* Valid for both TX and RX side */
 	urma_context_aggr_mode_t aggr_mode;
} bdp_v_conn_t;

void init_v_conn_on_send(bdp_v_conn_t *v_conn, void *target_vjetty, int target_dev_num);

typedef struct bdp_v_conn_node {
    hmap_node_t hmap_node;
    urma_jetty_id_t target_id; /* key */
    bdp_v_conn_t v_conn;
} bdp_v_conn_node_t;

int bdp_v_conn_table_create(bondp_hash_table_t *tbl, uint32_t size);

bdp_v_conn_t *bdp_v_conn_table_lookup(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id);

int bdp_v_conn_table_add_on_send(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id,
    void *target_vjetty, int target_dev_num, bdp_v_conn_t **v_conn_out, urma_context_aggr_mode_t aggr_mode);

int bdp_v_conn_table_add_on_recv(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id,
    bdp_v_conn_t **v_conn_out, urma_context_aggr_mode_t aggr_mode);

typedef struct bdp_v_conn_snd_so_queue_data {
    urma_jfs_wr_t *send_wr;
    wr_buf_extra_value_t ex_value;
    uint32_t send_wr_id;
} so_queue_data_t;

int bdp_v_conn_push_send_so(bdp_v_conn_t *v_conn, so_queue_data_t *data);

int bdp_v_conn_pop_send_so(bdp_v_conn_t *v_conn, so_queue_data_t *data);

typedef struct bdp_v_conn_rcv_so_queue_data {
    uint32_t msn;
    urma_cr_t cr;
} so_cr_queue_data_t;

int bdp_v_conn_push_recv_so_cr(bdp_v_conn_t *v_conn, so_cr_queue_data_t *data);

int bdp_v_conn_pop_recv_so_cr(bdp_v_conn_t *v_conn, so_cr_queue_data_t *data);

#endif // BONDP_CONNECTION_H