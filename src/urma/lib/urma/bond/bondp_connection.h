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

typedef struct bondp_conn {
    /* de-duplication */
    bdp_slide_wnd_t recv_wnd;
} bondp_conn_t;

int bondp_conn_table_create(bondp_hash_table_t *tbl, uint32_t size);

int bondp_conn_table_get_or_create(bondp_hash_table_t *tbl, urma_jetty_id_t *target_id, bondp_conn_t **conn);

#endif // BONDP_CONNECTION_H
