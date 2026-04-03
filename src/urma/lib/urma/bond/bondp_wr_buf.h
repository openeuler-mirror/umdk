/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider wr buf header file
 * Author: Wang Hang
 * Create: 2026-03-17
 * Note:
 * History: 2026-03-17   Create File
 */

#ifndef BONDP_WR_BUF_H
#define BONDP_WR_BUF_H

#include <stdint.h>

struct bondp_jetty_ctx;
struct bondp_v_connection;

typedef struct jfs_wr_entry {
    uint64_t wr_id;
    urma_jfs_wr_t wr;
    uint64_t user_ctx;
    struct bondp_jetty_ctx *bjetty_ctx;
    struct bondp_v_connection *v_conn;
    uint32_t send_idx;
} jfs_wr_entry_t;

typedef struct jfr_wr_entry {
    uint64_t wr_id;
    urma_jfr_wr_t wr;
    uint64_t user_ctx;
    struct bondp_jetty_ctx *bjetty_ctx;
    uint32_t recv_idx;
} jfr_wr_entry_t;

typedef struct xwr_buf {
    uint32_t max_wr_num;
    uint32_t latest_used;
    uint32_t wr_entry_size;
    void *entries;
} xwr_buf_t;

int wr_buf_init(xwr_buf_t *buf, uint32_t max_wr_num);
void wr_buf_uninit(xwr_buf_t *buf);

jfs_wr_entry_t *jfs_wr_buf_get(xwr_buf_t *buf, uint64_t wr_id);
jfr_wr_entry_t *jfr_wr_buf_get(xwr_buf_t *buf, uint64_t wr_id);

jfs_wr_entry_t *jfs_wr_buf_alloc(xwr_buf_t *buf);
jfr_wr_entry_t *jfr_wr_buf_alloc(xwr_buf_t *buf);

void jfs_wr_buf_release(jfs_wr_entry_t *entry);
void jfr_wr_buf_release(jfr_wr_entry_t *entry);

#endif // BONDP_WR_BUF_H
