/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond provider jetty context implementation
 * Author: Ma Chuan
 * Create: 2025-02-21
 * Note:
 * History: 2025-02-21   Create File
 */
#include <malloc.h>
#include "urma_api.h"
#include "urma_log.h"
#include "urma_private.h"
#include "bondp_types.h"
#include "bondp_connection.h"
#include "bondp_jetty_ctx.h"

#define BJETTY_CTX_PAGE_SIZE (0x1000) // 4KB

static int create_bjetty_wr_bufs(bjetty_ctx_t *bjetty_ctx, size_t wr_buf_size)
{
    int p = 0, q = 0; // error handler of jfs/jfr buf
    for (p = 0; p < bjetty_ctx->dev_num; ++p) {
        bjetty_ctx->jfs_bufs[p] = jfs_wr_buf_new(wr_buf_size);
        if (bjetty_ctx->jfs_bufs[p] == NULL) {
            goto DEL_JFS_BUF;
        }
    }
    for (q = 0; q < bjetty_ctx->dev_num; ++q) {
        bjetty_ctx->jfr_bufs[q] = jfr_wr_buf_new(wr_buf_size);
        if (bjetty_ctx->jfr_bufs[q] == NULL) {
            goto DEL_JFR_BUF;
        }
    }
    return 0;

DEL_JFR_BUF:
    for (int i = 0; i < q; ++i) {
        jfr_wr_buf_delete(bjetty_ctx->jfr_bufs[i]);
    }
DEL_JFS_BUF:
    for (int i = 0; i < p; ++i) {
        jfs_wr_buf_delete(bjetty_ctx->jfs_bufs[i]);
    }
    return -1;
}

static void destroy_bjetty_wr_bufs(bjetty_ctx_t *bjetty_ctx)
{
    for (int i = 0; i < bjetty_ctx->dev_num; ++i) {
        jfr_wr_buf_delete(bjetty_ctx->jfr_bufs[i]);
    }
    for (int i = 0; i < bjetty_ctx->dev_num; ++i) {
        jfs_wr_buf_delete(bjetty_ctx->jfs_bufs[i]);
    }
}

static int create_bjetty_segments(urma_context_t *ctx, bjetty_ctx_t *bjetty_ctx, size_t hdr_buf_size)
{
    urma_seg_cfg_t seg_cfg = {
        .va = 0,
        .len = hdr_buf_size,
        .flag = {
            .bs.token_policy = URMA_TOKEN_PLAIN_TEXT,
            .bs.cacheable = URMA_NON_CACHEABLE,
            .bs.access = URMA_ACCESS_LOCAL_ONLY,
            .bs.reserved = 0
        },
        // Only used in SEND ops, no need to set token_value.
        .token_value = {0},
        .user_ctx = (uintptr_t)NULL,
        .iova = 0
    };

    bjetty_ctx->hdr_buf_size = hdr_buf_size;
    bjetty_ctx->hdr_send_buf = memalign(BJETTY_CTX_PAGE_SIZE, hdr_buf_size);
    if (bjetty_ctx->hdr_send_buf == NULL) {
        return -1;
    }
    bjetty_ctx->hdr_recv_buf = memalign(BJETTY_CTX_PAGE_SIZE, hdr_buf_size);
    if (bjetty_ctx->hdr_recv_buf == NULL) {
        goto FREE_HDR_SEND_BUF;
    }
    seg_cfg.va = (uint64_t)bjetty_ctx->hdr_send_buf;
    bjetty_ctx->hdr_send_tseg = urma_register_seg(ctx, &seg_cfg);
    if (bjetty_ctx->hdr_send_tseg == NULL) {
        goto FREE_HDR_RECV_BUF;
    }
    seg_cfg.va = (uint64_t)bjetty_ctx->hdr_recv_buf;
    bjetty_ctx->hdr_recv_tseg = urma_register_seg(ctx, &seg_cfg);
    if (bjetty_ctx->hdr_recv_tseg == NULL) {
        goto UNREGISTER_SEND_BUF;
    }
    return 0;

UNREGISTER_SEND_BUF:
    urma_unregister_seg(bjetty_ctx->hdr_send_tseg);
FREE_HDR_RECV_BUF:
    free(bjetty_ctx->hdr_recv_buf);
FREE_HDR_SEND_BUF:
    free(bjetty_ctx->hdr_send_buf);
    return -1;
}

static void destroy_bjetty_segments(bjetty_ctx_t *bjetty_ctx)
{
    (void)urma_unregister_seg(bjetty_ctx->hdr_recv_tseg);
    (void)urma_unregister_seg(bjetty_ctx->hdr_send_tseg);
    free(bjetty_ctx->hdr_recv_buf);
    bjetty_ctx->hdr_recv_buf = NULL;
    free(bjetty_ctx->hdr_send_buf);
    bjetty_ctx->hdr_send_buf = NULL;
}

bjetty_ctx_t *create_bjetty_ctx(urma_context_t *ctx, bondp_comp_t *bdp_comp,
    size_t wr_buf_size, size_t hdr_buf_size)
{
    bjetty_ctx_t *bjetty_ctx = NULL;

    if (hdr_buf_size & (BJETTY_CTX_PAGE_SIZE - 1)) {
        URMA_LOG_ERR("Unaligned hdr_buf_size\n");
        return NULL;
    }

    bjetty_ctx = (bjetty_ctx_t *)calloc(1, sizeof(bjetty_ctx_t));
    if (bjetty_ctx == NULL) {
        return NULL;
    }
    bjetty_ctx->bond_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    bjetty_ctx->bdp_comp = bdp_comp;
    bjetty_ctx->dev_num = bdp_comp->dev_num;
    bjetty_ctx->pjettys = (urma_jetty_t **)bdp_comp->members;

    // set all pjettys as valid
    for (int i = 0; i < bdp_comp->dev_num; ++i) {
        if (bjetty_ctx->pjettys[i] == NULL) {
            bjetty_ctx->pjettys_error_done[i] = PJETTY_SUSPEND_DONE | PJETTY_FLUSH_ERROR_DONE;
            continue;
        }
        bjetty_ctx->pjettys_valid[i] = true;
    }

    if (create_bjetty_wr_bufs(bjetty_ctx, wr_buf_size)) {
        goto FREE_CTX;
    }
    if (create_bjetty_segments(ctx, bjetty_ctx, hdr_buf_size)) {
        goto DESTROY_WR_BUFS;
    }
    if (bdp_v_conn_table_create(&bjetty_ctx->v_conn_table, BONDP_MAX_NUM_JETTYS)) {
        goto DESTROY_SEGMENTS;
    }

    bjetty_ctx->direct_local_port = -1;
    bjetty_ctx->direct_target_port = -1;

    return bjetty_ctx;

DESTROY_SEGMENTS:
    destroy_bjetty_segments(bjetty_ctx);
DESTROY_WR_BUFS:
    destroy_bjetty_wr_bufs(bjetty_ctx);
FREE_CTX:
    free(bjetty_ctx);
    return NULL;
}

void destroy_bjetty_ctx(bjetty_ctx_t *bjetty_ctx)
{
    if (bjetty_ctx == NULL) {
        return;
    }
    bondp_hash_table_destroy(&bjetty_ctx->v_conn_table);
    destroy_bjetty_segments(bjetty_ctx);
    destroy_bjetty_wr_bufs(bjetty_ctx);
    free(bjetty_ctx);
}
