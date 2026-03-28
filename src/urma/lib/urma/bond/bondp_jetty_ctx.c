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

bjetty_ctx_t *create_bjetty_ctx(urma_context_t *ctx, bondp_comp_t *bdp_comp,
    size_t wr_buf_size)
{
    bjetty_ctx_t *bjetty_ctx = NULL;

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
    if (bdp_v_conn_table_create(&bjetty_ctx->v_conn_table, BONDP_MAX_NUM_JETTYS)) {
        goto DESTROY_WR_BUFS;
    }

    bjetty_ctx->direct_local_port = -1;
    bjetty_ctx->direct_target_port = -1;

    return bjetty_ctx;
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
    destroy_bjetty_wr_bufs(bjetty_ctx);
    free(bjetty_ctx);
}
