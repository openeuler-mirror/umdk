/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond provider jetty context implementation
 * Author: Ma Chuan
 * Create: 2025-02-21
 * Note:
 * History: 2025-02-21   Create File
 */
#include "urma_api.h"
#include "urma_log.h"
#include "urma_private.h"
#include "bondp_types.h"
#include "bondp_connection.h"
#include "bondp_jetty_ctx.h"

int init_bjetty_ctx(urma_context_t *ctx, bondp_comp_t *bdp_comp, bjetty_ctx_t *bjetty_ctx, size_t wr_buf_size)
{
    (void)wr_buf_size;
    bjetty_ctx->bond_ctx = CONTAINER_OF_FIELD(ctx, bondp_context_t, v_ctx);
    bjetty_ctx->bdp_comp = bdp_comp;

    // set all pjettys as valid
    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (bdp_comp->members[i] == NULL) {
            bjetty_ctx->pjettys_error_done[i] = PJETTY_SUSPEND_DONE | PJETTY_FLUSH_ERROR_DONE;
            continue;
        }
    }

    if (bdp_v_conn_table_create(&bjetty_ctx->v_conn_table, BONDP_MAX_NUM_JETTYS)) {
        return -1;
    }
    return 0;
}

void uninit_bjetty_ctx(bjetty_ctx_t *bjetty_ctx)
{
    if (bjetty_ctx == NULL) {
        return;
    }
    bondp_hash_table_destroy(&bjetty_ctx->v_conn_table);
    (void)memset(bjetty_ctx, 0, sizeof(*bjetty_ctx));
}
