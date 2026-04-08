/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond provider jetty context header file
 * Author: Ma Chuan
 * Create: 2025-02-21
 * Note:
 * History: 2025-02-21   Create File
 */
#ifndef BONDP_JETTY_CTX_H
#define BONDP_JETTY_CTX_H

#include "bondp_hash_table.h"
#include "bondp_types.h"
#include "urma_types.h"
#include "urma_ubagg.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pjetty_error_done_type {
    PJETTY_SUSPEND_DONE = 1,
    PJETTY_FLUSH_ERROR_DONE = 2
} pjetty_error_done_type_t;

int init_bjetty_ctx(urma_context_t *ctx, bondp_comp_t *bdp_jetty, bjetty_ctx_t *bjetty_ctx, size_t wr_buf_size);
void uninit_bjetty_ctx(bjetty_ctx_t *bjetty);

#ifdef __cplusplus
}
#endif
#endif // BONDP_JETTY_CTX_H
