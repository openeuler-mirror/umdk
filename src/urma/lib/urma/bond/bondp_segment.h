/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider segment header
 * Author: Ma Chuan
 * Create: 2025-02-18
 * Note:
 * History: 2025-02-18
 */
#ifndef BONDP_SEGMENT_H
#define BONDP_SEGMENT_H

#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bonding segment ops */
urma_token_id_t *bondp_alloc_token_id(urma_context_t *ctx);

urma_status_t bondp_free_token_id(urma_token_id_t *token_id);

urma_target_seg_t *bondp_register_seg(urma_context_t *ctx, urma_seg_cfg_t *seg_cfg);

urma_status_t bondp_unregister_seg(urma_target_seg_t *target_seg);

urma_target_seg_t *bondp_import_seg(urma_context_t *ctx, urma_seg_t *seg,
                                    urma_token_t *token, uint64_t addr, urma_import_seg_flag_t flag);

urma_status_t bondp_unimport_seg(urma_target_seg_t *target_seg);

void bondp_tseg_get(urma_target_seg_t *target_seg);

void bondp_tseg_put(urma_target_seg_t *target_seg);

#ifdef __cplusplus
}
#endif
#endif // BONDP_SEGMENT_H
