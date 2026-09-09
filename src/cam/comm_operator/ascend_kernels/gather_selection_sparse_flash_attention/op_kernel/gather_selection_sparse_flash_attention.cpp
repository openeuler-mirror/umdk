/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * See LICENSE in the root of the software repository for the full text of the License.
 */

#if ASC_DEVKIT_MAJOR >= 9
#include "kernel_basic_intf.h"
#else
#include "kernel_operator.h"
#endif
#include "gather_selection_sparse_flash_attention_template_tiling_key.h"
#include "arch22/gather_selection_sparse_flash_attention_kernel_mla.h"

using namespace AscendC;

template <typename QueryType, typename OutputType, int FLASH_DECODE, int LAYOUT_T, int KV_LAYOUT_T, int TEMPLATE_MODE>
__aicore__ inline void RunGsSfaOp(
    __gm__ uint8_t *query, __gm__ uint8_t *selectionKey, __gm__ uint8_t *selectionValue,
    __gm__ uint8_t *selectionTopkIndices, __gm__ uint8_t *keyScale, __gm__ uint8_t *valueScale,
    __gm__ uint8_t *selectionBlockTable, __gm__ uint8_t *actualSeqLengthsQuery, __gm__ uint8_t *fullKvActualSeq,
    __gm__ uint8_t *selectionBlockStatus, __gm__ uint8_t *fullKvCache, __gm__ uint8_t *fullBlockTable,
    __gm__ uint8_t *attentionOut, __gm__ uint8_t *selectionCacheOut, __gm__ uint8_t *selectionBlockTableOut,
    __gm__ uint8_t *selectionBlockStatusOut, __gm__ uint8_t *selectionActualSeqOut, __gm__ uint8_t *user,
    __gm__ uint8_t *tiling, TPipe *tPipe)
{
    GatherSelectionSparseFlashAttentionMla<
        QSFAType<QueryType, int8_t, OutputType, FLASH_DECODE, static_cast<QSFA_LAYOUT>(LAYOUT_T),
                 static_cast<QSFA_LAYOUT>(KV_LAYOUT_T), TEMPLATE_MODE>>
        gsSfaOp;
    GET_TILING_DATA_WITH_STRUCT(GatherSelectionSparseFlashAttentionTilingDataMla, gsSfaTilingDataIn, tiling);
    const GatherSelectionSparseFlashAttentionTilingDataMla *__restrict gsSfaTilingData = &gsSfaTilingDataIn;
    gsSfaOp.Init(query, selectionKey, selectionValue, selectionTopkIndices, keyScale, valueScale, selectionBlockTable,
                 actualSeqLengthsQuery, fullKvActualSeq, selectionBlockStatus, fullKvCache, fullBlockTable,
                 attentionOut, selectionCacheOut, selectionBlockTableOut, selectionBlockStatusOut,
                 selectionActualSeqOut, user, gsSfaTilingData, tiling, tPipe);
    gsSfaOp.Process();
}

template <int FLASH_DECODE, int PAGE_ATTENTION, int LAYOUT_T, int KV_LAYOUT_T, int TEMPLATE_MODE, int IS_SPLIT_G>
__global__ __aicore__ void gather_selection_sparse_flash_attention(
    __gm__ uint8_t *query, __gm__ uint8_t *selectionKey, __gm__ uint8_t *selectionValue,
    __gm__ uint8_t *selectionTopkIndices, __gm__ uint8_t *keyScale, __gm__ uint8_t *valueScale,
    __gm__ uint8_t *selectionBlockTable, __gm__ uint8_t *actualSeqLengthsQuery, __gm__ uint8_t *fullKvActualSeq,
    __gm__ uint8_t *sinks, __gm__ uint8_t *selectionBlockStatus, __gm__ uint8_t *fullKvCache,
    __gm__ uint8_t *fullBlockTable, __gm__ uint8_t *attentionOut, __gm__ uint8_t *selectionCacheOut,
    __gm__ uint8_t *selectionBlockTableOut, __gm__ uint8_t *selectionBlockStatusOut,
    __gm__ uint8_t *selectionActualSeqOut, __gm__ uint8_t *workspace, __gm__ uint8_t *tiling)
{
    KERNEL_TASK_TYPE_DEFAULT(KERNEL_TYPE_MIX_AIC_1_2);
    (void)sinks;
    (void)PAGE_ATTENTION;
    (void)IS_SPLIT_G;

    TPipe tPipe;
    __gm__ uint8_t *user = GetUserWorkspace(workspace);
    // OpDef input/output names drive ORIG_DTYPE_* macros (selection_key, not key).
    if constexpr (ORIG_DTYPE_QUERY == DT_FLOAT16 && ORIG_DTYPE_SELECTION_KEY == DT_INT8 &&
                  ORIG_DTYPE_ATTENTION_OUT == DT_FLOAT16) {
        RunGsSfaOp<half, half, FLASH_DECODE, LAYOUT_T, KV_LAYOUT_T, TEMPLATE_MODE>(
            query, selectionKey, selectionValue, selectionTopkIndices, keyScale, valueScale, selectionBlockTable,
            actualSeqLengthsQuery, fullKvActualSeq, selectionBlockStatus, fullKvCache, fullBlockTable, attentionOut,
            selectionCacheOut, selectionBlockTableOut, selectionBlockStatusOut, selectionActualSeqOut, user, tiling,
            &tPipe);
    } else {
        RunGsSfaOp<bfloat16_t, bfloat16_t, FLASH_DECODE, LAYOUT_T, KV_LAYOUT_T, TEMPLATE_MODE>(
            query, selectionKey, selectionValue, selectionTopkIndices, keyScale, valueScale, selectionBlockTable,
            actualSeqLengthsQuery, fullKvActualSeq, selectionBlockStatus, fullKvCache, fullBlockTable, attentionOut,
            selectionCacheOut, selectionBlockTableOut, selectionBlockStatusOut, selectionActualSeqOut, user, tiling,
            &tPipe);
    }
}
