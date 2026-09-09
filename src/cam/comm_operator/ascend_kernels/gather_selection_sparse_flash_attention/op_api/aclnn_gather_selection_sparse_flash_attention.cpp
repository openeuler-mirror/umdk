/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: GatherSelectionSparseFlashAttention aclnn wrapper
 */

#include "aclnn/opdev/platform.h"
#include "aclnnInner_gather_selection_sparse_flash_attention.h"
#include "aclnn_gather_selection_sparse_flash_attention.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnGatherSelectionSparseFlashAttentionGetWorkspaceSize(
    const aclTensor *query,
    aclTensor *selectionKeyRef,
    aclTensor *selectionValueRef,
    const aclTensor *selectionTopkIndices,
    const aclTensor *keyDequantScale,
    const aclTensor *valueDequantScale,
    aclTensor *selectionKvBlockTableRef,
    const aclTensor *actualSeqLengthsQuery,
    const aclTensor *fullKvActualSeq,
    const aclTensor *sinks,
    aclTensor *selectionKvBlockStatusRef,
    const aclTensor *fullKvCache,
    const aclTensor *fullKvBlockTable,
    double scaleValue,
    int64_t keyQuantMode,
    int64_t valueQuantMode,
    int64_t sparseBlockSize,
    char *layoutQuery,
    char *layoutKv,
    int64_t sparseMode,
    int64_t preTokens,
    int64_t nextTokens,
    int64_t attentionMode,
    int64_t quantScaleRepoMode,
    int64_t tileSize,
    int64_t ropeHeadDim,
    int64_t selectionTopkBlockSize,
    const aclTensor *attentionOut,
    const aclTensor *selectionKvActualSeqOut,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerGatherSelectionSparseFlashAttentionGetWorkspaceSize(
        query, selectionKeyRef, selectionValueRef, selectionTopkIndices, keyDequantScale, valueDequantScale,
        selectionKvBlockTableRef, actualSeqLengthsQuery, fullKvActualSeq, sinks, selectionKvBlockStatusRef,
        fullKvCache, fullKvBlockTable, scaleValue, keyQuantMode, valueQuantMode, sparseBlockSize, layoutQuery,
        layoutKv, sparseMode, preTokens, nextTokens, attentionMode, quantScaleRepoMode, tileSize, ropeHeadDim,
        selectionTopkBlockSize, attentionOut, selectionKvActualSeqOut, workspaceSize, executor);
}

aclnnStatus aclnnGatherSelectionSparseFlashAttention(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerGatherSelectionSparseFlashAttention(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
