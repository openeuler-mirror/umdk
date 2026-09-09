/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: GatherSelectionSparseFlashAttention aclnn interface header
 */

#ifndef ACLNN_GATHER_SELECTION_SPARSE_FLASH_ATTENTION_H_
#define ACLNN_GATHER_SELECTION_SPARSE_FLASH_ATTENTION_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) aclnnStatus aclnnGatherSelectionSparseFlashAttentionGetWorkspaceSize(
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
    aclOpExecutor **executor);

__attribute__((visibility("default"))) aclnnStatus aclnnGatherSelectionSparseFlashAttention(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
