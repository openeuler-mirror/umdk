/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add gather selection kv cache kernel
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create file
 */

#ifndef ACLNN_GATHER_SELECTION_KV_CACHE_H_
#define ACLNN_GATHER_SELECTION_KV_CACHE_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* funtion: aclnnGatherSelectionKvCacheGetWorkspaceSize
 * parameters :
 * selectionKRopeRef : required
 * selectionKvCacheRef : required
 * selectionKvBlockTableRef : required
 * selectionKvBlockStatusRef : required
 * selectionTopkIndices : required
 * fullKRope : required
 * fullKvCache : required
 * fullKvBlockTable : required
 * fullKvActualSeq : required
 * fullQActualSeq : required
 * selectionTopkBlockSize : optional
 * selectionKRopeRef : required
 * selectionKvCacheRef : required
 * selectionKvBlockTableRef : required
 * selectionKvBlockStatusRef : required
 * selectionKvActualSeqOut : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnGatherSelectionKvCacheGetWorkspaceSize(
    aclTensor *selectionKRopeRef,
    aclTensor *selectionKvCacheRef,
    aclTensor *selectionKvBlockTableRef,
    aclTensor *selectionKvBlockStatusRef,
    const aclTensor *selectionTopkIndices,
    const aclTensor *fullKRope,
    const aclTensor *fullKvCache,
    const aclTensor *fullKvBlockTable,
    const aclTensor *fullKvActualSeq,
    const aclTensor *fullQActualSeq,
    int64_t selectionTopkBlockSize,
    const aclTensor *selectionKvActualSeqOut,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

/* funtion: aclnnGatherSelectionKvCache
 * parameters :
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnGatherSelectionKvCache(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif