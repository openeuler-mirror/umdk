/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: GatherSelectionKvCacheCustom aclnn wrapper implementation
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create GatherSelectionKvCacheCustom aclnn wrapper
 */

#include <string.h>
#include "graph/types.h"
#include "aclnn/opdev/platform.h"
#include "aclnnInner_gather_selection_kv_cache_custom.h"
#include "aclnn_gather_selection_kv_cache_custom.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnGatherSelectionKvCacheCustomGetWorkspaceSize(
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
    aclOpExecutor **executor)
{
    return aclnnInnerGatherSelectionKvCacheCustomGetWorkspaceSize(
        selectionKRopeRef, selectionKvCacheRef, selectionKvBlockTableRef, selectionKvBlockStatusRef,
        selectionTopkIndices, fullKRope, fullKvCache, fullKvBlockTable, fullKvActualSeq, fullQActualSeq,
        selectionTopkBlockSize, selectionKvActualSeqOut, workspaceSize, executor);
}

aclnnStatus aclnnGatherSelectionKvCacheCustom(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerGatherSelectionKvCacheCustom(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
