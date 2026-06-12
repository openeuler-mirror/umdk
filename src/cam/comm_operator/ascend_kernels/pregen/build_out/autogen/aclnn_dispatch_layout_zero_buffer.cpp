/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add dispatch layout zero buffer interface source file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add dispatch layout zero buffer interface source file
 */
#include <string.h>

#include "aclnnInner_dispatch_layout.h"
#include "graph/types.h"
#include "aclnn_dispatch_layout_zero_buffer.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnDispatchLayoutZeroBufferGetWorkspaceSize(const aclTensor *topkIdx, int64_t numTokens, int64_t numRanks,
    int64_t numExperts, int64_t numTopk, int64_t localRankSize, const aclTensor *numTokensPerRank,
    const aclTensor *numTokensPerExpert, const aclTensor *isTokenInRank, const aclTensor *notifySendData,
    const aclTensor *sendTokenIdxSmall, uint64_t *workspaceSize, aclOpExecutor **executor)
{
    return aclnnInnerDispatchLayoutGetWorkspaceSize(topkIdx, numTokens, numRanks, numExperts, numTopk, localRankSize,
        numTokensPerRank, numTokensPerExpert, isTokenInRank, notifySendData, sendTokenIdxSmall, workspaceSize,
        executor);
}

aclnnStatus aclnnDispatchLayoutZeroBuffer(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerDispatchLayout(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
