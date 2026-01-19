/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add dispatch layout interface cpp file.
 * Create: 2026-01-05
 * Note:
 * History: 2026-01-05 add dispatch layout interface cpp file.
 */

#include "aclnn_dispatch_layout.h"
#include "aclnnInner_dispatch_layout.h"
#include "graph/types.h"
#include <string.h>

namespace {
    static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
    static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
    static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
}; // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnDispatchLayoutGetWorkspaceSize(const aclTensor *topkIdx, int64_t numTokens, int64_t numRanks,
                                                int64_t numExperts, int64_t numTopk, int64_t localRankSize,
                                                const aclTensor *numTokensPerRank, const aclTensor *numTokensPerExpert,
                                                const aclTensor *isTokenInRank, const aclTensor *notifySendData,
                                                const aclTensor *sendTokenIdxSmall, uint64_t *workspaceSize,
                                                aclOpExecutor **executor)
{
    return aclnnInnerDispatchLayoutGetWorkspaceSize(topkIdx, numTokens, numRanks, numExperts, numTopk, localRankSize,
                                                    numTokensPerRank, numTokensPerExpert, isTokenInRank, notifySendData,
                                                    sendTokenIdxSmall, workspaceSize, executor);
}

aclnnStatus aclnnDispatchLayout(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor, aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerDispatchLayout(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif