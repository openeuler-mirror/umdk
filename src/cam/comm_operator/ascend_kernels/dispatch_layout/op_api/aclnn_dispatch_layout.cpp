/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add dispatch layout interface cpp file.
 * Create: 2026-01-05
 * Note:
 * History: 2026-01-05 add dispatch layout interface cpp file.
 */

#include <string.h>
#include "graph/types.h"
#include "aclnn_dispatch_layout.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

extern aclnnStatus aclnnInnerDispatchLayoutGetWorkspaceSize(
    const aclTensor *topkIdx,
    int64_t numTokens,
    int64_t numRanks,
    int64_t numExperts,
    int64_t numTopk,
    const aclTensor *numTokensPerRank,
    const aclTensor *numTokensPerExpert,
    const aclTensor *isTokenInRank,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

extern aclnnStatus aclnnInnerDispatchLayout(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

aclnnStatus aclnnDispatchLayoutGetWorkspaceSize(
    const aclTensor *topkIdx,
    int64_t numTokens,
    int64_t numRanks,
    int64_t numExperts,
    int64_t numTopk,
    const aclTensor *numTokensPerRank,
    const aclTensor *numTokensPerExpert,
    const aclTensor *isTokenInRank,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerDispatchLayoutGetWorkspaceSize(topkIdx, numTokens, numRanks, numExperts, numTopk, numTokensPerRank,
                                                    numTokensPerExpert, isTokenInRank, workspaceSize, executor);
}

aclnnStatus aclnnDispatchLayout(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
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