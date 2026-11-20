/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: aclnn interface for afd_async_combine_recv.
 * Create: 2026-11-03
 * Note: pure forwarding to the msopgen-generated inner interface; no HCCL
 *       server type is set because the operator uses URMA jetty pointers.
 * History: 2026-11-03 create
 */

#include "aclnnInner_afd_async_combine_recv.h"
#include "aclnn_afd_async_combine_recv.h"

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnAfdAsyncCombineRecvGetWorkspaceSize(
    const aclTensor *payload,
    const aclTensor *taskInfo,
    const aclTensor *context,
    const aclTensor *controlBuffer,
    const aclTensor *roundLedger,
    const aclTensor *afdWorkspace,
    const aclTensor *tokenMask,
    char *groupEp,
    int64_t numExperts,
    int64_t numRanks,
    int64_t numTopk,
    int64_t roundStep,
    int64_t start,
    int64_t numHidden,
    int64_t numTokenCapacity,
    int64_t recvStatusWords,
    int64_t returnProgressBytes,
    int64_t timeoutCycles,
    int64_t numVecCores,
    const aclTensor *combinedX,
    const aclTensor *combinedTopkIdx,
    const aclTensor *topkWeights,
    const aclTensor *recvStatus,
    const aclTensor *returnProgress,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerAfdAsyncCombineRecvGetWorkspaceSize(payload, taskInfo, context,
        controlBuffer, roundLedger, afdWorkspace, tokenMask, groupEp, numExperts,
        numRanks, numTopk, roundStep, start, numHidden, numTokenCapacity,
        recvStatusWords, returnProgressBytes, timeoutCycles, numVecCores, combinedX,
        combinedTopkIdx, topkWeights, recvStatus, returnProgress, workspaceSize,
        executor);
}

aclnnStatus aclnnAfdAsyncCombineRecv(
    aclrtAllocatorAddr workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    return aclnnInnerAfdAsyncCombineRecv(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
