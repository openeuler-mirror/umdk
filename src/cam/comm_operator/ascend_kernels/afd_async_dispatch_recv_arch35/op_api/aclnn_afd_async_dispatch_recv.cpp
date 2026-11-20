/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: aclnn interface for afd_async_dispatch_recv.
 * Create: 2026-11-03
 * Note: pure forwarding to the msopgen-generated inner interface; no HCCL
 *       server type is set because the operator uses URMA jetty pointers.
 * History: 2026-11-03 create
 */

#include "aclnnInner_afd_async_dispatch_recv.h"
#include "aclnn_afd_async_dispatch_recv.h"

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnAfdAsyncDispatchRecvGetWorkspaceSize(
    const aclTensor *payload,
    const aclTensor *context,
    const aclTensor *active,
    const aclTensor *executionState,
    const aclTensor *afdWorkspace,
    const aclTensor *controlBuffer,
    char *groupEp,
    int64_t numRanks,
    int64_t numExperts,
    int64_t numTopk,
    int64_t numSourceLanes,
    int64_t numLayers,
    int64_t maxExpandedTokens,
    int64_t maxPaddedTokens,
    int64_t expertAlignment,
    int64_t numTokensPerStage,
    int64_t rankIdx,
    int64_t recvSfTokenStride,
    int64_t recvSfHiddenStride,
    int64_t payloadBytes,
    int64_t controlBytes,
    int64_t contextBytes,
    int64_t numHidden,
    int64_t numSfPacks,
    int64_t numVecCores,
    const aclTensor *recvX,
    const aclTensor *recvSf,
    const aclTensor *recvSrcMetadata,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerAfdAsyncDispatchRecvGetWorkspaceSize(payload, context, active,
        executionState, afdWorkspace, controlBuffer, groupEp, numRanks, numExperts,
        numTopk, numSourceLanes, numLayers, maxExpandedTokens, maxPaddedTokens,
        expertAlignment, numTokensPerStage, rankIdx, recvSfTokenStride,
        recvSfHiddenStride, payloadBytes, controlBytes, contextBytes, numHidden,
        numSfPacks, numVecCores, recvX, recvSf, recvSrcMetadata, workspaceSize, executor);
}

aclnnStatus aclnnAfdAsyncDispatchRecv(
    aclrtAllocatorAddr workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    return aclnnInnerAfdAsyncDispatchRecv(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
