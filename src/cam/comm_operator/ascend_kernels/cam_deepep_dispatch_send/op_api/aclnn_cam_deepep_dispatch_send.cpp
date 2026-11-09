/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: aclnn interface for cam_deepep_dispatch_send.
 * Create: 2026-11-03
 * Note: pure forwarding to the msopgen-generated inner interface; no HCCL
 *       server type is set because the operator uses URMA jetty pointers.
 * History: 2026-11-03 create
 */

#include <string.h>
#include "graph/types.h"
#include "aclnnInner_cam_deepep_dispatch_send.h"
#include "aclnn_cam_deepep_dispatch_send.h"

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnCamDeepepDispatchSendGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *sf,
    const aclTensor *topkIdx,
    const aclTensor *topkWeights,
    const aclTensor *tokenMask,
    const aclTensor *taskInfo,
    const aclTensor *context,
    const aclTensor *controlBuffer,
    const aclTensor *roundLedger,
    const aclTensor *afdWorkspace,
    const aclTensor *jettyPtrs,
    char *groupEp,
    int64_t numRanks,
    int64_t numExperts,
    int64_t numTopk,
    int64_t numTokensPerTile,
    int64_t sfTokenStride,
    int64_t sfHiddenStride,
    int64_t numSfPacks,
    int64_t timeoutCycles,
    int64_t sendStatusWords,
    int64_t numVecCores,
    const aclTensor *sendStatus,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerCamDeepepDispatchSendGetWorkspaceSize(x, sf, topkIdx, topkWeights,
        tokenMask, taskInfo, context, controlBuffer, roundLedger, afdWorkspace, jettyPtrs,
        groupEp, numRanks, numExperts, numTopk, numTokensPerTile, sfTokenStride,
        sfHiddenStride, numSfPacks, timeoutCycles, sendStatusWords, numVecCores,
        sendStatus, workspaceSize, executor);
}

aclnnStatus aclnnCamDeepepDispatchSend(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    return aclnnInnerCamDeepepDispatchSend(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
