/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: aclnn interface for cam_deepep_combine_send.
 * Create: 2026-11-03
 * Note: arg order mirrors the OpDef inputs, then attrs, then outputs.
 * History: 2026-11-03 create
 */

#ifndef ACLNN_CAM_DEEPEP_COMBINE_SEND_H_
#define ACLNN_CAM_DEEPEP_COMBINE_SEND_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnCamDeepepCombineSendGetWorkspaceSize
 * x : expert output, bf16 [max_padded_tokens, hidden]
 * srcMetadata : dispatch routing metadata, int32 [max_padded_tokens, 4]
 * context : AFD context blob, uint8 [context_bytes]
 * active : scheduler-published AFDActive blob, uint8
 * controlBuffer : AFD control arena, uint8 (advanced in place)
 * executionState : AFD execution scratch, uint8 (advanced in place)
 * afdWorkspace : caller-owned AFD workspace, uint8
 * jettyPtrs : URMA jetty addresses, int64 [num_endpoints]
 * groupEp : HCCL group name placeholder (reserved)
 * numSrcRanks / numRanks / numExperts / numTopk : model axes
 * numSourceLanes / numLayers : lane geometry
 * maxPaddedTokens / numTokensPerTile : tile bounds
 * rankIdx : this receiver's rank
 * timeoutCycles : device-side wait budget
 * completionBytes : length of the completion output
 * numVecCores : AIV blocks for this call, 0 = platform default
 * completion : AFD completion output, uint8 [completion_bytes]
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnCamDeepepCombineSendGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *srcMetadata,
    const aclTensor *context,
    const aclTensor *active,
    const aclTensor *controlBuffer,
    const aclTensor *executionState,
    const aclTensor *afdWorkspace,
    const aclTensor *jettyPtrs,
    char *groupEp,
    int64_t numSrcRanks,
    int64_t numRanks,
    int64_t numExperts,
    int64_t numTopk,
    int64_t numSourceLanes,
    int64_t numLayers,
    int64_t maxPaddedTokens,
    int64_t numTokensPerTile,
    int64_t rankIdx,
    int64_t timeoutCycles,
    int64_t completionBytes,
    int64_t numVecCores,
    const aclTensor *completion,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

/* function: aclnnCamDeepepCombineSend
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnCamDeepepCombineSend(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
