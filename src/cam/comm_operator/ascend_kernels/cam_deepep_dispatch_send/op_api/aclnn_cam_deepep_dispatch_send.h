/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: aclnn interface for cam_deepep_dispatch_send.
 * Create: 2026-11-03
 * Note: arg order mirrors the OpDef inputs, then attrs, then outputs.
 * History: 2026-11-03 create
 */

#ifndef ACLNN_CAM_DEEPEP_DISPATCH_SEND_H_
#define ACLNN_CAM_DEEPEP_DISPATCH_SEND_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnCamDeepepDispatchSendGetWorkspaceSize
 * x : token payload, bf16 [tokens, hidden]
 * sf : fp8 scale-factor packs, int16, may be empty when num_sf_packs == 0
 * topkIdx : routing indices, int64 [tokens, topk]
 * topkWeights : routing weights, float [tokens, topk]
 * tokenMask : validity mask, uint8 [tokens]
 * taskInfo : AFDTaskInfo slots, uint8 [slots * 64]
 * context : AFD context blob, uint8 [context_bytes]
 * controlBuffer : AFD control arena, uint8 [control_bytes]
 * roundLedger : AFDRoundLedger slots, uint8 [slots * 64]
 * afdWorkspace : caller-owned AFD workspace, uint8
 * jettyPtrs : URMA jetty addresses, int64 [num_endpoints]
 * groupEp : HCCL group name placeholder (reserved)
 * numRanks / numExperts / numTopk / numTokensPerTile : model axes
 * sfTokenStride / sfHiddenStride / numSfPacks : scale-factor layout
 * timeoutCycles : device-side wait budget
 * sendStatusWords : length of the send_status output
 * numVecCores : AIV blocks for this call, 0 = platform default
 * sendStatus : output status words, int32 [send_status_words]
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnCamDeepepDispatchSendGetWorkspaceSize(
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
    aclOpExecutor **executor);

/* function: aclnnCamDeepepDispatchSend
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnCamDeepepDispatchSend(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
