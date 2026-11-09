/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: aclnn interface for cam_deepep_dispatch_recv.
 * Create: 2026-11-03
 * Note: arg order mirrors the OpDef inputs, then attrs, then outputs.
 * History: 2026-11-03 create
 */

#ifndef ACLNN_CAM_DEEPEP_DISPATCH_RECV_H_
#define ACLNN_CAM_DEEPEP_DISPATCH_RECV_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnCamDeepepDispatchRecvGetWorkspaceSize
 * payload : inbound payload arena, uint8 [payload_bytes]
 * context : AFD context blob, uint8 [context_bytes]
 * active : scheduler-published AFDActive blob, uint8
 * executionState : AFD execution scratch, uint8 (advanced in place)
 * afdWorkspace : caller-owned AFD workspace, uint8
 * controlBuffer : AFD control arena, uint8 [control_bytes] (advanced in place)
 * groupEp : HCCL group name placeholder (reserved)
 * numRanks / numExperts / numTopk / numSourceLanes / numLayers : model axes
 * maxExpandedTokens / maxPaddedTokens : per-round token bounds
 * expertAlignment : per-expert row alignment
 * numTokensPerStage : stage tile size
 * rankIdx : this receiver's rank
 * recvSfTokenStride / recvSfHiddenStride / numSfPacks : scale-factor layout
 * numVecCores : AIV blocks for this call, 0 = platform default
 * payloadBytes / controlBytes / contextBytes : arena sizes
 * numHidden : hidden elements
 * recvX : expanded payload output, bf16 [max_padded_tokens, num_hidden]
 * recvSf : expanded scale-factor output, int16 [max_padded_tokens, num_sf_packs]
 * recvSrcMetadata : routing metadata output, int32 [max_padded_tokens, 4]
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnCamDeepepDispatchRecvGetWorkspaceSize(
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
    aclOpExecutor **executor);

/* function: aclnnCamDeepepDispatchRecv
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnCamDeepepDispatchRecv(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
