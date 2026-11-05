/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: aclnn interface for cam_deepep_combine_recv.
 * Create: 2026-11-03
 * Note: arg order mirrors the OpDef inputs, then attrs, then outputs.
 * History: 2026-11-03 create
 */

#ifndef ACLNN_CAM_DEEPEP_COMBINE_RECV_H_
#define ACLNN_CAM_DEEPEP_COMBINE_RECV_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnCamDeepepCombineRecvGetWorkspaceSize
 * payload : inbound payload arena, uint8 [payload_bytes]
 * taskInfo : AFDTaskInfo slots, uint8 [slots * 64]
 * context : AFD context blob, uint8 [context_bytes]
 * controlBuffer : AFD control arena, uint8 [control_bytes] (advanced in place)
 * roundLedger : AFDRoundLedger slots, uint8 (advanced in place)
 * afdWorkspace : caller-owned AFD workspace, uint8
 * tokenMask : token validity mask, bool [num_token_capacity]
 * groupEp : HCCL group name placeholder (reserved)
 * numExperts / numRanks / numTopk : model axes
 * roundStep : 1 enables multi-round credit tracking, 0 is single round
 * start : 1 admits the first transaction in round-step mode
 * numHidden : hidden elements
 * numTokenCapacity : output rows
 * recvStatusWords / returnProgressBytes : output lengths
 * timeoutCycles : device-side wait budget
 * numVecCores : AIV blocks for this call, 0 = platform default
 * combinedX : weighted reduction output, bf16 [capacity, num_hidden]
 * combinedTopkIdx : routing indices output, int64 [capacity, num_topk]
 * topkWeights : routing weights output, float [capacity, num_topk]
 * recvStatus : status words output, int32 [recv_status_words]
 * returnProgress : round progress output, uint8 [return_progress_bytes]
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnCamDeepepCombineRecvGetWorkspaceSize(
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
    aclOpExecutor **executor);

/* function: aclnnCamDeepepCombineRecv
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnCamDeepepCombineRecv(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
