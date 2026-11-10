/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: aclnn interface for cam_deepep_combine_send.
 * Create: 2026-11-03
 * Note: forwards to the msopgen-generated inner interface. The completion
 *       contract is checked here, before the executor is built: when the only
 *       output is empty the executor skips tiling and the kernel, so a zero
 *       attribute or an empty buffer would otherwise succeed as a no-op.
 * History: 2026-11-03 create
 *          2026-11-05 reject invalid completion_bytes/completion in the
 *                     public entry (R005-a F4)
 */

#include <memory>
#include <string.h>
#include "graph/types.h"
#include "aclnn/acl_meta.h"
#include "aclnn/opdev/op_errno.h"
#include "aclnn/opdev/op_log.h"
#include "aclnnInner_cam_deepep_combine_send.h"
#include "aclnn_cam_deepep_combine_send.h"

#ifdef __cplusplus
extern "C" {
#endif

// Upper bound of the completion byte count, mirrored from TilingFunc.
constexpr int64_t kMaxCompletionBytes = 65536;

static aclnnStatus CheckCombineSendCompletion(
    const aclTensor *completion, int64_t completionBytes)
{
    if (completionBytes <= 0 || completionBytes > kMaxCompletionBytes) {
        OP_LOGE(ACLNN_ERR_PARAM_INVALID,
            "combine_send: completion_bytes out of range: %ld",
            static_cast<long>(completionBytes));
        return ACLNN_ERR_PARAM_INVALID;
    }
    if (completion == nullptr) {
        OP_LOGE(ACLNN_ERR_PARAM_NULLPTR, "combine_send: completion is null");
        return ACLNN_ERR_PARAM_NULLPTR;
    }
    int64_t *viewDims = nullptr;
    uint64_t viewDimNum = 0;
    const aclnnStatus shapeStatus = aclGetViewShape(completion, &viewDims, &viewDimNum);
    // aclGetViewShape transfers ownership of the allocated dimensions to us.
    std::unique_ptr<int64_t[]> viewDimsOwner(viewDims);
    if (shapeStatus != OK || viewDims == nullptr || viewDimNum != 1 ||
        viewDims[0] != completionBytes) {
        OP_LOGE(ACLNN_ERR_PARAM_INVALID,
            "combine_send: completion must be 1-D [completion_bytes]");
        return ACLNN_ERR_PARAM_INVALID;
    }
    return OK;
}

aclnnStatus aclnnCamDeepepCombineSendGetWorkspaceSize(
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
    aclOpExecutor **executor)
{
    const aclnnStatus check = CheckCombineSendCompletion(completion, completionBytes);
    if (check != OK) {
        return check;
    }
    return aclnnInnerCamDeepepCombineSendGetWorkspaceSize(x, srcMetadata, context,
        active, controlBuffer, executionState, afdWorkspace, jettyPtrs, groupEp,
        numSrcRanks, numRanks, numExperts, numTopk, numSourceLanes, numLayers,
        maxPaddedTokens, numTokensPerTile, rankIdx, timeoutCycles, completionBytes,
        numVecCores,
        completion, workspaceSize, executor);
}

aclnnStatus aclnnCamDeepepCombineSend(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    return aclnnInnerCamDeepepCombineSend(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
