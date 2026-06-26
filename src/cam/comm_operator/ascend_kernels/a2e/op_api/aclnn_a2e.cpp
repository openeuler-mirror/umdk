/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add a2e interface cpp file.
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 add a2e interface cpp file.
 */

#include <string.h>
#include "graph/types.h"
#include "aclnn/opdev/platform.h"
#include "aclnnInner_a2e.h"
#include "aclnn_a2e.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnA2eGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *expertIds,
    const aclTensor *scales,
    int64_t batchSize,
    int64_t hiddenSize,
    int64_t topk,
    int64_t expertRankSize,
    int64_t attentionRankSize,
    int64_t rank,
    char *groupEp,
    int64_t aivNum,
    int64_t computeGate,
    const aclTensor *expandXOut,
    const aclTensor *simulateExpertIdsOut,
    const aclTensor *simulateExpertScalesOut,
    const aclTensor *attenBatchSize,
    const aclTensor *xActiveMaskOut,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerA2eGetWorkspaceSize(x, expertIds, scales, batchSize, hiddenSize,
        topk, expertRankSize, attentionRankSize, rank, groupEp, aivNum, computeGate, expandXOut, simulateExpertIdsOut,
        simulateExpertScalesOut, attenBatchSize, xActiveMaskOut, workspaceSize, executor);
}

aclnnStatus aclnnA2e(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerA2e(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif