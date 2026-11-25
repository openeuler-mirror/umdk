/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add afd_async_dispatch_send interface cpp file.
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 initial CAM port
 */

#include <string.h>
#include "graph/types.h"
#include "aclnnInner_afd_async_dispatch_send.h"
#include "aclnn_afd_async_dispatch_send.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnAfdAsyncDispatchSendGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *expertIds,
    const aclTensor *commArgs,
    int64_t magic,
    int64_t maxSeqLen,
    int64_t batchSize,
    int64_t hiddenSize,
    int64_t topk,
    int64_t moeRankNum,
    int64_t attnRankNum,
    int64_t routeExpertNumPerMoe,
    int64_t attnRankId,
    int64_t worldSize,
    int64_t layerIndex,
    int64_t tpSize,
    int64_t dynamicQuant,
    char *hcclGroupName,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerAfdAsyncDispatchSendGetWorkspaceSize(x, expertIds, commArgs,
        magic, maxSeqLen, batchSize, hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe,
        attnRankId, worldSize, layerIndex, tpSize, dynamicQuant, hcclGroupName, out, workspaceSize, executor);
}

aclnnStatus aclnnAfdAsyncDispatchSend(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerAfdAsyncDispatchSend(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
