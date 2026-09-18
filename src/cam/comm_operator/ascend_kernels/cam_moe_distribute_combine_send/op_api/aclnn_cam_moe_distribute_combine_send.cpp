/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add cam_moe_distribute_combine_send interface cpp file.
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#include <string.h>
#include "graph/types.h"
#include "aclnnInner_cam_moe_distribute_combine_send.h"
#include "aclnn_cam_moe_distribute_combine_send.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnCamMoeDistributeCombineSendGetWorkspaceSize(
    const aclTensor *expandX,
    const aclTensor *expandXShared,
    const aclTensor *commArgs,
    const aclTensor *batchInfo,
    int64_t magic,
    int64_t maxSeqLen,
    int64_t hiddenSize,
    int64_t topk,
    int64_t moeRankNum,
    int64_t attnRankNum,
    int64_t routeExpertNumPerMoe,
    int64_t moeRankId,
    int64_t worldSize,
    int64_t tpSize,
    char *hcclGroupName,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerCamMoeDistributeCombineSendGetWorkspaceSize(expandX, expandXShared, commArgs, batchInfo,
        magic, maxSeqLen, hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, moeRankId, worldSize,
        tpSize, hcclGroupName, out, workspaceSize, executor);
}

aclnnStatus aclnnCamMoeDistributeCombineSend(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerCamMoeDistributeCombineSend(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
