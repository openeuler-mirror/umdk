/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add cam_moe_distribute_combine_recv interface cpp file.
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#include <string.h>
#include "graph/types.h"
#include "aclnnInner_cam_moe_distribute_combine_recv.h"
#include "aclnn_cam_moe_distribute_combine_recv.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnCamMoeDistributeCombineRecvGetWorkspaceSize(
    const aclTensor *expandX,
    const aclTensor *expertIds,
    const aclTensor *expertScales,
    const aclTensor *commArgs,
    int64_t magic,
    int64_t batchSize,
    int64_t hiddenSize,
    int64_t topk,
    int64_t moeRankNum,
    int64_t attnRankNum,
    int64_t routeExpertNumPerMoe,
    int64_t attnRankId,
    int64_t worldSize,
    char *hcclGroupName,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerCamMoeDistributeCombineRecvGetWorkspaceSize(expandX, expertIds, expertScales, commArgs,
        magic, batchSize, hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, attnRankId, worldSize,
        hcclGroupName, out, workspaceSize, executor);
}

aclnnStatus aclnnCamMoeDistributeCombineRecv(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerCamMoeDistributeCombineRecv(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
