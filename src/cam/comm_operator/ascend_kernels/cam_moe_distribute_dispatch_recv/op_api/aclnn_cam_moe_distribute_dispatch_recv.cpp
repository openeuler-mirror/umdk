/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add cam_moe_distribute_dispatch_recv interface cpp file.
 * Create: 2026-09-17
 * Note:
 * History: 2026-09-17 port from cam_async repository
 */

#include <string.h>
#include "graph/types.h"
#include "aclnnInner_cam_moe_distribute_dispatch_recv.h"
#include "aclnn_cam_moe_distribute_dispatch_recv.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnCamMoeDistributeDispatchRecvGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *commArgs,
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
    int64_t dynamicQuant,
    char *hcclGroupName,
    const aclTensor *expandXOut,
    const aclTensor *expandXSharedOut,
    const aclTensor *dynamicScalesOut,
    const aclTensor *dynamicScalesSharedOut,
    const aclTensor *batchInfoOut,
    const aclTensor *epRecvCountRoutedOut,
    const aclTensor *epRecvCountSharedOut,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerCamMoeDistributeDispatchRecvGetWorkspaceSize(x, commArgs,
        magic, maxSeqLen, hiddenSize, topk, moeRankNum, attnRankNum, routeExpertNumPerMoe, moeRankId, worldSize,
        tpSize, dynamicQuant, hcclGroupName,
        expandXOut, expandXSharedOut, dynamicScalesOut, dynamicScalesSharedOut, batchInfoOut, epRecvCountRoutedOut,
        epRecvCountSharedOut, workspaceSize, executor);
}

aclnnStatus aclnnCamMoeDistributeDispatchRecv(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerCamMoeDistributeDispatchRecv(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
