/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe dispatch normal zero buffer interface source file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add moe dispatch normal zero buffer interface source file
 */
#include <string.h>

#include "aclnnInner_moe_dispatch_normal_zero_buffer.h"
#include "graph/types.h"
#include "aclnn_moe_dispatch_normal_zero_buffer.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnMoeDispatchNormalZeroBufferGetWorkspaceSize(
    const aclTensor *x, const aclTensor *topkIdx, const aclTensor *sendTokenIdx, const aclTensor *putOffset,
    int64_t epWorldSize, int64_t epRankId, int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum,
    int64_t quantMode, int64_t globalBs, uint64_t zeroBufferPtr, const aclTensor *recvX, const aclTensor *recvXScales,
    const aclTensor *assistInfoForCombine, const aclTensor *waitRecvCostStats, uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerMoeDispatchNormalZeroBufferGetWorkspaceSize(
        x, topkIdx, sendTokenIdx, putOffset, epWorldSize, epRankId, tpWorldSize, tpRankId, moeExpertNum, quantMode,
        globalBs, zeroBufferPtr, recvX, recvXScales, assistInfoForCombine, waitRecvCostStats, workspaceSize, executor);
}

aclnnStatus aclnnMoeDispatchNormalZeroBuffer(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerMoeDispatchNormalZeroBuffer(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
