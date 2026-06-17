/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe combine normal zero buffer interface source file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add moe combine normal zero buffer interface source file
 */
#include <string.h>

#include "aclnnInner_moe_combine_normal_zero_buffer.h"
#include "graph/types.h"
#include "aclnn_moe_combine_normal_zero_buffer.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnMoeCombineNormalZeroBufferGetWorkspaceSize(const aclTensor *recvX, const aclTensor *epRecvCounts,
    const aclTensor *recvTopkWeights, const aclTensor *topkIdx,
    const aclTensor *sendTokenIdx, const aclTensor *probGrad, uint64_t meta_data_ptr,
    int64_t epWorldSize, int64_t epRankId, int64_t tpWorldSize,
    int64_t tpRankId, int64_t moeExpertNum, int64_t globalBs,
    const aclTensor *out, const aclTensor *sendCostStats, const aclTensor *gradOut,
    uint64_t *workspaceSize, aclOpExecutor **executor)
{
    return aclnnInnerMoeCombineNormalZeroBufferGetWorkspaceSize(
        recvX, epRecvCounts, recvTopkWeights, topkIdx, sendTokenIdx, probGrad, meta_data_ptr, epWorldSize,
        epRankId, tpWorldSize, tpRankId, moeExpertNum, globalBs, out, sendCostStats, gradOut,
        workspaceSize, executor);
}

aclnnStatus aclnnMoeCombineNormalZeroBuffer(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerMoeCombineNormalZeroBuffer(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
