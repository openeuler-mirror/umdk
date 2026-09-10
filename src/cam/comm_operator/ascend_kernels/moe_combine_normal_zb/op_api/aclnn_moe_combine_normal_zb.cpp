/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe combine normal ZB interface source file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add moe combine normal ZB interface source file
 */
#include <string.h>

#include "aclnnInner_moe_combine_normal_zb.h"
#include "graph/types.h"
#include "aclnn_moe_combine_normal_zb.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnMoeCombineNormalZbGetWorkspaceSize(const aclTensor *recvX, const aclTensor *epRecvCounts,
    const aclTensor *recvTopkWeights, const aclTensor *topkIdx,
    const aclTensor *sendTokenIdx, uint64_t commMetaPtr,
    int64_t epWorldSize, int64_t epRankId, int64_t tpWorldSize,
    int64_t tpRankId, int64_t moeExpertNum, int64_t globalBs,
    const aclTensor *out, const aclTensor *sendCostStats,
    uint64_t *workspaceSize, aclOpExecutor **executor)
{
    return aclnnInnerMoeCombineNormalZbGetWorkspaceSize(
        recvX, epRecvCounts, recvTopkWeights, topkIdx, sendTokenIdx, commMetaPtr, epWorldSize, epRankId, tpWorldSize,
        tpRankId, moeExpertNum, globalBs, out, sendCostStats, workspaceSize, executor);
}

aclnnStatus aclnnMoeCombineNormalZb(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerMoeCombineNormalZb(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
