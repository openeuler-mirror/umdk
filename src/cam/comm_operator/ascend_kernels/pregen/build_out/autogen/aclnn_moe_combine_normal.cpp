/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add moe combine normal interface cpp file.
 * Create: 2025-12-04
 * Note:
 * History: 2025-12-04 add moe combine normal interface cpp file.
 */

#include "aclnn_moe_combine_normal.h"
#include "aclnnInner_moe_combine_normal.h"
#include "graph/types.h"
#include <string.h>

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnMoeCombineNormalGetWorkspaceSize(const aclTensor *recvX, const aclTensor *tokenSrcInfo,
                                                  const aclTensor *epRecvCounts, const aclTensor *recvTopkWeights,
                                                  const aclTensor *tpRecvCountsOptional, char *epGroupName,
                                                  int64_t epWorldSize, int64_t epRankId, char *tpGroupNameOptional,
                                                  int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum,
                                                  int64_t globalBs, const aclTensor *out,
                                                  const aclTensor *sendCostStats, uint64_t *workspaceSize,
                                                  aclOpExecutor **executor)
{
    return aclnnInnerMoeCombineNormalGetWorkspaceSize(recvX, tokenSrcInfo, epRecvCounts, recvTopkWeights,
                                                      tpRecvCountsOptional, epGroupName, epWorldSize, epRankId,
                                                      tpGroupNameOptional, tpWorldSize, tpRankId, moeExpertNum,
                                                      globalBs, out, sendCostStats, workspaceSize, executor);
}

aclnnStatus aclnnMoeCombineNormal(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor, aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerMoeCombineNormal(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif