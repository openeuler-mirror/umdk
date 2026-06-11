/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe dispatch lowlatency zero buffer interface source file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add moe dispatch lowlatency zero buffer interface source file
 */
#include <algorithm>

#include "aclnnInner_moe_dispatch_lowlatency_zero_buffer.h"
#include "graph/types.h"
#include "aclnn_moe_dispatch_lowlatency_zero_buffer.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnMoeDispatchLowlatencyZeroBufferGetWorkspaceSize(
    const aclTensor *x, const aclTensor *expertIds, const aclTensor *scalesOptional,
    const aclTensor *xActiveMaskOptional, const aclTensor *elasticInfoOptional, int64_t epWorldSize, int64_t epRankId,
    int64_t moeExpertNum, int64_t tpWorldSize, int64_t tpRankId, int64_t expertShardType, int64_t sharedExpertNum,
    int64_t sharedExpertRankNum, int64_t quantMode, int64_t globalBs, int64_t expertTokenNumsType, int64_t extInfo,
    char *commAlgOptional, int64_t zeroExpertNum, int64_t copyExpertNum, int64_t constExpertNum,
    const aclTensor *expandXOut, const aclTensor *dynamicScalesOut, const aclTensor *assistInfoForCombineOut,
    const aclTensor *expertTokenNumsOut, const aclTensor *epRecvCountOut, const aclTensor *tpRecvCountOut,
    uint64_t *workspaceSize, aclOpExecutor **executor)
{
    return aclnnInnerMoeDispatchLowlatencyZeroBufferGetWorkspaceSize(
        x, expertIds, scalesOptional, xActiveMaskOptional, elasticInfoOptional, epWorldSize, epRankId, moeExpertNum,
        tpWorldSize, tpRankId, expertShardType, sharedExpertNum, sharedExpertRankNum, quantMode, globalBs,
        expertTokenNumsType, extInfo, commAlgOptional, zeroExpertNum, copyExpertNum, constExpertNum, expandXOut,
        dynamicScalesOut, assistInfoForCombineOut, expertTokenNumsOut, epRecvCountOut, tpRecvCountOut, workspaceSize,
        executor);
}

aclnnStatus aclnnMoeDispatchLowlatencyZeroBuffer(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerMoeDispatchLowlatencyZeroBuffer(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
