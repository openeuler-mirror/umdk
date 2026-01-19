/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe combine shmem interface header file.
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 add moe combine shmem interface header file.
 */

#include <string.h>
#include "graph/types.h"
#include "aclnnInner_moe_combine_shmem.h"
#include "aclnn_moe_combine_shmem.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnMoeCombineShmemGetWorkspaceSize(const aclTensor *expandX, const aclTensor *expertIds,
    const aclTensor *expandIdx, const aclTensor *epSendCounts, const aclTensor *expertScales,
    const aclTensor *tpSendCountsOptional, const aclTensor *xActiveMaskOptional,
    const aclTensor *activationScaleOptional, const aclTensor *weightScaleOptional, const aclTensor *groupListOptional,
    const aclTensor *expandScalesOptional, int64_t epWorldSize, int64_t epRankId, int64_t moeExpertNum,
    int64_t tpWorldSize, int64_t tpRankId, int64_t expertShardType, int64_t sharedExpertNum,
    int64_t sharedExpertRankNum, int64_t globalBs, int64_t commQuantMode, int64_t extInfo, int64_t outDtype,
    int64_t groupListType, const aclTensor *out, uint64_t *workspaceSize, aclOpExecutor **executor)
{
    return aclnnInnerMoeCombineShmemGetWorkspaceSize(expandX, expertIds, expandIdx, epSendCounts, expertScales,
        tpSendCountsOptional, xActiveMaskOptional, activationScaleOptional, weightScaleOptional, groupListOptional,
        expandScalesOptional, epWorldSize, epRankId, moeExpertNum, tpWorldSize, tpRankId, expertShardType,
        sharedExpertNum, sharedExpertRankNum, globalBs, commQuantMode, extInfo, outDtype, groupListType,
        out, workspaceSize, executor);
}

aclnnStatus aclnnMoeCombineShmem(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor, aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerMoeCombineShmem(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif