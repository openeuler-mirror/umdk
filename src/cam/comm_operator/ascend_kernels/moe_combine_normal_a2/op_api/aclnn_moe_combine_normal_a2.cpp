/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: combine normal A2 interface part
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create combine normal A2 interface part
 */

#include <string.h>
#include "graph/types.h"
#include "aclnnInner_moe_combine_normal_a2.h"
#include "aclnn_moe_combine_normal_a2.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnMoeCombineNormalA2GetWorkspaceSize(
    const aclTensor *expandX,
    const aclTensor *expertIds,
    const aclTensor *expandIdx,
    const aclTensor *epSendCounts,
    const aclTensor *expertScales,
    const aclTensor *tpSendCountsOptional,
    const aclTensor *xActiveMaskOptional,
    const aclTensor *activationScaleOptional,
    const aclTensor *weightScaleOptional,
    const aclTensor *groupListOptional,
    const aclTensor *expandScalesOptional,
    const aclTensor *offsetInner,
    const aclTensor *offsetOuter,
    const aclTensor *countOuter,
    char *groupEp,
    int64_t epWorldSize,
    int64_t epRankId,
    int64_t moeExpertNum,
    char *groupTpOptional,
    int64_t tpWorldSize,
    int64_t tpRankId,
    int64_t expertShardType,
    int64_t sharedExpertNum,
    int64_t sharedExpertRankNum,
    int64_t globalBs,
    int64_t outDtype,
    int64_t commQuantMode,
    int64_t groupListType,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerMoeCombineNormalA2GetWorkspaceSize(
        expandX,
        expertIds,
        expandIdx,
        epSendCounts,
        expertScales,
        tpSendCountsOptional,
        xActiveMaskOptional,
        activationScaleOptional,
        weightScaleOptional,
        groupListOptional,
        expandScalesOptional,
        offsetInner,
        offsetOuter,
        countOuter,
        groupEp,
        epWorldSize,
        epRankId,
        moeExpertNum,
        groupTpOptional,
        tpWorldSize,
        tpRankId,
        expertShardType,
        sharedExpertNum,
        sharedExpertRankNum,
        globalBs,
        outDtype,
        commQuantMode,
        groupListType,
        out,
        workspaceSize,
        executor);
}

aclnnStatus aclnnMoeCombineNormalA2(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_AICPU);
    }
    return aclnnInnerMoeCombineNormalA2(
        workspace,
        workspaceSize,
        executor,
        stream);
}


#ifdef __cplusplus
}
#endif
