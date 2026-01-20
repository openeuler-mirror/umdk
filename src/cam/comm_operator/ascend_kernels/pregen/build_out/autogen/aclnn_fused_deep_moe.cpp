/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add fused deep moe interface cpp file.
 * Create: 2025-07-21
 * Note:
 * History: 2025-07-21 add fused deep moe interface cpp file.
 */

#include <string.h>
#include "graph/types.h"
#include "aclnn/opdev/platform.h"
#include "aclnnInner_fused_deep_moe.h"
#include "aclnn_fused_deep_moe.h"

namespace {
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
} // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnFusedDeepMoeGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *expertIds,
    const aclTensorList *gmm1PermutedWeight,
    const aclTensorList *gmm1PermutedWeightScale,
    const aclTensorList *gmm2Weight,
    const aclTensorList *gmm2WeightScale,
    const aclTensor *expertScales,
    const aclTensor *expertSmoothScalesOptional,
    const aclTensor *xActiveMaskOptional,
    char *groupEp,
    int64_t epRankSize,
    int64_t epRankId,
    int64_t moeExpertNum,
    int64_t sharedExpertNum,
    int64_t sharedExpertRankNum,
    int64_t quantMode,
    int64_t globalBs,
    const aclTensor *output,
    const aclTensor *expertTokenNums,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerFusedDeepMoeGetWorkspaceSize(x, expertIds, gmm1PermutedWeight, gmm1PermutedWeightScale,
        gmm2Weight, gmm2WeightScale, expertScales, expertSmoothScalesOptional, xActiveMaskOptional, groupEp,
        epRankSize, epRankId, moeExpertNum, sharedExpertNum, sharedExpertRankNum, quantMode, globalBs,
        output, expertTokenNums, workspaceSize, executor);
}

aclnnStatus aclnnFusedDeepMoe(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        if (op::GetCurrentPlatformInfo().GetSocVersion() == op::SocVersion::ASCEND910B) {
            NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_AICPU);
        } else {
            NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
        }
    }
    return aclnnInnerFusedDeepMoe(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif