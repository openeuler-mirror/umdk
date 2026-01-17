/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dispatch normal A2 interface part
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create dispatch normal A2 interface part
 */

#include <string.h>
#include "graph/types.h"
#include "aclnn_dispatch_normal_a2.h"
#include "aclnnInner_dispatch_normal_a2.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnDispatchNormalA2GetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *expertIds,
    const aclTensor *scalesOptional,
    const aclTensor *xActiveMaskOptional,
    const aclTensor *expertScalesOptional,
    const aclTensor *tokenServerIdxOptional,
    const aclTensor *tokenServerCntOptional,
    const aclTensor *epRankTokenCntOptional,
    const aclTensor *srcOffsetRankTokenIdxOptional,
    const aclTensor *dstOffsetRankTokenIdxOptional,
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
    int64_t quantMode,
    int64_t globalBs,
    int64_t expertTokenNumsType,
    const aclTensor *recvXOut,
    const aclTensor *dynamicScalesOut,
    const aclTensor *expandIdxOut,
    const aclTensor *expertTokenNumsOut,
    const aclTensor *epRecvCountOut,
    const aclTensor *expandScalesOut,
    const aclTensor *dispatchWaitRecvCostStatsOutOptional,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerDispatchNormalA2GetWorkspaceSize(
        x,
        expertIds,
        scalesOptional,
        xActiveMaskOptional,
        expertScalesOptional,
        tokenServerIdxOptional,
        tokenServerCntOptional,
        epRankTokenCntOptional,
        srcOffsetRankTokenIdxOptional,
        dstOffsetRankTokenIdxOptional,
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
        quantMode,
        globalBs,
        expertTokenNumsType,
        recvXOut,
        dynamicScalesOut,
        expandIdxOut,
        expertTokenNumsOut,
        epRecvCountOut,
        expandScalesOut,
        dispatchWaitRecvCostStatsOutOptional,
        workspaceSize,
        executor);
}

aclnnStatus aclnnDispatchNormalA2(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerDispatchNormalA2(
        workspace,
        workspaceSize,
        executor,
        stream);
}

#ifdef __cplusplus
}
#endif