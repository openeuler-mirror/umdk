/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe dispatch shmem interface header file.
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 add moe dispatch shmem interface header file.
 */

#include <string.h>
#include "graph/types.h"
#include "aclnn_moe_dispatch_shmem.h"
#include "aclnnInner_moe_dispatch_shmem.h"

namespace {
    static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0;
    static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_MTE = 1;
    static constexpr int32_t NNOPBASE_HCCL_SERVER_TYPE_END = 2;
}; // namespace
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, int32_t sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnMoeDispatchShmemGetWorkspaceSize(
    const aclTensor *x, const aclTensor *expertIds, const aclTensor *scalesOptional,
    const aclTensor *xActiveMaskOptional, int64_t epWorldSize, int64_t epRankId, int64_t moeExpertNum,
    int64_t tpWorldSize, int64_t tpRankId, int64_t expertShardType, int64_t sharedExpertNum,
    int64_t sharedExpertRankNum, int64_t quantMode, int64_t globalBs, int64_t expertTokenNumsType, int64_t extInfo,
    const aclTensor *expandXOut, const aclTensor *dynamicScalesOut, const aclTensor *expandIdxOut,
    const aclTensor *expertTokenNumsOut, const aclTensor *epRecvCountOut, const aclTensor *tpRecvCountOut,
    uint64_t *workspaceSize, aclOpExecutor **executor)
{
    return aclnnInnerMoeDispatchShmemGetWorkspaceSize(
        x, expertIds, scalesOptional, xActiveMaskOptional, epWorldSize, epRankId, moeExpertNum, tpWorldSize, tpRankId, expertShardType,
        sharedExpertNum, sharedExpertRankNum, quantMode, globalBs, expertTokenNumsType, extInfo, expandXOut, dynamicScalesOut,
        expandIdxOut, expertTokenNumsOut, epRecvCountOut, tpRecvCountOut, workspaceSize, executor);
}

aclnnStatus aclnnMoeDispatchShmem(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor, aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerMoeDispatchShmem(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif