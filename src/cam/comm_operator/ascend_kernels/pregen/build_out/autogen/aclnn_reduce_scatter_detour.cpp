/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add reduceScatter with detour interface cpp file.
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 add reduceScatter with detour interface cpp file.
 */

#include <string.h>
#include "graph/types.h"
#include "aclnn/opdev/platform.h"
#include "aclnn_reduce_scatter_detour.h"
#include "aclnnInner_reduce_scatter_detour.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnReduceScatterDetourGetWorkspaceSize(
    const aclTensor *sendData,
    const aclTensor *commRankIds,
    const aclTensor *commArgs,
    int64_t magic,
    int64_t rankSize,
    int64_t op,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerReduceScatterDetourGetWorkspaceSize(sendData, commRankIds, commArgs, magic, rankSize, op, out, workspaceSize, executor);
}

aclnnStatus aclnnReduceScatterDetour(
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
    return aclnnInnerReduceScatterDetour(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif