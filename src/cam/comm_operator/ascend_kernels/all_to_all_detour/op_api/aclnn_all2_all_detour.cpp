/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add all2all with detour interface cpp file.
 * Create: 2026-01-22
 * Note:
 * History: 2026-01-22 add all2all with detour interface cpp file.
 */

#include <string.h>
#include "graph/types.h"
#include "aclnn/opdev/platform.h"
#include "aclnnInner_all2_all_detour.h"
#include "aclnn_all2_all_detour.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnAll2AllDetourGetWorkspaceSize(
    const aclTensor *sendData,
    const aclTensor *commRankIds,
    const aclTensor *commArgs,
    int64_t magic,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerAll2AllDetourGetWorkspaceSize(sendData,
        commRankIds, commArgs, magic, out, workspaceSize, executor);
}

aclnnStatus aclnnAll2AllDetour(
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
    return aclnnInnerAll2AllDetour(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif