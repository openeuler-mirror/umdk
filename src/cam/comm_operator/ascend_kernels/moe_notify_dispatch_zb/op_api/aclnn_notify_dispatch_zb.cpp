/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add notify dispatch ZB interface source file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add notify dispatch ZB interface source file
 */
#include <string.h>

#include "aclnnInner_notify_dispatch_zb.h"
#include "graph/types.h"
#include "aclnn_notify_dispatch_zb.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnNotifyDispatchZbGetWorkspaceSize(const aclTensor *numTokensPerExpert, int64_t sendCount,
    int64_t rankSize, int64_t rankId, int64_t localRankSize,

    int64_t localRankId, int64_t topkNum, uint64_t commMetaPtr,
    const aclTensor *recvData, const aclTensor *totalRecvTokens,
    const aclTensor *maxBs, const aclTensor *recvTokensPerExpert,
    const aclTensor *putOffset, uint64_t *workspaceSize,
    aclOpExecutor **executor)
{
    return aclnnInnerNotifyDispatchZbGetWorkspaceSize(
        numTokensPerExpert, sendCount, rankSize, rankId, localRankSize, localRankId, topkNum, commMetaPtr, recvData,
        totalRecvTokens, maxBs, recvTokensPerExpert, putOffset, workspaceSize, executor);
}

aclnnStatus aclnnNotifyDispatchZb(void *workspace, uint64_t workspaceSize, aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerNotifyDispatchZb(workspace, workspaceSize, executor, stream);
}

#ifdef __cplusplus
}
#endif
