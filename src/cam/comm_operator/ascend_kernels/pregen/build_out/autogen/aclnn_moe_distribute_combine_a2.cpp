/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dispatch combine A2 interface part
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create combine normal A2 interface part
 */

#include <string.h>
#include "graph/types.h"
#include "aclnn_moe_distribute_combine_a2.h"
#include "aclnnInner_moe_distribute_combine_a2.h"

enum NnopbaseHcclServerType {
    NNOPBASE_HCCL_SERVER_TYPE_AICPU = 0,
    NNOPBASE_HCCL_SERVER_TYPE_MTE,
    NNOPBASE_HCCL_SERVER_TYPE_END
};
extern "C" void __attribute__((weak)) NnopbaseSetHcclServerType(void *executor, NnopbaseHcclServerType sType);

#ifdef __cplusplus
extern "C" {
#endif

aclnnStatus aclnnMoeDistributeCombineA2(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream)
{
    if (NnopbaseSetHcclServerType) {
        NnopbaseSetHcclServerType(executor, NNOPBASE_HCCL_SERVER_TYPE_MTE);
    }
    return aclnnInnerMoeDistributeCombineA2(
        workspace,
        workspaceSize,
        executor,
        stream);
}


#ifdef __cplusplus
}
#endif
