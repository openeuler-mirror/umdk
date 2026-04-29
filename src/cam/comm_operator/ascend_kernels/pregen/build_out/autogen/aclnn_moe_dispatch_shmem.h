/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe dispatch shmem interface cpp file.
 * Create: 2026-01-06
 * Note:
 * History: 2026-01-06 add moe dispatch shmem interface cpp file.
 */

#ifndef ACLNN_MOE_DISPATCH_SHMEM_H_
#define ACLNN_MOE_DISPATCH_SHMEM_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) aclnnStatus aclnnMoeDispatchShmemGetWorkspaceSize(
    const aclTensor *x, const aclTensor *expertIds, const aclTensor *scalesOptional,
    const aclTensor *xActiveMaskOptional, int64_t epWorldSize, int64_t epRankId, int64_t moeExpertNum,
    int64_t tpWorldSize, int64_t tpRankId, int64_t expertShardType, int64_t sharedExpertNum,
    int64_t sharedExpertRankNum, int64_t quantMode, int64_t globalBs, int64_t expertTokenNumsType, int64_t extInfo,
    int64_t windowSize, const aclTensor *expandXOut, const aclTensor *dynamicScalesOut, const aclTensor *expandIdxOut,
    const aclTensor *expertTokenNumsOut, const aclTensor *epRecvCountOut, const aclTensor *tpRecvCountOut,
    uint64_t *workspaceSize, aclOpExecutor **executor);

__attribute__((visibility("default"))) aclnnStatus aclnnMoeDispatchShmem(void *workspace,
                                                                         uint64_t workspaceSize,
                                                                         aclOpExecutor *executor,
                                                                         aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
