/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe dispatch normal ZB interface header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add moe dispatch normal ZB interface header file
 */
#ifndef ACLNN_MOE_DISPATCH_NORMAL_ZB_H_
#define ACLNN_MOE_DISPATCH_NORMAL_ZB_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) aclnnStatus aclnnMoeDispatchNormalZbGetWorkspaceSize(
    const aclTensor *x, const aclTensor *topkIdx, const aclTensor *sendTokenIdx, const aclTensor *putOffset,
    int64_t epWorldSize, int64_t epRankId, int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum,
    int64_t quantMode, int64_t globalBs, uint64_t commMetaPtr, const aclTensor *recvX, const aclTensor *recvXScales,
    uint64_t *workspaceSize, aclOpExecutor **executor);

__attribute__((visibility("default"))) aclnnStatus aclnnMoeDispatchNormalZb(
    void *workspace, uint64_t workspaceSize, aclOpExecutor *executor, aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
