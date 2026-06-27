/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add moe combine normal interface header file.
 * Create: 2025-12-04
 * Note:
 * History: 2025-12-04 add moe combine normal interface header file.
 */

#ifndef ACLNN_MOE_COMBINE_NORMAL_H_
#define ACLNN_MOE_COMBINE_NORMAL_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) aclnnStatus aclnnMoeCombineNormalGetWorkspaceSize(
    const aclTensor *recvX, const aclTensor *tokenSrcInfo, const aclTensor *epRecvCounts,
    const aclTensor *recvTopkWeights, const aclTensor *tpRecvCountsOptional, char *epGroupName, int64_t epWorldSize,
    int64_t epRankId, char *tpGroupNameOptional, int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum,
    int64_t globalBs, const aclTensor *out, const aclTensor *sendCostStats, uint64_t *workspaceSize,
    aclOpExecutor **executor);

__attribute__((visibility("default"))) aclnnStatus aclnnMoeCombineNormal(void *workspace, uint64_t workspaceSize,
                                                                         aclOpExecutor *executor, aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif