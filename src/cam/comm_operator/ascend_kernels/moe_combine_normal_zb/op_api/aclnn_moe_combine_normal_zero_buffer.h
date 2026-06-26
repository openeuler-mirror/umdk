/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe combine normal zero buffer interface header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add moe combine normal zero buffer interface header file
 */
#ifndef ACLNN_MOE_COMBINE_NORMAL_ZERO_BUFFER_H_
#define ACLNN_MOE_COMBINE_NORMAL_ZERO_BUFFER_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) aclnnStatus aclnnMoeCombineNormalZeroBufferGetWorkspaceSize(
    const aclTensor *recvX, const aclTensor *epRecvCounts, const aclTensor *recvTopkWeights, const aclTensor *topkIdx,
    const aclTensor *sendTokenIdx, const aclTensor *probGrad, uint64_t meta_data_ptr, int64_t epWorldSize,
    int64_t epRankId, int64_t tpWorldSize, int64_t tpRankId, int64_t moeExpertNum, int64_t globalBs,
    const aclTensor *out, const aclTensor *sendCostStats, const aclTensor *gradOut,
    uint64_t *workspaceSize, aclOpExecutor **executor);

__attribute__((visibility("default"))) aclnnStatus aclnnMoeCombineNormalZeroBuffer(
    void *workspace, uint64_t workspaceSize, aclOpExecutor *executor, aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
