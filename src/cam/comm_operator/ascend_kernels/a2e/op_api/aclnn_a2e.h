/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add a2e interface header file.
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 add a2e interface header file.
 */

#ifndef ACLNN_A2E_H_
#define ACLNN_A2E_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) aclnnStatus aclnnA2eGetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *expertIds,
    const aclTensor *scales,
    int64_t batchSize,
    int64_t hiddenSize,
    int64_t topk,
    int64_t expertRankSize,
    int64_t attentionRankSize,
    int64_t rank,
    char *groupEp,
    int64_t aivNum,
    int64_t computeGate,
    const aclTensor *expandXOut,
    const aclTensor *simulateExpertIdsOut,
    const aclTensor *simulateExpertScalesOut,
    const aclTensor *attenBatchSize,
    const aclTensor *xActiveMaskOut,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

__attribute__((visibility("default"))) aclnnStatus aclnnA2e(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
