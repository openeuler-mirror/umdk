/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add e2a interface header file.
 * Create: 2026-02-06
 * Note:
 * History: 2026-02-06 add e2a interface header file.
 */

#ifndef ACLNN_E2A_H_
#define ACLNN_E2A_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default")))
aclnnStatus aclnnE2aGetWorkspaceSize(
    const aclTensor *expandX,
    const aclTensor *attenBatchSize,
    int64_t batchSize,
    int64_t hiddenSize,
    int64_t topk,
    int64_t expertRankSize,
    int64_t attentionRankSize,
    int64_t rank,
    char *groupEp,
    int64_t aivNum,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

__attribute__((visibility("default")))
aclnnStatus aclnnE2a(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
