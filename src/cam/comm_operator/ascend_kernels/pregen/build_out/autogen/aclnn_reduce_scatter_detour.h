/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add reduceScatter with detour interface header file.
 * Create: 2026-01-05
 * Note:
 * History: 2026-01-05 add reduceScatter with detour interface header file.
 */

#ifndef ACLNN_REDUCE_SCATTER_DETOUR_H_
#define ACLNN_REDUCE_SCATTER_DETOUR_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) aclnnStatus aclnnReduceScatterDetourGetWorkspaceSize(
    const aclTensor *sendData,
    const aclTensor *commRankIds,
    const aclTensor *commArgs,
    int64_t magic,
    int64_t rankSize,
    int64_t op,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

__attribute__((visibility("default"))) aclnnStatus aclnnReduceScatterDetour(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus 
}
#endif
#endif