/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add all2all with detour interface header file.
 * Create: 2026-01-05
 * Note:
 * History: 2026-01-05 add all2all with detour interface header file.
 */

#ifndef ACLNN_ALL2ALL_DETOUR_H_
#define ACLNN_ALL2ALL_DETOUR_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) aclnnStatus aclnnAll2AllDetourGetWorkspaceSize(
    const aclTensor *sendData,
    const aclTensor *commRankIds,
    const aclTensor *commArgs,
    int64_t magic,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

__attribute__((visibility("default"))) aclnnStatus aclnnAll2AllDetour(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif
#endif