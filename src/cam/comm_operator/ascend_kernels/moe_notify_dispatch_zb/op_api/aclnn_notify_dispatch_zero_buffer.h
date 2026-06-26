/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add notify dispatch zero buffer interface header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add notify dispatch zero buffer interface header file
 */

#ifndef ACLNN_NOTIFY_DISPATCH_ZERO_BUFFER_H_
#define ACLNN_NOTIFY_DISPATCH_ZERO_BUFFER_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnNotifyDispatchZeroBufferGetWorkspaceSize
 * tokenPerExpertData : required
 * sendCount : required
 * rankSize : required
 * rankId : required
 * localRankSize : required
 * localRankId : required
 * topkNum : required
 * zeroBufferPtr : required
 * recvData : required
 * totalRecvTokens : required
 * maxBs : required
 * recvTokensPerExpert : required
 * putOffset : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnNotifyDispatchZeroBufferGetWorkspaceSize(
    const aclTensor *tokenPerExpertData, int64_t sendCount, int64_t rankSize, int64_t rankId, int64_t localRankSize,
    int64_t localRankId, int64_t topkNum, uint64_t zeroBufferPtr, const aclTensor *recvData,
    const aclTensor *totalRecvTokens, const aclTensor *maxBs, const aclTensor *recvTokensPerExpert,
    const aclTensor *putOffset, uint64_t *workspaceSize, aclOpExecutor **executor);

/* function: aclnnNotifyDispatchZeroBuffer
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnNotifyDispatchZeroBuffer(
    void *workspace, uint64_t workspaceSize, aclOpExecutor *executor, aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
