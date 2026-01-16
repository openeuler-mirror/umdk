/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add notify dispatch interface header file.
 * Create: 2026-01-05
 * Note:
 * History: 2026-01-05 add notify dispatch interface header file.
 */

#ifndef ACLNN_NOTIFY_DISPATCH_H_
#define ACLNN_NOTIFY_DISPATCH_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnNotifyDispatchGetWorkspaceSize
 * sendData : required
 * tokenPerExpertData : required
 * sendCount : required
 * numTokens : required
 * commGroup : required
 * rankSize : required
 * rankId : required
 * localRankSize : required
 * localRankId : required
 * sendDataOffset : required
 * recvData : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnNotifyDispatchGetWorkspaceSize(
    const aclTensor *sendData, const aclTensor *tokenPerExpertData, int64_t sendCount, int64_t numTokens,
    char *commGroup, int64_t rankSize, int64_t rankId, int64_t localRankSize, int64_t localRankId,
    const aclTensor *sendDataOffset, const aclTensor *recvData, const aclTensor *totalRecvTokens,
    const aclTensor *recvCount, const aclTensor *recvOffset, const aclTensor *maxBs,
    const aclTensor *recvTokensPerExpert, uint64_t *workspaceSize, aclOpExecutor **executor);

/* function: aclnnNotifyDispatch
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnNotifyDispatch(void *workspace, uint64_t workspaceSize,
                                                                       aclOpExecutor *executor, aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif