/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add dispatch layout ZB interface header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create add dispatch layout ZB interface header file
 */
#ifndef ACLNN_DISPATCH_LAYOUT_ZB_H_
#define ACLNN_DISPATCH_LAYOUT_ZB_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnDispatchLayoutZbGetWorkspaceSize
 * topkIdx : required
 * numTokens : required
 * numRanks : required
 * numExperts : required
 * numTopk : required
 * localRankSize : required
 * numTokensPerRank : required
 * numTokensPerExpert : required
 * isTokenInRank : required
 * notifySendData : required
 * sendTokenIdx : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnDispatchLayoutZbGetWorkspaceSize(
    const aclTensor *topkIdx, int64_t numTokens, int64_t numRanks, int64_t numExperts, int64_t numTopk,
    int64_t localRankSize, const aclTensor *numTokensPerRank, const aclTensor *numTokensPerExpert,
    const aclTensor *isTokenInRank, const aclTensor *notifySendData, const aclTensor *sendTokenIdx,
    uint64_t *workspaceSize, aclOpExecutor **executor);

/* function: aclnnDispatchLayoutZb
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnDispatchLayoutZb(
    void *workspace, uint64_t workspaceSize, aclOpExecutor *executor, aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
